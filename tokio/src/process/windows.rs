//! Windows asynchronous process handling.
//!
//! Like with Unix we don't actually have a way of registering a process with an
//! IOCP object. As a result we similarly need another mechanism for getting a
//! signal when a process has exited. For now this is implemented with the
//! `RegisterWaitForSingleObject` function in the kernel32.dll.
//!
//! This strategy is the same that libuv takes and essentially just queues up a
//! wait for the process in a kernel32-specific thread pool. Once the object is
//! notified (e.g. the process exits) then we have a callback that basically
//! just completes a `Oneshot`.
//!
//! The `poll_exit` implementation will attempt to wait for the process in a
//! nonblocking fashion, but failing that it'll fire off a
//! `RegisterWaitForSingleObject` and then wait on the other end of the oneshot
//! from then on out.
//!
//! # Child stdio and overlapped handles
//!
//! Child stdio handles are read via `Blocking<ArcFile>` on a thread-pool
//! thread. On Windows, `std::fs::File::read` aborts the process if the
//! underlying handle was opened with `FILE_FLAG_OVERLAPPED` (see
//! rust-lang/rust#81357). Handles of this kind can appear in the stdio chain
//! when a child process inherits them from a parent — for example, when an SSH
//! agent uses overlapped named pipes for IPC and those pipes end up inherited
//! across `CreateProcess`.
//!
//! To handle this, `stdio()` detects overlapped handles via
//! `NtQueryInformationFile` and wraps them in `OverlappedFile`, which performs
//! I/O with `ReadFile`/`WriteFile` and an explicit `OVERLAPPED` structure.
//! Seekable overlapped handles (`FILE_TYPE_DISK`) are rejected with an
//! `Unsupported` error because position tracking is not implemented.
//! Non-overlapped handles continue to use the original `std::fs::File` path.

use crate::io::{blocking::Blocking, AsyncRead, AsyncWrite, ReadBuf};
use crate::process::kill::Kill;
use crate::process::SpawnedChild;
use crate::sync::oneshot;

use std::fmt;
use std::fs::File as StdFile;
use std::future::Future;
use std::io;
use std::os::windows::prelude::{
    AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle,
};
use std::pin::Pin;
use std::process::Stdio;
use std::process::{Child as StdChild, ExitStatus};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use windows_sys::{
    Win32::Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE,
        ERROR_HANDLE_EOF, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE, STATUS_SUCCESS,
        WAIT_FAILED,
    },
    Win32::Storage::FileSystem::{GetFileType, ReadFile, WriteFile, FILE_TYPE_DISK},
    Win32::System::IO::{GetOverlappedResult, OVERLAPPED},
    Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, RegisterWaitForSingleObject, UnregisterWaitEx,
        WaitForSingleObject, INFINITE, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
    },
    Wdk::Storage::FileSystem::{
        FileModeInformation, NtQueryInformationFile, FILE_SYNCHRONOUS_IO_ALERT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    },
};

/// Returns `true` if `handle` was opened with `FILE_FLAG_OVERLAPPED`.
///
/// Uses `NtQueryInformationFile` with `FileModeInformation` to read the mode
/// flags. A handle is synchronous if either `FILE_SYNCHRONOUS_IO_NONALERT` or
/// `FILE_SYNCHRONOUS_IO_ALERT` is set; if neither flag is present the handle
/// is overlapped.
///
/// On any query failure the function conservatively returns `true` (assume
/// overlapped), routing the caller to the safe `OverlappedFile` path rather
/// than the `std::fs::File::read` path that may abort.
///
/// # Safety
///
/// `handle` must be a valid open `HANDLE`.
#[must_use]
unsafe fn is_overlapped_handle(handle: HANDLE) -> bool {
    // Zero-initialise the IO_STATUS_BLOCK out-parameter and call the NT
    // function in a single unsafe block — both operations form one logical
    // unit; splitting them would imply the zeroing carries independent
    // unsafety.
    let mut mode: u32 = 0;
    let status = unsafe {
        let mut io_status = std::mem::zeroed();
        NtQueryInformationFile(
            handle,
            &mut io_status,
            &mut mode as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            FileModeInformation,
        )
    };
    if status != STATUS_SUCCESS {
        // Conservatively treat unknown handles as overlapped so we never call
        // std::fs::File::read on one.
        return true;
    }
    (mode & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) == 0
}

/// Returns `true` if `handle` refers to a disk file (i.e. is seekable).
///
/// # Safety
///
/// `handle` must be a valid open `HANDLE`.
#[must_use]
unsafe fn is_seekable(handle: HANDLE) -> bool {
    unsafe { GetFileType(handle) == FILE_TYPE_DISK }
}

/// Mutable I/O state for an overlapped handle.
///
/// Kept behind a `Mutex` inside [`OverlappedInner`] so that concurrent
/// callers serialise their access to the `OVERLAPPED` struct and event handle
/// rather than racing on them.
struct OverlappedState {
    /// Manual-reset event used to signal I/O completion.  Created once at
    /// construction and closed in `Drop`.
    event: HANDLE,
}

// SAFETY: `HANDLE` is a pointer-sized integer.  `OverlappedState` is only
// ever accessed through `Mutex<OverlappedState>`; the mutex enforces exclusive
// access.
unsafe impl Send for OverlappedState {}

// SAFETY: all mutable access is serialised through the enclosing
// `Mutex<OverlappedState>` in `OverlappedInner`.
unsafe impl Sync for OverlappedState {}

impl Drop for OverlappedState {
    fn drop(&mut self) {
        // SAFETY: we own `event` and this is the only place it is closed.
        unsafe {
            CloseHandle(self.event);
        }
    }
}

/// The immutable part of an overlapped handle — the `HANDLE` value itself.
///
/// Storing `handle` outside the `Mutex` means [`OverlappedInner::as_raw_handle`]
/// can return it cheaply without acquiring any lock, matching the expectation
/// that handle accessors are non-blocking.
struct OverlappedInner {
    /// The underlying overlapped `HANDLE`.  Immutable after construction.
    handle: HANDLE,
    /// Mutable per-operation state, serialised by the mutex.
    state: Mutex<OverlappedState>,
}

// SAFETY: `HANDLE` is a pointer-sized integer.  `handle` is immutable after
// construction.  All mutable access to `state` is serialised by the `Mutex`.
unsafe impl Send for OverlappedInner {}
unsafe impl Sync for OverlappedInner {}

impl OverlappedInner {
    /// Takes ownership of `handle` and creates a dedicated manual-reset event
    /// for overlapped I/O completion.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid `HANDLE` opened with `FILE_FLAG_OVERLAPPED`
    /// and must not be owned by any other value after this call.
    unsafe fn new(handle: HANDLE) -> io::Result<Self> {
        // lpEventAttributes = null  → default security, not inheritable
        // bManualReset      = 1     → manual-reset; we reset it ourselves
        // bInitialState     = 0     → initially unsignaled
        // lpName            = null  → unnamed
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(OverlappedInner {
            handle,
            state: Mutex::new(OverlappedState { event }),
        })
    }

    fn as_raw_handle(&self) -> HANDLE {
        // `handle` is immutable after construction; no lock needed.
        self.handle
    }
}

impl Drop for OverlappedInner {
    fn drop(&mut self) {
        // SAFETY: we own `handle` and this is the only place it is closed.
        // `state` (and the event inside it) is dropped by its own `Drop` impl.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// A wrapper around an overlapped `HANDLE` that implements [`io::Read`] and
/// [`io::Write`] correctly by using `ReadFile`/`WriteFile` with an explicit
/// `OVERLAPPED` structure and a dedicated per-instance manual-reset event.
///
/// This avoids the `process::abort()` in
/// `std::sys::pal::windows::handle::Handle::synchronous_read` that fires when
/// `std::fs::File::read` is called on a handle opened with
/// `FILE_FLAG_OVERLAPPED`.
///
/// Using a dedicated event object (rather than waiting on the file handle
/// itself) eliminates the ambiguity that made the stdlib's fallback
/// `WaitForSingleObject`-on-file-handle approach unreliable.
///
/// # Seekable overlapped handles
///
/// `ReadFile`/`WriteFile` on overlapped handles do not advance an implicit
/// file position.  For pipes and character devices this is irrelevant because
/// the kernel ignores the `Offset`/`OffsetHigh` fields of the `OVERLAPPED`
/// struct.  For disk files (`FILE_TYPE_DISK`) opened with
/// `FILE_FLAG_OVERLAPPED`, omitting position tracking would cause silent data
/// corruption.  [`stdio`] detects this combination and returns an
/// `Unsupported` error rather than constructing an `OverlappedFile`, so this
/// type is only ever instantiated for non-seekable handles.
///
/// See: <https://github.com/rust-lang/rust/issues/81357>
struct OverlappedFile(OverlappedInner);

impl io::Read for OverlappedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let state = self.0.state.lock().unwrap();
        // SAFETY: all Win32 calls are made with valid, owned handles and
        // correctly initialised OVERLAPPED / buffer pointers.  The OVERLAPPED
        // struct lives on the stack for the duration of this call.  The
        // `INFINITE` wait below guarantees the kernel has released its
        // reference to the struct before `read` returns, making stack
        // allocation sound.
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = state.event;
            let mut bytes_read: u32 = 0;

            let ok = ReadFile(
                self.0.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            );

            if ok != 0 {
                // Completed synchronously.
                return Ok(bytes_read as usize);
            }

            match GetLastError() {
                ERROR_IO_PENDING => {
                    // Wait for completion on our dedicated event object.
                    // `INFINITE` means we block until the kernel signals it,
                    // which guarantees the OVERLAPPED struct is no longer
                    // referenced when we proceed.
                    let wait = WaitForSingleObject(state.event, INFINITE);
                    if wait == WAIT_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    let mut transferred: u32 = 0;
                    // bWait = 0: we already waited above.
                    let ok = GetOverlappedResult(
                        self.0.handle,
                        &mut overlapped,
                        &mut transferred,
                        0,
                    );
                    if ok == 0 {
                        match GetLastError() {
                            ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => return Ok(0),
                            e => return Err(io::Error::from_raw_os_error(e as i32)),
                        }
                    }
                    Ok(transferred as usize)
                }
                ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => Ok(0),
                e => Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }
}

impl io::Write for OverlappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let state = self.0.state.lock().unwrap();
        // SAFETY: same rationale as `Read` above.
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = state.event;
            let mut bytes_written: u32 = 0;

            let ok = WriteFile(
                self.0.handle,
                buf.as_ptr().cast(),
                buf.len() as u32,
                &mut bytes_written,
                &mut overlapped,
            );

            if ok != 0 {
                return Ok(bytes_written as usize);
            }

            match GetLastError() {
                ERROR_IO_PENDING => {
                    let wait = WaitForSingleObject(state.event, INFINITE);
                    if wait == WAIT_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    let mut transferred: u32 = 0;
                    let ok = GetOverlappedResult(
                        self.0.handle,
                        &mut overlapped,
                        &mut transferred,
                        0,
                    );
                    if ok == 0 {
                        match GetLastError() {
                            // A broken pipe on write is a real error: the
                            // reader has gone away and data was not delivered.
                            // Map to BrokenPipe rather than Ok(0) so callers
                            // are not misled into thinking the write succeeded.
                            ERROR_BROKEN_PIPE => {
                                return Err(io::Error::from(io::ErrorKind::BrokenPipe))
                            }
                            ERROR_HANDLE_EOF => return Ok(0),
                            e => return Err(io::Error::from_raw_os_error(e as i32)),
                        }
                    }
                    Ok(transferred as usize)
                }
                ERROR_BROKEN_PIPE => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                ERROR_HANDLE_EOF => Ok(0),
                e => Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[must_use = "futures do nothing unless polled"]
pub(crate) struct Child {
    child: StdChild,
    waiting: Option<Waiting>,
}

impl fmt::Debug for Child {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Child")
            .field("pid", &self.id())
            .field("child", &self.child)
            .field("waiting", &"..")
            .finish()
    }
}

struct Waiting {
    rx: oneshot::Receiver<()>,
    wait_object: HANDLE,
    tx: *mut Option<oneshot::Sender<()>>,
}

unsafe impl Sync for Waiting {}
unsafe impl Send for Waiting {}

pub(crate) fn build_child(mut child: StdChild) -> io::Result<SpawnedChild> {
    let stdin = child.stdin.take().map(stdio).transpose()?;
    let stdout = child.stdout.take().map(stdio).transpose()?;
    let stderr = child.stderr.take().map(stdio).transpose()?;

    Ok(SpawnedChild {
        child: Child {
            child,
            waiting: None,
        },
        stdin,
        stdout,
        stderr,
    })
}

impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

impl Kill for Child {
    fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

impl Future for Child {
    type Output = io::Result<ExitStatus>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = Pin::get_mut(self);
        loop {
            if let Some(ref mut w) = inner.waiting {
                match Pin::new(&mut w.rx).poll(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(_)) => panic!("should not be canceled"),
                    Poll::Pending => return Poll::Pending,
                }
                let status = inner.try_wait()?.expect("not ready yet");
                return Poll::Ready(Ok(status));
            }

            if let Some(e) = inner.try_wait()? {
                return Poll::Ready(Ok(e));
            }
            let (tx, rx) = oneshot::channel();
            let ptr = Box::into_raw(Box::new(Some(tx)));
            let mut wait_object = null_mut();
            let rc = unsafe {
                RegisterWaitForSingleObject(
                    &mut wait_object,
                    inner.child.as_raw_handle() as _,
                    Some(callback),
                    ptr as *mut _,
                    INFINITE,
                    WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
                )
            };
            if rc == 0 {
                let err = io::Error::last_os_error();
                drop(unsafe { Box::from_raw(ptr) });
                return Poll::Ready(Err(err));
            }
            inner.waiting = Some(Waiting {
                rx,
                wait_object,
                tx: ptr,
            });
        }
    }
}

impl AsRawHandle for Child {
    fn as_raw_handle(&self) -> RawHandle {
        self.child.as_raw_handle()
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        unsafe {
            let rc = UnregisterWaitEx(self.wait_object, INVALID_HANDLE_VALUE);
            if rc == 0 {
                panic!("failed to unregister: {}", io::Error::last_os_error());
            }
            drop(Box::from_raw(self.tx));
        }
    }
}

unsafe extern "system" fn callback(ptr: *mut std::ffi::c_void, _timer_fired: bool) {
    let complete = unsafe { &mut *(ptr as *mut Option<oneshot::Sender<()>>) };
    let _ = complete.take().unwrap().send(());
}

/// The inner handle held by an [`ArcFile`].
///
/// `Sync` (non-overlapped) handles are wrapped in `StdFile`.
/// Overlapped handles are wrapped in `OverlappedFile`.  Concurrent I/O
/// callers are serialised by the `Mutex<OverlappedState>` *inside*
/// `OverlappedFile` — there is no outer `Mutex` here.  `ArcFile::read` and
/// `ArcFile::write` take `&mut self`, which gives them exclusive access to
/// the `Arc` reference; they then reach through to `OverlappedFile::read` /
/// `OverlappedFile::write`, which take `&mut self` and acquire the inner lock.
///
/// `OverlappedInner::handle` is stored *outside* the inner `Mutex` (as a
/// bare field on `OverlappedInner`) so that [`ArcFile::as_raw_handle`] can
/// return it without acquiring any lock.
enum ArcFileInner {
    Sync(StdFile),
    Overlapped(OverlappedFile),
}

// SAFETY: `ArcFileInner::Overlapped` contains `OverlappedFile`, which wraps
// `OverlappedInner`.  `OverlappedInner` is `Send + Sync` — `handle` is
// immutable after construction, and all mutable state is behind a `Mutex`.
unsafe impl Send for ArcFileInner {}
unsafe impl Sync for ArcFileInner {}

/// A cloneable, cheaply shared file handle that correctly handles both
/// synchronous and overlapped Windows HANDLEs.
///
/// Cloning increments an `Arc` reference count; no duplication of the
/// underlying OS handle occurs.  All clones share the same `ArcFileInner`.
#[derive(Clone)]
struct ArcFile(Arc<ArcFileInner>);

impl fmt::Debug for ArcFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.0 {
            ArcFileInner::Sync(_) => write!(f, "ArcFile(Sync)"),
            ArcFileInner::Overlapped(_) => write!(f, "ArcFile(Overlapped)"),
        }
    }
}

impl ArcFile {
    fn sync(file: StdFile) -> Self {
        ArcFile(Arc::new(ArcFileInner::Sync(file)))
    }

    fn overlapped(file: OverlappedFile) -> Self {
        ArcFile(Arc::new(ArcFileInner::Overlapped(file)))
    }

    fn as_raw_handle(&self) -> RawHandle {
        match &*self.0 {
            ArcFileInner::Sync(f) => f.as_raw_handle(),
            // `OverlappedInner::handle` is immutable after construction;
            // read it directly without acquiring the I/O-state mutex.
            ArcFileInner::Overlapped(f) => f.0.as_raw_handle() as RawHandle,
        }
    }
}

impl io::Read for ArcFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &*self.0 {
            ArcFileInner::Sync(f) => (&*f).read(bytes),
            // SAFETY: We need `&mut OverlappedFile` to call `read`, but the
            // `Arc` only gives us `&OverlappedFile`.  The cast is sound because
            // `OverlappedFile::read` never aliases its own fields unsafely: all
            // mutable state (`OVERLAPPED` struct, event handle) is accessed only
            // after acquiring `Mutex<OverlappedState>`.  Any concurrent caller
            // reaching the same `OverlappedFile` through a different `ArcFile`
            // clone will block on that same mutex, so there is no data race.
            ArcFileInner::Overlapped(f) => unsafe {
                (&mut *(f as *const OverlappedFile as *mut OverlappedFile)).read(bytes)
            },
        }
    }
}

impl io::Write for ArcFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &*self.0 {
            ArcFileInner::Sync(f) => (&*f).write(bytes),
            // SAFETY: same rationale as `Read` above — all mutable state in
            // `OverlappedFile` is guarded by `Mutex<OverlappedState>`.
            ArcFileInner::Overlapped(f) => unsafe {
                (&mut *(f as *const OverlappedFile as *mut OverlappedFile)).write(bytes)
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &*self.0 {
            ArcFileInner::Sync(f) => (&*f).flush(),
            ArcFileInner::Overlapped(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChildStdio {
    // Retains a clone of the ArcFile so we can return the raw handle even
    // while the Blocking<ArcFile> inside `io` is occupied on a thread-pool
    // thread.
    inner: ArcFile,
    // Drives I/O operations asynchronously via the blocking thread pool.
    io: Blocking<ArcFile>,
}

impl ChildStdio {
    pub(super) fn into_owned_handle(self) -> io::Result<OwnedHandle> {
        convert_to_file(self).map(OwnedHandle::from)
    }
}

impl AsRawHandle for ChildStdio {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

impl AsyncRead for ChildStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Wrap a raw stdio handle for use with Tokio's blocking I/O layer.
///
/// Detects whether the handle was opened with `FILE_FLAG_OVERLAPPED` using
/// `NtQueryInformationFile`.  Overlapped handles are wrapped in
/// [`OverlappedFile`], which performs I/O via `ReadFile`/`WriteFile` with an
/// explicit `OVERLAPPED` structure, avoiding the `process::abort()` triggered
/// by `std::fs::File::read` on such handles (see rust-lang/rust#81357).
/// Non-overlapped handles continue to use the original `std::fs::File` path.
///
/// See: <https://github.com/rust-lang/rust/issues/81357>
///      <https://github.com/rust-lang/rust/pull/98950>
pub(super) fn stdio<T>(io: T) -> io::Result<ChildStdio>
where
    T: IntoRawHandle,
{
    let raw_handle = io.into_raw_handle() as HANDLE;

    // SAFETY: `raw_handle` is a valid open handle — it was just produced by
    // `into_raw_handle` on a live stdio object.
    let arc_file = if unsafe { is_overlapped_handle(raw_handle) } {
        // SAFETY: same as above.
        if unsafe { is_seekable(raw_handle) } {
            // Seekable overlapped handles would require position tracking
            // inside OverlappedFile (since ReadFile/WriteFile on overlapped
            // handles do not advance an implicit file pointer).  That is out
            // of scope for this targeted fix; fail loudly rather than
            // silently corrupting data.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "child stdio handle is a seekable overlapped file; \
                this configuration is not supported",
            ));
        }
        // SAFETY: `raw_handle` is a valid overlapped handle that is not owned
        // by any other value after `into_raw_handle`.
        let overlapped = unsafe { OverlappedFile(OverlappedInner::new(raw_handle)?) };
        ArcFile::overlapped(overlapped)
    } else {
        // Synchronous handle: unchanged behaviour from before this patch.
        // SAFETY: `raw_handle` is a valid handle transferred from the caller.
        let file = unsafe { StdFile::from_raw_handle(raw_handle as RawHandle) };
        ArcFile::sync(file)
    };

    // SAFETY: the `Read` implementation of `ArcFile` does not read from the
    // buffer it is passed and correctly reports the number of bytes written.
    let io = unsafe { Blocking::new(arc_file.clone()) };
    Ok(ChildStdio { inner: arc_file, io })
}

fn convert_to_file(child_stdio: ChildStdio) -> io::Result<StdFile> {
    let ChildStdio { inner, io } = child_stdio;
    // Drop `io` first to release its clone of the Arc before we try
    // `try_unwrap` below.
    drop(io);

    match Arc::try_unwrap(inner.0) {
        Ok(ArcFileInner::Sync(f)) => Ok(f),
        Ok(ArcFileInner::Overlapped(f)) => {
            // We are the sole owner of the OverlappedFile.  Duplicate the
            // underlying handle as a synchronous StdFile for the caller, then
            // let the OverlappedFile (and its event) drop normally.
            //
            // NOTE: `DuplicateHandle` with `DUPLICATE_SAME_ACCESS` preserves
            // the original access rights but produces a *new* kernel handle
            // object.  The duplicate will be synchronous if and only if the
            // source was opened synchronously — an overlapped source yields an
            // overlapped duplicate.  Callers of `into_owned_handle` must not
            // use the returned handle for blocking std I/O; it is intended for
            // passing to child processes via `Stdio::from` or similar.
            duplicate_handle_raw(f.0.handle)
            // `f` drops here, closing the original overlapped handle and event.
        }
        Err(arc) => {
            // Other clones of the Arc still exist (e.g. a `ChildStdio` on
            // another task).  Duplicate the handle so the caller gets an
            // independent StdFile without disturbing the live clone.
            match &*arc {
                ArcFileInner::Sync(f) => duplicate_handle(f),
                // See NOTE above regarding the duplicate being overlapped.
                ArcFileInner::Overlapped(f) => duplicate_handle_raw(f.0.handle),
            }
        }
    }
}

pub(crate) fn convert_to_stdio(child_stdio: ChildStdio) -> io::Result<Stdio> {
    convert_to_file(child_stdio).map(Stdio::from)
}

fn duplicate_handle<T: AsRawHandle>(io: &T) -> io::Result<StdFile> {
    duplicate_handle_raw(io.as_raw_handle() as HANDLE)
}

fn duplicate_handle_raw(handle: HANDLE) -> io::Result<StdFile> {
    unsafe {
        let mut dup_handle = INVALID_HANDLE_VALUE;
        let cur_proc = GetCurrentProcess();

        let status = DuplicateHandle(
            cur_proc,
            handle,
            cur_proc,
            &mut dup_handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        );

        if status == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(StdFile::from_raw_handle(dup_handle as RawHandle))
    }
}
