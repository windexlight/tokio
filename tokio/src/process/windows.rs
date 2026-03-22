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

use crate::io::{blocking::Blocking, AsyncRead, AsyncWrite, ReadBuf};
use crate::process::kill::Kill;
use crate::process::SpawnedChild;
use crate::sync::oneshot;

use std::fmt;
use std::fs::File as StdFile;
use std::future::Future;
use std::io;
use std::os::windows::prelude::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::pin::Pin;
use std::process::Stdio;
use std::process::{Child as StdChild, ExitStatus};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use windows_sys::{
    Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE,
        STATUS_SUCCESS, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
        WAIT_FAILED,
    },
    Win32::Storage::FileSystem::{ReadFile, WriteFile, GetFileType, FILE_TYPE_DISK},
    Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, RegisterWaitForSingleObject, UnregisterWaitEx,
        WaitForSingleObject, INFINITE, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
    },
    Win32::System::IO::{GetOverlappedResult, OVERLAPPED},
    Wdk::Storage::FileSystem::{
        FileModeInformation, NtQueryInformationFile, FILE_SYNCHRONOUS_IO_ALERT,
        FILE_SYNCHRONOUS_IO_NONALERT,
    },
};

/// Returns true if the handle was opened with FILE_FLAG_OVERLAPPED.
///
/// Uses `NtQueryInformationFile` with `FileModeInformation` to read the mode
/// flags for the handle. A handle is synchronous if either
/// `FILE_SYNCHRONOUS_IO_NONALERT` or `FILE_SYNCHRONOUS_IO_ALERT` is set; if
/// neither flag is present the handle is overlapped.
///
/// On any query failure we conservatively return `true` (assume overlapped),
/// which routes the caller to the safe `OverlappedFile` path rather than the
/// `std::fs::File::read` path that may abort.
unsafe fn is_overlapped_handle(handle: HANDLE) -> bool {
    // NtQueryInformationFile requires an IO_STATUS_BLOCK as an out-parameter.
    // We only care about the return value of the syscall, not the status block.
    let mut io_status = unsafe { std::mem::zeroed() };
    let mut mode: u32 = 0;
    let status = unsafe {
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

fn is_seekable(handle: HANDLE) -> bool {
    unsafe { GetFileType(handle) == FILE_TYPE_DISK }
}

/// A wrapper around an overlapped `HANDLE` that implements [`io::Read`] and
/// [`io::Write`] correctly by using `ReadFile`/`WriteFile` with an explicit
/// `OVERLAPPED` structure and a dedicated per-instance manual-reset event.
///
/// This avoids the `process::abort()` in
/// `std::sys::pal::windows::handle::Handle::synchronous_read` that fires when
/// `std::fs::File::read` is called on a handle that was opened with
/// `FILE_FLAG_OVERLAPPED`.
///
/// Using a dedicated event object (rather than waiting on the file handle
/// itself) eliminates the ambiguity that made the stdlib's fallback
/// `WaitForSingleObject`-on-file-handle approach unreliable.
///
/// Note: `ReadFile`/`WriteFile` on overlapped handles do not advance an
/// implicit file position — the `Offset`/`OffsetHigh` fields of the
/// `OVERLAPPED` struct control position for seekable files. For named pipes
/// (the primary use case here) position is irrelevant. If this type is ever
/// extended to seekable overlapped files, position tracking will be needed.
///
/// See: <https://github.com/rust-lang/rust/issues/81357>
struct OverlappedFile {
    handle: HANDLE,
    event: HANDLE,
}

// SAFETY: `HANDLE` is a pointer-sized integer. We have exclusive ownership of
// both `handle` and `event`; no other code touches them concurrently.
unsafe impl Send for OverlappedFile {}

// SAFETY: All mutable access is serialised through `Mutex<OverlappedFile>` at
// the `ArcFile` layer; `OverlappedFile` itself does not allow shared mutation.
unsafe impl Sync for OverlappedFile {}

impl OverlappedFile {
    /// Takes ownership of `handle` and creates a dedicated manual-reset event
    /// for overlapped I/O completion.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid `HANDLE` opened with `FILE_FLAG_OVERLAPPED`
    /// and must not be owned by any other value after this call.
    unsafe fn new(handle: HANDLE) -> io::Result<Self> {
        // lpEventAttributes = null  → default security, not inheritable
        // bManualReset = 1          → manual-reset; we reset it ourselves
        // bInitialState = 0         → initially unsignaled
        // lpName = null             → unnamed
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(OverlappedFile { handle, event })
    }

    fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OverlappedFile {
    fn drop(&mut self) {
        // SAFETY: we own both handles and this is the only place they are closed.
        unsafe {
            CloseHandle(self.event);
            CloseHandle(self.handle);
        }
    }
}

impl io::Read for OverlappedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: all Win32 calls are made with valid, owned handles and
        // correctly initialised OVERLAPPED / buffer pointers. The OVERLAPPED
        // struct lives on the stack for the duration of the operation and is
        // not moved while the kernel has a reference to it.
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = self.event;
            let mut bytes_read: u32 = 0;

            let ok = ReadFile(
                self.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            );

            if ok != 0 {
                // Completed synchronously.
                return Ok(bytes_read as usize);
            }

            match windows_sys::Win32::Foundation::GetLastError() {
                ERROR_IO_PENDING => {
                    // Wait for the overlapped operation to complete on our
                    // dedicated event object.
                    let wait = WaitForSingleObject(self.event, INFINITE);
                    if wait == WAIT_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    let mut transferred: u32 = 0;
                    // bWait = 0: don't wait again, we already waited above.
                    let ok = GetOverlappedResult(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        0,
                    );
                    if ok == 0 {
                        match windows_sys::Win32::Foundation::GetLastError() {
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
        // SAFETY: same rationale as `Read` above.
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = self.event;
            let mut bytes_written: u32 = 0;

            let ok = WriteFile(
                self.handle,
                buf.as_ptr().cast(),
                buf.len() as u32,
                &mut bytes_written,
                &mut overlapped,
            );

            if ok != 0 {
                return Ok(bytes_written as usize);
            }

            match windows_sys::Win32::Foundation::GetLastError() {
                ERROR_IO_PENDING => {
                    let wait = WaitForSingleObject(self.event, INFINITE);
                    if wait == WAIT_FAILED {
                        return Err(io::Error::last_os_error());
                    }
                    let mut transferred: u32 = 0;
                    let ok = GetOverlappedResult(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        0,
                    );
                    if ok == 0 {
                        match windows_sys::Win32::Foundation::GetLastError() {
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
/// `Sync` (non-overlapped) handles are wrapped directly in `StdFile`.
/// Overlapped handles are wrapped in `OverlappedFile` behind a `Mutex` so that
/// concurrent callers — e.g. two blocking-pool threads racing on the same
/// `ArcFile` clone — serialise their I/O rather than racing on the `OVERLAPPED`
/// structure and event handle inside `OverlappedFile`.
enum ArcFileInner {
    Sync(StdFile),
    Overlapped(Mutex<OverlappedFile>),
}

/// A cloneable, cheaply shared file handle that correctly handles both
/// synchronous and overlapped Windows HANDLEs.
///
/// Cloning increments an `Arc` reference count; no duplication of the
/// underlying OS handle occurs. All clones share the same `ArcFileInner`.
#[derive(Clone)]
struct ArcFile(Arc<ArcFileInner>);

impl fmt::Debug for ArcFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.as_ref() {
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
        ArcFile(Arc::new(ArcFileInner::Overlapped(Mutex::new(file))))
    }

    fn as_raw_handle(&self) -> RawHandle {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => f.as_raw_handle(),
            ArcFileInner::Overlapped(f) => {
                // SAFETY: we only read the handle field, which is set at
                // construction and never mutated.
                f.lock().unwrap().as_raw_handle() as RawHandle
            }
        }
    }
}

impl io::Read for ArcFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => {
                // SAFETY: `&StdFile` implements `Read`; this is the same
                // approach used by the original code.
                (&*f).read(bytes)
            }
            ArcFileInner::Overlapped(f) => f.lock().unwrap().read(bytes),
        }
    }
}

impl io::Write for ArcFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => (&*f).write(bytes),
            ArcFileInner::Overlapped(f) => f.lock().unwrap().write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.as_ref() {
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
/// `NtQueryInformationFile`. Overlapped handles are wrapped in
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

    let arc_file = if unsafe { is_overlapped_handle(raw_handle) } {
        if is_seekable(raw_handle) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "child stdio handle is a seekable overlapped file; \
                this configuration is not supported",
            ));
        }
        // Overlapped handle: wrap it so that reads/writes go through the
        // ReadFile/WriteFile + OVERLAPPED path rather than std::fs::File::read.
        let overlapped = unsafe { OverlappedFile::new(raw_handle)? };
        ArcFile::overlapped(overlapped)
    } else {
        // Synchronous handle: unchanged behaviour from before this patch.
        let file = unsafe { StdFile::from_raw_handle(raw_handle as RawHandle) };
        ArcFile::sync(file)
    };

    let io_clone = arc_file.clone();
    // SAFETY: the `Read` implementation of `io_clone` does not read from the
    // buffer it is borrowing and correctly reports the number of bytes written.
    let io = unsafe { Blocking::new(io_clone) };
    Ok(ChildStdio { inner: arc_file, io })
}

fn convert_to_file(child_stdio: ChildStdio) -> io::Result<StdFile> {
    let ChildStdio { inner, io } = child_stdio;
    // Drop `io` first to release its clone of the Arc before we try
    // `try_unwrap` below.
    drop(io);

    match Arc::try_unwrap(inner.0) {
        Ok(ArcFileInner::Sync(f)) => Ok(f),
        Ok(ArcFileInner::Overlapped(m)) => {
            // We are the sole owner of the OverlappedFile. Duplicate the
            // underlying handle as a plain synchronous StdFile, then let the
            // OverlappedFile (and its event) drop normally.
            let f = m.into_inner().unwrap();
            duplicate_handle_raw(f.handle)
            // `f` drops here, closing the original overlapped handle.
        }
        Err(arc) => {
            // Other clones of the Arc still exist (e.g. a `ChildStdio` on
            // another task). Duplicate the handle so the caller gets an
            // independent StdFile without disturbing the live clone.
            match arc.as_ref() {
                ArcFileInner::Sync(f) => duplicate_handle(f),
                ArcFileInner::Overlapped(m) => {
                    duplicate_handle_raw(m.lock().unwrap().handle)
                }
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
