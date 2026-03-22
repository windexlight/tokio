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
use std::sync::Arc;
use std::task::{Context, Poll};

use windows_sys::{
    Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE, STATUS_SUCCESS,
        ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
    },
    Win32::Storage::FileSystem::{
        ReadFile, WriteFile,
    },
    Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, RegisterWaitForSingleObject, UnregisterWaitEx,
        WaitForSingleObject, INFINITE, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
    },
    Win32::System::IO::{GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED},
    Wdk::Storage::FileSystem::{
        FileModeInformation,
        FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_SYNCHRONOUS_IO_ALERT,
        NtQueryInformationFile,
    },
};

/// Returns true if the handle was opened with FILE_FLAG_OVERLAPPED.
/// On any query failure, conservatively returns true (assume overlapped).
unsafe fn is_overlapped_handle(handle: HANDLE) -> bool {
    let mut io_status: IO_STATUS_BLOCK = std::mem::zeroed();
    let mut mode: u32 = 0;
    let status = NtQueryInformationFile(
        handle,
        &mut io_status,
        &mut mode as *mut u32 as *mut std::ffi::c_void,
        std::mem::size_of::<u32>() as u32,
        FileModeInformation,
    );
    if status != STATUS_SUCCESS {
        return true;
    }
    (mode & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) == 0
}

/// A wrapper around an overlapped HANDLE that implements io::Read and io::Write
/// correctly by using ReadFile/WriteFile with an explicit OVERLAPPED structure
/// and a dedicated per-instance event object.
///
/// This avoids the abort in std::sys::pal::windows::handle::Handle::synchronous_read
/// that fires when std::fs::File::read() is called on an overlapped handle.
///
/// See: https://github.com/rust-lang/rust/issues/81357
struct OverlappedFile {
    handle: HANDLE,
    event: HANDLE,
}

// Safety: HANDLE is just a pointer-sized integer; we own both handles exclusively.
unsafe impl Send for OverlappedFile {}
unsafe impl Sync for OverlappedFile {}

impl OverlappedFile {
    /// Takes ownership of `handle`. Creates a dedicated manual-reset event for I/O.
    unsafe fn new(handle: HANDLE) -> io::Result<Self> {
        // Manual-reset event, initially unsignaled.
        let event = CreateEventW(null_mut(), 1, 0, null_mut());
        if event == std::ptr::null_mut() || event == INVALID_HANDLE_VALUE {
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
        unsafe {
            CloseHandle(self.event);
            CloseHandle(self.handle);
        }
    }
}

impl io::Read for OverlappedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = self.event;
            let mut bytes_read: u32 = 0;

            let ok = ReadFile(
                self.handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            );

            if ok != 0 {
                // Completed synchronously.
                return Ok(bytes_read as usize);
            }

            let err = windows_sys::Win32::Foundation::GetLastError();
            match err {
                ERROR_IO_PENDING => {
                    // Wait for the overlapped operation on our dedicated event.
                    WaitForSingleObject(self.event, INFINITE);
                    let mut transferred: u32 = 0;
                    let got = GetOverlappedResult(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        0, // don't wait again, already waited above
                    );
                    if got == 0 {
                        let e = windows_sys::Win32::Foundation::GetLastError();
                        if e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF {
                            return Ok(0); // EOF
                        }
                        return Err(io::Error::from_raw_os_error(e as i32));
                    }
                    Ok(transferred as usize)
                }
                ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => Ok(0), // EOF
                e => Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }
}

impl io::Write for OverlappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = self.event;
            let mut bytes_written: u32 = 0;

            let ok = WriteFile(
                self.handle,
                buf.as_ptr() as *const _,
                buf.len() as u32,
                &mut bytes_written,
                &mut overlapped,
            );

            if ok != 0 {
                return Ok(bytes_written as usize);
            }

            let err = windows_sys::Win32::Foundation::GetLastError();
            match err {
                ERROR_IO_PENDING => {
                    WaitForSingleObject(self.event, INFINITE);
                    let mut transferred: u32 = 0;
                    let got = GetOverlappedResult(
                        self.handle,
                        &mut overlapped,
                        &mut transferred,
                        0,
                    );
                    if got == 0 {
                        let e = windows_sys::Win32::Foundation::GetLastError();
                        if e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF {
                            return Ok(0);
                        }
                        return Err(io::Error::from_raw_os_error(e as i32));
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

/// A file handle that can be either a plain std::fs::File (for synchronous handles)
/// or an OverlappedFile (for overlapped handles). Implements io::Read and io::Write
/// for both cases, routing to the appropriate implementation.
enum ArcFileInner {
    Sync(Arc<StdFile>),
    Overlapped(Arc<OverlappedFile>),
}

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
        ArcFile(Arc::new(ArcFileInner::Sync(Arc::new(file))))
    }

    fn overlapped(file: OverlappedFile) -> Self {
        ArcFile(Arc::new(ArcFileInner::Overlapped(Arc::new(file))))
    }

    fn as_raw_handle(&self) -> RawHandle {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => f.as_raw_handle(),
            ArcFileInner::Overlapped(f) => f.as_raw_handle() as RawHandle,
        }
    }


}

impl io::Read for ArcFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => (&**f).read(bytes),
            ArcFileInner::Overlapped(f) => {
                // Safety: Blocking<ArcFile> ensures only one thread calls read at a time.
                let f = unsafe { &mut *(Arc::as_ptr(f) as *mut OverlappedFile) };
                f.read(bytes)
            }
        }
    }
}

impl io::Write for ArcFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.0.as_ref() {
            ArcFileInner::Sync(f) => (&**f).write(bytes),
            ArcFileInner::Overlapped(f) => {
                let f = unsafe { &mut *(Arc::as_ptr(f) as *mut OverlappedFile) };
                f.write(bytes)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ChildStdio {
    // Used for accessing the raw handle, even if the io version is busy
    inner: ArcFile,
    // For doing I/O operations asynchronously
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

/// Wrap a raw stdio handle for use with Tokio's Blocking I/O.
///
/// If the handle is overlapped, wraps it in OverlappedFile which uses
/// ReadFile/WriteFile with an explicit OVERLAPPED + event object, correctly
/// handling async I/O without aborting. Non-overlapped handles use the
/// original std::fs::File path unchanged.
///
/// See: https://github.com/rust-lang/rust/issues/81357
///      https://github.com/rust-lang/rust/pull/98950
pub(super) fn stdio<T>(io: T) -> io::Result<ChildStdio>
where
    T: IntoRawHandle,
{
    let raw_handle = io.into_raw_handle() as HANDLE;

    let arc_file = if unsafe { is_overlapped_handle(raw_handle) } {
        // Overlapped handle: use OverlappedFile which reads via ReadFile + OVERLAPPED.
        let overlapped = unsafe { OverlappedFile::new(raw_handle)? };
        ArcFile::overlapped(overlapped)
    } else {
        // Synchronous handle: use std::fs::File as before.
        let file = unsafe { StdFile::from_raw_handle(raw_handle as RawHandle) };
        ArcFile::sync(file)
    };

    let io_clone = arc_file.clone();
    // SAFETY: the `Read` implementation of `io_clone` does not
    // read from the buffer it is borrowing and correctly
    // reports the length of the data written into the buffer.
    let io = unsafe { Blocking::new(io_clone) };
    Ok(ChildStdio { inner: arc_file, io })
}

fn convert_to_file(child_stdio: ChildStdio) -> io::Result<StdFile> {
    let ChildStdio { inner, io } = child_stdio;
    drop(io);

    match Arc::try_unwrap(inner.0) {
        Ok(ArcFileInner::Sync(arc)) => {
            Arc::try_unwrap(arc).or_else(|arc| duplicate_handle(&*arc))
        }
        Ok(ArcFileInner::Overlapped(arc)) => {
            // Duplicate the handle as a plain StdFile.
            // The OverlappedFile will be dropped (closing original handle) after duplication.
            match Arc::try_unwrap(arc) {
                Ok(f) => duplicate_handle_raw(f.handle),
                Err(arc) => duplicate_handle_raw(arc.handle),
            }
        }
        Err(arc) => {
            // Arc still has other owners; duplicate whichever variant.
            match arc.as_ref() {
                ArcFileInner::Sync(f) => duplicate_handle(&**f),
                ArcFileInner::Overlapped(f) => duplicate_handle_raw(f.handle),
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
