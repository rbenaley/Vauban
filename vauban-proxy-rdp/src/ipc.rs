//! Async IPC wrapper for communication with vauban-web and supervisor.

pub use crate::error::{IpcError, IpcResult};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io;
use std::os::unix::io::RawFd;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// Async wrapper for IPC channel using tokio's AsyncFd.
pub struct AsyncIpcChannel {
    inner: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
}

impl AsyncIpcChannel {
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        let read_fd = channel.read_fd();
        set_nonblocking(read_fd)?;
        let read_async_fd = AsyncFd::new(read_fd)?;
        Ok(Self {
            inner: channel,
            read_async_fd,
        })
    }

    pub fn send(&self, msg: &Message) -> IpcResult<()> {
        self.inner.send(msg).map_err(IpcError::from)
    }

    pub async fn recv(&self) -> IpcResult<Message> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| IpcError::ReceiveFailed(e.to_string()))?;

            match self.inner.try_recv() {
                Ok(msg) => return Ok(msg),
                Err(shared::ipc::IpcError::Io(ref e))
                    if e.kind() == io::ErrorKind::WouldBlock =>
                {
                    guard.clear_ready();
                    continue;
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    return Err(IpcError::ConnectionClosed);
                }
                Err(e) => {
                    return Err(IpcError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
    // SAFETY: fcntl with valid arguments on a valid fd.
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
