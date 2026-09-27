// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! Async wrapper around [`shared::ipc::IpcChannel`] (tokio `AsyncFd`).
//!
//! Same pattern as `vauban-proxy-ssh::ipc::AsyncIpcChannel` — needed so
//! the vault decrypt client can await replies without blocking the
//! web IPC poll loop.

use shared::ipc::IpcChannel;
use shared::messages::Message;
use std::io;
use std::os::unix::io::RawFd;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

pub struct AsyncIpcChannel {
    inner: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("IPC connection closed")]
    ConnectionClosed,
    #[error("IPC receive failed: {0}")]
    ReceiveFailed(String),
    #[error("IPC send failed: {0}")]
    SendFailed(String),
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

    pub fn send(&self, msg: &Message) -> Result<(), IpcError> {
        self.inner
            .send(msg)
            .map_err(|e| IpcError::SendFailed(e.to_string()))
    }

    pub async fn recv(&self) -> Result<Message, IpcError> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| IpcError::ReceiveFailed(e.to_string()))?;

            match self.inner.try_recv() {
                Ok(msg) => return Ok(msg),
                Err(shared::ipc::IpcError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
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
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};
    // SAFETY: fcntl on a valid pipe fd owned by this process.
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
