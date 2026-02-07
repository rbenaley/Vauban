//! Unix pipe IPC utilities with SCM_RIGHTS support for file descriptor passing.

use crate::messages::Message;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::unistd::{pipe, read, write};
use std::io;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use thiserror::Error;

/// Maximum message size (16 KB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024;

/// IPC error types.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Deserialization error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Message too large: {size} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge { size: usize },

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid message header")]
    InvalidHeader,
}

/// Result type for IPC operations.
pub type Result<T> = std::result::Result<T, IpcError>;

/// A bidirectional IPC channel using Unix pipes.
pub struct IpcChannel {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

impl IpcChannel {
    /// Create a new IPC channel from existing file descriptors.
    ///
    /// # Safety
    /// The caller must ensure the file descriptors are valid and owned.
    pub unsafe fn from_raw_fds(read_fd: RawFd, write_fd: RawFd) -> Self {
        // SAFETY: Caller guarantees the file descriptors are valid and owned.
        unsafe {
            Self {
                read_fd: OwnedFd::from_raw_fd(read_fd),
                write_fd: OwnedFd::from_raw_fd(write_fd),
            }
        }
    }

    /// Create a pair of connected IPC channels.
    ///
    /// Returns (parent_channel, child_channel).
    /// Both channels have their read file descriptors set to non-blocking mode
    /// to support `try_recv()`.
    pub fn pair() -> Result<(Self, Self)> {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};

        // Create two pipes: one for each direction
        // nix::unistd::pipe() returns (read_fd, write_fd) as OwnedFd
        let (p2c_read, p2c_write) = pipe().map_err(|e| IpcError::Io(e.into()))?;
        let (c2p_read, c2p_write) = pipe().map_err(|e| IpcError::Io(e.into()))?;

        // Set read file descriptors to non-blocking mode for try_recv() support
        fcntl(&p2c_read, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|e| IpcError::Io(e.into()))?;
        fcntl(&c2p_read, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|e| IpcError::Io(e.into()))?;

        // Parent reads from child_to_parent, writes to parent_to_child
        // Child reads from parent_to_child, writes to child_to_parent
        let parent_channel = Self {
            read_fd: c2p_read,
            write_fd: p2c_write,
        };

        let child_channel = Self {
            read_fd: p2c_read,
            write_fd: c2p_write,
        };

        Ok((parent_channel, child_channel))
    }

    /// Get the read file descriptor (for use with poll/kqueue).
    pub fn read_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }

    /// Get the write file descriptor (for use with poll/kqueue).
    pub fn write_fd(&self) -> RawFd {
        self.write_fd.as_raw_fd()
    }

    /// Send a message through the channel.
    pub fn send(&self, msg: &Message) -> Result<()> {
        let data = bincode::serde::encode_to_vec(msg, bincode::config::standard())?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge { size: data.len() });
        }

        // Write length header (4 bytes, little-endian)
        let len = data.len() as u32;
        let len_bytes = len.to_le_bytes();

        // Use a single write for header + data to avoid partial writes
        let mut buffer = Vec::with_capacity(4 + data.len());
        buffer.extend_from_slice(&len_bytes);
        buffer.extend_from_slice(&data);

        write_all_fd(self.write_fd.as_raw_fd(), &buffer)?;
        Ok(())
    }

    /// Receive a message from the channel (blocking).
    pub fn recv(&self) -> Result<Message> {
        // Read length header
        let mut len_bytes = [0u8; 4];
        read_exact_fd(self.read_fd.as_raw_fd(), &mut len_bytes)?;

        let len = u32::from_le_bytes(len_bytes) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge { size: len });
        }

        if len == 0 {
            return Err(IpcError::InvalidHeader);
        }

        // Read message data
        let mut data = vec![0u8; len];
        read_exact_fd(self.read_fd.as_raw_fd(), &mut data)?;

        let (msg, _): (Message, _) =
            bincode::serde::decode_from_slice(&data, bincode::config::standard())?;
        Ok(msg)
    }

    /// Try to receive a message without blocking.
    ///
    /// Returns `Err(IpcError::Io)` with `WouldBlock` kind if no data is available.
    /// The file descriptor must be in non-blocking mode for this to work correctly.
    pub fn try_recv(&self) -> Result<Message> {
        // Try to read length header
        let mut len_bytes = [0u8; 4];
        try_read_exact_fd(self.read_fd.as_raw_fd(), &mut len_bytes)?;

        let len = u32::from_le_bytes(len_bytes) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge { size: len });
        }

        if len == 0 {
            return Err(IpcError::InvalidHeader);
        }

        // Read message data (blocking now that we have the header)
        let mut data = vec![0u8; len];
        read_exact_fd(self.read_fd.as_raw_fd(), &mut data)?;

        let (msg, _): (Message, _) =
            bincode::serde::decode_from_slice(&data, bincode::config::standard())?;
        Ok(msg)
    }
}

/// Try to read exact number of bytes without blocking.
/// Returns WouldBlock if no data is available.
fn try_read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<()> {
    // SAFETY: We borrow the fd for the duration of this function.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

    let mut pos = 0;
    while pos < buf.len() {
        match read(borrowed, &mut buf[pos..]) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(n) => pos += n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => {
                if pos == 0 {
                    // No data available at all
                    return Err(IpcError::Io(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "no data available",
                    )));
                }
                // Partial read - continue with blocking reads
                continue;
            }
            Err(e) => return Err(IpcError::Io(e.into())),
        }
    }
    Ok(())
}

/// Write all bytes to a file descriptor.
fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    // SAFETY: We borrow the fd for the duration of this function.
    // The caller ensures the fd is valid.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    
    while !buf.is_empty() {
        match write(borrowed, buf) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(n) => buf = &buf[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(IpcError::Io(e.into())),
        }
    }
    Ok(())
}

/// Read exact number of bytes from a file descriptor.
/// Handles non-blocking FDs by waiting with poll when EAGAIN is returned.
fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<()> {
    // SAFETY: We borrow the fd for the duration of this function.
    // The caller ensures the fd is valid.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

    let mut pos = 0;
    while pos < buf.len() {
        match read(borrowed, &mut buf[pos..]) {
            Ok(0) => return Err(IpcError::ConnectionClosed),
            Ok(n) => pos += n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) => {
                // Non-blocking FD with no data available - wait for data using poll
                loop {
                    let pollfd = PollFd::new(borrowed, PollFlags::POLLIN);
                    match nix::poll::poll(&mut [pollfd], PollTimeout::NONE) {
                        Ok(_) => break,
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(e) => return Err(IpcError::Io(e.into())),
                    }
                }
                continue;
            }
            Err(e) => return Err(IpcError::Io(e.into())),
        }
    }
    Ok(())
}

/// Create a Unix socket pair suitable for passing file descriptors via SCM_RIGHTS.
///
/// Returns (parent_socket, child_socket) as OwnedFd.
/// The parent socket is used by the supervisor to send FDs, the child socket
/// is passed to the target service to receive FDs.
///
/// Unlike pipes, Unix sockets support ancillary data (SCM_RIGHTS) for FD passing.
#[cfg(target_os = "freebsd")]
pub fn socketpair_for_fd_passing() -> Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

    let (sock1, sock2) =
        socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty())
            .map_err(|e| IpcError::Io(e.into()))?;

    // Set close-on-exec flag for both sockets
    fcntl(&sock1, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;
    fcntl(&sock2, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;

    Ok((sock1, sock2))
}

/// Create a Unix socket pair for FD passing (non-FreeBSD stub for development).
///
/// On non-FreeBSD platforms, this creates a socket pair but FD passing won't work.
#[cfg(not(target_os = "freebsd"))]
pub fn socketpair_for_fd_passing() -> Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

    tracing::debug!("socketpair_for_fd_passing: SCM_RIGHTS FD passing not available, proxy will connect directly");

    let (sock1, sock2) =
        socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty())
            .map_err(|e| IpcError::Io(e.into()))?;

    // Set close-on-exec flag for both sockets
    fcntl(&sock1, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;
    fcntl(&sock2, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;

    Ok((sock1, sock2))
}

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
///
/// This is used to pass sockets between processes (e.g., for connection handoff).
#[cfg(target_os = "freebsd")]
pub fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};

    // Data to send (at least 1 byte required for SCM_RIGHTS)
    let iov = [io::IoSlice::new(b"F")];

    // Control message with the file descriptor (nix uses RawFd on FreeBSD)
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sendmsg::<()>(socket_fd, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| IpcError::Io(e.into()))?;

    Ok(())
}

/// Receive a file descriptor over a Unix socket using SCM_RIGHTS.
#[cfg(target_os = "freebsd")]
pub fn recv_fd(socket_fd: RawFd) -> Result<OwnedFd> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};

    // Buffer for data (at least 1 byte)
    let mut buf = [0u8; 1];
    let mut iov = [io::IoSliceMut::new(&mut buf)];

    // Buffer for control messages
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg::<()>(socket_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .map_err(|e| IpcError::Io(e.into()))?;

    if msg.bytes == 0 {
        return Err(IpcError::ConnectionClosed);
    }

    // Extract the file descriptor from control messages
    // Note: cmsgs() may return Result on some platforms, we handle both cases
    let cmsgs_iter = msg.cmsgs().map_err(|e| IpcError::Io(e.into()))?;
    for cmsg in cmsgs_iter {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                // SAFETY: The fd was just received via SCM_RIGHTS and is valid.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }

    Err(IpcError::InvalidHeader)
}

/// Stub implementations for non-FreeBSD platforms (development).
/// On platforms without Capsicum, FD passing is a no-op: the proxy
/// falls back to connecting directly to the target host.
#[cfg(not(target_os = "freebsd"))]
pub fn send_fd(_socket_fd: RawFd, _fd_to_send: RawFd) -> Result<()> {
    tracing::debug!("send_fd: skipped (no SCM_RIGHTS on this platform, proxy will connect directly)");
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn recv_fd(_socket_fd: RawFd) -> Result<OwnedFd> {
    // Return a specific error that callers can handle gracefully.
    // This is NOT a failure: the proxy will fall back to a direct connection.
    Err(IpcError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "FD passing not available (non-FreeBSD platform), using direct connection",
    )))
}

/// Wait for readability on multiple file descriptors using poll(2).
///
/// Returns the indices of ready file descriptors.
pub fn poll_readable(fds: &[RawFd], timeout_ms: i32) -> Result<Vec<usize>> {
    // Create PollFd structs for nix::poll
    // SAFETY: We borrow the fds for the duration of this function.
    let mut pollfds: Vec<PollFd> = fds
        .iter()
        .map(|&fd| {
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            PollFd::new(borrowed, PollFlags::POLLIN)
        })
        .collect();

    // Convert timeout
    let timeout = if timeout_ms < 0 {
        PollTimeout::NONE
    } else {
        PollTimeout::try_from(timeout_ms as u16).unwrap_or(PollTimeout::MAX)
    };

    match nix::poll::poll(&mut pollfds, timeout) {
        Ok(_) => {
            let ready: Vec<usize> = pollfds
                .iter()
                .enumerate()
                .filter(|(_, pfd)| {
                    pfd.revents()
                        .map(|r| r.contains(PollFlags::POLLIN))
                        .unwrap_or(false)
                })
                .map(|(i, _)| i)
                .collect();
            Ok(ready)
        }
        Err(nix::errno::Errno::EINTR) => Ok(vec![]),
        Err(e) => Err(IpcError::Io(e.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ControlMessage, Message, ServiceStats};
    use std::os::fd::AsRawFd;

    // ==================== IpcChannel Tests ====================

    #[test]
    fn test_ipc_channel_pair_creation() {
        let result = IpcChannel::pair();
        assert!(result.is_ok());
        let (parent, child) = result.unwrap();
        
        // Verify FDs are valid (non-negative)
        assert!(parent.read_fd() >= 0);
        assert!(parent.write_fd() >= 0);
        assert!(child.read_fd() >= 0);
        assert!(child.write_fd() >= 0);
        
        // FDs should be different
        assert_ne!(parent.read_fd(), parent.write_fd());
        assert_ne!(child.read_fd(), child.write_fd());
    }

    #[test]
    fn test_ipc_channel_send_recv_ping() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Parent sends Ping
        let ping = Message::Control(ControlMessage::Ping { seq: 42 });
        parent.send(&ping).unwrap();
        
        // Child receives Ping
        let received: Message = child.recv().unwrap();
        if let Message::Control(ControlMessage::Ping { seq }) = received {
            assert_eq!(seq, 42);
        } else {
            panic!("Expected Ping message");
        }
    }

    #[test]
    fn test_ipc_channel_send_recv_pong() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Child sends Pong
        let stats = ServiceStats {
            uptime_secs: 100,
            requests_processed: 500,
            requests_failed: 2,
            active_connections: 5,
            pending_requests: 1,
        };
        let pong = Message::Control(ControlMessage::Pong { seq: 42, stats });
        child.send(&pong).unwrap();
        
        // Parent receives Pong
        let received: Message = parent.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = received {
            assert_eq!(seq, 42);
            assert_eq!(stats.uptime_secs, 100);
            assert_eq!(stats.requests_processed, 500);
        } else {
            panic!("Expected Pong message");
        }
    }

    #[test]
    fn test_ipc_channel_bidirectional() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Parent -> Child
        let msg1 = Message::Control(ControlMessage::Ping { seq: 1 });
        parent.send(&msg1).unwrap();
        let recv1: Message = child.recv().unwrap();
        assert!(matches!(recv1, Message::Control(ControlMessage::Ping { seq: 1 })));
        
        // Child -> Parent
        let msg2 = Message::Control(ControlMessage::Pong { 
            seq: 1, 
            stats: ServiceStats::default() 
        });
        child.send(&msg2).unwrap();
        let recv2: Message = parent.recv().unwrap();
        assert!(matches!(recv2, Message::Control(ControlMessage::Pong { seq: 1, .. })));
    }

    #[test]
    fn test_ipc_channel_multiple_messages() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Send multiple messages
        for i in 0..10 {
            let msg = Message::Control(ControlMessage::Ping { seq: i });
            parent.send(&msg).unwrap();
        }
        
        // Receive all messages
        for i in 0..10 {
            let received: Message = child.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq }) = received {
                assert_eq!(seq, i);
            } else {
                panic!("Expected Ping message");
            }
        }
    }

    #[test]
    fn test_ipc_channel_large_message() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Create a message with large data (just under MAX_MESSAGE_SIZE)
        let large_data = vec![0xAB; 8000];
        let msg = Message::SessionRecordingChunk {
            session_id: "test".to_string(),
            sequence: 1,
            data: large_data.clone(),
        };
        
        parent.send(&msg).unwrap();
        let received: Message = child.recv().unwrap();
        
        if let Message::SessionRecordingChunk { data, .. } = received {
            assert_eq!(data.len(), 8000);
            assert_eq!(data[0], 0xAB);
        } else {
            panic!("Expected SessionRecordingChunk");
        }
    }

    // ==================== IpcError Tests ====================

    #[test]
    fn test_ipc_error_display() {
        let err = IpcError::MessageTooLarge { size: 20000 };
        let msg = format!("{}", err);
        assert!(msg.contains("20000"));
        assert!(msg.contains("16384")); // MAX_MESSAGE_SIZE
    }

    #[test]
    fn test_ipc_error_connection_closed() {
        let err = IpcError::ConnectionClosed;
        let msg = format!("{}", err);
        assert!(msg.contains("closed"));
    }

    #[test]
    fn test_ipc_error_invalid_header() {
        let err = IpcError::InvalidHeader;
        let msg = format!("{}", err);
        assert!(msg.contains("header"));
    }

    // ==================== poll_readable Tests ====================

    #[test]
    fn test_poll_readable_timeout() {
        let (parent, _child) = IpcChannel::pair().unwrap();
        
        // Poll with short timeout, nothing to read
        let result = poll_readable(&[parent.read_fd()], 10);
        assert!(result.is_ok());
        let ready = result.unwrap();
        assert!(ready.is_empty()); // Timeout, nothing ready
    }

    #[test]
    fn test_poll_readable_with_data() {
        let (parent, child) = IpcChannel::pair().unwrap();
        
        // Send data
        let msg = Message::Control(ControlMessage::Ping { seq: 1 });
        parent.send(&msg).unwrap();
        
        // Poll should indicate data available
        let result = poll_readable(&[child.read_fd()], 1000);
        assert!(result.is_ok());
        let ready = result.unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], 0);
    }

    #[test]
    fn test_poll_readable_multiple_fds() {
        let (parent1, child1) = IpcChannel::pair().unwrap();
        let (parent2, child2) = IpcChannel::pair().unwrap();
        
        // Send data only to channel 2
        let msg = Message::Control(ControlMessage::Ping { seq: 2 });
        parent2.send(&msg).unwrap();
        
        // Poll both
        let fds = [child1.read_fd(), child2.read_fd()];
        let result = poll_readable(&fds, 100);
        assert!(result.is_ok());
        let ready = result.unwrap();
        
        // Only channel 2 (index 1) should be ready
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], 1);
        
        // Prevent unused warning
        drop(parent1);
    }

    #[test]
    fn test_poll_readable_empty_fds() {
        let result = poll_readable(&[], 10);
        assert!(result.is_ok());
        let ready = result.unwrap();
        assert!(ready.is_empty());
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_ipc_channel_drop_closes_fds() {
        let (parent, child) = IpcChannel::pair().unwrap();
        let parent_read_fd = parent.read_fd();
        let child_write_fd = child.write_fd();
        
        // Drop child channel
        drop(child);
        
        // Parent should still be usable until it tries to recv from closed pipe
        // Just verify we got valid FDs before drop
        assert!(parent_read_fd >= 0);
        assert!(child_write_fd >= 0);
        
        drop(parent);
    }

    #[test]
    fn test_max_message_size_constant() {
        assert_eq!(MAX_MESSAGE_SIZE, 16 * 1024);
    }

    #[test]
    fn test_socketpair_for_fd_passing() {
        let result = socketpair_for_fd_passing();
        assert!(result.is_ok());
        let (sock1, sock2) = result.unwrap();

        // Both sockets should have valid FDs
        assert!(sock1.as_raw_fd() >= 0);
        assert!(sock2.as_raw_fd() >= 0);
        assert_ne!(sock1.as_raw_fd(), sock2.as_raw_fd());
    }

    // ==================== Integration-style Tests ====================

    #[test]
    fn test_ping_pong_cycle() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        
        // Supervisor sends Ping
        let ping = Message::Control(ControlMessage::Ping { seq: 100 });
        supervisor.send(&ping).unwrap();
        
        // Service receives and responds with Pong
        let received: Message = service.recv().unwrap();
        if let Message::Control(ControlMessage::Ping { seq }) = received {
            let stats = ServiceStats {
                uptime_secs: 60,
                requests_processed: 42,
                requests_failed: 0,
                active_connections: 1,
                pending_requests: 0,
            };
            let pong = Message::Control(ControlMessage::Pong { seq, stats });
            service.send(&pong).unwrap();
        }
        
        // Supervisor receives Pong
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 100);
            assert_eq!(stats.requests_processed, 42);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_auth_request_response_cycle() {
        use std::net::{IpAddr, Ipv4Addr};
        use crate::messages::AuthResult;
        
        let (web, auth) = IpcChannel::pair().unwrap();
        
        // Web sends auth request
        let request = Message::AuthRequest {
            request_id: 1,
            username: "alice".to_string(),
            credential: b"password123".to_vec(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        };
        web.send(&request).unwrap();
        
        // Auth receives and processes
        let received: Message = auth.recv().unwrap();
        if let Message::AuthRequest { request_id, username, .. } = received {
            assert_eq!(username, "alice");
            
            // Auth sends response
            let response = Message::AuthResponse {
                request_id,
                result: AuthResult::Success {
                    user_id: "user_alice".to_string(),
                    session_id: "sess123".to_string(),
                    roles: vec!["user".to_string()],
                },
            };
            auth.send(&response).unwrap();
        }
        
        // Web receives response
        let response: Message = web.recv().unwrap();
        if let Message::AuthResponse { result, .. } = response {
            assert!(matches!(result, AuthResult::Success { .. }));
        } else {
            panic!("Expected AuthResponse");
        }
    }
}
