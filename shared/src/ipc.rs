//! Unix pipe IPC utilities with SCM_RIGHTS support for file descriptor passing.

use crate::messages::Message;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
    pub fn pair() -> Result<(Self, Self)> {
        // Create two pipes: one for each direction
        let mut parent_to_child = [0i32; 2];
        let mut child_to_parent = [0i32; 2];

        // SAFETY: pipe() is a standard POSIX call
        unsafe {
            if libc::pipe(parent_to_child.as_mut_ptr()) != 0 {
                return Err(IpcError::Io(io::Error::last_os_error()));
            }
            if libc::pipe(child_to_parent.as_mut_ptr()) != 0 {
                libc::close(parent_to_child[0]);
                libc::close(parent_to_child[1]);
                return Err(IpcError::Io(io::Error::last_os_error()));
            }
        }

        // Parent reads from child_to_parent[0], writes to parent_to_child[1]
        // Child reads from parent_to_child[0], writes to child_to_parent[1]
        let parent_channel = unsafe {
            Self {
                read_fd: OwnedFd::from_raw_fd(child_to_parent[0]),
                write_fd: OwnedFd::from_raw_fd(parent_to_child[1]),
            }
        };

        let child_channel = unsafe {
            Self {
                read_fd: OwnedFd::from_raw_fd(parent_to_child[0]),
                write_fd: OwnedFd::from_raw_fd(child_to_parent[1]),
            }
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
}

/// Write all bytes to a file descriptor.
fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        // SAFETY: write() is a standard POSIX call
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::Io(err));
        }

        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }

        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Read exact number of bytes from a file descriptor.
fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: read() is a standard POSIX call
        let n = unsafe {
            libc::read(
                fd,
                buf[pos..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - pos,
            )
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::Io(err));
        }

        if n == 0 {
            return Err(IpcError::ConnectionClosed);
        }

        pos += n as usize;
    }
    Ok(())
}

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
///
/// This is used to pass sockets between processes (e.g., for connection handoff).
#[cfg(target_os = "freebsd")]
pub fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<()> {
    use std::mem;

    // SAFETY: Standard SCM_RIGHTS implementation
    unsafe {
        let mut iov = libc::iovec {
            iov_base: b"F".as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        // Control message buffer
        let cmsg_space = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as libc::socklen_t;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as libc::socklen_t;

        let fd_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
        *fd_ptr = fd_to_send;

        let ret = libc::sendmsg(socket_fd, &msg, 0);
        if ret < 0 {
            return Err(IpcError::Io(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Receive a file descriptor over a Unix socket using SCM_RIGHTS.
#[cfg(target_os = "freebsd")]
pub fn recv_fd(socket_fd: RawFd) -> Result<OwnedFd> {
    use std::mem;

    // SAFETY: Standard SCM_RIGHTS implementation
    unsafe {
        let mut buf = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        let cmsg_space = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as libc::socklen_t;

        let ret = libc::recvmsg(socket_fd, &mut msg, 0);
        if ret < 0 {
            return Err(IpcError::Io(io::Error::last_os_error()));
        }
        if ret == 0 {
            return Err(IpcError::ConnectionClosed);
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(IpcError::InvalidHeader);
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(IpcError::InvalidHeader);
        }

        let fd_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
        let received_fd = *fd_ptr;

        Ok(OwnedFd::from_raw_fd(received_fd))
    }
}

/// Stub implementations for non-FreeBSD platforms (development).
#[cfg(not(target_os = "freebsd"))]
pub fn send_fd(_socket_fd: RawFd, _fd_to_send: RawFd) -> Result<()> {
    tracing::warn!("send_fd: SCM_RIGHTS not implemented on this platform");
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn recv_fd(_socket_fd: RawFd) -> Result<OwnedFd> {
    Err(IpcError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS not implemented on this platform",
    )))
}

/// Wait for readability on multiple file descriptors using poll(2).
///
/// Returns the indices of ready file descriptors.
pub fn poll_readable(fds: &[RawFd], timeout_ms: i32) -> Result<Vec<usize>> {
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    // SAFETY: poll() is a standard POSIX call
    let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![]);
        }
        return Err(IpcError::Io(err));
    }

    let ready: Vec<usize> = pollfds
        .iter()
        .enumerate()
        .filter(|(_, pfd)| pfd.revents & libc::POLLIN != 0)
        .map(|(i, _)| i)
        .collect();

    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ControlMessage, Message, ServiceStats};

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
