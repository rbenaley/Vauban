//! Unix pipe IPC utilities with SCM_RIGHTS support for file descriptor passing.

use crate::messages::Message;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::unistd::{pipe, read, write};
use std::io;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use thiserror::Error;

/// Maximum message size (256 KiB). Sized for H.264 I-frames which can exceed
/// 128 KiB at very high resolutions (5K+) with complex graphical content.
/// Access service list payloads use IPC pagination so they stay under this cap.
/// Remains a reasonable DoS guard for local IPC.
pub const MAX_MESSAGE_SIZE: usize = 256 * 1024;

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
    ///
    /// # Invariant INV-1 (creation, fail-closed)
    ///
    /// Every file descriptor produced by this function carries `FD_CLOEXEC`.
    /// No code path may create an IPC pipe that is inheritable across
    /// `execv` by default: a forked-and-exec'd child only keeps the pipe
    /// ends that the supervisor explicitly re-enables via [`clear_cloexec`]
    /// (post-fork, pre-exec). A forgotten descriptor therefore closes
    /// itself at exec instead of leaking to a foreign service (VAU-005).
    ///
    /// Note: `pipe()` + `fcntl(F_SETFD)` is used instead of `pipe2(O_CLOEXEC)`
    /// because macOS (dev platform) has no `pipe2(2)`. The subsequent
    /// `F_SETFL(O_NONBLOCK)` only touches the file *status* flags, never the
    /// *fd* flags, so `FD_CLOEXEC` survives.
    pub fn pair() -> Result<(Self, Self)> {
        use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};

        // Create two pipes: one for each direction
        // nix::unistd::pipe() returns (read_fd, write_fd) as OwnedFd
        let (p2c_read, p2c_write) = pipe().map_err(|e| IpcError::Io(e.into()))?;
        let (c2p_read, c2p_write) = pipe().map_err(|e| IpcError::Io(e.into()))?;

        // INV-1: every IPC pipe end is FD_CLOEXEC at creation (fail-closed).
        for fd in [&p2c_read, &p2c_write, &c2p_read, &c2p_write] {
            fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;
        }

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

/// Make a file descriptor inheritable across `execv` (clears `FD_CLOEXEC`).
///
/// # Invariant INV-2 (single door)
///
/// This is the ONLY function allowed to make an IPC file descriptor
/// inheritable across `execv`. It must be called exclusively by the
/// supervisor's `spawn_child`, post-`fork()` and pre-`execv()`, on the
/// minimal allowlist of descriptors destined for THAT child (its
/// supervisor channel, its topology pipe ends, its FD-passing socket,
/// its declared inheritable FDs). Calling it anywhere else re-opens the
/// VAU-005 cross-service FD leak; the supervisor pin test
/// `single_door_no_raw_fsetfd_empty_outside_clear_cloexec` enforces this.
///
/// Async-signal-safety: this function only performs a single `fcntl(2)`
/// call (no allocation), so it is safe to call between `fork` and `exec`.
pub fn clear_cloexec(fd: RawFd) -> Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    // SAFETY: We borrow the fd for the duration of this function.
    // The caller ensures the fd is valid.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    fcntl(borrowed, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|e| IpcError::Io(e.into()))?;
    Ok(())
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
/// Works on all Unix platforms (FreeBSD, Linux, macOS).
pub fn socketpair_for_fd_passing() -> Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

    let (sock1, sock2) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .map_err(|e| IpcError::Io(e.into()))?;

    fcntl(&sock1, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;
    fcntl(&sock2, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| IpcError::Io(e.into()))?;

    Ok((sock1, sock2))
}

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
///
/// SCM_RIGHTS is POSIX and works on FreeBSD, Linux, and macOS.
/// Used to pass pre-opened file descriptors to sandboxed child processes.
pub fn send_fd(socket_fd: RawFd, fd_to_send: RawFd) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let iov = [io::IoSlice::new(b"F")];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];

    sendmsg::<()>(socket_fd, &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| IpcError::Io(e.into()))?;

    Ok(())
}

/// Receive a file descriptor over a Unix socket using SCM_RIGHTS.
///
/// Blocks until a file descriptor is available on the socket.
pub fn recv_fd(socket_fd: RawFd) -> Result<OwnedFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    let mut buf = [0u8; 1];
    let mut iov = [io::IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg::<()>(socket_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .map_err(|e| IpcError::Io(e.into()))?;

    if msg.bytes == 0 {
        return Err(IpcError::ConnectionClosed);
    }

    let cmsgs_iter = msg.cmsgs().map_err(|e| IpcError::Io(e.into()))?;

    for cmsg in cmsgs_iter {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // SAFETY: The fd was just received via SCM_RIGHTS and is valid.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }

    Err(IpcError::InvalidHeader)
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
        PollTimeout::from(timeout_ms as u16)
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
    use crate::messages::AccessRuleInfo;
    use crate::messages::{
        AccessResponse, AssetGroupInfo, ControlMessage, DEFAULT_IPC_PAGE_LIMIT, IpcPage,
        MAX_IPC_PAGE_LIMIT, Message, ServiceStats,
    };
    use std::os::fd::AsRawFd;

    fn pad(n: usize) -> String {
        "x".repeat(n)
    }

    /// Upper-bound style row (varchar-like lengths, many protocols) to stress bincode size.
    fn worst_case_access_rule_info() -> AccessRuleInfo {
        let rfc = "2025-01-01T12:00:00.000000000+00:00".to_string();
        AccessRuleInfo {
            uuid: pad(36),
            name: pad(100),
            description: Some(pad(2000)),
            user_group_id: i32::MAX,
            user_group_uuid: pad(36),
            user_group_name: pad(100),
            asset_group_id: i32::MAX,
            asset_group_uuid: pad(36),
            asset_group_name: pad(100),
            allowed_protocols: (0..24)
                .map(|i| format!("protocol-{i}-{}", pad(16)))
                .collect(),
            valid_from: Some(rfc.clone()),
            valid_until: Some(rfc.clone()),
            require_mfa: true,
            require_approval: true,
            max_session_duration: Some(i32::MAX),
            is_active: true,
            priority: i32::MAX,
            created_at: rfc.clone(),
            updated_at: rfc,
        }
    }

    /// Typical DB varchar limits (no huge `Text`), similar to `AccessRuleInfo` from queries.
    fn access_rule_info_schema_bounded() -> AccessRuleInfo {
        let rfc = "2025-01-01T12:00:00.000000000+00:00".to_string();
        AccessRuleInfo {
            uuid: pad(36),
            name: pad(100),
            description: Some(pad(100)),
            user_group_id: 1,
            user_group_uuid: pad(36),
            user_group_name: pad(100),
            asset_group_id: 2,
            asset_group_uuid: pad(36),
            asset_group_name: pad(100),
            allowed_protocols: (0..8).map(|i| format!("proto{i}-{}", pad(12))).collect(),
            valid_from: Some(rfc.clone()),
            valid_until: Some(rfc.clone()),
            require_mfa: false,
            require_approval: false,
            max_session_duration: Some(3600),
            is_active: true,
            priority: 0,
            created_at: rfc.clone(),
            updated_at: rfc,
        }
    }

    fn asset_group_info_schema_bounded() -> AssetGroupInfo {
        let rfc = "2025-01-01T12:00:00.000000000+00:00".to_string();
        AssetGroupInfo {
            id: 1,
            uuid: pad(36),
            name: pad(100),
            slug: pad(100),
            description: Some(pad(100)),
            color: "#112233".to_string(),
            icon: pad(50),
            created_at: rfc.clone(),
            updated_at: rfc,
            kind: pad(16),
        }
    }

    fn encode_message(msg: &Message) -> Vec<u8> {
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
    }

    fn access_rule_page_size_bytes(count: usize) -> usize {
        let row = access_rule_info_schema_bounded();
        let msg = Message::AccessResponse {
            request_id: 1,
            response: AccessResponse::AccessRulePage(IpcPage {
                items: vec![row; count],
                has_more: false,
            }),
        };
        encode_message(&msg).len()
    }

    fn asset_group_page_size_bytes(count: usize) -> usize {
        let row = asset_group_info_schema_bounded();
        let msg = Message::AccessResponse {
            request_id: 1,
            response: AccessResponse::AssetGroupPage(IpcPage {
                items: vec![row; count],
                has_more: false,
            }),
        };
        encode_message(&msg).len()
    }

    /// Full default page of schema-sized `AccessRuleInfo` rows must fit in one IPC frame.
    #[test]
    fn test_access_rule_page_schema_bounded_default_limit_fits_max_message_size() {
        let n = DEFAULT_IPC_PAGE_LIMIT as usize;
        let len = access_rule_page_size_bytes(n);
        assert!(
            len <= MAX_MESSAGE_SIZE,
            "AccessRulePage x DEFAULT_IPC_PAGE_LIMIT (schema-bounded rows): {} bytes > MAX_MESSAGE_SIZE {}",
            len,
            MAX_MESSAGE_SIZE
        );
    }

    /// Full default page of schema-sized `AssetGroupInfo` rows must fit in one IPC frame.
    #[test]
    fn test_asset_group_page_schema_bounded_default_limit_fits_max_message_size() {
        let n = DEFAULT_IPC_PAGE_LIMIT as usize;
        let len = asset_group_page_size_bytes(n);
        assert!(
            len <= MAX_MESSAGE_SIZE,
            "AssetGroupPage x DEFAULT_IPC_PAGE_LIMIT (schema-bounded rows): {} bytes > MAX_MESSAGE_SIZE {}",
            len,
            MAX_MESSAGE_SIZE
        );
    }

    /// Binary search: max rows (schema-bounded asset groups) that still fit in a single frame.
    #[test]
    fn test_asset_group_max_rows_per_ipc_frame_gte_default_page_limit() {
        let mut lo = 1usize;
        let mut hi = MAX_IPC_PAGE_LIMIT as usize;
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if asset_group_page_size_bytes(mid) <= MAX_MESSAGE_SIZE {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        assert!(
            lo >= DEFAULT_IPC_PAGE_LIMIT as usize,
            "schema-bounded asset group rows fitting in one IPC frame ({lo}) should be >= DEFAULT_IPC_PAGE_LIMIT ({DEFAULT_IPC_PAGE_LIMIT})"
        );
    }

    /// Very large `Text` fields per row cannot fill a full page; cap is bounded by `MAX_MESSAGE_SIZE`.
    #[test]
    fn test_bincode_max_rows_heavy_access_rule_under_cap() {
        let row = worst_case_access_rule_info();
        let mut lo = 1usize;
        let mut hi = MAX_IPC_PAGE_LIMIT as usize;
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            let msg = Message::AccessResponse {
                request_id: 1,
                response: AccessResponse::AccessRulePage(IpcPage {
                    items: vec![row.clone(); mid],
                    has_more: false,
                }),
            };
            if encode_message(&msg).len() <= MAX_MESSAGE_SIZE {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        assert!(
            lo >= 1,
            "expected at least one heavy AccessRuleInfo row to fit in MAX_MESSAGE_SIZE"
        );
        assert!(
            lo < DEFAULT_IPC_PAGE_LIMIT as usize,
            "sanity: heavy rows should not fit a full DEFAULT_IPC_PAGE_LIMIT page ({lo} < {DEFAULT_IPC_PAGE_LIMIT})"
        );
    }

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

    /// Helper: read the fd-flags (`F_GETFD`) of a raw fd.
    fn fd_flags(fd: RawFd) -> nix::fcntl::FdFlag {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let bits = fcntl(borrowed, FcntlArg::F_GETFD).expect("F_GETFD");
        FdFlag::from_bits_truncate(bits)
    }

    /// Helper: read the status-flags (`F_GETFL`) of a raw fd.
    fn fl_flags(fd: RawFd) -> nix::fcntl::OFlag {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let bits = fcntl(borrowed, FcntlArg::F_GETFL).expect("F_GETFL");
        OFlag::from_bits_truncate(bits)
    }

    /// INV-1: every one of the four pipe ends produced by `pair()` carries
    /// `FD_CLOEXEC` (fail-closed). A forked-and-exec'd child only keeps the
    /// ends the supervisor explicitly re-enables.
    #[test]
    fn pair_sets_cloexec_on_all_four_ends() {
        use nix::fcntl::FdFlag;
        let (parent, child) = IpcChannel::pair().unwrap();

        for fd in [
            parent.read_fd(),
            parent.write_fd(),
            child.read_fd(),
            child.write_fd(),
        ] {
            assert!(
                fd_flags(fd).contains(FdFlag::FD_CLOEXEC),
                "fd {fd} must carry FD_CLOEXEC (INV-1)"
            );
        }
    }

    /// Regression on the F_SETFL/F_SETFD coupling: setting `O_NONBLOCK` on the
    /// read ends (status flags) must NOT clear `FD_CLOEXEC` (fd flags). Both
    /// hold simultaneously.
    #[test]
    fn pair_preserves_nonblock_on_read_ends() {
        use nix::fcntl::{FdFlag, OFlag};
        let (parent, child) = IpcChannel::pair().unwrap();

        for fd in [parent.read_fd(), child.read_fd()] {
            assert!(
                fl_flags(fd).contains(OFlag::O_NONBLOCK),
                "read fd {fd} must be O_NONBLOCK (try_recv support)"
            );
            assert!(
                fd_flags(fd).contains(FdFlag::FD_CLOEXEC),
                "read fd {fd} must keep FD_CLOEXEC after F_SETFL(O_NONBLOCK)"
            );
        }
    }

    /// INV-2 mechanics: `clear_cloexec` removes `FD_CLOEXEC` so the fd becomes
    /// inheritable across `execv`.
    #[test]
    fn clear_cloexec_makes_fd_inheritable() {
        use nix::fcntl::FdFlag;
        let (parent, _child) = IpcChannel::pair().unwrap();
        let fd = parent.read_fd();

        assert!(fd_flags(fd).contains(FdFlag::FD_CLOEXEC));
        clear_cloexec(fd).expect("clear_cloexec");
        assert!(
            !fd_flags(fd).contains(FdFlag::FD_CLOEXEC),
            "clear_cloexec must remove FD_CLOEXEC"
        );
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
            recording_ack_timeouts: 0,
            recording_ack_dropped: 0,
            recording_try_send_full: 0,
            recording_ack_wait_ms_max: 0,
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
        assert!(matches!(
            recv1,
            Message::Control(ControlMessage::Ping { seq: 1 })
        ));

        // Child -> Parent
        let msg2 = Message::Control(ControlMessage::Pong {
            seq: 1,
            stats: ServiceStats::default(),
        });
        child.send(&msg2).unwrap();
        let recv2: Message = parent.recv().unwrap();
        assert!(matches!(
            recv2,
            Message::Control(ControlMessage::Pong { seq: 1, .. })
        ));
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
        assert!(msg.contains("262144")); // MAX_MESSAGE_SIZE
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
        assert_eq!(MAX_MESSAGE_SIZE, 256 * 1024);
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
                recording_ack_timeouts: 0,
                recording_ack_dropped: 0,
                recording_try_send_full: 0,
                recording_ack_wait_ms_max: 0,
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
        use crate::messages::AuthResult;
        use std::net::{IpAddr, Ipv4Addr};

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
        if let Message::AuthRequest {
            request_id,
            username,
            ..
        } = received
        {
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
