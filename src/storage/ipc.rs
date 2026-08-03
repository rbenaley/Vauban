//! Length-prefixed Unix IPC + SCM_RIGHTS FD via `passfd`.
//!
//! Architecture prefers SOCK_SEQPACKET; macOS lacks AF_UNIX SEQPACKET, so we
//! use SOCK_STREAM with a u32 BE length header (message-oriented framing).

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use passfd::FdPassingExt;

use super::error::{StorageError, StorageErrorCode};
use super::protocol::{MAX_MSG_BYTES, StorageRequest, StorageResponse};

pub fn encode_request(req: &StorageRequest) -> Result<Vec<u8>, StorageError> {
    let body = serde_json::to_vec(req)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("encode: {e}")))?;
    if body.len() > MAX_MSG_BYTES {
        return Err(StorageError::new(StorageErrorCode::Io, "message too large"));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn encode_response(resp: &StorageResponse) -> Result<Vec<u8>, StorageError> {
    let body = serde_json::to_vec(resp)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("encode: {e}")))?;
    if body.len() > MAX_MSG_BYTES {
        return Err(StorageError::new(StorageErrorCode::Io, "message too large"));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn read_exact_len(stream: &mut UnixStream, len: usize) -> Result<Vec<u8>, StorageError> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("read: {e}")))?;
    Ok(buf)
}

pub fn recv_request(stream: &mut UnixStream) -> Result<StorageRequest, StorageError> {
    let hdr = read_exact_len(stream, 4)?;
    let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    if len == 0 || len > MAX_MSG_BYTES {
        return Err(StorageError::new(StorageErrorCode::Io, "bad frame len"));
    }
    let body = read_exact_len(stream, len)?;
    serde_json::from_slice(&body)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("decode req: {e}")))
}

pub fn recv_response(stream: &mut UnixStream) -> Result<StorageResponse, StorageError> {
    let hdr = read_exact_len(stream, 4)?;
    let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    if len == 0 || len > MAX_MSG_BYTES {
        return Err(StorageError::new(StorageErrorCode::Io, "bad frame len"));
    }
    let body = read_exact_len(stream, len)?;
    serde_json::from_slice(&body)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("decode resp: {e}")))
}

pub fn send_bytes(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), StorageError> {
    stream
        .write_all(bytes)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("write: {e}")))?;
    Ok(())
}

pub fn send_fd(stream: &UnixStream, fd: impl AsRawFd) -> Result<(), StorageError> {
    stream
        .send_fd(fd.as_raw_fd())
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("send_fd: {e}")))?;
    Ok(())
}

pub fn recv_fd(stream: &UnixStream) -> Result<OwnedFd, StorageError> {
    let raw = stream
        .recv_fd()
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("recv_fd: {e}")))?;
    // SAFETY: `passfd` transfers ownership of a new FD from the kernel.
    #[allow(unsafe_code)]
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    Ok(owned)
}

pub fn bind_socket(path: &str) -> Result<UnixListener, StorageError> {
    let _ = std::fs::remove_file(path);
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("socket dir: {e}")))?;
    }
    UnixListener::bind(path)
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("bind: {e}")))
}

/// Peer UID for socket-mode authz.
pub fn peer_uid(stream: &UnixStream) -> Result<u32, StorageError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let cred = getsockopt(stream, PeerCredentials)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("peercred: {e}")))?;
        Ok(cred.uid())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: getpeereid probes peer credentials on a connected Unix FD.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if rc != 0 {
            return Err(StorageError::new(StorageErrorCode::Io, "getpeereid failed"));
        }
        Ok(uid as u32)
    }
}
