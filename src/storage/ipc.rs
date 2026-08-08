//! Length-prefixed Unix IPC + SCM_RIGHTS FD via `unix-ancillary`.
//!
//! Architecture prefers SOCK_SEQPACKET; macOS lacks AF_UNIX SEQPACKET, so we
//! use SOCK_STREAM with a u32 BE length header (message-oriented framing).
//! FD handoff uses the safe `OwnedFd` / `BorrowedFd` API from `unix-ancillary`
//! (unsafe FFI stays in that dependency + `nix` for peer credentials).

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

use unix_ancillary::UnixStreamExt;

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

/// Send one FD over the Unix stream (dummy data byte + SCM_RIGHTS).
pub fn send_fd(stream: &UnixStream, fd: impl AsFd) -> Result<(), StorageError> {
    stream
        .send_fds(b"\0", &[fd.as_fd()])
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("send_fd: {e}")))?;
    Ok(())
}

/// Receive one FD transferred with [`send_fd`].
pub fn recv_fd(stream: &UnixStream) -> Result<OwnedFd, StorageError> {
    let received = stream
        .recv_fds::<1>()
        .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("recv_fd: {e}")))?;
    received
        .fds
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::new(StorageErrorCode::Io, "recv_fd: no fd in ancillary"))
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
        let (uid, _gid) = nix::unistd::getpeereid(stream)
            .map_err(|e| StorageError::new(StorageErrorCode::Io, format!("peercred: {e}")))?;
        Ok(uid.as_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn send_recv_fd_round_trip_without_unsafe_in_caller() {
        let (tx, rx) = UnixStream::pair().expect("pair");
        let mut src = tempfile::tempfile().expect("tempfile");
        src.write_all(b"handoff-payload").expect("write");
        src.flush().expect("flush");
        src.seek(SeekFrom::Start(0)).expect("seek");

        send_fd(&tx, &src).expect("send_fd");
        let owned = recv_fd(&rx).expect("recv_fd");
        let mut got = std::fs::File::from(owned);
        let mut buf = String::new();
        got.read_to_string(&mut buf).expect("read received fd");
        assert_eq!(buf, "handoff-payload");
    }
}
