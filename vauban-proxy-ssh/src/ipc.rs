//! Async IPC clients for communication with other Vauban services.
//!
//! Note: the defense-in-depth RBAC re-check client used to live in this
//! module as `AccessRbacClient`. It now lives in `shared::access_guard`
//! so it can be shared across every protocol proxy (SSH, RDP, future
//! VNC / industrial protocols) without duplication. See
//! `docs/runbooks/ipc_topology_debugging.md` for the full rationale.

pub use crate::error::{IpcError, IpcResult};
use shared::ipc::IpcChannel;
use shared::messages::Message;
use shared::pipe_store::EXIT_CODE_RESPAWN;
use std::io;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// How the process should terminate after the main loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExit {
    /// Supervisor-requested drain / clean shutdown.
    Normal,
    /// Web IPC died at runtime: ask the supervisor to linked-respawn.
    RespawnRequested,
}

/// Outcome of one `web_channel.recv()` after error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRecvAction {
    Handle,
    Respawn,
    QuietExit,
    RecordFailure,
}

/// Shape of a web-channel recv used by [`classify_web_recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRecvClass {
    Ok,
    Closed,
    Other,
}

/// Pure decision for the web-IPC arm of the proxy main loop.
pub fn classify_web_recv(class: WebRecvClass, shutdown_requested: bool) -> WebRecvAction {
    match class {
        WebRecvClass::Ok => WebRecvAction::Handle,
        WebRecvClass::Closed if shutdown_requested => WebRecvAction::QuietExit,
        WebRecvClass::Closed => WebRecvAction::Respawn,
        WebRecvClass::Other => WebRecvAction::RecordFailure,
    }
}

/// Map a [`ServiceExit`] to the process exit code the supervisor watches.
pub fn service_exit_code(exit: ServiceExit) -> ExitCode {
    match exit {
        ServiceExit::Normal => ExitCode::SUCCESS,
        ServiceExit::RespawnRequested => ExitCode::from(EXIT_CODE_RESPAWN as u8),
    }
}

/// Async wrapper for IPC channel using tokio's AsyncFd.
///
/// EOF is sticky: the first `ConnectionClosed` is returned once; later
/// `recv` calls park on a pending future so a closed pipe cannot spin
/// the main `select!` at INFO.
pub struct AsyncIpcChannel {
    /// The underlying blocking IPC channel.
    inner: IpcChannel,
    /// Async file descriptor for the read end.
    read_async_fd: AsyncFd<RawFd>,
    closed: AtomicBool,
}

impl AsyncIpcChannel {
    /// Create a new async IPC channel from a blocking one.
    pub fn new(channel: IpcChannel) -> io::Result<Self> {
        let read_fd = channel.read_fd();

        // Set the read fd to non-blocking
        set_nonblocking(read_fd)?;

        let read_async_fd = AsyncFd::new(read_fd)?;

        Ok(Self {
            inner: channel,
            read_async_fd,
            closed: AtomicBool::new(false),
        })
    }

    /// Send a message asynchronously.
    /// Note: Writes are typically small and complete immediately, so we don't
    /// need full async write support for this use case.
    pub fn send(&self, msg: &Message) -> IpcResult<()> {
        self.inner.send(msg).map_err(IpcError::from)
    }

    /// Receive a message asynchronously.
    pub async fn recv(&self) -> IpcResult<Message> {
        if self.closed.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
            return Err(IpcError::ConnectionClosed);
        }
        loop {
            // Wait for the fd to be readable
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| IpcError::ReceiveFailed(e.to_string()))?;

            // Try to receive
            match self.inner.try_recv() {
                Ok(msg) => return Ok(msg),
                Err(shared::ipc::IpcError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Clear readiness and wait again
                    guard.clear_ready();
                    continue;
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    guard.clear_ready();
                    self.closed.store(true, Ordering::SeqCst);
                    return Err(IpcError::ConnectionClosed);
                }
                Err(e) => {
                    return Err(IpcError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};

    // SAFETY: We're calling fcntl with valid arguments on a valid fd.
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

// SECURITY: A `VaultClient` lived here that emitted a legacy "get credential
// by id" IPC verb and silently mapped the resulting `Ok(None)` to "no
// credential available". That verb has been removed from `shared::messages`
// because it could be (mis)interpreted as "no credential needed -> allow the
// connection". Credential retrieval uses encrypted-transit verbs
// (`VaultEncrypt` / `VaultDecrypt`) via `VaultDecryptClient`.
//
// Recording events go through `audit_tx` (`Message::SshRecording*`) — there
// is no separate AuditClient stub in this crate (I-SSH-1).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SshCredential;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_set_nonblocking() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        // Set non-blocking
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());

        // Verify it's non-blocking
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_other_flags() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe for testing
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();

        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let original_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };

        // Set non-blocking
        set_nonblocking(read_fd.as_raw_fd()).unwrap();

        // Check that O_NONBLOCK is set and other flags are preserved
        let new_flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new_flags, original_flags | O_NONBLOCK);
    }

    #[test]
    fn test_ssh_credential_password_clone() {
        let cred = SshCredential::Password(SecretString::from("test123".to_string()));
        let cloned = cred.clone();
        match &cloned {
            SshCredential::Password(p) => assert_eq!(p.expose_secret(), "test123"),
            _ => panic!("Expected Password variant"),
        }
    }

    #[test]
    fn test_ssh_credential_private_key_clone() {
        let cred = SshCredential::PrivateKey {
            key_pem: SecretString::from("key-data".to_string()),
            passphrase: None,
        };
        let cloned = cred.clone();
        match &cloned {
            SshCredential::PrivateKey {
                key_pem,
                passphrase,
            } => {
                assert_eq!(key_pem.expose_secret(), "key-data");
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected PrivateKey variant"),
        }
    }

    #[test]
    fn test_ssh_credential_debug() {
        let cred = SshCredential::Password(SecretString::from("secret".to_string()));
        let debug = format!("{:?}", cred);
        assert!(debug.contains("Password"));
        assert!(
            !debug.contains("secret"),
            "credential must be redacted in debug"
        );
    }

    #[test]
    fn classify_web_recv_table() {
        assert_eq!(
            classify_web_recv(WebRecvClass::Ok, false),
            WebRecvAction::Handle
        );
        assert_eq!(
            classify_web_recv(WebRecvClass::Closed, false),
            WebRecvAction::Respawn
        );
        assert_eq!(
            classify_web_recv(WebRecvClass::Closed, true),
            WebRecvAction::QuietExit
        );
        assert_eq!(
            classify_web_recv(WebRecvClass::Other, false),
            WebRecvAction::RecordFailure
        );
    }

    #[test]
    fn service_exit_maps_to_exit_code() {
        assert_eq!(service_exit_code(ServiceExit::Normal), ExitCode::SUCCESS);
        assert_eq!(
            service_exit_code(ServiceExit::RespawnRequested),
            ExitCode::from(EXIT_CODE_RESPAWN as u8)
        );
    }

    fn pair_async() -> (AsyncIpcChannel, IpcChannel) {
        let (peer, local) = IpcChannel::pair().expect("pair");
        (AsyncIpcChannel::new(local).expect("async"), peer)
    }

    #[tokio::test]
    async fn recv_delivers_then_closed_once() {
        use shared::messages::{ControlMessage, Message};
        use std::time::Duration;
        let (async_ch, peer) = pair_async();
        peer.send(&Message::Control(ControlMessage::Ping { seq: 1 }))
            .expect("send");
        match async_ch.recv().await.expect("msg") {
            Message::Control(ControlMessage::Ping { seq }) => assert_eq!(seq, 1),
            other => panic!("{other:?}"),
        }
        drop(peer);
        assert!(matches!(
            async_ch.recv().await,
            Err(IpcError::ConnectionClosed)
        ));
        let second = tokio::time::timeout(Duration::from_millis(200), async_ch.recv()).await;
        assert!(second.is_err(), "sticky EOF must not resolve again");
    }

    #[tokio::test]
    async fn battle_recv_after_eof_never_spins() {
        use std::time::Duration;
        let (async_ch, peer) = pair_async();
        drop(peer);
        let cpu_before = process_cpu_millis();
        assert!(matches!(
            async_ch.recv().await,
            Err(IpcError::ConnectionClosed)
        ));
        for _ in 0..64 {
            let parked = tokio::time::timeout(Duration::from_millis(8), async_ch.recv()).await;
            assert!(parked.is_err(), "sticky EOF must stay pending");
        }
        let cpu_delta = process_cpu_millis() - cpu_before;
        assert!(
            cpu_delta < 50,
            "EOF must not spin the reactor (cpu_delta_ms={cpu_delta})"
        );
    }

    fn process_cpu_millis() -> i64 {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if rc != 0 {
            return 0;
        }
        let user = usage.ru_utime.tv_sec * 1000 + i64::from(usage.ru_utime.tv_usec) / 1000;
        let sys = usage.ru_stime.tv_sec * 1000 + i64::from(usage.ru_stime.tv_usec) / 1000;
        user + sys
    }

    #[tokio::test]
    async fn e2e_select_exits_respawn_on_web_eof() {
        use std::time::Duration;
        let (web_async, web_peer) = pair_async();
        let (sup_async, _sup_peer) = pair_async();
        drop(web_peer);
        let shutdown = false;
        let exit = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = web_async.recv() => {
                        let class = match result {
                            Ok(_) => WebRecvClass::Ok,
                            Err(IpcError::ConnectionClosed) => WebRecvClass::Closed,
                            Err(_) => WebRecvClass::Other,
                        };
                        match classify_web_recv(class, shutdown) {
                            WebRecvAction::Respawn => return ServiceExit::RespawnRequested,
                            WebRecvAction::QuietExit => return ServiceExit::Normal,
                            WebRecvAction::Handle | WebRecvAction::RecordFailure => {}
                        }
                    }
                    _ = sup_async.recv() => {}
                }
            }
        })
        .await
        .expect("select must finish");
        assert_eq!(exit, ServiceExit::RespawnRequested);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use shared::messages::{ControlMessage, Message};
    use std::time::Duration;

    proptest! {
        #[test]
        fn recv_n_messages_then_closed_once(n in 0usize..16) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            rt.block_on(async move {
                let (peer, local) = IpcChannel::pair().expect("pair");
                let async_ch = AsyncIpcChannel::new(local).expect("async");
                for seq in 0..n as u64 {
                    peer.send(&Message::Control(ControlMessage::Ping { seq }))
                        .expect("send");
                }
                for seq in 0..n as u64 {
                    match async_ch.recv().await.expect("msg") {
                        Message::Control(ControlMessage::Ping { seq: got }) => {
                            assert_eq!(got, seq);
                        }
                        other => panic!("{other:?}"),
                    }
                }
                drop(peer);
                assert!(matches!(
                    async_ch.recv().await,
                    Err(IpcError::ConnectionClosed)
                ));
                let parked =
                    tokio::time::timeout(Duration::from_millis(200), async_ch.recv()).await;
                assert!(parked.is_err());
            });
        }
    }
}
