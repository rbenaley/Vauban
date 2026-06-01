//! LDAPS bind orchestration, reusable by the binary AND the E2E tests.
//!
//! Given a connected-on-demand directory socket (brokered by the supervisor
//! via SCM_RIGHTS), this module performs the full login: request the socket,
//! receive the FD, terminate TLS, and run an LDAP simple bind, all within a
//! tight timeout budget. The plaintext password never transits the supervisor.

use std::os::fd::OwnedFd;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shared::ipc::{IpcChannel, poll_readable, recv_fd};
use shared::messages::{ControlMessage, LdapBindOutcome, Message, Service};
use tracing::warn;

use crate::{outcome_from_result_code, tls};

/// Everything needed to run an LDAPS bind, built once (pre-seal) from the
/// supervisor's `AuthLdapProvision`. Cheap to clone (the rustls config is an
/// `Arc`), so a handler can snapshot it and release its borrow on the service
/// state before the (potentially state-mutating) broker round-trip.
#[derive(Clone)]
pub struct LdapRuntime {
    /// rustls client config trusting the directory CA.
    pub client_config: Arc<rustls::ClientConfig>,
    /// Directory host (used for the broker request AND TLS SNI/hostname).
    pub host: String,
    /// Directory port.
    pub port: u16,
    /// Bind DN template; `{username}` is substituted per request.
    pub dn_template: String,
    /// Per-attempt budget (broker round-trip + TLS handshake + bind).
    pub timeout: Duration,
    /// SCM_RIGHTS socket on which the supervisor hands us the connected FD.
    pub fd_passing_socket: RawFd,
}

/// Run one LDAP bind. `on_control` is invoked for every
/// [`ControlMessage`] observed on the supervisor channel while waiting for the
/// broker response, so the caller can keep answering heartbeats during the
/// (brief) blocking window. Returns a coarse [`LdapBindOutcome`]; the web layer
/// collapses all non-success variants to a single generic response.
pub fn brokered_bind<F: FnMut(ControlMessage)>(
    supervisor: &IpcChannel,
    rt: &LdapRuntime,
    username: &str,
    password: &str,
    mut on_control: F,
) -> LdapBindOutcome {
    let started = Instant::now();
    let session_id = format!("ldap-{:016x}", rand::random::<u64>());
    let broker_request_id: u64 = rand::random();

    // Step 1: ask the supervisor to connect to the directory and hand us the
    // socket. The supervisor gates this on its `[auth.ldaps]` whitelist; the
    // session_token is empty (auth is key-less by design).
    let request = Message::TcpConnectRequest {
        request_id: broker_request_id,
        session_id: session_id.clone(),
        host: rt.host.clone(),
        port: rt.port,
        target_service: Service::Auth,
        session_token: Vec::new(),
    };
    if let Err(e) = supervisor.send(&request) {
        warn!("LDAP broker request send failed: {e}");
        return LdapBindOutcome::Unreachable;
    }

    // Step 2: wait for the supervisor's TcpConnectResponse. The FD is sent via
    // SCM_RIGHTS BEFORE this response, so by the time it arrives the FD is
    // already queued on our fd-passing socket.
    match wait_for_tcp_connect_response(supervisor, &session_id, rt.timeout, &mut on_control) {
        Some(true) => {}
        Some(false) => {
            warn!(host = %rt.host, port = rt.port, "supervisor refused LDAP broker connect");
            return LdapBindOutcome::Unreachable;
        }
        None => {
            warn!("timed out awaiting LDAP broker response");
            return LdapBindOutcome::Unreachable;
        }
    }

    // Step 3: receive the connected FD (non-blocking: poll then a single
    // recv_fd). Never block the mono-thread loop on a missing FD.
    let owned_fd = match receive_brokered_fd(rt.fd_passing_socket) {
        Some(fd) => fd,
        None => {
            warn!("no brokered FD available after successful broker response");
            return LdapBindOutcome::Unreachable;
        }
    };

    // SAFETY: the FD was just received via SCM_RIGHTS and is exclusively owned.
    let mut tcp = unsafe { std::net::TcpStream::from_raw_fd(owned_fd.into_raw_fd()) };

    // Apply the remaining time budget so the TLS handshake + bind cannot wedge
    // the loop.
    let remaining = rt.timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        warn!("LDAP timeout budget exhausted before TLS handshake");
        return LdapBindOutcome::Unreachable;
    }
    let _ = tcp.set_read_timeout(Some(remaining));
    let _ = tcp.set_write_timeout(Some(remaining));

    // Step 4: TLS (SNI/hostname = configured host, chain validated against the
    // provisioned CA) + LDAP simple bind.
    let dn = rt.dn_template.replace("{username}", username);
    match tls::simple_bind_over_tls(
        Arc::clone(&rt.client_config),
        &rt.host,
        &mut tcp,
        &dn,
        password.as_bytes(),
    ) {
        Ok(code) => outcome_from_result_code(code),
        Err(e) => classify_bind_error(&e),
    }
}

/// Map an `io::Error` raised during the TLS handshake or bind to a coarse
/// outcome. Timeouts / connection resets are transport-level (`Unreachable`);
/// everything else (handshake / certificate / protocol) is `TlsError`.
pub fn classify_bind_error(e: &std::io::Error) -> LdapBindOutcome {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::TimedOut
        | ErrorKind::WouldBlock
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => {
            warn!("LDAP bind transport error: {e}");
            LdapBindOutcome::Unreachable
        }
        _ => {
            warn!("LDAP bind TLS/protocol error: {e}");
            LdapBindOutcome::TlsError
        }
    }
}

/// Block (within `budget`) for the supervisor's `TcpConnectResponse` matching
/// `session_id`. Control messages are surfaced to `on_control` so heartbeats
/// are not dropped during the bind. Returns `Some(success)` or `None` on
/// timeout / IPC error.
fn wait_for_tcp_connect_response<F: FnMut(ControlMessage)>(
    supervisor: &IpcChannel,
    session_id: &str,
    budget: Duration,
    on_control: &mut F,
) -> Option<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        match poll_readable(&[supervisor.read_fd()], ms) {
            Ok(ready) if !ready.is_empty() => match supervisor.recv() {
                Ok(Message::TcpConnectResponse {
                    session_id: sid,
                    success,
                    ..
                }) if sid == session_id => return Some(success),
                Ok(Message::Control(ctrl)) => on_control(ctrl),
                Ok(_) => { /* unrelated; keep waiting */ }
                Err(_) => return None,
            },
            Ok(_) => { /* poll timeout; loop re-checks the deadline */ }
            Err(_) => return None,
        }
    }
}

/// Non-blocking receive of the brokered FD: poll the fd-passing socket briefly
/// then do a single `recv_fd`. Returns `None` rather than blocking the loop.
fn receive_brokered_fd(fd_passing_socket: RawFd) -> Option<OwnedFd> {
    for _ in 0..10 {
        match poll_readable(&[fd_passing_socket], 50) {
            Ok(ready) if !ready.is_empty() => match recv_fd(fd_passing_socket) {
                Ok(fd) => return Some(fd),
                Err(e) => {
                    warn!("recv_fd on brokered socket failed: {e}");
                    return None;
                }
            },
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
    None
}
