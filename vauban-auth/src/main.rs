// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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

//! Vauban Authentication Service
//!
//! Handles:
//! - User authentication (password, tokens)
//! - Multi-factor authentication (TOTP/HOTP)
//! - SSO integration (OIDC/SAML)
//! - LDAP/AD synchronization

use anyhow::{Context, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use shared::ipc::{IpcChannel, poll_readable};
use shared::messages::{
    AuthResult, ControlMessage, LdapBindOutcome, Message, SensitiveString, ServiceStats,
};
use shared::sandbox as capsicum;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use vauban_auth::bind::LdapRuntime;

/// Argon2id parameters, read from environment before sandbox entry.
struct Argon2Params {
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kb: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    shutdown_requested: bool,
    argon2_params: Argon2Params,
    /// LDAPS bind runtime; `None` when LDAP auth is disabled.
    ldap: Option<LdapRuntime>,
}

impl ServiceState {
    fn new(argon2_params: Argon2Params) -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
            argon2_params,
            ldap: None,
        }
    }

    fn argon2(&self) -> Result<Argon2<'_>> {
        let params = argon2::Params::new(
            self.argon2_params.memory_kb,
            self.argon2_params.iterations,
            self.argon2_params.parallelism,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
        Ok(Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-auth starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-auth exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-auth error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_service() -> Result<()> {
    let ipc_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let ipc_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    let argon2_params = load_argon2_params();

    let web_channel = parse_topology_channel("WEB");

    // LDAPS broker socket: the supervisor `connect()`s to the
    // directory and hands us the connected FD over this SCM_RIGHTS socket.
    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|v| v.parse().ok());
    let ldap_enabled = std::env::var("VAUBAN_LDAP_ENABLED")
        .map(|v| v == "true")
        .unwrap_or(false);

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_ARGON2_MEMORY_KB");
        std::env::remove_var("VAUBAN_ARGON2_ITERATIONS");
        std::env::remove_var("VAUBAN_ARGON2_PARALLELISM");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_LDAP_ENABLED");
    }

    // SAFETY: FDs are passed from supervisor and are valid
    let supervisor_channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    info!(
        memory_kb = argon2_params.memory_kb,
        iterations = argon2_params.iterations,
        parallelism = argon2_params.parallelism,
        "Argon2id parameters loaded"
    );

    // PRE-SEAL: if LDAP is enabled, the supervisor sends an AuthLdapProvision
    // (url + dn_template + CA PEM + timeout) BEFORE we seal the sandbox, so we
    // can build the rustls client config while filesystem/parsing is still
    // available. Mirrors the TlsCertProvision flow in vauban-web. The CA is a
    // trust anchor, not a secret; no bind password is ever delivered here.
    let ldap_runtime = if ldap_enabled {
        match build_ldap_runtime(&supervisor_channel, fd_passing_socket) {
            Ok(rt) => {
                info!(host = %rt.host, port = rt.port, "LDAPS bind runtime initialized");
                Some(rt)
            }
            Err(e) => {
                // Fail-closed: LDAP was promised but we could not initialize.
                // We keep running (local accounts still work) but every LDAP
                // bind will report Unreachable.
                error!("Failed to initialize LDAPS runtime: {e:#}");
                None
            }
        }
    } else {
        None
    };

    let mut all_fds = vec![ipc_read_fd, ipc_write_fd];
    let mut peer_channels: Vec<(&str, &IpcChannel)> = Vec::new();

    if let Some(ref ch) = web_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("web", ch));
    }

    // The fd-passing socket must survive the sandbox seal so we can recv_fd
    // on it. Declare it ONLY as a dedicated fd-receiver (SCM_RIGHTS recvmsg),
    // never also as an IPC pipe: on FreeBSD/Capsicum the same fd would be
    // narrowed twice with incompatible rights sets (read_write has `write`
    // but not `getsockopt`; fd_receiver has `getsockopt` but not `write`),
    // and the second `cap_rights_limit` fails with ENOTCAPABLE (errno 93).
    // This matches proxy-ssh / proxy-rdp / proxy-iacs.
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    // Typestate: `sealed` proves the sandbox was committed. It is threaded
    // into `main_loop`, making "run the loop without entering the sandbox"
    // a compile error.
    let sealed =
        capsicum::setup_service_sandbox_extended(&all_fds, None, fd_receiver_fds.as_deref())
            .context("Failed to setup sandbox")?;

    capsicum::log_main_loop_start(
        &sealed,
        &format!("starting main loop ({} peer channels)", peer_channels.len()),
    );

    let mut state = ServiceState::new(argon2_params);
    state.ldap = ldap_runtime;
    main_loop(sealed, &supervisor_channel, &peer_channels, &mut state)
}

/// Wait (pre-seal) for the supervisor's `AuthLdapProvision` and build the
/// rustls client config. Bounded wait: provisioning is sent right after spawn,
/// before any heartbeat. Control messages received in the meantime are
/// ignored (the supervisor's heartbeat grace period is far longer than this
/// wait). Returns an error if no fd-passing socket is available, the
/// provisioning never arrives, or the CA / URL is unusable.
fn build_ldap_runtime(
    supervisor: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
) -> Result<LdapRuntime> {
    let fd_passing_socket = fd_passing_socket
        .context("LDAP enabled but no VAUBAN_FD_PASSING_SOCKET provided by supervisor")?;

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bind_provision = None;
    let mut resolve_plan = None;
    while bind_provision.is_none() || resolve_plan.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            anyhow::bail!(
                "timed out waiting for AuthLdapProvision / AuthLdapAggregationProvision from supervisor"
            );
        }
        let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = poll_readable(&[supervisor.read_fd()], ms)
            .context("poll error while waiting for LDAP provision")?;
        if ready.is_empty() {
            continue;
        }
        match supervisor.recv() {
            Ok(Message::AuthLdapProvision {
                url,
                dn_template,
                ca_pem,
                timeout_secs,
            }) => bind_provision = Some((url, dn_template, ca_pem, timeout_secs)),
            Ok(Message::AuthLdapAggregationProvision { resolve_plan: plan }) => {
                resolve_plan = Some(plan);
            }
            Ok(other) => {
                // Heartbeats etc. may interleave; ignore until provisioning.
                warn!(
                    "Ignoring {:?} while awaiting LDAP provision",
                    std::mem::discriminant(&other)
                );
            }
            Err(e) => anyhow::bail!("IPC error while awaiting LDAP provision: {e}"),
        }
    }

    let (url, dn_template, ca_pem, timeout_secs) =
        bind_provision.context("AuthLdapProvision missing after wait")?;
    let resolve_plan = resolve_plan.context("AuthLdapAggregationProvision missing after wait")?;
    let (host, port) = vauban_auth::parse_ldaps_endpoint(&url)
        .with_context(|| format!("invalid ldaps:// url from supervisor: {url:?}"))?;
    let client_config = vauban_auth::tls::build_client_config(&ca_pem)
        .context("failed to build rustls client config from provisioned CA")?;

    Ok(LdapRuntime {
        client_config,
        host,
        port,
        dn_template,
        timeout: Duration::from_secs(timeout_secs.max(1)),
        fd_passing_socket,
        resolve_plan,
    })
}

/// Parse topology channel env vars for a peer service.
/// Returns None if the env vars are not set (dev mode without full topology).
fn parse_topology_channel(service_suffix: &str) -> Option<IpcChannel> {
    let read_var = format!("VAUBAN_{}_IPC_READ", service_suffix);
    let write_var = format!("VAUBAN_{}_IPC_WRITE", service_suffix);

    let read_fd: RawFd = std::env::var(&read_var).ok()?.parse().ok()?;
    let write_fd: RawFd = std::env::var(&write_var).ok()?.parse().ok()?;

    Some(unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) })
}

fn load_argon2_params() -> Argon2Params {
    let memory_kb = std::env::var("VAUBAN_ARGON2_MEMORY_KB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(19456);
    let iterations = std::env::var("VAUBAN_ARGON2_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let parallelism = std::env::var("VAUBAN_ARGON2_PARALLELISM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    Argon2Params {
        memory_kb,
        iterations,
        parallelism,
    }
}

fn main_loop(
    _sealed: capsicum::Entered,
    supervisor: &IpcChannel,
    peers: &[(&str, &IpcChannel)],
    state: &mut ServiceState,
) -> Result<()> {
    let mut poll_fds: Vec<RawFd> = vec![supervisor.read_fd()];
    for (_, ch) in peers {
        poll_fds.push(ch.read_fd());
    }

    loop {
        if state.shutdown_requested {
            info!("Shutdown flag set, exiting main loop to run destructors");
            return Ok(());
        }

        let ready_indices = poll_readable(&poll_fds, 1000)?;

        if ready_indices.is_empty() {
            continue;
        }

        for &idx in &ready_indices {
            if idx == 0 {
                match supervisor.recv() {
                    Ok(msg) => {
                        if let Err(e) = dispatch_message(supervisor, supervisor, state, msg) {
                            warn!("Error handling supervisor message: {}", e);
                            state.requests_failed += 1;
                        }
                    }
                    Err(shared::ipc::IpcError::ConnectionClosed) => {
                        info!("Supervisor IPC connection closed, exiting");
                        return Ok(());
                    }
                    Err(e) => {
                        error!("Supervisor IPC receive error: {}", e);
                        state.requests_failed += 1;
                    }
                }
            } else {
                let peer_idx = idx - 1;
                if peer_idx < peers.len() {
                    let (name, channel) = peers[peer_idx];
                    match channel.recv() {
                        Ok(msg) => {
                            if let Err(e) = dispatch_message(channel, supervisor, state, msg) {
                                warn!("Error handling message from {}: {}", name, e);
                                state.requests_failed += 1;
                            }
                        }
                        Err(shared::ipc::IpcError::ConnectionClosed) => {
                            info!("IPC connection from {} closed", name);
                        }
                        Err(e) => {
                            error!("IPC receive error from {}: {}", name, e);
                            state.requests_failed += 1;
                        }
                    }
                }
            }
        }
    }
}

/// Route an inbound message. `AuthLdapBind` needs the supervisor channel (to
/// request the brokered TCP socket) in addition to the reply channel, so it is
/// dispatched here rather than inside [`handle_message`].
fn dispatch_message(
    reply: &IpcChannel,
    supervisor: &IpcChannel,
    state: &mut ServiceState,
    msg: Message,
) -> Result<()> {
    match msg {
        Message::AuthLdapBind {
            request_id,
            username,
            password,
        } => handle_ldap_bind(reply, supervisor, state, request_id, username, password),
        Message::AuthLdapBindAndSearch {
            request_id,
            username,
            password,
        } => handle_ldap_bind_and_search(reply, supervisor, state, request_id, username, password),
        other => handle_message(reply, state, other),
    }
}

/// Handle an `AuthLdapBind` request from vauban-web.
///
/// Performs a brokered TCP connect (via the supervisor), terminates TLS, and
/// runs an LDAP simple bind, all within a tight timeout budget. The plaintext
/// password never leaves this sandboxed process toward the supervisor. Every
/// failure mode maps to a coarse [`LdapBindOutcome`]; vauban-web collapses all
/// non-success outcomes to a single generic response (anti-enumeration).
fn handle_ldap_bind(
    reply: &IpcChannel,
    supervisor: &IpcChannel,
    state: &mut ServiceState,
    request_id: u64,
    username: String,
    password: SensitiveString,
) -> Result<()> {
    state.requests_processed += 1;

    // Take an owned snapshot so we drop the borrow on `state.ldap` before the
    // broker round-trip (whose `on_control` callback mutates `state`).
    let runtime = state.ldap.clone();
    let outcome = match runtime {
        Some(rt) => vauban_auth::bind::brokered_bind(
            supervisor,
            &rt,
            &username,
            password.as_str(),
            // Keep answering heartbeats during the (brief) blocking window.
            |ctrl| {
                let _ = handle_control(supervisor, state, ctrl);
            },
        ),
        None => {
            warn!(
                request_id,
                "AuthLdapBind received but LDAP is not configured; fail-closed"
            );
            LdapBindOutcome::Unreachable
        }
    };

    if !matches!(outcome, LdapBindOutcome::Success) {
        state.requests_failed += 1;
    }

    reply.send(&Message::AuthLdapBindResponse {
        request_id,
        outcome,
    })?;
    Ok(())
}

fn handle_ldap_bind_and_search(
    reply: &IpcChannel,
    supervisor: &IpcChannel,
    state: &mut ServiceState,
    request_id: u64,
    username: String,
    password: SensitiveString,
) -> Result<()> {
    state.requests_processed += 1;
    let runtime = state.ldap.clone();
    let (outcome, group_keys) = match runtime {
        Some(rt) => vauban_auth::bind::brokered_bind_and_search(
            supervisor,
            &rt,
            &username,
            password.as_str(),
            |ctrl| {
                let _ = handle_control(supervisor, state, ctrl);
            },
        ),
        None => {
            warn!(
                request_id,
                "AuthLdapBindAndSearch received but LDAP is not configured; fail-closed"
            );
            (
                shared::messages::LdapBindAndSearchOutcome::BindUnreachable,
                Vec::new(),
            )
        }
    };
    if matches!(
        outcome,
        shared::messages::LdapBindAndSearchOutcome::BindInvalidCredentials
            | shared::messages::LdapBindAndSearchOutcome::BindUnreachable
            | shared::messages::LdapBindAndSearchOutcome::BindTlsError
    ) {
        state.requests_failed += 1;
    }
    reply.send(&Message::AuthLdapBindAndSearchResponse {
        request_id,
        outcome,
        group_keys,
    })?;
    Ok(())
}

fn handle_message(channel: &IpcChannel, state: &mut ServiceState, msg: Message) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),

        // SECURITY: `AuthRequest` is a legacy IPC verb whose end-to-end logic
        // (credential lookup + lockout + session minting) was never implemented
        // in this service. Returning `Success` here would be a complete
        // authentication bypass for any caller that wires this verb up. We
        // fail closed -- the supported flow is `AuthVerifyPassword`
        // (and `AuthHashPassword` for hash creation), which `vauban-web`
        // already uses. If you need a higher-level verb, design it
        // explicitly; do not re-enable this branch.
        Message::AuthRequest {
            request_id,
            username,
            credential: _,
            source_ip,
        } => {
            warn!(
                request_id,
                %source_ip,
                user = %username,
                "Refusing AuthRequest: this IPC verb is not implemented; use AuthVerifyPassword"
            );
            state.requests_processed += 1;
            state.requests_failed += 1;

            let response = Message::AuthResponse {
                request_id,
                result: AuthResult::Failure {
                    reason: "auth.request_not_implemented".to_string(),
                },
            };
            channel.send(&response)?;
            Ok(())
        }

        // SECURITY: same rationale as `AuthRequest` -- the inline MFA
        // verification path was a stub that always returned success. Real
        // TOTP verification happens in `vauban-vault` via `VaultMfaVerify`,
        // and the high-level orchestration lives in `vauban-web`. We fail
        // closed so a stray caller cannot silently bypass MFA.
        Message::MfaVerify {
            request_id,
            challenge_id,
            code: _,
        } => {
            warn!(
                request_id,
                %challenge_id,
                "Refusing MfaVerify: this IPC verb is not implemented; use VaultMfaVerify"
            );
            state.requests_processed += 1;
            state.requests_failed += 1;

            let response = Message::MfaVerifyResponse {
                request_id,
                success: false,
                session_id: None,
            };
            channel.send(&response)?;
            Ok(())
        }

        Message::AuthVerifyPassword {
            request_id,
            password_hash,
            password,
        } => {
            state.requests_processed += 1;

            let valid = match PasswordHash::new(&password_hash) {
                Ok(parsed_hash) => match state.argon2() {
                    Ok(argon2) => argon2
                        .verify_password(password.as_str().as_bytes(), &parsed_hash)
                        .is_ok(),
                    Err(e) => {
                        error!(request_id, "Argon2 init error: {}", e);
                        state.requests_failed += 1;
                        false
                    }
                },
                Err(e) => {
                    warn!(request_id, "Invalid password hash format: {}", e);
                    false
                }
            };

            let response = Message::AuthVerifyPasswordResponse { request_id, valid };
            channel.send(&response)?;
            Ok(())
        }

        Message::AuthHashPassword {
            request_id,
            password,
        } => {
            state.requests_processed += 1;

            let (hash, error) = match state.argon2() {
                Ok(argon2) => {
                    let salt = SaltString::generate(&mut OsRng);
                    match argon2.hash_password(password.as_str().as_bytes(), &salt) {
                        Ok(h) => (Some(h.to_string()), None),
                        Err(e) => {
                            state.requests_failed += 1;
                            (None, Some(format!("Hash error: {}", e)))
                        }
                    }
                }
                Err(e) => {
                    state.requests_failed += 1;
                    (None, Some(format!("Argon2 init error: {}", e)))
                }
            };

            let response = Message::AuthHashPasswordResponse {
                request_id,
                hash,
                error,
            };
            channel.send(&response)?;
            Ok(())
        }

        _ => {
            warn!("Unexpected message type");
            Ok(())
        }
    }
}

fn handle_control(
    channel: &IpcChannel,
    state: &mut ServiceState,
    ctrl: ControlMessage,
) -> Result<()> {
    match ctrl {
        ControlMessage::Ping { seq } => {
            let stats = ServiceStats {
                uptime_secs: state.start_time.elapsed().as_secs(),
                requests_processed: state.requests_processed,
                requests_failed: state.requests_failed,
                active_connections: 0,
                pending_requests: 0,
                recording_ack_timeouts: 0,
                recording_ack_dropped: 0,
                recording_try_send_full: 0,
                recording_ack_wait_ms_max: 0,
            };
            let pong = Message::Control(ControlMessage::Pong { seq, stats });
            channel.send(&pong)?;
        }

        ControlMessage::Drain => {
            info!("Drain requested");
            state.draining = true;
            let response = Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            });
            channel.send(&response)?;
        }

        ControlMessage::Shutdown => {
            info!("Shutdown requested, setting graceful shutdown flag");
            // Set flag instead of exit(0) so the main loop breaks
            // and all destructors run.
            state.shutdown_requested = true;
        }

        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_state() -> ServiceState {
        ServiceState::new(Argon2Params::default())
    }

    // ==================== ServiceState Tests ====================

    #[test]
    fn test_service_state_default() {
        let state = test_state();
        assert_eq!(state.requests_processed, 0);
        assert_eq!(state.requests_failed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_service_state_uptime() {
        let state = test_state();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(state.start_time.elapsed().as_millis() >= 10);
    }

    #[test]
    fn test_argon2_params_default() {
        let params = Argon2Params::default();
        assert_eq!(params.memory_kb, 19456);
        assert_eq!(params.iterations, 2);
        assert_eq!(params.parallelism, 1);
    }

    // ==================== handle_control Tests ====================

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();
        state.requests_processed = 100;
        state.requests_failed = 5;

        // Handle Ping
        let ping = ControlMessage::Ping { seq: 42 };
        handle_control(&service, &mut state, ping).unwrap();

        // Read Pong response
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 42);
            assert_eq!(stats.requests_processed, 100);
            assert_eq!(stats.requests_failed, 5);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // Handle Drain
        let drain = ControlMessage::Drain;
        handle_control(&service, &mut state, drain).unwrap();

        // State should be draining
        assert!(state.draining);

        // Read DrainComplete response
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::DrainComplete { pending_requests }) = response {
            assert_eq!(pending_requests, 0);
        } else {
            panic!("Expected DrainComplete");
        }
    }

    // ==================== handle_message Tests ====================

    /// Regression test for the placeholder `AuthRequest` handler.
    ///
    /// Historically this stub returned `AuthResult::Success` for any input,
    /// which would have been a complete authentication bypass for any caller
    /// that wired the verb up. The handler must now fail closed with a
    /// machine-readable reason. This test guards against re-introducing
    /// the bypass.
    #[test]
    fn test_handle_message_auth_request_fails_closed() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let request = Message::AuthRequest {
            request_id: 1,
            username: "testuser".to_string(),
            credential: b"password".to_vec(),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        handle_message(&auth, &mut state, request).unwrap();

        // Failure must still be counted -- it is a refused request.
        assert_eq!(state.requests_processed, 1);
        assert_eq!(state.requests_failed, 1);

        let response: Message = web.recv().unwrap();
        match response {
            Message::AuthResponse {
                request_id,
                result: AuthResult::Failure { reason },
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(
                    reason, "auth.request_not_implemented",
                    "Failure reason must be the documented error code"
                );
            }
            other => panic!("Expected AuthResponse with Failure, got {:?}", other),
        }
    }

    /// Regression test for the placeholder `MfaVerify` handler.
    ///
    /// Historically this stub returned `success: true` with a placeholder
    /// session id. The handler must now fail closed (no success, no
    /// session id) so a stray caller cannot bypass MFA. Real MFA
    /// verification lives in `vauban-vault` (`VaultMfaVerify`).
    #[test]
    fn test_handle_message_mfa_verify_fails_closed() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let request = Message::MfaVerify {
            request_id: 2,
            challenge_id: "chal123".to_string(),
            code: "123456".to_string(),
        };

        handle_message(&auth, &mut state, request).unwrap();

        assert_eq!(state.requests_processed, 1);
        assert_eq!(state.requests_failed, 1);

        let response: Message = web.recv().unwrap();
        match response {
            Message::MfaVerifyResponse {
                request_id,
                success,
                session_id,
            } => {
                assert_eq!(request_id, 2);
                assert!(!success, "Stub MFA verify must NEVER return success");
                assert!(
                    session_id.is_none(),
                    "Stub MFA verify must NEVER mint a session id"
                );
            }
            other => panic!("Expected MfaVerifyResponse, got {:?}", other),
        }
    }

    /// Even with arbitrary inputs (empty username, all-zero credentials,
    /// empty MFA code), the stubs must always fail. This is a defence
    /// in depth against future refactors that might "trust" certain inputs.
    #[test]
    fn test_auth_stubs_never_succeed_for_any_input() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let inputs = vec![
            ("", b"".to_vec()),
            ("admin", b"admin".to_vec()),
            ("root", vec![0u8; 32]),
            ("\0\0\0", vec![0xFFu8; 256]),
        ];
        for (i, (user, cred)) in inputs.into_iter().enumerate() {
            let req = Message::AuthRequest {
                request_id: 1000 + i as u64,
                username: user.to_string(),
                credential: cred,
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            };
            handle_message(&auth, &mut state, req).unwrap();
            let response: Message = web.recv().unwrap();
            match response {
                Message::AuthResponse {
                    result: AuthResult::Success { .. },
                    ..
                } => panic!("AuthRequest stub must never return Success"),
                Message::AuthResponse {
                    result: AuthResult::Failure { .. },
                    ..
                } => {}
                other => panic!("Unexpected response: {:?}", other),
            }
        }

        for (i, code) in ["", "000000", "999999", "abcdef"].iter().enumerate() {
            let req = Message::MfaVerify {
                request_id: 2000 + i as u64,
                challenge_id: format!("chal-{}", i),
                code: code.to_string(),
            };
            handle_message(&auth, &mut state, req).unwrap();
            let response: Message = web.recv().unwrap();
            match response {
                Message::MfaVerifyResponse { success: true, .. } => {
                    panic!("MfaVerify stub must never return success")
                }
                Message::MfaVerifyResponse {
                    success: false,
                    session_id,
                    ..
                } => assert!(session_id.is_none()),
                other => panic!("Unexpected response: {:?}", other),
            }
        }
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // Handle Control message via handle_message
        let msg = Message::Control(ControlMessage::Ping { seq: 99 });
        handle_message(&service, &mut state, msg).unwrap();

        // Read Pong response
        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 99, .. })
        ));
    }

    #[test]
    fn test_handle_message_unexpected() {
        let (_supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // Handle unexpected message type (should not panic)
        let msg = Message::RbacCheck {
            request_id: 1,
            subject: "user".to_string(),
            object: "resource".to_string(),
            action: "read".to_string(),
        };

        let result = handle_message(&service, &mut state, msg);
        assert!(result.is_ok());
    }

    // ==================== Argon2id Tests ====================

    #[test]
    fn test_hash_password_and_verify() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let hash_req = Message::AuthHashPassword {
            request_id: 10,
            password: SensitiveString::new("my-secure-password".to_string()),
        };
        handle_message(&auth, &mut state, hash_req).unwrap();
        assert_eq!(state.requests_processed, 1);

        let response: Message = web.recv().unwrap();
        let hash = if let Message::AuthHashPasswordResponse {
            request_id,
            hash,
            error,
        } = response
        {
            assert_eq!(request_id, 10);
            assert!(error.is_none());
            hash.expect("hash should be Some")
        } else {
            panic!("Expected AuthHashPasswordResponse");
        };

        assert!(hash.starts_with("$argon2id$"));

        let verify_req = Message::AuthVerifyPassword {
            request_id: 11,
            password_hash: hash,
            password: SensitiveString::new("my-secure-password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();
        assert_eq!(state.requests_processed, 2);

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 11);
            assert!(valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    #[test]
    fn test_verify_wrong_password() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let hash_req = Message::AuthHashPassword {
            request_id: 20,
            password: SensitiveString::new("correct-password".to_string()),
        };
        handle_message(&auth, &mut state, hash_req).unwrap();

        let response: Message = web.recv().unwrap();
        let hash = if let Message::AuthHashPasswordResponse { hash, .. } = response {
            hash.unwrap()
        } else {
            panic!("Expected AuthHashPasswordResponse");
        };

        let verify_req = Message::AuthVerifyPassword {
            request_id: 21,
            password_hash: hash,
            password: SensitiveString::new("wrong-password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 21);
            assert!(!valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let verify_req = Message::AuthVerifyPassword {
            request_id: 30,
            password_hash: "not-a-valid-hash".to_string(),
            password: SensitiveString::new("password".to_string()),
        };
        handle_message(&auth, &mut state, verify_req).unwrap();

        let response: Message = web.recv().unwrap();
        if let Message::AuthVerifyPasswordResponse { request_id, valid } = response {
            assert_eq!(request_id, 30);
            assert!(!valid);
        } else {
            panic!("Expected AuthVerifyPasswordResponse");
        }
    }

    // ==================== Multiple Requests Tests ====================

    #[test]
    fn test_multiple_auth_requests() {
        let (web, auth) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // Send multiple auth requests
        for i in 0..5 {
            let request = Message::AuthRequest {
                request_id: i,
                username: format!("user{}", i),
                credential: b"password".to_vec(),
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            };
            handle_message(&auth, &mut state, request).unwrap();
        }

        // All requests should be processed
        assert_eq!(state.requests_processed, 5);

        // Read all responses
        for i in 0..5 {
            let response: Message = web.recv().unwrap();
            if let Message::AuthResponse { request_id, .. } = response {
                assert_eq!(request_id, i);
            } else {
                panic!("Expected AuthResponse");
            }
        }
    }

    // ==================== ServiceStats Tests ====================

    #[test]
    fn test_service_stats_in_pong() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // Process some requests
        state.requests_processed = 42;
        state.requests_failed = 3;

        // Wait a bit for uptime
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Send Ping
        let ping = ControlMessage::Ping { seq: 1 };
        handle_control(&service, &mut state, ping).unwrap();

        // Check stats in Pong
        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { stats, .. }) = response {
            assert_eq!(stats.requests_processed, 42);
            assert_eq!(stats.requests_failed, 3);
            // uptime_secs is u64, so always valid - just verify it exists
            let _ = stats.uptime_secs;
        } else {
            panic!("Expected Pong");
        }
    }

    // ==================== Structural Regression Tests ====================

    /// Helper: Extract production code (before #[cfg(test)]).
    fn prod_source() -> &'static str {
        let full = include_str!("main.rs");
        if let Some(idx) = full.find("#[cfg(test)]") {
            &full[..idx]
        } else {
            full
        }
    }

    #[test]
    fn test_no_process_exit_in_production_code() {
        let source = prod_source();
        assert!(
            !source.contains("process::exit"),
            "service must not call process::exit() in production code"
        );
    }

    #[test]
    fn test_has_shutdown_requested_flag() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested"),
            "ServiceState must have a shutdown_requested flag"
        );
    }

    #[test]
    fn test_main_loop_checks_shutdown_flag() {
        let source = prod_source();
        let main_loop_start = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop_start..];
        assert!(
            main_loop_source.contains("shutdown_requested"),
            "main_loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        let handle_ctrl_start = source
            .find("fn handle_control")
            .expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "handle_control must set shutdown_requested = true on Shutdown"
        );
    }

    #[test]
    fn test_argon2_env_vars_removed() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_ARGON2_MEMORY_KB\")"),
            "Argon2 env vars must be cleared after reading"
        );
    }

    #[test]
    fn test_handles_auth_verify_password() {
        let source = prod_source();
        assert!(
            source.contains("AuthVerifyPassword"),
            "handle_message must handle AuthVerifyPassword"
        );
    }

    #[test]
    fn test_handles_auth_hash_password() {
        let source = prod_source();
        assert!(
            source.contains("AuthHashPassword"),
            "handle_message must handle AuthHashPassword"
        );
    }

    /// Source-level guard against re-introducing the `AuthRequest`/
    /// `MfaVerify` stub bypass. We scan the production source for the
    /// telltale return shapes from the old stubs.
    #[test]
    fn test_source_does_not_mint_placeholder_session() {
        let source = prod_source();
        assert!(
            !source.contains("placeholder-session"),
            "production code must not mint placeholder sessions \
             (this string was the historical stub bypass)"
        );
    }

    /// `vauban-auth` must never mint `AuthResult::Success` itself: that would
    /// mean the service pretends to authenticate without going through the
    /// real password verification flow (`AuthVerifyPassword`). The high-level
    /// orchestration that turns a successful password check into a session
    /// lives in `vauban-web`, not here.
    #[test]
    fn test_production_code_never_constructs_auth_result_success() {
        let source = prod_source();
        assert!(
            !source.contains("AuthResult::Success"),
            "production code must never construct AuthResult::Success \
             (only verify primitives are exposed by this service)"
        );
    }

    /// `vauban-auth` must never return a positive `MfaVerifyResponse`: real
    /// TOTP verification lives in `vauban-vault` (`VaultMfaVerify`). If a
    /// caller sends `MfaVerify` to this service it must fail closed.
    #[test]
    fn test_production_code_never_returns_mfa_verify_success() {
        let source = prod_source();
        // We allow the literal `success: false` (the explicit fail-closed
        // response). We forbid `success: true` anywhere in production code.
        assert!(
            !source.contains("success: true"),
            "production code must never return MfaVerifyResponse with success=true"
        );
    }
}
