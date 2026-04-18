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

//! Vauban Access Control Service
//!
//! Handles:
//! - Role-Based Access Control using Casbin (feature-level)
//! - Instance-level access rules (SQL-based, per-asset authorization)
//! - Policy evaluation and caching
//! - Authorization decisions

use vauban_access::{db, handlers};

use anyhow::{Context, Result};
use casbin::prelude::*;
use shared::capsicum;
use shared::ipc::{IpcChannel, poll_readable};
use shared::messages::{AccessResponse, ControlMessage, Message, RbacResult, ServiceStats};
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    /// Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow destructors to run.
    shutdown_requested: bool,
    /// Casbin policy enforcer, loaded before sandbox entry.
    /// None only in tests or when env vars are not set (dev without supervisor).
    enforcer: Option<Enforcer>,
    /// Database connection pool for access rules and groups.
    /// None only in tests or dev mode without DATABASE_URL.
    db_pool: Option<db::DbPool>,
    /// Tokio runtime for running async DB queries in the sync main loop.
    /// Created once at startup; None only in tests without DB.
    rt: Option<tokio::runtime::Runtime>,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
            enforcer: None,
            db_pool: None,
            rt: None,
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-access starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-access exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-access error: {:#}", e);
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

    let model_path = std::env::var("VAUBAN_ACCESS_MODEL_PATH").ok();
    let policy_path = std::env::var("VAUBAN_ACCESS_POLICY_PATH").ok();
    let database_url = std::env::var("VAUBAN_DATABASE_URL").ok();

    let web_channel = parse_topology_channel("WEB");

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_ACCESS_MODEL_PATH");
        std::env::remove_var("VAUBAN_ACCESS_POLICY_PATH");
        std::env::remove_var("VAUBAN_DATABASE_URL");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
    }

    let supervisor_channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    let enforcer = Some(load_casbin_enforcer(
        model_path.as_deref(),
        policy_path.as_deref(),
    )?);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    let db_pool = if let Some(ref url) = database_url {
        let pool_size = 4;
        let pool = db::create_pool_sandboxed(url, pool_size)?;
        rt.block_on(db::force_create_all_connections(&pool, pool_size))?;
        info!(
            "Database pool ready ({} connections pre-established)",
            pool_size
        );
        Some(pool)
    } else {
        warn!("VAUBAN_DATABASE_URL not set, running without database (dev mode)");
        None
    };

    info!("Resources opened, preparing to enter sandbox");

    let mut all_fds = vec![ipc_read_fd, ipc_write_fd];
    let mut peer_channels: Vec<(&str, &IpcChannel)> = Vec::new();

    if let Some(ref ch) = web_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("web", ch));
    }

    let db_fd = if db_pool.is_some() {
        database_url
            .as_ref()
            .and_then(|_| std::env::var("VAUBAN_DB_FD").ok())
            .and_then(|v| v.parse::<RawFd>().ok())
    } else {
        None
    };
    capsicum::setup_service_sandbox(&all_fds, db_fd).context("Failed to setup sandbox")?;

    info!(
        "Entered Capsicum sandbox, starting main loop ({} peer channels)",
        peer_channels.len()
    );

    let mut state = ServiceState {
        enforcer,
        db_pool,
        rt: Some(rt),
        ..ServiceState::default()
    };
    main_loop(&supervisor_channel, &peer_channels, &mut state)
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

/// Load the Casbin enforcer from model and policy files.
///
/// Must be called BEFORE entering the Capsicum sandbox, since file access
/// is required to read model.conf and policy.csv.
///
/// Hard requirement: both environment variables must be set. vauban-access
/// is the sole source of truth for authorization and cannot run without an
/// enforcer; there is no fallback policy.
fn load_casbin_enforcer(model_path: Option<&str>, policy_path: Option<&str>) -> Result<Enforcer> {
    let (model, policy) = match (model_path, policy_path) {
        (Some(m), Some(p)) => (m, p),
        _ => anyhow::bail!(
            "VAUBAN_ACCESS_MODEL_PATH and VAUBAN_ACCESS_POLICY_PATH must both be set; \
             vauban-access refuses to start without a Casbin model and policy."
        ),
    };
    info!(model = %model, policy = %policy, "Loading Casbin model and policies");
    let model_string = model.to_string();
    let policy_string = policy.to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create Casbin tokio runtime")?;
    let casbin_model = rt
        .block_on(DefaultModel::from_file(model_string))
        .map_err(|e| anyhow::anyhow!("Failed to load Casbin model: {}", e))?;
    let adapter = FileAdapter::new(policy_string);
    let enforcer = rt
        .block_on(Enforcer::new(casbin_model, adapter))
        .map_err(|e| anyhow::anyhow!("Failed to create Casbin enforcer: {}", e))?;
    info!(
        policies = enforcer.get_all_policy().len(),
        roles = enforcer.get_all_roles().len(),
        "Casbin enforcer loaded"
    );
    Ok(enforcer)
}

fn main_loop(
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
                        if let Err(e) = handle_message(supervisor, state, msg) {
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
                            if let Err(e) = handle_message(channel, state, msg) {
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

fn handle_message(channel: &IpcChannel, state: &mut ServiceState, msg: Message) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),

        Message::RbacCheck {
            request_id,
            subject,
            object,
            action,
        } => {
            state.requests_processed += 1;

            let result = if let Some(ref enforcer) = state.enforcer {
                match enforcer.enforce(vec![subject.clone(), object.clone(), action.clone()]) {
                    Ok(allowed) => {
                        debug!(
                            subject = %subject,
                            object = %object,
                            action = %action,
                            allowed,
                            "RBAC check"
                        );
                        RbacResult {
                            allowed,
                            reason: if allowed {
                                None
                            } else {
                                Some("Policy denied".to_string())
                            },
                        }
                    }
                    Err(e) => {
                        error!(
                            subject = %subject,
                            object = %object,
                            action = %action,
                            error = %e,
                            "Casbin enforce error, denying by default"
                        );
                        RbacResult {
                            allowed: false,
                            reason: Some(format!("Enforcer error: {}", e)),
                        }
                    }
                }
            } else {
                // No enforcer loaded: this should only happen in unit tests that
                // explicitly build a `ServiceState::default()`. Production always
                // has an enforcer because `load_casbin_enforcer` hard-fails when
                // model/policy paths are missing.
                error!(
                    subject = %subject,
                    object = %object,
                    action = %action,
                    "RBAC policy engine not loaded - denying by default"
                );
                RbacResult {
                    allowed: false,
                    reason: Some("RBAC policy engine not configured".to_string()),
                }
            };

            let response = Message::RbacResponse { request_id, result };
            channel.send(&response)?;
            Ok(())
        }

        Message::AccessRequest {
            request_id,
            request,
        } => {
            state.requests_processed += 1;

            let response = match (&state.db_pool, &state.rt) {
                (Some(pool), Some(rt)) => {
                    rt.block_on(handlers::handle_access_request(pool, request))
                }
                _ => {
                    warn!("AccessRequest received but no DB pool available");
                    AccessResponse::Error("Database not configured".to_string())
                }
            };

            let msg = Message::AccessResponse {
                request_id,
                response,
            };
            channel.send(&msg)?;
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

    // ==================== Helpers ====================

    fn test_config_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("config")
            .join("access")
    }

    fn test_enforcer() -> Enforcer {
        let dir = test_config_dir();
        let model = dir.join("model.conf");
        let policy = dir.join("default_policy.csv");
        load_casbin_enforcer(
            Some(model.to_str().unwrap()),
            Some(policy.to_str().unwrap()),
        )
        .expect("Failed to load test enforcer")
    }

    fn state_with_enforcer() -> ServiceState {
        ServiceState {
            enforcer: Some(test_enforcer()),
            ..ServiceState::default()
        }
    }

    // ==================== Basic Tests ====================

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed, 0);
        assert_eq!(state.requests_failed, 0);
        assert!(!state.draining);
        assert!(state.enforcer.is_none());
    }

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState {
            requests_processed: 50,
            ..ServiceState::default()
        };

        let ping = ControlMessage::Ping { seq: 10 };
        handle_control(&service, &mut state, ping).unwrap();

        let response: Message = supervisor.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 10);
            assert_eq!(stats.requests_processed, 50);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        handle_control(&service, &mut state, ControlMessage::Drain).unwrap();
        assert!(state.draining);

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::DrainComplete { .. })
        ));
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let msg = Message::Control(ControlMessage::Ping { seq: 5 });
        handle_message(&service, &mut state, msg).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 5, .. })
        ));
    }

    // ==================== No-enforcer deny-by-default test ====================

    #[test]
    fn test_rbac_denies_when_no_enforcer_configured() {
        // The hardcoded fallback has been removed: if the enforcer is missing
        // (which can only happen inside unit tests that intentionally build a
        // `ServiceState::default()`), the handler must deny the request.
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let request = Message::RbacCheck {
            request_id: 42,
            subject: "role:superuser".to_string(),
            object: "users".to_string(),
            action: "write".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { request_id, result } = response {
            assert_eq!(request_id, 42);
            assert!(
                !result.allowed,
                "RBAC must deny when no Casbin enforcer is loaded (no debug fallback)"
            );
        } else {
            panic!("Expected RbacResponse");
        }
    }

    // ==================== Casbin Enforcer Tests ====================

    #[test]
    fn test_load_casbin_enforcer_success() {
        let enforcer = test_enforcer();
        assert!(
            !enforcer.get_all_policy().is_empty(),
            "Enforcer must have loaded policies"
        );
    }

    #[test]
    fn test_load_casbin_enforcer_error_when_no_paths() {
        // No fallback: missing paths must be a hard startup error.
        let result = load_casbin_enforcer(None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_casbin_enforcer_error_when_partial_paths() {
        let result = load_casbin_enforcer(Some("model.conf"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_casbin_superuser_has_full_access() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let request = Message::RbacCheck {
            request_id: 1,
            subject: "role:superuser".to_string(),
            object: "users".to_string(),
            action: "write".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { result, .. } = response {
            assert!(result.allowed, "superuser must have full access");
        } else {
            panic!("Expected RbacResponse");
        }
    }

    #[test]
    fn test_casbin_superuser_wildcard() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        for (obj, act) in [
            ("anything", "any_action"),
            ("admin", "delete"),
            ("users", "write"),
        ] {
            let request = Message::RbacCheck {
                request_id: 100,
                subject: "role:superuser".to_string(),
                object: obj.to_string(),
                action: act.to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { result, .. } = response {
                assert!(result.allowed, "superuser must be allowed for {obj}/{act}");
            } else {
                panic!("Expected RbacResponse");
            }
        }
    }

    #[test]
    fn test_casbin_staff_allowed_permissions() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let allowed = [
            ("users", "read"),
            ("users", "write"),
            ("assets", "read"),
            ("assets", "write"),
            ("sessions", "read"),
            ("sessions", "write"),
            ("groups", "read"),
            ("groups", "write"),
            ("access_rules", "read"),
            ("access_rules", "write"),
            ("admin", "view"),
        ];

        for (obj, act) in allowed {
            let request = Message::RbacCheck {
                request_id: 200,
                subject: "role:staff".to_string(),
                object: obj.to_string(),
                action: act.to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { result, .. } = response {
                assert!(result.allowed, "staff must be allowed for {obj}/{act}");
            } else {
                panic!("Expected RbacResponse");
            }
        }
    }

    #[test]
    fn test_casbin_staff_denied_unknown_resource() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let request = Message::RbacCheck {
            request_id: 300,
            subject: "role:staff".to_string(),
            object: "superadmin_panel".to_string(),
            action: "delete".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { result, .. } = response {
            assert!(
                !result.allowed,
                "staff must be denied for unknown resources"
            );
        } else {
            panic!("Expected RbacResponse");
        }
    }

    #[test]
    fn test_casbin_user_limited_access() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let allowed = [
            ("assets", "read"),
            ("profile", "read"),
            ("profile", "write"),
        ];

        for (obj, act) in allowed {
            let request = Message::RbacCheck {
                request_id: 400,
                subject: "role:user".to_string(),
                object: obj.to_string(),
                action: act.to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { result, .. } = response {
                assert!(result.allowed, "user must be allowed for {obj}/{act}");
            } else {
                panic!("Expected RbacResponse");
            }
        }
    }

    #[test]
    fn test_casbin_user_denied_admin() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let denied = [
            ("admin", "view"),
            ("users", "write"),
            ("groups", "write"),
            ("assets", "write"),
            ("sessions", "read"),
            ("sessions", "create"),
        ];

        for (obj, act) in denied {
            let request = Message::RbacCheck {
                request_id: 500,
                subject: "role:user".to_string(),
                object: obj.to_string(),
                action: act.to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { result, .. } = response {
                assert!(!result.allowed, "user must be denied for {obj}/{act}");
            } else {
                panic!("Expected RbacResponse");
            }
        }
    }

    #[test]
    fn test_casbin_unknown_role_denied() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        let request = Message::RbacCheck {
            request_id: 600,
            subject: "role:unknown".to_string(),
            object: "assets".to_string(),
            action: "read".to_string(),
        };
        handle_message(&service, &mut state, request).unwrap();

        let response: Message = client.recv().unwrap();
        if let Message::RbacResponse { result, .. } = response {
            assert!(!result.allowed, "unknown role must be denied");
        } else {
            panic!("Expected RbacResponse");
        }
    }

    /// Verify that the RBAC response preserves the request_id correctly.
    #[test]
    fn test_rbac_check_preserves_request_id() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        for id in [0, 1, 100, u64::MAX] {
            let request = Message::RbacCheck {
                request_id: id,
                subject: "role:superuser".to_string(),
                object: "resource:test".to_string(),
                action: "read".to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();

            let response: Message = client.recv().unwrap();
            if let Message::RbacResponse { request_id, .. } = response {
                assert_eq!(request_id, id, "RBAC response must echo request_id={id}");
            } else {
                panic!("Expected RbacResponse for request_id={id}");
            }
        }
    }

    /// Verify that each RBAC check increments the requests_processed counter.
    #[test]
    fn test_rbac_check_increments_counter() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = state_with_enforcer();

        assert_eq!(state.requests_processed, 0);

        for i in 1..=5 {
            let request = Message::RbacCheck {
                request_id: i,
                subject: "role:superuser".to_string(),
                object: "resource:any".to_string(),
                action: "read".to_string(),
            };
            handle_message(&service, &mut state, request).unwrap();
            assert_eq!(state.requests_processed, i);

            let _ = client.recv().unwrap();
        }
    }

    // ==================== Structural Regression Tests ====================

    /// Non-regression: the historical `#[cfg(debug_assertions)]` allow-all
    /// fallback has been removed. `vauban-access` is now mandatory at
    /// runtime — if the enforcer is missing, every request is denied.
    ///
    /// The forbidden substrings are reconstructed at runtime so that the
    /// assertion strings never match themselves.
    #[test]
    fn test_rbac_fallback_has_been_removed_from_prod_source() {
        let source = prod_source();

        let forbidden_dbg_cfg = format!("#[{}(debug_assertions)]", "cfg");
        assert!(
            !source.contains(&forbidden_dbg_cfg),
            "vauban-access production code must not contain debug-gated RBAC fallbacks"
        );

        let forbidden_not_dbg_cfg = format!("#[{}(not(debug_assertions))]", "cfg");
        assert!(
            !source.contains(&forbidden_not_dbg_cfg),
            "vauban-access production code must not split RBAC behavior by build profile"
        );

        let forbidden_fallback_str = format!("RBAC {}", "fallback");
        assert!(
            !source.contains(&forbidden_fallback_str),
            "vauban-access production code must not reference the legacy RBAC fallback"
        );

        // Production code MUST contain at least one deny-by-default path.
        assert!(
            source.contains("allowed: false"),
            "vauban-access production code must keep at least one deny-by-default path"
        );
    }

    /// Verify that Casbin enforcer loading is present in the source.
    #[test]
    fn test_casbin_integration_structural() {
        let source = include_str!("main.rs");

        assert!(
            source.contains("Enforcer::new"),
            "vauban-access must create a Casbin Enforcer"
        );
        assert!(
            source.contains("VAUBAN_ACCESS_MODEL_PATH"),
            "vauban-access must read VAUBAN_ACCESS_MODEL_PATH"
        );
        assert!(
            source.contains("VAUBAN_ACCESS_POLICY_PATH"),
            "vauban-access must read VAUBAN_ACCESS_POLICY_PATH"
        );
        assert!(
            source.contains("enforcer.enforce"),
            "vauban-access must call enforcer.enforce()"
        );
    }

    // ==================== Structural Regression Tests ====================

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
}
