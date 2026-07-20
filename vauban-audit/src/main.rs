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

//! Vauban Audit Service
//!
//! Handles:
//! - WORM (Write Once Read Many) audit storage
//! - Session recording storage (fMP4 for RDP)
//! - Real-time alerts
//! - Audit log queries

mod fmp4_writer;
mod recording_manager;
mod ssh_recording_manager;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use recording_manager::RecordingManager;
use shared::ipc::{IpcChannel, poll_readable, recv_fd};
use shared::messages::{AuditEventType, ControlMessage, Message, ServiceStats};
use shared::sandbox as capsicum;
use ssh_recording_manager::SshRecordingManager;
use std::net::IpAddr;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};
use vauban_audit::iacs_recording_manager::{self, IacsRecordingManager};
use vauban_audit::worm::{AuditRecord, GENESIS_HASH, WormLog};

/// Seal the chain (Ed25519) every N persisted records inside a segment.
const SEAL_THRESHOLD: u64 = 64;
/// Rotate to a fresh segment every M persisted records.
const ROTATION_THRESHOLD: u64 = 10_000;

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    /// Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow destructors to run.
    shutdown_requested: bool,

    // ===== WORM audit log (tamper-evident, append-only) =====
    /// The current append-only WORM segment. Opened lazily on the first
    /// `AuditEvent` (the segment FD is brokered by the supervisor).
    worm: Option<WormLog>,
    /// Ed25519 signing key (seed unsealed from the vault at boot). When `None`
    /// the log is hash-chained but NOT sealed (`BestEffort`); when
    /// `audit_required` is set, a missing key is a hard boot failure.
    signing_key: Option<SigningKey>,
    /// Fail-closed switch: refuse to run without a signing key.
    audit_required: bool,
    /// Events durably persisted to the WORM log (hash-chained).
    events_persisted: u64,
    /// Events that could NOT be persisted (broker/write failure) -> `AuditNack`.
    events_failed: u64,
    /// Monotonic base for unique segment file names within this process run.
    segment_counter: u64,
    /// Number of segment rotations performed so far this run.
    rotations: u64,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
            worm: None,
            signing_key: None,
            audit_required: false,
            events_persisted: 0,
            events_failed: 0,
            segment_counter: 0,
            rotations: 0,
        }
    }
}

/// Current Unix time in seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Civil (year, month) from a Unix timestamp, dependency-free
/// (Howard Hinnant's `civil_from_days`). Used to lay out WORM segments under
/// a `YYYY/MM/` subtree the supervisor broker validates.
fn epoch_to_year_month(secs: u64) -> (i64, u32) {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32)
}

/// Build a WORM segment name (`YYYY/MM/audit-<n>.jsonl`) for the given rotation
/// index. The supervisor broker re-validates this shape (no `..`, fixed
/// subtree) before opening it append-only.
fn segment_name_for(state: &ServiceState, rotation_index: u64) -> String {
    let (y, m) = epoch_to_year_month(now_secs());
    let n = state.segment_counter.wrapping_add(rotation_index);
    format!("{y:04}/{m:02}/audit-{n}.jsonl")
}

fn main() -> ExitCode {
    // Offline admin subcommand: `vauban-audit verify <segment.jsonl>`.
    // Replays the hash chain and verifies every Ed25519 seal. Runs WITHOUT the
    // service tracing banner so its output is script-friendly.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("verify") {
        return run_verify(args.get(2).map(String::as_str));
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-audit starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-audit exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-audit error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

/// Offline integrity verification of a WORM segment file.
///
/// Exit code 0 = chain + seals valid; 2 = tamper/usage error.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_verify(path: Option<&str>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("usage: vauban-audit verify <segment.jsonl>");
        return ExitCode::from(2);
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("verify: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let reader = std::io::BufReader::new(file);
    match vauban_audit::worm::verify_reader(reader, vauban_audit::worm::GENESIS_HASH, 0) {
        Ok(report) => {
            println!(
                "OK: {} records ({} events, {} seals), head={}, next_seq={}",
                report.records,
                report.events,
                report.seals,
                hex::encode(report.head),
                report.next_seq
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("TAMPER/INVALID: {e}");
            ExitCode::from(2)
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

    let recording_enabled: bool = std::env::var("VAUBAN_RECORDING_ENABLED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);

    // Interval (ms) between periodic `fdatasync` sweeps of the active SSH/RDP
    // recordings. 0 disables the sweep entirely (legacy behaviour, instant
    // rollback knob). Default 1000 ms => at most ~1 s of media lost on a
    // power loss / kernel panic.
    let recording_fsync_interval_ms: u64 = std::env::var("VAUBAN_RECORDING_FSYNC_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|s| s.parse().ok());

    let proxy_rdp_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_PROXY_RDP_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_PROXY_RDP_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Proxy-RDP IPC channel available for recording");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_PROXY_RDP_IPC_READ/WRITE not set (RDP recording disabled)");
                None
            }
        }
    } else {
        None
    };

    let proxy_ssh_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_PROXY_SSH_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_PROXY_SSH_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Proxy-SSH IPC channel available for recording");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_PROXY_SSH_IPC_READ/WRITE not set (SSH recording disabled)");
                None
            }
        }
    } else {
        None
    };

    let proxy_iacs_fds: Option<(RawFd, RawFd)> = if recording_enabled {
        let r: Option<RawFd> = std::env::var("VAUBAN_PROXY_IACS_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_PROXY_IACS_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Proxy-IACS IPC channel available for recording");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_PROXY_IACS_IPC_READ/WRITE not set (IACS recording disabled)");
                None
            }
        }
    } else {
        None
    };

    // Web -> Audit pipe: the source of the broad AuditEvent stream (always
    // present, independent of recording). On the audit side the supervisor
    // labels this edge VAUBAN_WEB_IPC_*.
    let web_fds: Option<(RawFd, RawFd)> = {
        let r: Option<RawFd> = std::env::var("VAUBAN_WEB_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_WEB_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => {
                info!("Web IPC channel available for audit events");
                Some((r, w))
            }
            _ => {
                debug!("VAUBAN_WEB_IPC_READ/WRITE not set (no web audit producer)");
                None
            }
        }
    };

    // Audit -> Vault pipe: used ONCE at boot to unseal the Ed25519 signing-key
    // seed (VaultDecrypt{domain=audit}).
    let vault_fds: Option<(RawFd, RawFd)> = {
        let r: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_READ")
            .ok()
            .and_then(|s| s.parse().ok());
        let w: Option<RawFd> = std::env::var("VAUBAN_VAULT_IPC_WRITE")
            .ok()
            .and_then(|s| s.parse().ok());
        match (r, w) {
            (Some(r), Some(w)) => Some((r, w)),
            _ => None,
        }
    };

    // Sealed Ed25519 signing-key seed (ciphertext `v1:...`) and fail-closed
    // switch. Both provisioned by the supervisor.
    let sealed_signing_key: Option<String> = std::env::var("VAUBAN_AUDIT_SIGNING_KEY_SEALED").ok();
    let audit_required: bool = std::env::var("VAUBAN_AUDIT_REQUIRED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false);

    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_RECORDING_ENABLED");
        std::env::remove_var("VAUBAN_RECORDING_FSYNC_INTERVAL_MS");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_WRITE");
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_WRITE");
        std::env::remove_var("VAUBAN_PROXY_IACS_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_IACS_IPC_WRITE");
        std::env::remove_var("VAUBAN_WEB_IPC_READ");
        std::env::remove_var("VAUBAN_WEB_IPC_WRITE");
        std::env::remove_var("VAUBAN_VAULT_IPC_READ");
        std::env::remove_var("VAUBAN_VAULT_IPC_WRITE");
        std::env::remove_var("VAUBAN_AUDIT_SIGNING_KEY_SEALED");
        std::env::remove_var("VAUBAN_AUDIT_REQUIRED");
    }

    let channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    let proxy_rdp_channel = proxy_rdp_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    let proxy_ssh_channel = proxy_ssh_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    let proxy_iacs_channel = proxy_iacs_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    let web_channel = web_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });
    let vault_channel = vault_fds.map(|(r, w)| unsafe { IpcChannel::from_raw_fds(r, w) });

    info!("Resources opened, preparing to enter sandbox");

    let mut ipc_fds = vec![ipc_read_fd, ipc_write_fd];
    if let Some((r, w)) = proxy_rdp_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = proxy_ssh_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = proxy_iacs_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = web_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    if let Some((r, w)) = vault_fds {
        ipc_fds.push(r);
        ipc_fds.push(w);
    }
    // The fd_passing socket only ever receives fds via SCM_RIGHTS (recvmsg):
    // declare it as a dedicated fd-receiver so Capsicum narrows it to
    // fd_receiver_socket rights (no write) and OpenBSD gets the `recvfd`
    // pledge promise. It MUST NOT also appear in `ipc_fds` (one fd, one kind).
    let fd_receiver_fds: Option<Vec<RawFd>> = fd_passing_socket.map(|fd| vec![fd]);

    let sealed =
        capsicum::setup_service_sandbox_extended(&ipc_fds, None, fd_receiver_fds.as_deref())
            .context("Failed to setup sandbox")?;

    if recording_enabled {
        capsicum::log_main_loop_start(
            &sealed,
            &format!(
                "starting main loop with recording enabled (fd_passing = {})",
                fd_passing_socket.is_some()
            ),
        );
    } else {
        capsicum::log_main_loop_start(&sealed, "starting main loop");
    }

    let mut state = ServiceState {
        segment_counter: now_secs(),
        audit_required,
        ..ServiceState::default()
    };

    // Unseal the Ed25519 signing-key seed from the vault (best-effort retry).
    // BestEffort: continue hash-chained-but-unsealed when unavailable, unless
    // `audit_required` makes a missing key a hard boot failure (fail-closed).
    match unseal_signing_key(vault_channel.as_ref(), sealed_signing_key.as_deref()) {
        Some(key) => {
            info!("Audit signing key unsealed; WORM segments will be Ed25519-sealed");
            state.signing_key = Some(key);
        }
        None => {
            if state.audit_required {
                return Err(anyhow::anyhow!(
                    "VAUBAN_AUDIT_REQUIRED is set but the signing key could not be unsealed"
                ));
            }
            warn!(
                "Audit signing key unavailable; WORM log is hash-chained but NOT \
                 Ed25519-sealed (BestEffort mode)"
            );
        }
    }

    let mut recording_mgr = if recording_enabled {
        Some(RecordingManager::new())
    } else {
        None
    };

    let mut ssh_recording_mgr = if recording_enabled {
        Some(SshRecordingManager::new())
    } else {
        None
    };

    let mut iacs_recording_mgr = if recording_enabled {
        Some(IacsRecordingManager::new())
    } else {
        None
    };

    main_loop(
        MainLoopContext {
            channel: &channel,
            proxy_rdp_channel: proxy_rdp_channel.as_ref(),
            proxy_ssh_channel: proxy_ssh_channel.as_ref(),
            proxy_iacs_channel: proxy_iacs_channel.as_ref(),
            web_channel: web_channel.as_ref(),
            state: &mut state,
            recording_mgr: &mut recording_mgr,
            ssh_recording_mgr: &mut ssh_recording_mgr,
            iacs_recording_mgr: &mut iacs_recording_mgr,
            fd_passing_socket,
            recording_fsync_interval_ms,
        },
        sealed,
    )
}

struct MainLoopContext<'a> {
    channel: &'a IpcChannel,
    proxy_rdp_channel: Option<&'a IpcChannel>,
    proxy_ssh_channel: Option<&'a IpcChannel>,
    proxy_iacs_channel: Option<&'a IpcChannel>,
    web_channel: Option<&'a IpcChannel>,
    state: &'a mut ServiceState,
    recording_mgr: &'a mut Option<RecordingManager>,
    ssh_recording_mgr: &'a mut Option<SshRecordingManager>,
    iacs_recording_mgr: &'a mut Option<IacsRecordingManager>,
    fd_passing_socket: Option<RawFd>,
    /// Period (ms) between `fdatasync` sweeps; 0 disables the sweep.
    recording_fsync_interval_ms: u64,
}

fn main_loop(ctx: MainLoopContext<'_>, _sealed: capsicum::Entered) -> Result<()> {
    let MainLoopContext {
        channel,
        proxy_rdp_channel,
        proxy_ssh_channel,
        proxy_iacs_channel,
        web_channel,
        state,
        recording_mgr,
        ssh_recording_mgr,
        iacs_recording_mgr,
        fd_passing_socket,
        recording_fsync_interval_ms,
    } = ctx;
    let mut poll_fds: Vec<RawFd> = vec![channel.read_fd()];

    // Wake at least every `fsync` interval so the periodic durability sweep
    // runs even when no IPC traffic arrives (capped at 1 s, the legacy value).
    let poll_timeout_ms: i32 = if recording_fsync_interval_ms == 0 {
        1000
    } else {
        recording_fsync_interval_ms.min(1000) as i32
    };
    let mut last_sync_sweep = Instant::now();

    let rdp_poll_idx = if let Some(rdp_ch) = proxy_rdp_channel {
        poll_fds.push(rdp_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    let ssh_poll_idx = if let Some(ssh_ch) = proxy_ssh_channel {
        poll_fds.push(ssh_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    let iacs_poll_idx = if let Some(iacs_ch) = proxy_iacs_channel {
        poll_fds.push(iacs_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    let web_poll_idx = if let Some(web_ch) = web_channel {
        poll_fds.push(web_ch.read_fd());
        Some(poll_fds.len() - 1)
    } else {
        None
    };

    loop {
        // Check shutdown flag before blocking on poll.
        if state.shutdown_requested {
            info!("Shutdown flag set, exiting main loop to run destructors");
            // Final durability sweep: flush + fdatasync any session that still
            // has buffered bytes so a clean shutdown never loses recording tail.
            run_fsync_sweep(recording_mgr, ssh_recording_mgr);
            return Ok(());
        }

        let ready = poll_readable(&poll_fds, poll_timeout_ms)?;

        // Periodic durability sweep. Runs before the `ready.is_empty()`
        // early-continue so an idle service (poll timed out, no IPC traffic)
        // still flushes + fdatasyncs sessions that received data just before
        // going quiet. Time-gated, so it is a cheap no-op most iterations.
        if recording_fsync_interval_ms > 0
            && last_sync_sweep.elapsed() >= Duration::from_millis(recording_fsync_interval_ms)
        {
            run_fsync_sweep(recording_mgr, ssh_recording_mgr);
            last_sync_sweep = Instant::now();
        }

        if ready.is_empty() {
            continue;
        }

        // Index 0 is always the supervisor channel
        if ready.contains(&0) {
            match channel.recv() {
                Ok(msg) => {
                    if let Err(e) = handle_message(
                        channel,
                        state,
                        recording_mgr,
                        ssh_recording_mgr,
                        fd_passing_socket,
                        msg,
                    ) {
                        warn!("Error handling message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("IPC connection closed, exiting");
                    return Ok(());
                }
                Err(e) => {
                    error!("IPC receive error: {}", e);
                    state.requests_failed += 1;
                }
            }
        }

        // Proxy-RDP channel (if present)
        if let Some(idx) = rdp_poll_idx
            && ready.contains(&idx)
        {
            // SAFETY: rdp_poll_idx is only Some when proxy_rdp_channel is Some
            #[allow(clippy::unwrap_used)]
            let rdp_ch = proxy_rdp_channel.unwrap();
            match rdp_ch.recv() {
                Ok(msg) => {
                    let result = if matches!(msg, Message::AuditEvent { .. }) {
                        route_audit_event(rdp_ch, channel, fd_passing_socket, state, msg)
                    } else {
                        handle_recording_message(
                            state,
                            recording_mgr,
                            channel,
                            fd_passing_socket,
                            msg,
                        )
                    };
                    if let Err(e) = result {
                        warn!("Error handling recording message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Proxy-RDP IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Proxy-RDP IPC receive error");
                }
            }
        }

        // Proxy-SSH channel (if present)
        if let Some(idx) = ssh_poll_idx
            && ready.contains(&idx)
        {
            // SAFETY: ssh_poll_idx is only Some when proxy_ssh_channel is Some
            #[allow(clippy::unwrap_used)]
            let ssh_ch = proxy_ssh_channel.unwrap();
            match ssh_ch.recv() {
                Ok(msg) => {
                    let result = if matches!(msg, Message::AuditEvent { .. }) {
                        route_audit_event(ssh_ch, channel, fd_passing_socket, state, msg)
                    } else {
                        handle_ssh_recording_message(
                            state,
                            ssh_recording_mgr,
                            channel,
                            fd_passing_socket,
                            msg,
                        )
                    };
                    if let Err(e) = result {
                        warn!("Error handling SSH recording message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Proxy-SSH IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Proxy-SSH IPC receive error");
                }
            }
        }

        // Proxy-IACS channel (if present)
        if let Some(idx) = iacs_poll_idx
            && ready.contains(&idx)
        {
            #[allow(clippy::unwrap_used)]
            let iacs_ch = proxy_iacs_channel.unwrap();
            match iacs_ch.recv() {
                Ok(msg) => {
                    let result = if matches!(msg, Message::AuditEvent { .. }) {
                        route_audit_event(iacs_ch, channel, fd_passing_socket, state, msg)
                    } else {
                        handle_iacs_recording_message(
                            state,
                            iacs_recording_mgr,
                            channel,
                            iacs_ch,
                            fd_passing_socket,
                            msg,
                        )
                    };
                    if let Err(e) = result {
                        warn!("Error handling IACS recording message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Proxy-IACS IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Proxy-IACS IPC receive error");
                }
            }
        }

        // Web channel (if present): the broad AuditEvent stream from vauban-web.
        if let Some(idx) = web_poll_idx
            && ready.contains(&idx)
        {
            // SAFETY: web_poll_idx is only Some when web_channel is Some.
            #[allow(clippy::unwrap_used)]
            let web_ch = web_channel.unwrap();
            match web_ch.recv() {
                Ok(msg) => {
                    if let Err(e) =
                        route_audit_event(web_ch, channel, fd_passing_socket, state, msg)
                    {
                        warn!("Error handling web audit message: {}", e);
                        state.requests_failed += 1;
                    }
                }
                Err(shared::ipc::IpcError::ConnectionClosed) => {
                    info!("Web IPC connection closed");
                }
                Err(e) => {
                    debug!(error = %e, "Web IPC receive error");
                }
            }
        }
    }
}

/// Flush + `fdatasync` every dirty SSH/RDP recording session (best-effort).
///
/// Aggregates both managers' [`SyncStats`] and emits one debug line per sweep
/// when anything was synced or errored. IACS is intentionally untouched: it
/// already runs its own per-batch `fdatasync` with backpressure.
fn run_fsync_sweep(
    recording_mgr: &mut Option<RecordingManager>,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
) {
    let mut stats = recording_manager::SyncStats::default();
    if let Some(mgr) = recording_mgr.as_mut() {
        stats.merge(mgr.sync_dirty());
    }
    if let Some(mgr) = ssh_recording_mgr.as_mut() {
        stats.merge(mgr.sync_dirty());
    }
    if stats.synced > 0 || stats.errors > 0 {
        debug!(
            synced = stats.synced,
            skipped = stats.skipped,
            errors = stats.errors,
            "Recording fdatasync sweep"
        );
    }
}

fn handle_message(
    channel: &IpcChannel,
    state: &mut ServiceState,
    recording_mgr: &mut Option<RecordingManager>,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),

        Message::AuditEvent {
            timestamp,
            event_type,
            user_id,
            session_id,
            source_ip,
            details,
        } => {
            // Persist to the WORM log; ack ONLY after a durable append, nack on
            // failure (fail-closed). On the supervisor channel the reply and
            // broker channel are the same.
            handle_audit_event(
                channel,
                channel,
                fd_passing_socket,
                state,
                timestamp,
                event_type,
                user_id,
                session_id,
                source_ip,
                details,
            )
        }

        Message::SessionRecordingChunk {
            session_id,
            sequence,
            data,
        } => {
            info!(
                "Session recording chunk: session={} seq={} size={}",
                session_id,
                sequence,
                data.len()
            );
            state.requests_processed += 1;

            // TODO: Write to S3/MinIO storage
            Ok(())
        }

        // RDP recording messages can also arrive on the supervisor channel
        Message::RdpRecordingStart { .. }
        | Message::RdpVideoFrame { .. }
        | Message::RdpRecordingEnd { .. } => {
            handle_recording_message(state, recording_mgr, channel, fd_passing_socket, msg)
        }

        // SSH recording messages can also arrive on the supervisor channel
        Message::SshRecordingStart { .. }
        | Message::SshRecordingData { .. }
        | Message::SshRecordingEnd { .. } => {
            handle_ssh_recording_message(state, ssh_recording_mgr, channel, fd_passing_socket, msg)
        }

        _ => {
            warn!("Unexpected message type");
            Ok(())
        }
    }
}

/// Route an `AuditEvent` that arrived on a producer channel into the WORM log.
///
/// `reply_channel` is the channel the event arrived on (where the
/// `AuditAck`/`AuditNack` correlation reply is sent); `supervisor_channel` is
/// always the supervisor control channel (where segment FDs are brokered).
fn route_audit_event(
    reply_channel: &IpcChannel,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    state: &mut ServiceState,
    msg: Message,
) -> Result<()> {
    if let Message::AuditEvent {
        timestamp,
        event_type,
        user_id,
        session_id,
        source_ip,
        details,
    } = msg
    {
        handle_audit_event(
            reply_channel,
            supervisor_channel,
            fd_passing_socket,
            state,
            timestamp,
            event_type,
            user_id,
            session_id,
            source_ip,
            details,
        )
    } else {
        debug!("Non-audit message on audit producer channel, ignoring");
        Ok(())
    }
}

/// Persist one audit event to the tamper-evident WORM log, then reply.
///
/// Fail-closed: an `AuditAck` is sent ONLY after the event has been durably
/// appended (and `sync_all`'d) to the hash chain. Any failure to open a
/// segment or write the record yields an `AuditNack` (the producer treats the
/// event as not recorded) and increments the `events_failed` anomaly counter.
#[allow(clippy::too_many_arguments)]
fn handle_audit_event(
    reply_channel: &IpcChannel,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    state: &mut ServiceState,
    timestamp: u64,
    event_type: AuditEventType,
    user_id: Option<String>,
    session_id: Option<String>,
    source_ip: Option<IpAddr>,
    details: String,
) -> Result<()> {
    info!(
        category = event_type.category(),
        ?event_type,
        user = ?user_id,
        session = ?session_id,
        "Audit event received"
    );

    // Lazily open the first segment (FD brokered by the supervisor).
    if state.worm.is_none() {
        let segment_name = segment_name_for(state, 0);
        match request_audit_log_file_from_supervisor(
            supervisor_channel,
            fd_passing_socket,
            &segment_name,
        ) {
            Ok(file) => {
                state.worm = Some(WormLog::new(file, segment_name, GENESIS_HASH, 0));
            }
            Err(e) => {
                state.events_failed += 1;
                state.requests_failed += 1;
                warn!(error = %e, "audit: failed to open WORM segment; event NOT persisted");
                reply_channel.send(&Message::AuditNack {
                    timestamp,
                    error: format!("worm segment open failed: {e}"),
                })?;
                return Ok(());
            }
        }
    }

    let record = AuditRecord {
        timestamp,
        event_type: format!("{event_type:?}"),
        user_id,
        session_id,
        source_ip: source_ip.map(|ip| ip.to_string()),
        details,
    };

    let append_result = match state.worm.as_mut() {
        Some(worm) => worm.append_event(&record),
        None => {
            // Unreachable: we just ensured a segment above.
            state.events_failed += 1;
            reply_channel.send(&Message::AuditNack {
                timestamp,
                error: "worm not initialized".to_string(),
            })?;
            return Ok(());
        }
    };

    match append_result {
        Ok(_) => {
            state.events_persisted += 1;
            state.requests_processed += 1;

            // Seal on the threshold (Ed25519), when a key is available.
            let should_seal = state
                .worm
                .as_ref()
                .is_some_and(|w| w.records_in_segment().is_multiple_of(SEAL_THRESHOLD));
            if should_seal
                && let (Some(worm), Some(key)) = (state.worm.as_mut(), state.signing_key.as_ref())
                && let Err(e) = worm.seal(key, timestamp)
            {
                warn!(error = %e, "audit: failed to seal WORM segment");
            }

            // Rotate to a fresh segment past the size threshold (chain
            // continues across files).
            let should_rotate = state
                .worm
                .as_ref()
                .is_some_and(|w| w.records_in_segment() >= ROTATION_THRESHOLD);
            if should_rotate {
                rotate_segment(supervisor_channel, fd_passing_socket, state);
            }

            reply_channel.send(&Message::AuditAck { timestamp })?;
            Ok(())
        }
        Err(e) => {
            state.events_failed += 1;
            state.requests_failed += 1;
            warn!(error = %e, "audit: WORM append failed; event NOT persisted");
            reply_channel.send(&Message::AuditNack {
                timestamp,
                error: format!("worm append failed: {e}"),
            })?;
            Ok(())
        }
    }
}

/// Seal (if a key is available) and rotate the WORM log into a fresh segment.
fn rotate_segment(
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    state: &mut ServiceState,
) {
    // Seal the closing segment first.
    if let (Some(worm), Some(key)) = (state.worm.as_mut(), state.signing_key.as_ref())
        && let Err(e) = worm.seal(key, now_secs())
    {
        warn!(error = %e, "audit: failed to seal segment before rotation");
    }
    let next_index = state.rotations + 1;
    let segment_name = segment_name_for(state, next_index);
    match request_audit_log_file_from_supervisor(
        supervisor_channel,
        fd_passing_socket,
        &segment_name,
    ) {
        Ok(file) => {
            if let Some(worm) = state.worm.as_mut()
                && let Err(e) = worm.rotate(file, segment_name)
            {
                warn!(error = %e, "audit: failed to rotate WORM segment");
            } else {
                state.rotations = next_index;
            }
        }
        Err(e) => {
            warn!(error = %e, "audit: failed to open next WORM segment; staying on current");
        }
    }
}

/// Request an APPEND-ONLY WORM segment FD from the supervisor broker.
///
/// Unlike `request_file_from_supervisor`, the path is a confined `segment_name`
/// under the fixed `audit/` subtree (the supervisor opens it `O_APPEND`, never
/// truncating, and rejects any `..`).
fn request_audit_log_file_from_supervisor(
    channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    segment_name: &str,
) -> Result<std::fs::File> {
    let fd_socket =
        fd_passing_socket.ok_or_else(|| anyhow::anyhow!("no fd_passing socket available"))?;

    channel.send(&Message::AuditLogFileRequest {
        request_id: 0,
        segment_name: segment_name.to_string(),
    })?;

    loop {
        match channel.recv() {
            Ok(Message::AuditLogFileResponse {
                request_id: _,
                success,
                error,
            }) => {
                if !success {
                    return Err(anyhow::anyhow!(
                        "supervisor refused audit segment: {}",
                        error.unwrap_or_default()
                    ));
                }
                let owned_fd =
                    recv_fd(fd_socket).map_err(|e| anyhow::anyhow!("recv_fd failed: {e}"))?;
                let file = unsafe { std::fs::File::from_raw_fd(owned_fd.into_raw_fd()) };
                return Ok(file);
            }
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let stats = ServiceStats {
                    uptime_secs: 0,
                    requests_processed: 0,
                    requests_failed: 0,
                    active_connections: 0,
                    pending_requests: 0,
                };
                let _ = channel.send(&Message::Control(ControlMessage::Pong { seq, stats }));
            }
            Ok(other) => {
                debug!(msg = ?other, "Unexpected message while waiting for AuditLogFileResponse");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "IPC error waiting for AuditLogFileResponse: {e}"
                ));
            }
        }
    }
}

/// Unseal the Ed25519 signing-key seed via `VaultDecrypt{domain=audit}`.
///
/// Bounded retry over the vault channel. Returns `None` when the vault is
/// unavailable, the env ciphertext is absent, or the decrypted seed is not 32
/// bytes (the caller decides BestEffort vs. fail-closed).
fn unseal_signing_key(
    vault_channel: Option<&IpcChannel>,
    sealed_ciphertext: Option<&str>,
) -> Option<SigningKey> {
    let vault = vault_channel?;
    let ciphertext = sealed_ciphertext?;
    if ciphertext.is_empty() {
        return None;
    }

    const MAX_ATTEMPTS: u32 = 5;
    for attempt in 1..=MAX_ATTEMPTS {
        if vault
            .send(&Message::VaultDecrypt {
                request_id: attempt as u64,
                domain: "audit".to_string(),
                ciphertext: ciphertext.to_string(),
            })
            .is_err()
        {
            warn!(
                attempt,
                "audit: failed to send VaultDecrypt for signing key"
            );
            continue;
        }
        match vault.recv() {
            Ok(Message::VaultDecryptResponse {
                plaintext: Some(seed),
                error: None,
                ..
            }) => {
                // The vault decrypts to a UTF-8 String, so the 32-byte seed is
                // transported base64-encoded; decode it back to raw bytes.
                let decoded = BASE64.decode(seed.as_str().trim()).ok();
                if let Some(arr) = decoded.and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                    return Some(SigningKey::from_bytes(&arr));
                }
                warn!("audit: unsealed signing seed is not 32 bytes (base64)");
                return None;
            }
            Ok(Message::VaultDecryptResponse { error, .. }) => {
                warn!(attempt, error = ?error, "audit: vault refused signing-key decrypt");
            }
            Ok(other) => {
                debug!(msg = ?other, "audit: unexpected vault reply while unsealing");
            }
            Err(e) => {
                warn!(attempt, error = %e, "audit: vault IPC error while unsealing");
            }
        }
    }
    None
}

fn handle_recording_message(
    state: &mut ServiceState,
    recording_mgr: &mut Option<RecordingManager>,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    let Some(mgr) = recording_mgr.as_mut() else {
        debug!("Recording not enabled, ignoring recording message");
        return Ok(());
    };

    match msg {
        Message::RdpRecordingStart {
            session_id,
            width: _,
            height: _,
        } => {
            let relative_path = RecordingManager::compute_relative_path(&session_id);
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &relative_path,
            ) {
                Ok(file) => {
                    mgr.start_session(&session_id, file, relative_path);
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to obtain recording file from supervisor");
                }
            }
            state.requests_processed += 1;
        }
        Message::RdpVideoFrame {
            session_id,
            timestamp_us,
            is_keyframe,
            width,
            height,
            data,
        } => {
            match mgr.handle_frame(&session_id, timestamp_us, is_keyframe, width, height, &data) {
                recording_manager::FrameResult::Processed => {}
                recording_manager::FrameResult::NewSegmentNeeded { relative_path } => {
                    match request_file_from_supervisor(
                        supervisor_channel,
                        fd_passing_socket,
                        &session_id,
                        &relative_path,
                    ) {
                        Ok(file) => mgr.provide_segment_file(&session_id, file),
                        Err(e) => {
                            error!(session_id, error = %e, "Failed to obtain new segment file");
                        }
                    }
                }
            }
            state.requests_processed += 1;
        }
        Message::RdpRecordingEnd { session_id } => {
            if let Some(result) = mgr.end_session(&session_id) {
                let meta_json = RecordingManager::serialize_meta_json(&result.segments);
                match request_file_from_supervisor(
                    supervisor_channel,
                    fd_passing_socket,
                    &session_id,
                    &result.meta_json_relative_path,
                ) {
                    Ok(meta_file) => {
                        use std::io::Write;
                        let mut meta_file = meta_file;
                        if let Err(e) = meta_file
                            .write_all(meta_json.as_bytes())
                            .and_then(|_| meta_file.flush())
                        {
                            error!(session_id, error = %e, "Failed to write meta.json");
                        } else {
                            info!(session_id, "meta.json written successfully");
                        }
                    }
                    Err(e) => {
                        error!(session_id, error = %e, "Failed to obtain meta.json file from supervisor");
                    }
                }
            }
            state.requests_processed += 1;
        }
        _ => {
            debug!("Non-recording message on recording handler");
        }
    }

    Ok(())
}

fn handle_ssh_recording_message(
    state: &mut ServiceState,
    ssh_recording_mgr: &mut Option<SshRecordingManager>,
    supervisor_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    let Some(mgr) = ssh_recording_mgr.as_mut() else {
        debug!("SSH recording not enabled, ignoring SSH recording message");
        return Ok(());
    };

    match msg {
        Message::SshRecordingStart {
            session_id,
            width,
            height,
            asset_name,
            username,
        } => {
            let relative_path = SshRecordingManager::compute_relative_path(&session_id);
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &relative_path,
            ) {
                Ok(file) => {
                    mgr.start_session(
                        &session_id,
                        ssh_recording_manager::SshSessionStartParams {
                            file,
                            relative_path,
                            width,
                            height,
                            asset_name,
                            username,
                        },
                    );
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to obtain SSH recording file from supervisor");
                }
            }
            state.requests_processed += 1;
        }
        Message::SshRecordingData {
            session_id,
            timestamp_us,
            event_type,
            data,
        } => {
            mgr.handle_data(&session_id, timestamp_us, event_type, &data);
            state.requests_processed += 1;
        }
        Message::SshRecordingEnd { session_id } => {
            if let Some(result) = mgr.end_session(&session_id) {
                let meta_json = SshRecordingManager::serialize_meta_json(&result);
                match request_file_from_supervisor(
                    supervisor_channel,
                    fd_passing_socket,
                    &session_id,
                    &result.meta_json_relative_path,
                ) {
                    Ok(meta_file) => {
                        use std::io::Write;
                        let mut meta_file = meta_file;
                        if let Err(e) = meta_file
                            .write_all(meta_json.as_bytes())
                            .and_then(|_| meta_file.flush())
                        {
                            error!(session_id, error = %e, "Failed to write SSH meta.json");
                        } else {
                            info!(session_id, "SSH meta.json written successfully");
                        }
                    }
                    Err(e) => {
                        error!(session_id, error = %e, "Failed to obtain SSH meta.json file from supervisor");
                    }
                }
            }
            state.requests_processed += 1;
        }
        _ => {
            debug!("Non-SSH-recording message on SSH recording handler");
        }
    }

    Ok(())
}

fn handle_iacs_recording_message(
    state: &mut ServiceState,
    iacs_recording_mgr: &mut Option<IacsRecordingManager>,
    supervisor_channel: &IpcChannel,
    proxy_iacs_channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    msg: Message,
) -> Result<()> {
    let Some(mgr) = iacs_recording_mgr.as_mut() else {
        debug!("IACS recording not enabled, ignoring IACS recording message");
        return Ok(());
    };

    match msg {
        Message::IacsRecordingSessionStart {
            session_id,
            user_uuid,
            asset_uuid,
            ews_fingerprint,
            peer_ip,
            authenticated_at_us,
            connected_at_us,
        } => {
            let info = crate::iacs_recording_manager::IacsSessionStartInfo {
                user_uuid,
                asset_uuid,
                ews_fingerprint,
                peer_ip,
                authenticated_at_us,
                connected_at_us,
            };
            let session_json_relative = mgr.start_session(&session_id, info.clone());
            let session_json =
                IacsRecordingManager::serialize_session_json(&session_id, &info, None);
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &session_json_relative,
            ) {
                Ok(mut file) => {
                    use std::io::Write;
                    if let Err(e) = file
                        .write_all(session_json.as_bytes())
                        .and_then(|_| file.flush())
                    {
                        error!(session_id, error = %e, "Failed to write IACS session.json");
                    } else {
                        info!(session_id, "IACS session.json written at auth");
                    }
                }
                Err(e) => {
                    error!(
                        session_id,
                        error = %e,
                        "Failed to obtain IACS session.json file from supervisor"
                    );
                }
            }
            state.requests_processed += 1;
        }
        Message::IacsRecordingChannelStart {
            session_id,
            channel_id,
            target_host,
            target_port,
            opened_at_us,
            client_ip,
            client_port,
            server_ip,
            server_port,
            connected_at_us,
        } => {
            let relative_path = IacsRecordingManager::compute_channel_pcap_path(
                &session_id,
                channel_id,
                connected_at_us,
            );
            match request_file_from_supervisor(
                supervisor_channel,
                fd_passing_socket,
                &session_id,
                &relative_path,
            ) {
                Ok(file) => {
                    let endpoints = crate::iacs_recording_manager::IacsChannelEndpoints {
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                    };
                    mgr.start_channel(
                        &session_id,
                        channel_id,
                        file,
                        target_host,
                        target_port,
                        opened_at_us,
                        connected_at_us,
                        endpoints,
                    );
                }
                Err(e) => {
                    error!(
                        session_id,
                        channel_id,
                        error = %e,
                        "Failed to obtain IACS PCAP file from supervisor"
                    );
                }
            }
            state.requests_processed += 1;
        }
        Message::IacsRecordingData {
            session_id,
            channel_id,
            batch_seq,
            direction,
            timestamp_us,
            data,
        } => {
            match mgr.handle_data(
                &session_id,
                channel_id,
                batch_seq,
                direction,
                timestamp_us,
                &data,
            ) {
                Ok(acked_seq) => {
                    proxy_iacs_channel.send(&Message::IacsRecordingDataAck {
                        session_id: session_id.clone(),
                        channel_id,
                        batch_seq: acked_seq,
                    })?;
                }
                Err(e) => {
                    warn!(
                        session_id,
                        channel_id,
                        batch_seq,
                        error = ?e,
                        "IACS recording batch rejected"
                    );
                    state.requests_failed += 1;
                }
            }
            state.requests_processed += 1;
        }
        Message::IacsRecordingChannelEnd {
            session_id,
            channel_id,
            closed_at_us,
        } => {
            if let Some(paths) = mgr.end_channel(&session_id, channel_id, closed_at_us) {
                match request_gzip_from_supervisor(
                    supervisor_channel,
                    &session_id,
                    &paths.src_relative,
                    &paths.dst_relative,
                ) {
                    Ok((dst_size, blake3_hex)) => {
                        mgr.finalize_channel_gzip(&session_id, channel_id, blake3_hex, dst_size);
                    }
                    Err(e) => {
                        error!(
                            session_id,
                            channel_id,
                            error = %e,
                            "Failed to gzip IACS PCAP via supervisor"
                        );
                    }
                }
            }
            state.requests_processed += 1;
        }
        Message::IacsRecordingSessionEnd { session_id, reason } => {
            if let Some(result) = mgr.end_session(&session_id) {
                // `meta.json` is written even with `channels: []`:
                // a zero-channel authenticated login still leaves a
                // complete, hydratable audit bundle.
                let meta_json = IacsRecordingManager::serialize_meta_json(&result);
                match request_file_from_supervisor(
                    supervisor_channel,
                    fd_passing_socket,
                    &session_id,
                    &result.meta_json_relative_path,
                ) {
                    Ok(meta_file) => {
                        use std::io::Write;
                        let mut meta_file = meta_file;
                        if let Err(e) = meta_file
                            .write_all(meta_json.as_bytes())
                            .and_then(|_| meta_file.flush())
                        {
                            error!(session_id, error = %e, "Failed to write IACS meta.json");
                        } else {
                            info!(session_id, "IACS meta.json written successfully");
                        }
                    }
                    Err(e) => {
                        error!(
                            session_id,
                            error = %e,
                            "Failed to obtain IACS meta.json file from supervisor"
                        );
                    }
                }

                // Rewrite `session.json` with the close cause when
                // the session carried auth-time identity.
                if let (Some(rel), Some(info)) =
                    (&result.session_json_relative_path, &result.start_info)
                {
                    let ended_at_us = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;
                    let session_json = IacsRecordingManager::serialize_session_json(
                        &session_id,
                        info,
                        Some((ended_at_us, &reason)),
                    );
                    match request_file_from_supervisor(
                        supervisor_channel,
                        fd_passing_socket,
                        &session_id,
                        rel,
                    ) {
                        Ok(mut file) => {
                            use std::io::Write;
                            if let Err(e) = file
                                .write_all(session_json.as_bytes())
                                .and_then(|_| file.flush())
                            {
                                error!(session_id, error = %e, "Failed to rewrite IACS session.json");
                            } else {
                                info!(session_id, reason, "IACS session.json finalized");
                            }
                        }
                        Err(e) => {
                            error!(
                                session_id,
                                error = %e,
                                "Failed to obtain IACS session.json file from supervisor"
                            );
                        }
                    }
                }
            }
            state.requests_processed += 1;
        }
        _ => {
            debug!("Non-IACS-recording message on IACS recording handler");
        }
    }

    Ok(())
}

/// Request gzip of a PCAP file from the supervisor via IPC.
fn request_gzip_from_supervisor(
    channel: &IpcChannel,
    session_id: &str,
    src_relative: &str,
    dst_relative: &str,
) -> Result<(u64, String)> {
    channel.send(&Message::RecordingFileGzipRequest {
        request_id: 0,
        session_id: session_id.to_string(),
        src_relative: src_relative.to_string(),
        dst_relative: dst_relative.to_string(),
    })?;

    loop {
        match channel.recv() {
            Ok(Message::RecordingFileGzipResponse {
                request_id: _,
                session_id: sid,
                success,
                dst_size,
                blake3_hex,
                error,
            }) => {
                if sid != session_id {
                    warn!(expected = session_id, got = %sid, "Mismatched RecordingFileGzipResponse session_id");
                    continue;
                }
                if !success {
                    return Err(anyhow::anyhow!(
                        "supervisor refused gzip: {}",
                        error.unwrap_or_default()
                    ));
                }
                let hash = blake3_hex.ok_or_else(|| {
                    anyhow::anyhow!("supervisor gzip succeeded but no blake3_hex")
                })?;
                return Ok((dst_size, hash));
            }
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let stats = ServiceStats {
                    uptime_secs: 0,
                    requests_processed: 0,
                    requests_failed: 0,
                    active_connections: 0,
                    pending_requests: 0,
                };
                let _ = channel.send(&Message::Control(ControlMessage::Pong { seq, stats }));
            }
            Ok(other) => {
                debug!(msg = ?other, "Unexpected message while waiting for RecordingFileGzipResponse");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "IPC error waiting for RecordingFileGzipResponse: {e}"
                ));
            }
        }
    }
}

/// Request a file from the supervisor via IPC + SCM_RIGHTS.
///
/// Sends a `RecordingFileRequest`, waits for the `RecordingFileResponse`,
/// and receives the file descriptor on the fd_passing socket.
fn request_file_from_supervisor(
    channel: &IpcChannel,
    fd_passing_socket: Option<RawFd>,
    session_id: &str,
    relative_path: &str,
) -> Result<std::fs::File> {
    let fd_socket =
        fd_passing_socket.ok_or_else(|| anyhow::anyhow!("no fd_passing socket available"))?;

    channel.send(&Message::RecordingFileRequest {
        request_id: 0,
        session_id: session_id.to_string(),
        relative_path: relative_path.to_string(),
        read_only: false,
    })?;

    // Blocking wait for response. Handle Pings while waiting.
    loop {
        match channel.recv() {
            Ok(Message::RecordingFileResponse {
                request_id: _,
                session_id: sid,
                success,
                error,
            }) => {
                if sid != session_id {
                    warn!(expected = session_id, got = %sid, "Mismatched RecordingFileResponse session_id");
                    continue;
                }
                if !success {
                    return Err(anyhow::anyhow!(
                        "supervisor refused file creation: {}",
                        error.unwrap_or_default()
                    ));
                }
                let owned_fd =
                    recv_fd(fd_socket).map_err(|e| anyhow::anyhow!("recv_fd failed: {e}"))?;
                let file = unsafe { std::fs::File::from_raw_fd(owned_fd.into_raw_fd()) };
                return Ok(file);
            }
            Ok(Message::Control(ControlMessage::Ping { seq })) => {
                let stats = ServiceStats {
                    uptime_secs: 0,
                    requests_processed: 0,
                    requests_failed: 0,
                    active_connections: 0,
                    pending_requests: 0,
                };
                let _ = channel.send(&Message::Control(ControlMessage::Pong { seq, stats }));
            }
            Ok(other) => {
                debug!(msg = ?other, "Unexpected message while waiting for RecordingFileResponse");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "IPC error waiting for RecordingFileResponse: {e}"
                ));
            }
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
            seal_on_lifecycle(state, "drain");
            let response = Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            });
            channel.send(&response)?;
        }
        ControlMessage::Shutdown => {
            info!("Shutdown requested, setting graceful shutdown flag");
            // Seal the WORM chain head before exiting so the on-disk log ends
            // on a verifiable signature.
            seal_on_lifecycle(state, "shutdown");
            // Set flag instead of exit(0) so the main loop breaks
            // and all destructors run.
            state.shutdown_requested = true;
        }
        _ => {}
    }
    Ok(())
}

/// Seal the current WORM segment on a lifecycle boundary (drain/shutdown),
/// when a signing key and an open segment are both available.
fn seal_on_lifecycle(state: &mut ServiceState, reason: &str) {
    if let (Some(worm), Some(key)) = (state.worm.as_mut(), state.signing_key.as_ref()) {
        match worm.seal(key, now_secs()) {
            Ok(_) => info!(reason, "audit: WORM segment sealed"),
            Err(e) => warn!(reason, error = %e, "audit: failed to seal WORM segment"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::AuditEventType;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_service_state_default() {
        let state = ServiceState::default();
        assert_eq!(state.requests_processed, 0);
        assert!(!state.draining);
    }

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        handle_control(&service, &mut state, ControlMessage::Ping { seq: 99 }).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 99, .. })
        ));
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

    /// Build a WormLog backed by a fresh tempfile (skips the broker so the
    /// append path can be exercised in-process).
    fn tempfile_worm() -> WormLog {
        let f = tempfile::tempfile().unwrap();
        WormLog::new(f, "test/seg.jsonl".to_string(), GENESIS_HASH, 0)
    }

    /// Fail-closed: with no open segment AND no fd_passing socket, the broker
    /// open fails -> the event is NACKed, never ACKed, and counted as failed.
    #[test]
    fn test_audit_event_fail_closed_without_broker() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();

        let event = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::AuthFailure,
            user_id: Some("alice".to_string()),
            session_id: None,
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            details: "bad password".to_string(),
        };
        handle_message(&service, &mut state, &mut None, &mut None, None, event).unwrap();

        assert_eq!(state.events_persisted, 0);
        assert_eq!(state.events_failed, 1);

        let response: Message = client.recv().unwrap();
        assert!(
            matches!(
                response,
                Message::AuditNack {
                    timestamp: 1706140800,
                    ..
                }
            ),
            "expected AuditNack, got {response:?}"
        );
    }

    /// Success path: with an open WORM segment, an event is durably appended,
    /// the chain head advances, and the producer is ACKed.
    #[test]
    fn test_audit_event_appends_and_acks() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState {
            worm: Some(tempfile_worm()),
            ..ServiceState::default()
        };
        let head_before = state.worm.as_ref().unwrap().head();

        let event = Message::AuditEvent {
            timestamp: 1706140800,
            event_type: AuditEventType::SessionStart,
            user_id: Some("alice".to_string()),
            session_id: Some("sess123".to_string()),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            details: "SSH session started".to_string(),
        };
        handle_message(&service, &mut state, &mut None, &mut None, None, event).unwrap();

        assert_eq!(state.events_persisted, 1);
        assert_eq!(state.events_failed, 0);
        assert_ne!(
            state.worm.as_ref().unwrap().head(),
            head_before,
            "chain head must advance after a persisted event"
        );

        let response: Message = client.recv().unwrap();
        assert!(
            matches!(
                response,
                Message::AuditAck {
                    timestamp: 1706140800
                }
            ),
            "expected AuditAck, got {response:?}"
        );
    }

    #[test]
    fn test_handle_message_session_recording() {
        let (_client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let chunk = Message::SessionRecordingChunk {
            session_id: "sess123".to_string(),
            sequence: 1,
            data: vec![0; 1024],
        };
        handle_message(
            &service,
            &mut state,
            &mut recording_mgr,
            &mut None,
            None,
            chunk,
        )
        .unwrap();

        assert_eq!(state.requests_processed, 1);
    }

    #[test]
    fn test_handle_message_control() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let msg = Message::Control(ControlMessage::Ping { seq: 11 });
        handle_message(
            &service,
            &mut state,
            &mut recording_mgr,
            &mut None,
            None,
            msg,
        )
        .unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 11, .. })
        ));
    }

    #[test]
    fn test_multiple_audit_events() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState {
            worm: Some(tempfile_worm()),
            ..ServiceState::default()
        };

        for i in 0..5 {
            let event = Message::AuditEvent {
                timestamp: 1000 + i,
                event_type: AuditEventType::AuthSuccess,
                user_id: Some(format!("user{}", i)),
                session_id: None,
                source_ip: None,
                details: "Login".to_string(),
            };
            handle_message(&service, &mut state, &mut None, &mut None, None, event).unwrap();
        }

        assert_eq!(state.events_persisted, 5);
        assert_eq!(state.requests_processed, 5);

        for i in 0..5 {
            let response: Message = client.recv().unwrap();
            if let Message::AuditAck { timestamp } = response {
                assert_eq!(timestamp, 1000 + i);
            } else {
                panic!("Expected AuditAck");
            }
        }
    }

    #[test]
    fn test_handle_recording_message_without_manager() {
        let (_sup, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut recording_mgr = None;

        let msg = Message::RdpRecordingStart {
            session_id: "test".to_string(),
            width: 1920,
            height: 1080,
        };
        handle_recording_message(&mut state, &mut recording_mgr, &service, None, msg).unwrap();
        assert_eq!(state.requests_processed, 0);
    }

    #[test]
    fn test_handle_recording_message_with_manager_via_fd_passing() {
        use shared::ipc::{send_fd, socketpair_for_fd_passing};
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let (supervisor_channel, audit_channel) = IpcChannel::pair().unwrap();
        let (supervisor_fd_sock, audit_fd_sock) = socketpair_for_fd_passing().unwrap();

        let audit_fd_sock_raw = audit_fd_sock.as_raw_fd();

        let mut state = ServiceState::default();
        let mut recording_mgr = Some(RecordingManager::new());

        // Simulate supervisor in a background thread
        let dir_path = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let msg = supervisor_channel.recv().unwrap();
            if let Message::RecordingFileRequest {
                request_id,
                session_id,
                relative_path,
                ..
            } = msg
            {
                let full_path = dir_path.join(&relative_path);
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                let file = std::fs::File::create(&full_path).unwrap();
                send_fd(supervisor_fd_sock.as_raw_fd(), file.as_raw_fd()).unwrap();
                supervisor_channel
                    .send(&Message::RecordingFileResponse {
                        request_id,
                        session_id,
                        success: true,
                        error: None,
                    })
                    .unwrap();
            } else {
                panic!("Expected RecordingFileRequest");
            }
        });

        let msg = Message::RdpRecordingStart {
            session_id: "rec-test".to_string(),
            width: 1920,
            height: 1080,
        };
        handle_recording_message(
            &mut state,
            &mut recording_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            msg,
        )
        .unwrap();
        assert_eq!(state.requests_processed, 1);

        handle.join().unwrap();
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

    // ==================== SSH Recording Integration Tests ====================

    #[test]
    fn test_handle_ssh_recording_message_without_manager() {
        let (_sup, service) = IpcChannel::pair().unwrap();
        let mut state = ServiceState::default();
        let mut ssh_mgr = None;

        let msg = Message::SshRecordingStart {
            session_id: "test".to_string(),
            width: 80,
            height: 24,
            asset_name: "host".to_string(),
            username: "user".to_string(),
        };
        handle_ssh_recording_message(&mut state, &mut ssh_mgr, &service, None, msg).unwrap();
        assert_eq!(state.requests_processed, 0);
    }

    #[test]
    fn test_handle_ssh_recording_full_ipc_flow() {
        use shared::ipc::{send_fd, socketpair_for_fd_passing};
        use shared::messages::SshRecordingEvent;
        use std::os::unix::io::AsRawFd;

        let dir = tempfile::tempdir().unwrap();
        let (supervisor_channel, audit_channel) = IpcChannel::pair().unwrap();
        let (supervisor_fd_sock, audit_fd_sock) = socketpair_for_fd_passing().unwrap();

        let audit_fd_sock_raw = audit_fd_sock.as_raw_fd();

        let mut state = ServiceState::default();
        let mut ssh_mgr = Some(SshRecordingManager::new());

        let dir_path = dir.path().to_path_buf();

        // Supervisor thread: handles 2 file requests (session.cast + meta.json)
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let msg = supervisor_channel.recv().unwrap();
                if let Message::RecordingFileRequest {
                    request_id,
                    session_id,
                    relative_path,
                    ..
                } = msg
                {
                    let full_path = dir_path.join(&relative_path);
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let file = std::fs::File::create(&full_path).unwrap();
                    send_fd(supervisor_fd_sock.as_raw_fd(), file.as_raw_fd()).unwrap();
                    supervisor_channel
                        .send(&Message::RecordingFileResponse {
                            request_id,
                            session_id,
                            success: true,
                            error: None,
                        })
                        .unwrap();
                } else {
                    panic!("Expected RecordingFileRequest, got {:?}", msg);
                }
            }
        });

        // Start SSH recording
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingStart {
                session_id: "ssh-ipc-test".to_string(),
                width: 120,
                height: 40,
                asset_name: "prod-server".to_string(),
                username: "admin".to_string(),
            },
        )
        .unwrap();
        assert_eq!(state.requests_processed, 1);

        // Send data events
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 0,
                event_type: SshRecordingEvent::Output,
                data: b"$ ".to_vec(),
            },
        )
        .unwrap();

        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 500_000,
                event_type: SshRecordingEvent::Input,
                data: b"ls\r".to_vec(),
            },
        )
        .unwrap();

        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingData {
                session_id: "ssh-ipc-test".to_string(),
                timestamp_us: 1_000_000,
                event_type: SshRecordingEvent::Output,
                data: b"file1  file2\r\n".to_vec(),
            },
        )
        .unwrap();

        // End recording (triggers meta.json write)
        handle_ssh_recording_message(
            &mut state,
            &mut ssh_mgr,
            &audit_channel,
            Some(audit_fd_sock_raw),
            Message::SshRecordingEnd {
                session_id: "ssh-ipc-test".to_string(),
            },
        )
        .unwrap();

        handle.join().unwrap();

        // Verify .cast file is valid asciicast v2
        let cast_files: Vec<_> = walkdir(dir.path(), "session.cast");
        assert_eq!(cast_files.len(), 1, "Exactly one session.cast file");

        let cast_content = std::fs::read_to_string(&cast_files[0]).unwrap();
        let lines: Vec<&str> = cast_content.lines().collect();
        assert!(lines.len() >= 4, "Header + 3 events minimum");

        // Verify header
        let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);
        assert_eq!(header["height"], 40);

        // Verify events are valid JSON arrays
        for line in &lines[1..] {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(event.is_array(), "Event must be a JSON array");
            assert_eq!(
                event.as_array().unwrap().len(),
                3,
                "Event must have 3 elements"
            );
        }

        // Verify meta.json exists and is valid
        let meta_files: Vec<_> = walkdir(dir.path(), "meta.json");
        assert_eq!(meta_files.len(), 1, "Exactly one meta.json file");

        let meta_content = std::fs::read_to_string(&meta_files[0]).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta["format"], "asciicast-v2");
        assert!(meta["blake3_hex"].as_str().unwrap().len() == 64);
        assert_eq!(meta["total_events"], 3);
        assert_eq!(meta["width"], 120);
        assert_eq!(meta["height"], 40);
    }

    fn walkdir(root: &std::path::Path, filename: &str) -> Vec<std::path::PathBuf> {
        let mut results = Vec::new();
        fn visit(dir: &std::path::Path, filename: &str, results: &mut Vec<std::path::PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        visit(&path, filename, results);
                    } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
                        results.push(path);
                    }
                }
            }
        }
        visit(root, filename, &mut results);
        results
    }

    // ==================== SSH Recording Structural Tests ====================

    #[test]
    fn test_ssh_recording_handler_exists() {
        let source = prod_source();
        assert!(
            source.contains("fn handle_ssh_recording_message"),
            "handle_ssh_recording_message function must exist"
        );
    }

    #[test]
    fn test_ssh_recording_main_loop_polls_ssh_channel() {
        let source = prod_source();
        let main_loop = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop..];
        assert!(
            main_loop_source.contains("ssh_poll_idx"),
            "main_loop must poll the SSH recording channel"
        );
    }

    #[test]
    fn test_ssh_recording_env_vars_cleaned() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_PROXY_SSH_IPC_READ\")"),
            "SSH IPC env vars must be cleaned up"
        );
        assert!(
            source.contains("remove_var(\"VAUBAN_PROXY_SSH_IPC_WRITE\")"),
            "SSH IPC env vars must be cleaned up"
        );
    }

    #[test]
    fn test_iacs_recording_handler_exists() {
        let source = prod_source();
        assert!(
            source.contains("fn handle_iacs_recording_message"),
            "handle_iacs_recording_message function must exist"
        );
    }

    #[test]
    fn test_iacs_recording_main_loop_polls_iacs_channel() {
        let source = prod_source();
        let main_loop = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop..];
        assert!(
            main_loop_source.contains("iacs_poll_idx"),
            "main_loop must poll the IACS recording channel"
        );
    }

    #[test]
    fn test_iacs_recording_env_vars_cleaned() {
        let source = prod_source();
        assert!(
            source.contains("remove_var(\"VAUBAN_PROXY_IACS_IPC_READ\")"),
            "IACS IPC env vars must be cleaned up"
        );
    }
}
