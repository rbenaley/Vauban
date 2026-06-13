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

//! Vauban Vault Service
//!
//! Pure cryptographic service for encryption-at-rest of secrets.
//! Encrypts TOTP secrets and SSH credentials that would otherwise be stored in plaintext.
//!
//! Properties:
//! - No database, no network, no async runtime
//! - Synchronous poll(2)-based event loop
//! - Master key read from file before Capsicum sandbox entry
//! - All derived keys held in memory, zeroized on drop
//! - Plaintext zeroized immediately after each operation

mod authz;
mod transit;

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use shared::ipc::{IpcChannel, poll_readable};
use shared::messages::{ControlMessage, Message, ServiceStats};
use shared::sandbox as capsicum;
use tracing::{error, info, warn};

use vauban_vault::keyring::{Keyring, MasterKey};

/// Default path for the master key file (production).
const DEFAULT_MASTER_KEY_PATH: &str = "/var/vauban/vault/master.key";

/// Default path for the key version file (production).
const DEFAULT_KEY_VERSION_PATH: &str = "/var/vauban/vault/key_version";

/// Service runtime state.
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    /// Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow Drop/Zeroize to run (MasterKey, Keyring).
    shutdown_requested: bool,
    /// VAU-002 anomaly counter: vault requests refused by the per-peer
    /// capability matrix (a compromised / misconfigured peer asking for a
    /// domain/verb it is not entitled to). Surfaced via `warn!` per event.
    requests_denied: u64,
    keyrings: HashMap<String, Keyring>,
}

fn main() -> ExitCode {
    // Provisioning subcommand: generate + seal the audit WORM Ed25519 signing
    // key. Runs offline (no IPC/sandbox) using the same master key + keyring.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("seal-audit-key") {
        return seal_audit_key_main(args.get(2).map(String::as_str));
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("vauban-vault starting");

    match run_service() {
        Ok(()) => {
            info!("vauban-vault exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("vauban-vault error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_service() -> Result<()> {
    // ── Parse supervisor IPC FDs ──
    let ipc_read_fd: RawFd = std::env::var("VAUBAN_IPC_READ")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_READ")?;
    let ipc_write_fd: RawFd = std::env::var("VAUBAN_IPC_WRITE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .context("Invalid VAUBAN_IPC_WRITE")?;

    // ── Parse topology pipe FDs (peer services) ──
    let web_channel = parse_topology_channel("WEB");
    let auth_channel = parse_topology_channel("AUTH");
    let proxy_ssh_channel = parse_topology_channel("PROXY_SSH");
    let proxy_rdp_channel = parse_topology_channel("PROXY_RDP");
    let audit_channel = parse_topology_channel("AUDIT");

    // ── Clear ALL environment variables immediately ──
    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        for suffix in ["WEB", "AUTH", "PROXY_SSH", "PROXY_RDP", "AUDIT"] {
            std::env::remove_var(format!("VAUBAN_{}_IPC_READ", suffix));
            std::env::remove_var(format!("VAUBAN_{}_IPC_WRITE", suffix));
        }
    }

    let supervisor_channel = unsafe { IpcChannel::from_raw_fds(ipc_read_fd, ipc_write_fd) };

    // ── Load master key (BEFORE sandbox) ──
    let master_key = load_master_key()?;
    let key_version = load_key_version()?;
    info!(
        "Loaded master key, building keyrings with {} version(s)",
        key_version
    );

    // ── Build keyrings ──
    let mut keyrings = HashMap::new();
    keyrings.insert(
        "mfa".to_string(),
        Keyring::new(master_key.as_bytes(), "mfa", key_version),
    );
    keyrings.insert(
        "credentials".to_string(),
        Keyring::new(master_key.as_bytes(), "credentials", key_version),
    );
    keyrings.insert(
        "audit".to_string(),
        Keyring::new(master_key.as_bytes(), "audit", key_version),
    );
    // master_key is dropped here -- MasterKey::drop() zeroizes the memory
    drop(master_key);

    for kr in keyrings.values() {
        info!(
            domain = kr.domain(),
            version = kr.current_version(),
            "Keyring ready"
        );
    }
    info!("Keyrings built, preparing to enter sandbox");

    // ── Collect all FDs for sandbox ──
    let mut all_fds = vec![ipc_read_fd, ipc_write_fd];
    let mut peer_channels: Vec<(&str, &IpcChannel)> = Vec::new();

    if let Some(ref ch) = web_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("web", ch));
    }
    if let Some(ref ch) = auth_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("auth", ch));
    }
    if let Some(ref ch) = proxy_ssh_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("proxy_ssh", ch));
    }
    if let Some(ref ch) = proxy_rdp_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("proxy_rdp", ch));
    }
    if let Some(ref ch) = audit_channel {
        all_fds.push(ch.read_fd());
        all_fds.push(ch.write_fd());
        peer_channels.push(("audit", ch));
    }

    let sealed =
        capsicum::setup_service_sandbox(&all_fds, None).context("Failed to setup sandbox")?;

    capsicum::log_main_loop_start(
        &sealed,
        &format!("starting main loop ({} peer channels)", peer_channels.len()),
    );

    let mut state = ServiceState {
        start_time: Instant::now(),
        requests_processed: 0,
        requests_failed: 0,
        draining: false,
        shutdown_requested: false,
        requests_denied: 0,
        keyrings,
    };

    main_loop(sealed, &supervisor_channel, &peer_channels, &mut state)
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

/// Load the master key from file.
///
/// The file path can be overridden with `VAUBAN_VAULT_MASTER_KEY_PATH`.
/// In development, the file can be created with:
/// `dd if=/dev/urandom of=master.key bs=32 count=1`
/// Resolve the default output path for the sealed audit signing key when the
/// operator does not pass one explicitly on the command line.
///
/// The sealed key MUST land where the supervisor later looks for it, i.e. under
/// the *audit WORM log root* configured per environment (`[audit] log_path` --
/// or the optional `[audit] signing_key_path` override -- in the TOML). Because
/// this provisioning subcommand runs OUTSIDE the supervisor (no config file is
/// parsed here), the path is resolved from the environment, in priority order:
///
/// 1. `VAUBAN_AUDIT_SIGNING_KEY_PATH` -- explicit full path (mirror of the
///    `[audit] signing_key_path` config override).
/// 2. `VAUBAN_AUDIT_LOG_PATH` -- the audit log root (mirror of `[audit]
///    log_path`); the key is placed at `<root>/signing_key.sealed`, the exact
///    location the supervisor reads.
/// 3. relative `audit/signing_key.sealed` -- workspace-local dev fallback
///    (matches `log_path = "audit"` in development.toml).
///
/// This deliberately drops the former hard-coded absolute
/// `/var/vauban/recordings/audit/...` default, which does not exist in dev and
/// conflated the WORM log with the deletable session-recordings tree.
fn default_sealed_audit_key_path() -> String {
    if let Ok(explicit) = std::env::var("VAUBAN_AUDIT_SIGNING_KEY_PATH")
        && !explicit.trim().is_empty()
    {
        return explicit;
    }
    if let Ok(root) = std::env::var("VAUBAN_AUDIT_LOG_PATH")
        && !root.trim().is_empty()
    {
        return std::path::Path::new(&root)
            .join("signing_key.sealed")
            .to_string_lossy()
            .into_owned();
    }
    std::path::Path::new("audit")
        .join("signing_key.sealed")
        .to_string_lossy()
        .into_owned()
}

/// CLI wrapper for `vauban-vault seal-audit-key [output_path]`.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn seal_audit_key_main(output: Option<&str>) -> ExitCode {
    match seal_audit_key(output) {
        Ok(path) => {
            println!("audit signing key sealed -> {path}");
            println!("public key written -> {path}.pub");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("seal-audit-key failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Generate a fresh Ed25519 seed, seal it with the `audit` keyring (AES-GCM),
/// and write `<output>` (sealed ciphertext) + `<output>.pub` (base64 public
/// key). The supervisor passes the sealed ciphertext to the audit child via
/// `VAUBAN_AUDIT_SIGNING_KEY_SEALED`; audit unseals it through
/// `VaultDecrypt{domain=audit}` at boot.
fn seal_audit_key(output: Option<&str>) -> Result<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::SigningKey;
    use zeroize::Zeroize;

    let default_path = default_sealed_audit_key_path();
    let output = output.unwrap_or(default_path.as_str());

    let master_key = load_master_key()?;
    let key_version = load_key_version()?;
    let keyring = Keyring::new(master_key.as_bytes(), "audit", key_version);

    // 32-byte random Ed25519 seed.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("rng failure: {e}"))?;

    // The vault transports plaintext as a UTF-8 String, so seal the seed
    // base64-encoded (audit base64-decodes after VaultDecrypt).
    let seed_b64 = BASE64.encode(seed);
    let ciphertext = keyring
        .encrypt(seed_b64.as_bytes())
        .context("failed to seal audit signing seed")?;

    let signing = SigningKey::from_bytes(&seed);
    let pub_b64 = BASE64.encode(signing.verifying_key().to_bytes());
    seed.zeroize();

    let out_path = std::path::Path::new(output);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create output directory")?;
    }
    std::fs::write(out_path, ciphertext.as_bytes()).context("failed to write sealed key")?;
    std::fs::write(format!("{output}.pub"), pub_b64.as_bytes())
        .context("failed to write public key")?;

    Ok(output.to_string())
}

fn load_master_key() -> Result<MasterKey> {
    let path = std::env::var("VAUBAN_VAULT_MASTER_KEY_PATH")
        .unwrap_or_else(|_| DEFAULT_MASTER_KEY_PATH.to_string());
    // SAFETY: single-threaded at this point
    unsafe { std::env::remove_var("VAUBAN_VAULT_MASTER_KEY_PATH") };

    MasterKey::from_file(&path).context(format!("Failed to load master key from '{}'", path))
}

/// Load the key version from file or environment variable.
fn load_key_version() -> Result<u32> {
    // Try env var first (development mode)
    if let Ok(v) = std::env::var("VAUBAN_VAULT_KEY_VERSION") {
        // SAFETY: single-threaded at this point
        unsafe { std::env::remove_var("VAUBAN_VAULT_KEY_VERSION") };
        let version: u32 = v
            .parse()
            .context("VAUBAN_VAULT_KEY_VERSION must be a number")?;
        if version == 0 {
            anyhow::bail!("Key version must be >= 1");
        }
        return Ok(version);
    }

    // Try file path from env var or default
    let path = std::env::var("VAUBAN_VAULT_KEY_VERSION_PATH")
        .unwrap_or_else(|_| DEFAULT_KEY_VERSION_PATH.to_string());
    // SAFETY: single-threaded at this point
    unsafe { std::env::remove_var("VAUBAN_VAULT_KEY_VERSION_PATH") };

    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let version: u32 = content
                .trim()
                .parse()
                .context(format!("Invalid key version in '{}'", path))?;
            if version == 0 {
                anyhow::bail!("Key version must be >= 1");
            }
            Ok(version)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "Key version file '{}' not found, defaulting to version 1",
                path
            );
            Ok(1)
        }
        Err(e) => Err(e).context(format!("Failed to read key version from '{}'", path)),
    }
}

fn main_loop(
    _sealed: capsicum::Entered,
    supervisor: &IpcChannel,
    peers: &[(&str, &IpcChannel)],
    state: &mut ServiceState,
) -> Result<()> {
    // Build the list of read FDs to poll.
    // Index 0 = supervisor, indices 1..N = peers
    let mut poll_fds: Vec<RawFd> = vec![supervisor.read_fd()];
    for (_, ch) in peers {
        poll_fds.push(ch.read_fd());
    }

    loop {
        // Check shutdown flag before blocking on poll.
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
                // Message from supervisor
                match supervisor.recv() {
                    Ok(msg) => {
                        if let Err(e) = handle_supervisor_message(supervisor, state, msg) {
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
                // Message from a peer service (idx - 1 in peers array)
                let peer_idx = idx - 1;
                if peer_idx < peers.len() {
                    let (name, channel) = peers[peer_idx];
                    match channel.recv() {
                        Ok(msg) => {
                            if let Err(e) = handle_peer_message(channel, state, msg, name) {
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

fn handle_supervisor_message(
    channel: &IpcChannel,
    state: &mut ServiceState,
    msg: Message,
) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),
        // VAU-002: the supervisor channel is control-only. The supervisor peer
        // has NO vault capability, so any forwarded vault verb is refused
        // here (closing the pre-fix implicit full-access forwarding path).
        // The authorization gate runs BEFORE handle_vault_request.
        other => {
            if !authz::is_authorized(authz::VaultPeer::Supervisor, &other) {
                deny_vault_request(
                    channel,
                    state,
                    &other,
                    authz::VaultPeer::Supervisor.as_str(),
                );
                return Ok(());
            }
            handle_vault_request(channel, state, other)
        }
    }
}

fn handle_peer_message(
    channel: &IpcChannel,
    state: &mut ServiceState,
    msg: Message,
    peer_name: &str,
) -> Result<()> {
    match msg {
        Message::Control(ctrl) => handle_control(channel, state, ctrl),
        // VAU-002: authorize on the supervisor-attested channel label BEFORE
        // any crypto. `peer_name` is the label the vault assigned the channel
        // at init from the env-var suffix the supervisor set; it is not
        // forgeable on the wire. An unknown label maps to `None` -> deny.
        other => {
            let authorized = authz::VaultPeer::from_channel_label(peer_name)
                .is_some_and(|peer| authz::is_authorized(peer, &other));
            if !authorized {
                deny_vault_request(channel, state, &other, peer_name);
                return Ok(());
            }
            handle_vault_request(channel, state, other)
        }
    }
}

/// VAU-002: refuse a vault request denied by the per-peer capability matrix.
///
/// Increments the anomaly counter, logs a structured `warn!`, and replies with
/// a typed `unauthorized` response (carrying NO secret material) so the
/// caller's pending request resolves instead of hanging until timeout.
fn deny_vault_request(
    channel: &IpcChannel,
    state: &mut ServiceState,
    msg: &Message,
    peer_label: &str,
) {
    state.requests_denied += 1;
    let (verb, domain) = authz::verb_and_domain(msg).unwrap_or(("non-vault", "-"));
    warn!(
        peer = peer_label,
        verb = verb,
        domain = domain,
        "vault request denied (capability matrix)"
    );
    if let Some(resp) = authz::denied_response(msg)
        && let Err(e) = channel.send(&resp)
    {
        warn!("failed to send vault denial response: {}", e);
    }
}

fn handle_vault_request(
    channel: &IpcChannel,
    state: &mut ServiceState,
    msg: Message,
) -> Result<()> {
    let response = match msg {
        Message::VaultEncrypt {
            request_id,
            domain,
            ref plaintext,
        } => {
            state.requests_processed += 1;
            transit::handle_encrypt(&state.keyrings, request_id, &domain, plaintext)
        }

        Message::VaultDecrypt {
            request_id,
            domain,
            ciphertext,
        } => {
            state.requests_processed += 1;
            transit::handle_decrypt(&state.keyrings, request_id, &domain, &ciphertext)
        }

        Message::VaultMfaGenerate {
            request_id,
            username,
            issuer,
        } => {
            state.requests_processed += 1;
            transit::handle_mfa_generate(&state.keyrings, request_id, &username, &issuer)
        }

        Message::VaultMfaVerify {
            request_id,
            encrypted_secret,
            code,
        } => {
            state.requests_processed += 1;
            transit::handle_mfa_verify(&state.keyrings, request_id, &encrypted_secret, &code)
        }

        Message::VaultMfaGetSecret {
            request_id,
            encrypted_secret,
        } => {
            state.requests_processed += 1;
            transit::handle_mfa_get_secret(&state.keyrings, request_id, &encrypted_secret)
        }

        // SECURITY: Earlier revisions of this file accepted two legacy
        // "get-by-id" vault verbs that returned `data: None` /
        // `credential: None` silently as placeholder responses. They have
        // been removed from `shared::messages` entirely (see the security
        // audit follow-up to the AuthRequest/MfaVerify hardening) because a
        // future caller could have interpreted `Ok(None)` as "no credential
        // needed for this asset" and bypassed authentication. All vault
        // traffic must now go through the encrypted-transit verbs
        // (`VaultEncrypt` / `VaultDecrypt` / `VaultMfa*`) handled above. Any
        // other message reaches the catch-all arm below, which fail-closes by
        // dropping the request without sending a response.
        _ => {
            warn!("Unexpected message type in vault (refusing fail-closed)");
            state.requests_failed += 1;
            return Ok(());
        }
    };

    channel.send(&response)?;
    // SensitiveString fields in MFA responses are zeroized automatically on drop.
    Ok(())
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
            // and Drop/Zeroize destructors run (MasterKey, Keyring).
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

    fn test_keyrings() -> HashMap<String, Keyring> {
        let mk = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let mut keyrings = HashMap::new();
        keyrings.insert("mfa".to_string(), Keyring::new(&mk, "mfa", 1));
        keyrings.insert(
            "credentials".to_string(),
            Keyring::new(&mk, "credentials", 1),
        );
        keyrings
    }

    fn test_state() -> ServiceState {
        ServiceState {
            start_time: Instant::now(),
            requests_processed: 0,
            requests_failed: 0,
            draining: false,
            shutdown_requested: false,
            requests_denied: 0,
            keyrings: test_keyrings(),
        }
    }

    /// The seal-audit-key default output must follow the configured recording
    /// storage root (never a hard-coded absolute path), in env priority order.
    #[test]
    fn test_default_sealed_audit_key_path_resolution() {
        // SAFETY: the vault test binary runs single-threaded (--test-threads=1).
        unsafe {
            std::env::remove_var("VAUBAN_AUDIT_SIGNING_KEY_PATH");
            std::env::remove_var("VAUBAN_AUDIT_LOG_PATH");
        }

        // 3. No env -> workspace-local dev fallback, never /var/vauban, and NOT
        //    under the recordings tree.
        let fallback = default_sealed_audit_key_path();
        assert_eq!(fallback, "audit/signing_key.sealed");
        assert!(!fallback.starts_with("/var/vauban"));
        assert!(!fallback.contains("recordings"));

        // 2. audit log root -> derived <root>/signing_key.sealed.
        unsafe { std::env::set_var("VAUBAN_AUDIT_LOG_PATH", "/var/vauban/audit") };
        assert_eq!(
            default_sealed_audit_key_path(),
            "/var/vauban/audit/signing_key.sealed"
        );

        // 1. explicit override wins over the log root.
        unsafe { std::env::set_var("VAUBAN_AUDIT_SIGNING_KEY_PATH", "/secrets/audit.sealed") };
        assert_eq!(default_sealed_audit_key_path(), "/secrets/audit.sealed");

        // An empty override falls through to the log-root derivation.
        unsafe { std::env::set_var("VAUBAN_AUDIT_SIGNING_KEY_PATH", "  ") };
        assert_eq!(
            default_sealed_audit_key_path(),
            "/var/vauban/audit/signing_key.sealed"
        );

        unsafe {
            std::env::remove_var("VAUBAN_AUDIT_SIGNING_KEY_PATH");
            std::env::remove_var("VAUBAN_AUDIT_LOG_PATH");
        }
    }

    #[test]
    fn test_handle_control_ping() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        handle_control(&service, &mut state, ControlMessage::Ping { seq: 7 }).unwrap();

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::Pong { seq: 7, .. })
        ));
    }

    #[test]
    fn test_handle_control_drain() {
        let (supervisor, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        handle_control(&service, &mut state, ControlMessage::Drain).unwrap();
        assert!(state.draining);

        let response: Message = supervisor.recv().unwrap();
        assert!(matches!(
            response,
            Message::Control(ControlMessage::DrainComplete { .. })
        ));
    }

    #[test]
    fn test_handle_vault_encrypt_via_main() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let msg = Message::VaultEncrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("my-password".to_string()),
        };
        handle_vault_request(&service, &mut state, msg).unwrap();
        assert_eq!(state.requests_processed, 1);

        let response = client.recv().unwrap();
        if let Message::VaultEncryptResponse {
            ciphertext: Some(ct),
            error: None,
            ..
        } = response
        {
            assert!(ct.starts_with("v1:"));
        } else {
            panic!("Expected VaultEncryptResponse success");
        }
    }

    #[test]
    fn test_handle_vault_decrypt_via_main() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // First encrypt
        let enc_msg = Message::VaultEncrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("secret-data".to_string()),
        };
        handle_vault_request(&service, &mut state, enc_msg).unwrap();
        let enc_response = client.recv().unwrap();
        let ciphertext = match enc_response {
            Message::VaultEncryptResponse {
                ciphertext: Some(ct),
                ..
            } => ct,
            _ => panic!("Expected encrypt response"),
        };

        // Then decrypt
        let dec_msg = Message::VaultDecrypt {
            request_id: 2,
            domain: "credentials".to_string(),
            ciphertext,
        };
        handle_vault_request(&service, &mut state, dec_msg).unwrap();

        let dec_response = client.recv().unwrap();
        if let Message::VaultDecryptResponse {
            plaintext: Some(pt),
            error: None,
            ..
        } = dec_response
        {
            assert_eq!(pt.as_str(), "secret-data");
        } else {
            panic!("Expected VaultDecryptResponse success");
        }
    }

    #[test]
    fn test_handle_vault_mfa_generate_via_main() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let msg = Message::VaultMfaGenerate {
            request_id: 1,
            username: "testuser".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        handle_vault_request(&service, &mut state, msg).unwrap();

        let response = client.recv().unwrap();
        if let Message::VaultMfaGenerateResponse {
            encrypted_secret: Some(enc),
            plaintext_secret: Some(pt),
            error: None,
            ..
        } = response
        {
            assert!(enc.starts_with("v1:"));
            assert!(!pt.as_str().is_empty());
        } else {
            panic!("Expected MfaGenerateResponse success");
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
            "vauban-vault must not call process::exit() in production code"
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
        // Find the main_loop function and verify it checks shutdown_requested
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
        // Find handle_control and verify it sets shutdown_requested
        let handle_ctrl_start = source
            .find("fn handle_control")
            .expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "handle_control must set shutdown_requested = true on Shutdown"
        );
    }

    /// SECURITY: the legacy fail-open Vault handlers MUST NOT come back.
    /// Reconstruct the forbidden tokens at runtime so this test never matches
    /// against itself.
    #[test]
    fn test_source_does_not_contain_legacy_vault_handlers() {
        let source = prod_source();
        let prefix = "Vault";
        for suffix in [
            "GetSecret",
            "SecretResponse",
            "GetCredential",
            "CredentialResponse",
        ] {
            let forbidden = format!("Message::{}{}", prefix, suffix);
            assert!(
                !source.contains(&forbidden),
                "vauban-vault production code must not reference the legacy \
                 verb `{}` (it returned data/credential: None silently and \
                 was removed for security; encrypted-transit verbs only)",
                forbidden
            );
        }

        let banner = format!(
            "{} vault {} ({})",
            "Legacy", "messages", "placeholder responses"
        );
        assert!(
            !source.contains(&banner),
            "vauban-vault production code must not carry the legacy \
             placeholder-responses banner comment"
        );
    }

    /// SECURITY: handle_vault_request must fail-closed on unknown variants
    /// (no response sent, requests_failed incremented).
    #[test]
    fn test_handle_vault_request_fail_closed_branch() {
        let source = prod_source();
        let start = source
            .find("fn handle_vault_request")
            .expect("handle_vault_request must exist");
        let body = &source[start..];
        assert!(
            body.contains("refusing fail-closed"),
            "handle_vault_request must contain a fail-closed catch-all that \
             refuses to respond to unknown verbs"
        );
        assert!(
            body.contains("requests_failed"),
            "handle_vault_request fail-closed branch must increment requests_failed"
        );
    }

    // ==================== VAU-002 Per-Peer Authorization ====================
    //
    // Behavioral / E2E tests at the trust boundary: drive the REAL
    // recv -> authorize -> transit -> respond path of `handle_peer_message`
    // (and `handle_supervisor_message`) over a genuine `IpcChannel::pair()`,
    // with a supervisor-attested peer label, and read the response on the
    // client end. This demonstrates the capability matrix is enforced exactly
    // where a compromised peer would cross the pipe.

    /// E2E: a `web` channel may encrypt then decrypt a credential (round-trip).
    #[test]
    fn test_vau002_web_channel_credentials_roundtrip() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let enc = Message::VaultEncrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("hunter2".to_string()),
        };
        handle_peer_message(&service, &mut state, enc, "web").unwrap();
        let ct = match client.recv().unwrap() {
            Message::VaultEncryptResponse {
                ciphertext: Some(c),
                error: None,
                ..
            } => c,
            other => panic!("expected encrypt success, got {other:?}"),
        };

        let dec = Message::VaultDecrypt {
            request_id: 2,
            domain: "credentials".to_string(),
            ciphertext: ct,
        };
        handle_peer_message(&service, &mut state, dec, "web").unwrap();
        match client.recv().unwrap() {
            Message::VaultDecryptResponse {
                plaintext: Some(pt),
                error: None,
                ..
            } => assert_eq!(pt.as_str(), "hunter2"),
            other => panic!("expected decrypt success, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 0);
    }

    /// SECURITY E2E: a compromised `proxy_ssh` peer is REFUSED when it tries to
    /// decrypt the `mfa` domain -- NO plaintext is returned and the anomaly
    /// counter increments. This is the core VAU-002 property: one compromised
    /// peer can no longer pivot to another domain's secrets.
    #[test]
    fn test_vau002_proxy_ssh_denied_mfa_decrypt_no_leak() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        // web legitimately produces an mfa ciphertext.
        let gen_msg = Message::VaultMfaGenerate {
            request_id: 1,
            username: "u".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        handle_peer_message(&service, &mut state, gen_msg, "web").unwrap();
        let enc_secret = match client.recv().unwrap() {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(s),
                ..
            } => s,
            other => panic!("expected generate success, got {other:?}"),
        };

        // proxy_ssh attempts to decrypt the mfa secret -> DENIED, no leak.
        let dec = Message::VaultDecrypt {
            request_id: 2,
            domain: "mfa".to_string(),
            ciphertext: enc_secret,
        };
        handle_peer_message(&service, &mut state, dec, "proxy_ssh").unwrap();
        match client.recv().unwrap() {
            Message::VaultDecryptResponse {
                plaintext: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unauthorized"), "error was: {e}"),
            other => panic!("expected unauthorized denial, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 1);
    }

    /// proxy_ssh CAN decrypt the credentials domain (its read-only grant).
    #[test]
    fn test_vau002_proxy_ssh_allowed_credentials_decrypt() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let enc = Message::VaultEncrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("pw".to_string()),
        };
        handle_peer_message(&service, &mut state, enc, "web").unwrap();
        let ct = match client.recv().unwrap() {
            Message::VaultEncryptResponse {
                ciphertext: Some(c),
                ..
            } => c,
            other => panic!("got {other:?}"),
        };

        let dec = Message::VaultDecrypt {
            request_id: 2,
            domain: "credentials".to_string(),
            ciphertext: ct,
        };
        handle_peer_message(&service, &mut state, dec, "proxy_ssh").unwrap();
        match client.recv().unwrap() {
            Message::VaultDecryptResponse {
                plaintext: Some(pt),
                error: None,
                ..
            } => assert_eq!(pt.as_str(), "pw"),
            other => panic!("got {other:?}"),
        }
        assert_eq!(state.requests_denied, 0);
    }

    /// auth may verify an MFA code but is REFUSED MfaGetSecret (no exfiltration
    /// of the raw TOTP secret).
    #[test]
    fn test_vau002_auth_can_verify_but_not_get_secret() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let gen_msg = Message::VaultMfaGenerate {
            request_id: 1,
            username: "u".to_string(),
            issuer: "VAUBAN".to_string(),
        };
        handle_peer_message(&service, &mut state, gen_msg, "web").unwrap();
        let enc_secret = match client.recv().unwrap() {
            Message::VaultMfaGenerateResponse {
                encrypted_secret: Some(s),
                ..
            } => s,
            other => panic!("got {other:?}"),
        };

        // auth verifies a (wrong) code -> ALLOWED, returns valid=false.
        let verify = Message::VaultMfaVerify {
            request_id: 2,
            encrypted_secret: enc_secret.clone(),
            code: "000000".to_string(),
        };
        handle_peer_message(&service, &mut state, verify, "auth").unwrap();
        match client.recv().unwrap() {
            Message::VaultMfaVerifyResponse {
                valid: false,
                error: None,
                ..
            } => {}
            other => panic!("expected verify allowed, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 0);

        // auth attempts to exfiltrate the secret -> DENIED.
        let get = Message::VaultMfaGetSecret {
            request_id: 3,
            encrypted_secret: enc_secret,
        };
        handle_peer_message(&service, &mut state, get, "auth").unwrap();
        match client.recv().unwrap() {
            Message::VaultMfaGetSecretResponse {
                plaintext_secret: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unauthorized"), "error was: {e}"),
            other => panic!("expected get_secret denied, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 1);
    }

    /// An unknown channel label is denied (defense against a mislabeled pipe).
    #[test]
    fn test_vau002_unknown_peer_label_denied() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let dec = Message::VaultDecrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            ciphertext: "v1:AAAA".to_string(),
        };
        handle_peer_message(&service, &mut state, dec, "proxy_iacs").unwrap();
        match client.recv().unwrap() {
            Message::VaultDecryptResponse {
                plaintext: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unauthorized"), "error was: {e}"),
            other => panic!("expected denial, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 1);
    }

    /// The supervisor channel is control-only: a forwarded vault verb is
    /// refused, but Control still works.
    #[test]
    fn test_vau002_supervisor_channel_denies_vault_verbs() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let enc = Message::VaultEncrypt {
            request_id: 1,
            domain: "credentials".to_string(),
            plaintext: SensitiveString::new("x".to_string()),
        };
        handle_supervisor_message(&service, &mut state, enc).unwrap();
        match client.recv().unwrap() {
            Message::VaultEncryptResponse {
                ciphertext: None,
                error: Some(e),
                ..
            } => assert!(e.contains("unauthorized"), "error was: {e}"),
            other => panic!("expected supervisor denial, got {other:?}"),
        }
        assert_eq!(state.requests_denied, 1);

        // Control still works over the supervisor channel.
        handle_supervisor_message(
            &service,
            &mut state,
            Message::Control(ControlMessage::Ping { seq: 9 }),
        )
        .unwrap();
        match client.recv().unwrap() {
            Message::Control(ControlMessage::Pong { seq: 9, .. }) => {}
            other => panic!("expected pong, got {other:?}"),
        }
    }

    // ---------- VAU-002 structural regression (source pins) ----------

    /// Production part of authz.rs (before #[cfg(test)]).
    fn authz_prod_source() -> &'static str {
        let full = include_str!("authz.rs");
        match full.find("#[cfg(test)]") {
            Some(idx) => &full[..idx],
            None => full,
        }
    }

    /// handle_peer_message MUST authorize BEFORE handling the vault request.
    #[test]
    fn test_vau002_peer_message_authorizes_before_handling() {
        let source = prod_source();
        let start = source
            .find("fn handle_peer_message")
            .expect("handle_peer_message must exist");
        let body = &source[start..];
        let authz_pos = body
            .find("is_authorized")
            .expect("handle_peer_message must call is_authorized");
        let handle_pos = body
            .find("handle_vault_request")
            .expect("handle_peer_message must call handle_vault_request");
        assert!(
            authz_pos < handle_pos,
            "is_authorized must be checked BEFORE handle_vault_request in handle_peer_message"
        );
    }

    /// handle_supervisor_message MUST gate vault verbs as the Supervisor peer.
    #[test]
    fn test_vau002_supervisor_message_gates_vault_verbs() {
        let source = prod_source();
        let start = source
            .find("fn handle_supervisor_message")
            .expect("handle_supervisor_message must exist");
        let body_full = &source[start..];
        let end = body_full
            .find("fn handle_peer_message")
            .unwrap_or(body_full.len());
        let body = &body_full[..end];
        assert!(
            body.contains("VaultPeer::Supervisor"),
            "supervisor handler must authorize as the Supervisor peer (control-only)"
        );
        assert!(
            body.contains("is_authorized"),
            "supervisor handler must call is_authorized before handle_vault_request"
        );
    }

    /// The authz matrix MUST be fail-closed: a `_ => false` catch-all and NO
    /// fail-open `_ => true` arm.
    #[test]
    fn test_vau002_authz_matrix_is_fail_closed() {
        let source = authz_prod_source();
        assert!(
            source.contains("_ => false"),
            "is_authorized must end with a fail-closed `_ => false` arm"
        );
        assert!(
            !source.contains("_ => true"),
            "is_authorized must NOT contain a fail-open `_ => true` arm"
        );
    }
}
