//! Vauban Vault Service
//!
//! Pure cryptographic service for encryption-at-rest of secrets.
//! Resolves M-1 (TOTP secrets in plaintext) and C-2 (SSH credentials in plaintext).
//!
//! Properties:
//! - No database, no network, no async runtime
//! - Synchronous poll(2)-based event loop
//! - Master key read from file before Capsicum sandbox entry
//! - All derived keys held in memory, zeroized on drop
//! - Plaintext zeroized immediately after each operation

mod transit;

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use shared::capsicum;
use shared::ipc::{poll_readable, IpcChannel};
use shared::messages::{ControlMessage, Message, ServiceStats};
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
    /// M-8: Flag set by ControlMessage::Shutdown to break the main loop
    /// and allow Drop/Zeroize to run (MasterKey, Keyring).
    shutdown_requested: bool,
    keyrings: HashMap<String, Keyring>,
}

fn main() -> ExitCode {
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

    // ── Clear ALL environment variables immediately ──
    // SAFETY: We are the only thread at this point, no concurrent access.
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        for suffix in ["WEB", "AUTH", "PROXY_SSH", "PROXY_RDP"] {
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

    capsicum::setup_service_sandbox(&all_fds, None).context("Failed to setup sandbox")?;

    info!(
        "Entered Capsicum sandbox, starting main loop ({} peer channels)",
        peer_channels.len()
    );

    let mut state = ServiceState {
        start_time: Instant::now(),
        requests_processed: 0,
        requests_failed: 0,
        draining: false,
        shutdown_requested: false,
        keyrings,
    };

    main_loop(
        &supervisor_channel,
        &peer_channels,
        &mut state,
    )
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
        let version: u32 = v.parse().context("VAUBAN_VAULT_KEY_VERSION must be a number")?;
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
        // M-8/M-10: Check shutdown flag before blocking on poll.
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
                            if let Err(e) =
                                handle_peer_message(channel, state, msg, name)
                            {
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
        // Supervisor may also forward vault requests in some topologies
        other => handle_vault_request(channel, state, other),
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
        other => {
            tracing::debug!("Vault request from {}", peer_name);
            handle_vault_request(channel, state, other)
        }
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

        // Legacy vault messages (placeholder responses)
        Message::VaultGetSecret { request_id, path } => {
            info!("Legacy vault get secret: {}", path);
            state.requests_processed += 1;
            Message::VaultSecretResponse {
                request_id,
                data: None,
            }
        }

        Message::VaultGetCredential {
            request_id,
            asset_id,
            credential_type,
        } => {
            info!(
                "Legacy vault get credential: {} ({})",
                asset_id, credential_type
            );
            state.requests_processed += 1;
            Message::VaultCredentialResponse {
                request_id,
                credential: None,
            }
        }

        _ => {
            warn!("Unexpected message type in vault");
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
            // M-8/M-10: Set flag instead of exit(0) so the main loop breaks
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
            keyrings: test_keyrings(),
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

    #[test]
    fn test_handle_legacy_vault_get_secret() {
        let (client, service) = IpcChannel::pair().unwrap();
        let mut state = test_state();

        let msg = Message::VaultGetSecret {
            request_id: 99,
            path: "/secrets/db".to_string(),
        };
        handle_vault_request(&service, &mut state, msg).unwrap();

        let response = client.recv().unwrap();
        if let Message::VaultSecretResponse { data: None, .. } = response {
            // Legacy returns None
        } else {
            panic!("Expected VaultSecretResponse with None data");
        }
    }

    // ==================== M-8/M-10 Structural Regression Tests ====================

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
    fn test_m8_no_process_exit_in_production_code() {
        let source = prod_source();
        assert!(
            !source.contains("process::exit"),
            "M-8/M-10: vauban-vault must not call process::exit() in production code"
        );
    }

    #[test]
    fn test_m8_has_shutdown_requested_flag() {
        let source = prod_source();
        assert!(
            source.contains("shutdown_requested"),
            "M-8/M-10: ServiceState must have a shutdown_requested flag"
        );
    }

    #[test]
    fn test_m8_main_loop_checks_shutdown_flag() {
        let source = prod_source();
        // Find the main_loop function and verify it checks shutdown_requested
        let main_loop_start = source.find("fn main_loop").expect("main_loop must exist");
        let main_loop_source = &source[main_loop_start..];
        assert!(
            main_loop_source.contains("shutdown_requested"),
            "M-8/M-10: main_loop must check shutdown_requested flag"
        );
    }

    #[test]
    fn test_m8_handle_control_sets_shutdown_flag() {
        let source = prod_source();
        // Find handle_control and verify it sets shutdown_requested
        let handle_ctrl_start = source.find("fn handle_control").expect("handle_control must exist");
        let handle_ctrl_source = &source[handle_ctrl_start..];
        assert!(
            handle_ctrl_source.contains("shutdown_requested = true"),
            "M-8/M-10: handle_control must set shutdown_requested = true on Shutdown"
        );
    }
}
