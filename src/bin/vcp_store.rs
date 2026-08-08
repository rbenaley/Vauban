//! `vcp-store` — sandboxed artifact helper (architecture 1.2).
//!
//! Production: load `vcp-store.conf` (`--config` or default beside portal
//! config). Spawn accept path: parent passes `--blob-path` / `--listen` /
//! quota flags (same UID, no peercred filter).
//!
//! Ops CLI (separate invocation, no accept loop):
//!   vcp-store pending-ops                  # pending credentials + in-flight challenges
//!   vcp-store list-keys                    # pending / active / expired / revoked
//!   vcp-store approve-key --fingerprint <hex>
//!
//! Config for the ops CLI:
//! - `--blob-path PATH` — open that root
//! - `--config PATH` — load a `vcp-store.conf`-shaped helper TOML
//! - else — production `vcp-store.conf` (`/var/db/vcp/storage`, …)

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use vcp::cli::{HelpStyle, styled_literal_col, version_line, wants_help, wants_version};
use vcp::config::{Config, Environment, StorageConfig, StorageIpcMode, StoreHelperConfig};
use vcp::storage::STORE_LOG_TARGET;
use vcp::storage::capsicum;
use vcp::storage::engine::StorageEngine;
use vcp::storage::ipc::{bind_socket, peer_uid};
use vcp::storage::server::serve_connection;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(err) = run() {
        eprintln!("vcp-store: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if wants_help(&args) {
        print!("{}", cli_usage());
        return Ok(());
    }
    if wants_version(&args) {
        println!("{}", version_line("vcp-store"));
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("pending-ops") | Some("list-keys") | Some("approve-key") => {
            return run_ops_cli(&args);
        }
        _ => {}
    }

    let mut config_path: Option<PathBuf> = None;
    let mut blob_path = None;
    let mut listen = None;
    let mut spawn_mode = false;
    let mut production = false;
    let mut expected_uid: Option<u32> = None;
    let mut max_artifact_bytes: Option<u64> = None;
    let mut max_image_bytes: Option<u64> = None;
    let mut max_concurrent_uploads: Option<u32> = None;
    let mut max_images_per_org: Option<u32> = None;
    let mut upload_ttl_secs: Option<u64> = None;
    let mut webauthn_required: Option<bool> = None;
    let mut webauthn_origin: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = args.get(i).map(PathBuf::from);
            }
            "--blob-path" => {
                i += 1;
                blob_path = args.get(i).cloned();
            }
            "--listen" => {
                i += 1;
                listen = args.get(i).cloned();
            }
            "--spawn-mode" => spawn_mode = true,
            "--production" => production = true,
            "--expected-uid" => {
                i += 1;
                expected_uid = args.get(i).and_then(|s| s.parse().ok());
            }
            "--max-artifact-bytes" => {
                i += 1;
                max_artifact_bytes = args.get(i).and_then(|s| s.parse().ok());
            }
            "--max-image-bytes" => {
                i += 1;
                max_image_bytes = args.get(i).and_then(|s| s.parse().ok());
            }
            "--max-concurrent-uploads" => {
                i += 1;
                max_concurrent_uploads = args.get(i).and_then(|s| s.parse().ok());
            }
            "--max-images-per-org" => {
                i += 1;
                max_images_per_org = args.get(i).and_then(|s| s.parse().ok());
            }
            "--upload-ttl-secs" => {
                i += 1;
                upload_ttl_secs = args.get(i).and_then(|s| s.parse().ok());
            }
            "--webauthn-required" => {
                i += 1;
                webauthn_required = args.get(i).and_then(|s| match s.as_str() {
                    "true" | "1" => Some(true),
                    "false" | "0" => Some(false),
                    _ => None,
                });
            }
            "--webauthn-origin" => {
                i += 1;
                webauthn_origin = args.get(i).cloned();
            }
            other => {
                return Err(format!(
                    "unknown arg: {other}\n\n{}",
                    cli_usage().trim_end()
                ));
            }
        }
        i += 1;
    }

    let (cfg, listen_path, expected_uid) = if spawn_mode {
        let blob = blob_path.ok_or_else(|| "--blob-path required in spawn mode".to_string())?;
        let listen = listen.ok_or_else(|| "--listen required in spawn mode".to_string())?;
        let blob_path = PathBuf::from(&blob);
        if !blob_path.is_absolute() {
            return Err("blob_path must be absolute".into());
        }
        let defaults = StorageConfig::default();
        let mut cfg = StorageConfig {
            blob_path: blob,
            ipc: StorageIpcMode::Spawn,
            socket_path: listen.clone(),
            helper_path: String::new(),
            max_artifact_bytes: max_artifact_bytes.unwrap_or(defaults.max_artifact_bytes),
            max_image_bytes: max_image_bytes.unwrap_or(defaults.max_image_bytes),
            max_concurrent_uploads: max_concurrent_uploads
                .unwrap_or(defaults.max_concurrent_uploads),
            max_images_per_org: max_images_per_org.unwrap_or(defaults.max_images_per_org),
            upload_ttl_secs: upload_ttl_secs.unwrap_or(defaults.upload_ttl_secs),
            expected_peer_uid: None,
            webauthn_required: webauthn_required.unwrap_or(defaults.webauthn_required),
            webauthn_origin: webauthn_origin.unwrap_or(defaults.webauthn_origin),
            ..defaults
        };
        cfg.derive_webauthn_rp_id().map_err(|e| e.to_string())?;
        (cfg, listen, None)
    } else {
        let path = match config_path {
            Some(p) => p,
            None => {
                let dir = Config::find_config_dir().map_err(|e| e.to_string())?;
                StoreHelperConfig::default_path(dir)
            }
        };
        let helper = StoreHelperConfig::load(&path).map_err(|e| e.to_string())?;
        let mut cfg = helper.to_storage_config();
        if let Some(b) = blob_path {
            cfg.blob_path = b;
        }
        let listen = listen.unwrap_or_else(|| helper.listen.clone());
        cfg.socket_path = listen.clone();
        if let Some(v) = max_artifact_bytes {
            cfg.max_artifact_bytes = v;
        }
        if let Some(v) = max_image_bytes {
            cfg.max_image_bytes = v;
        }
        if let Some(v) = max_concurrent_uploads {
            cfg.max_concurrent_uploads = v;
        }
        if let Some(v) = max_images_per_org {
            cfg.max_images_per_org = v;
        }
        if let Some(v) = upload_ttl_secs {
            cfg.upload_ttl_secs = v;
        }
        if let Some(v) = webauthn_required {
            cfg.webauthn_required = v;
        }
        if let Some(v) = webauthn_origin {
            cfg.webauthn_origin = v;
            cfg.derive_webauthn_rp_id().map_err(|e| e.to_string())?;
        }
        let peer = expected_uid.or(helper.expected_peer_uid);
        if production && peer.is_none() {
            return Err(
                "production requires expected_peer_uid in vcp-store.conf or --expected-uid".into(),
            );
        }
        let blob_path = PathBuf::from(&cfg.blob_path);
        if !blob_path.is_absolute() {
            return Err("blob_path must be absolute".into());
        }
        (cfg, listen, peer)
    };

    StorageEngine::validate_production_webauthn(production, &cfg)?;

    let blob_root = PathBuf::from(&cfg.blob_path);

    // Process hygiene (best-effort portable). umask is process-global;
    // call before serving. FFI lives in `nix`.
    #[cfg(unix)]
    {
        use nix::sys::stat::{Mode, umask};
        umask(Mode::from_bits_truncate(0o077));
    }

    let engine = StorageEngine::open(&blob_root, cfg).map_err(|e| e.to_string())?;
    if spawn_mode {
        warn!(
            target: STORE_LOG_TARGET,
            "storage helper shares vcp uid (dev mode)"
        );
    }

    // Capsicum forbids open/connect/bind by path after cap_enter. Pre-open the
    // IPC endpoint (connect to parent in spawn mode, or bind the listen sock),
    // then enter capability mode before serving.
    if spawn_mode {
        let stream = std::os::unix::net::UnixStream::connect(&listen_path)
            .map_err(|e| format!("connect parent: {e}"))?;
        info!(
            target: STORE_LOG_TARGET,
            path = %listen_path,
            "vcp-store connected (spawn)"
        );
        capsicum::enter_capability_mode(production);
        serve_connection(&engine, stream);
        return Ok(());
    }

    let listener = bind_socket(&listen_path).map_err(|e| e.to_string())?;
    info!(
        target: STORE_LOG_TARGET,
        path = %listen_path,
        "vcp-store listening"
    );
    capsicum::enter_capability_mode(production);
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(err) => {
                warn!(target: STORE_LOG_TARGET, error = %err, "accept failed");
                continue;
            }
        };
        if let Some(want) = expected_uid {
            match peer_uid(&stream) {
                Ok(uid) if uid == want => {}
                Ok(uid) => {
                    warn!(
                        target: STORE_LOG_TARGET,
                        uid,
                        expected = want,
                        "reject peer uid"
                    );
                    continue;
                }
                Err(err) => {
                    warn!(target: STORE_LOG_TARGET, error = %err, "peercred failed");
                    continue;
                }
            }
        }
        serve_connection(&engine, stream);
    }
    Ok(())
}

/// Full CLI usage for the daemon accept loop and the ops KEY commands.
///
/// Layout + ANSI styles mirror clap / `vcp --help`.
fn cli_usage() -> String {
    cli_usage_with(HelpStyle::auto())
}

fn cli_usage_with(style: HelpStyle) -> String {
    let usage = style.header("Usage:");
    let commands = style.header("Commands:");
    let options = style.header("Options:");
    let bin = style.literal("vcp-store");
    let opts = style.placeholder("[OPTIONS]");
    let cmd = style.placeholder("<COMMAND>");
    let pending = styled_literal_col(style, "pending-ops", 11);
    let list = styled_literal_col(style, "list-keys", 11);
    let approve = styled_literal_col(style, "approve-key", 11);
    let help_cmd = styled_literal_col(style, "help", 11);
    // One options column: short flags left-aligned; long-only flags get a
    // 4-space lead-in so `--` lines up under `-h, --help`, and every
    // description starts at the same screen column.
    const OPT_COL: usize = 32;
    let opt_help = styled_literal_col(style, "-h, --help", OPT_COL);
    let opt_ver = styled_literal_col(style, "-V, --version", OPT_COL);
    let opt_config = styled_option(style, "--config", "<PATH>", OPT_COL);
    let opt_blob = styled_option(style, "--blob-path", "<PATH>", OPT_COL);
    let opt_listen = styled_option(style, "--listen", "<PATH>", OPT_COL);
    let opt_spawn = styled_long_flag(style, "--spawn-mode", OPT_COL);
    let opt_prod = styled_long_flag(style, "--production", OPT_COL);
    let opt_uid = styled_option(style, "--expected-uid", "<UID>", OPT_COL);
    let opt_art = styled_option(style, "--max-artifact-bytes", "<N>", OPT_COL);
    let opt_img = styled_option(style, "--max-image-bytes", "<N>", OPT_COL);
    let opt_up = styled_option(style, "--max-concurrent-uploads", "<N>", OPT_COL);
    let opt_org = styled_option(style, "--max-images-per-org", "<N>", OPT_COL);
    let opt_ttl = styled_option(style, "--upload-ttl-secs", "<N>", OPT_COL);
    let opt_wa = styled_option(style, "--webauthn-required", "<BOOL>", OPT_COL);
    let opt_origin = styled_option(style, "--webauthn-origin", "<URL>", OPT_COL);
    let fp = format!(
        "{} {}",
        style.literal("--fingerprint"),
        style.placeholder("<HEX>")
    );
    format!(
        "\
VCP storage helper - sandboxed artifact daemon and KEY ops

{usage} {bin} {opts}
       {bin} {cmd}

When no command is given, load vcp-store.conf (or --config) and accept Unix
SEQPACKET connections on --listen. Ops commands open meta.sqlite under the
blob root (separate invocation).

{commands}
  {pending}  List pending WebAuthn KEY enrolments and in-flight challenges
  {list}  List stored WebAuthn credentials
  {approve}  Activate a pending KEY ({fp})
  {help_cmd}  Print this message

{options}
  {opt_help}  Print help
  {opt_ver}  Print version
  {opt_config}  Helper TOML (default: beside portal config)
  {opt_blob}  Absolute blob root
  {opt_listen}  Unix SEQPACKET socket path
  {opt_spawn}  Parent-spawned accept path (no peercred filter)
  {opt_prod}  Require expected_peer_uid / --expected-uid
  {opt_uid}  Peercred allow-list (socket mode)
  {opt_art}  Max release artifact size
  {opt_img}  Max tenant image size
  {opt_up}  Max in-flight uploads
  {opt_org}  Max images retained per org
  {opt_ttl}  Staging upload TTL
  {opt_wa}  Require WebAuthn for release commit
  {opt_origin}  WebAuthn RP origin
"
    )
}

/// Long-only flag: 4 leading spaces so `--` aligns under `-h, --help`.
fn styled_long_flag(style: HelpStyle, flag: &str, width: usize) -> String {
    let plain = format!("    {flag}");
    let painted = format!("    {}", style.literal(flag));
    let pad = width.saturating_sub(plain.len());
    format!("{painted}{}", " ".repeat(pad))
}

fn styled_option(style: HelpStyle, flag: &str, value: &str, width: usize) -> String {
    let plain = format!("    {flag} {value}");
    let painted = format!("    {} {}", style.literal(flag), style.placeholder(value));
    // ANSI makes `painted` longer than the visible width; pad using the plain
    // width so the description column stays aligned in the terminal.
    let pad = width.saturating_sub(plain.len());
    format!("{painted}{}", " ".repeat(pad))
}

fn ops_cli_usage() -> String {
    ops_cli_usage_with(HelpStyle::auto())
}

fn ops_cli_usage_with(style: HelpStyle) -> String {
    let usage = style.header("Usage:");
    let commands = style.header("Commands:");
    let options = style.header("Options:");
    let bin = style.literal("vcp-store");
    let cmd = style.placeholder("<COMMAND>");
    let pending = styled_literal_col(style, "pending-ops", 11);
    let list = styled_literal_col(style, "list-keys", 11);
    let approve = styled_literal_col(style, "approve-key", 11);
    let help_cmd = styled_literal_col(style, "help", 11);
    const OPT_COL: usize = 28;
    let opt_help = styled_literal_col(style, "-h, --help", OPT_COL);
    let opt_ver = styled_literal_col(style, "-V, --version", OPT_COL);
    let opt_config = styled_option(style, "--config", "<PATH>", OPT_COL);
    let opt_blob = styled_option(style, "--blob-path", "<PATH>", OPT_COL);
    let opt_fp = styled_option(style, "--fingerprint", "<HEX>", OPT_COL);
    let fp = format!(
        "{} {}",
        style.literal("--fingerprint"),
        style.placeholder("<HEX>")
    );
    format!(
        "\
VCP storage helper - KEY ops

{usage} {bin} {cmd}

{commands}
  {pending}  List pending credentials and in-flight challenges
  {list}  List all credentials (pending / active / expired / revoked)
  {approve}  Activate a pending credential ({fp})
  {help_cmd}  Print this message

{options}
  {opt_help}  Print help
  {opt_ver}  Print version
  {opt_config}  Helper TOML
  {opt_blob}  Absolute blob root
  {opt_fp}  Credential fingerprint (approve-key)
"
    )
}

fn run_ops_cli(args: &[String]) -> Result<(), String> {
    let mut config_path: Option<PathBuf> = None;
    let mut blob_path: Option<String> = None;
    let mut fingerprint: Option<String> = None;
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let mut i = if cmd.is_empty() { 0 } else { 1 };
    if !matches!(cmd, "pending-ops" | "list-keys" | "approve-key") {
        return Err(ops_cli_usage());
    }
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = args.get(i).map(PathBuf::from);
            }
            "--blob-path" => {
                i += 1;
                blob_path = args.get(i).cloned();
            }
            "--fingerprint" => {
                i += 1;
                fingerprint = args.get(i).cloned();
            }
            other => return Err(format!("unknown arg: {other}\n\n{}", ops_cli_usage())),
        }
        i += 1;
    }
    let cfg = load_key_cfg(config_path, blob_path)?;
    let blob = cfg.blob_path.clone();
    let engine = StorageEngine::open(&blob, cfg).map_err(|e| {
        format!(
            "{e}\n\
             hint: ops CLI opens the helper blob root (meta.sqlite). Pass \
             --blob-path PATH or --config PATH, or rely on the default \
             vcp-store.conf ({prod}).",
            prod = "/var/db/vcp/storage",
        )
    })?;
    match cmd {
        "pending-ops" => print_pending_ops(&engine),
        "list-keys" => print_key_list(&engine),
        "approve-key" => {
            let fp =
                fingerprint.ok_or_else(|| "--fingerprint required for approve-key".to_string())?;
            engine.key_approve(&fp).map_err(|e| e.to_string())?;
            println!("activated fingerprint={fp}");
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn cred_display_status(status: &str, revoked_at: Option<i64>) -> &'static str {
    if revoked_at.is_some() {
        "revoked"
    } else if status == "pending" {
        "pending"
    } else if status == "expired" {
        "expired"
    } else {
        "active"
    }
}

fn format_activated_at(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "Pending".into())
}

/// `revoked_at` null means "not revoked". Only label that as Active once the
/// key was activated — Pending/Expired rows use "Pending" (never "Active").
fn format_revoked_at(revoked_at: Option<i64>, activated_at: Option<i64>) -> String {
    match revoked_at {
        Some(n) => n.to_string(),
        None if activated_at.is_some() => "Active".into(),
        None => "Pending".into(),
    }
}

/// Print pending credentials (E2 approve queue) then in-flight ceremony challenges
/// (architecture 1.2 §6.6 cross-check). Binding JSON stays in SQLite; the CLI
/// surfaces the canonical `summary` column only.
fn print_pending_ops(engine: &StorageEngine) -> Result<(), String> {
    use vcp::storage::webauthn::credential_fingerprint;

    let creds = engine
        .list_pending_credentials_cli()
        .map_err(|e| e.to_string())?;
    println!("Pending credentials (awaiting: approve-key --fingerprint …)");
    let rows: Vec<Vec<String>> = creds
        .iter()
        .map(|row| {
            vec![
                credential_fingerprint(&row.credential_id, &row.public_key_cose),
                row.admin_label.clone(),
                row.user_handle.clone(),
                row.created_at.to_string(),
            ]
        })
        .collect();
    print_ascii_table(
        &["fingerprint", "label", "user_handle", "created_at"],
        &rows,
    );

    let challenges = engine
        .list_pending_challenges_cli()
        .map_err(|e| e.to_string())?;
    println!();
    println!("In-flight challenges (ceremony cross-check)");
    let ch_rows: Vec<Vec<String>> = challenges
        .iter()
        .map(|row| {
            vec![
                row.challenge_id.clone(),
                row.op.clone(),
                row.summary.clone(),
                row.expires_at.to_string(),
            ]
        })
        .collect();
    print_ascii_table(&["challenge_id", "op", "summary", "expires_at"], &ch_rows);
    Ok(())
}

fn print_key_list(engine: &StorageEngine) -> Result<(), String> {
    use vcp::storage::webauthn::credential_fingerprint;

    let creds = engine
        .list_all_credentials_cli()
        .map_err(|e| e.to_string())?;
    println!("webauthn_credentials");
    let rows: Vec<Vec<String>> = creds
        .iter()
        .map(|row| {
            vec![
                credential_fingerprint(&row.credential_id, &row.public_key_cose),
                row.admin_label.clone(),
                cred_display_status(row.status.as_str(), row.revoked_at).to_owned(),
                row.sign_count.to_string(),
                row.created_at.to_string(),
                format_activated_at(row.activated_at),
                format_revoked_at(row.revoked_at, row.activated_at),
            ]
        })
        .collect();
    print_ascii_table(
        &[
            "fingerprint",
            "label",
            "status",
            "sign_count",
            "created_at",
            "activated_at",
            "revoked_at",
        ],
        &rows,
    );
    Ok(())
}

/// Box-drawn table (litecli / SQLite CLI style) for ops readability.
fn print_ascii_table(headers: &[&str], rows: &[Vec<String>]) {
    print!("{}", format_ascii_table(headers, rows));
}

fn format_ascii_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "(empty)\n".into();
    }
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let rule = |left: char, mid: char, right: char, fill: char| {
        let mut s = String::new();
        s.push(left);
        for (i, w) in widths.iter().enumerate() {
            if i > 0 {
                s.push(mid);
            }
            s.extend(std::iter::repeat_n(fill, w + 2));
        }
        s.push(right);
        s
    };

    let emit_row = |cells: &[String]| {
        let mut s = String::from("│");
        for (i, w) in widths.iter().enumerate() {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            s.push(' ');
            s.push_str(cell);
            s.extend(std::iter::repeat_n(
                ' ',
                w.saturating_sub(cell.chars().count()),
            ));
            s.push(' ');
            s.push('│');
        }
        s
    };

    let mut out = String::new();
    out.push_str(&rule('╭', '┬', '╮', '─'));
    out.push('\n');
    out.push_str(&emit_row(
        &headers.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
    ));
    out.push('\n');
    out.push_str(&rule('╞', '╪', '╡', '═'));
    out.push('\n');
    for (idx, row) in rows.iter().enumerate() {
        out.push_str(&emit_row(row));
        out.push('\n');
        if idx + 1 < rows.len() {
            out.push_str(&rule('├', '┼', '┤', '─'));
            out.push('\n');
        }
    }
    out.push_str(&rule('╰', '┴', '╯', '─'));
    out.push('\n');
    out
}

/// Resolve blob root for the ops CLI (not the accept-loop serve path).
fn load_key_cfg(
    config_path: Option<PathBuf>,
    blob_override: Option<String>,
) -> Result<StorageConfig, String> {
    let env = env::var("VCP_ENVIRONMENT")
        .map(|e| Environment::parse(&e))
        .unwrap_or(Environment::Production);
    load_key_cfg_with_env(config_path, blob_override, env)
}

/// Testable core of [`load_key_cfg`] (env injected; no process env read).
fn load_key_cfg_with_env(
    config_path: Option<PathBuf>,
    blob_override: Option<String>,
    env: Environment,
) -> Result<StorageConfig, String> {
    if let Some(blob) = blob_override {
        let abs = absolute_blob_path(&blob)?;
        return Ok(StorageConfig {
            blob_path: abs,
            ipc: StorageIpcMode::Inline,
            ..StorageConfig::default()
        });
    }
    if let Some(path) = config_path {
        let helper = StoreHelperConfig::load(&path).map_err(|e| e.to_string())?;
        return Ok(helper.to_storage_config());
    }

    match env {
        Environment::Development | Environment::Testing => {
            let dir = Config::find_config_dir().map_err(|e| e.to_string())?;
            let portal = Config::load_with_environment(dir, env).map_err(|e| {
                format!("load portal config: {e}\nhint: pass --blob-path or --config")
            })?;
            if portal.storage.blob_path.trim().is_empty() {
                return Err("storage.blob_path empty (pass --blob-path)".into());
            }
            Ok(portal.storage)
        }
        Environment::Production => {
            let dir = Config::find_config_dir().map_err(|e| e.to_string())?;
            let path = StoreHelperConfig::default_path(dir);
            let helper = StoreHelperConfig::load(&path).map_err(|e| e.to_string())?;
            Ok(helper.to_storage_config())
        }
    }
}

fn absolute_blob_path(blob: &str) -> Result<String, String> {
    let path = Path::new(blob);
    if path.is_absolute() {
        return Ok(blob.to_owned());
    }
    let cwd = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    Ok(cwd.join(path).to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        absolute_blob_path, cli_usage_with, cred_display_status, format_activated_at,
        format_ascii_table, format_revoked_at, load_key_cfg_with_env, ops_cli_usage_with,
    };
    use std::path::PathBuf;
    use vcp::cli::{HelpStyle, wants_help, wants_version};
    use vcp::config::Environment;

    #[test]
    fn ascii_table_matches_sqlite_style_frame() {
        let table = format_ascii_table(
            &["label", "status"],
            &[
                vec!["Macbook".into(), "active".into()],
                vec!["Richard-Apple".into(), "pending".into()],
            ],
        );
        assert!(table.starts_with('╭'));
        assert!(table.contains('╞'));
        assert!(table.contains("│ label"));
        assert!(table.contains("Richard-Apple"));
        assert!(table.trim_end().ends_with('╯'));
    }

    #[test]
    fn ascii_table_empty() {
        assert_eq!(format_ascii_table(&["a"], &[]), "(empty)\n");
    }

    #[test]
    fn revoked_overrides_active_status() {
        assert_eq!(cred_display_status("active", Some(1)), "revoked");
        assert_eq!(cred_display_status("active", None), "active");
        assert_eq!(cred_display_status("pending", None), "pending");
        assert_eq!(cred_display_status("expired", None), "expired");
    }

    #[test]
    fn timestamp_null_labels() {
        assert_eq!(format_activated_at(None), "Pending");
        assert_eq!(format_activated_at(Some(42)), "42");
        assert_eq!(format_revoked_at(None, None), "Pending");
        assert_eq!(format_revoked_at(None, Some(42)), "Active");
        assert_eq!(format_revoked_at(Some(99), Some(42)), "99");
    }

    #[test]
    fn load_key_cfg_blob_override_wins_over_env() {
        let dir = tempfile::tempdir().unwrap();
        let abs = dir.path().canonicalize().unwrap();
        let cfg = load_key_cfg_with_env(
            None,
            Some(abs.to_string_lossy().into_owned()),
            Environment::Production,
        )
        .unwrap();
        assert_eq!(PathBuf::from(&cfg.blob_path), abs);
    }

    #[test]
    fn load_key_cfg_testing_uses_portal_blob_path() {
        let cfg = load_key_cfg_with_env(None, None, Environment::Testing).unwrap();
        assert!(
            cfg.blob_path.contains("vcp-storage-test"),
            "got {}",
            cfg.blob_path
        );
    }

    #[test]
    fn load_key_cfg_development_uses_portal_blob_path() {
        let cfg = load_key_cfg_with_env(None, None, Environment::Development).unwrap();
        assert!(
            cfg.blob_path.contains("vcp-storage"),
            "got {}",
            cfg.blob_path
        );
    }

    #[test]
    fn absolute_blob_path_passthrough_and_relative() {
        let abs = absolute_blob_path("/tmp/vcp-blobs").unwrap();
        assert_eq!(abs, "/tmp/vcp-blobs");
        let rel = absolute_blob_path("relative-blob").unwrap();
        assert!(rel.ends_with("relative-blob"));
        assert!(PathBuf::from(&rel).is_absolute());
    }

    #[test]
    fn wants_help_recognizes_common_forms() {
        assert!(wants_help(&["--help".into()]));
        assert!(wants_help(&["-h".into()]));
        assert!(wants_help(&["help".into()]));
        assert!(wants_help(&[
            "approve-key".into(),
            "--fingerprint".into(),
            "ab".into(),
            "--help".into(),
        ]));
        assert!(!wants_help(&["pending-ops".into()]));
        assert!(!wants_help(&["--config".into(), "x".into()]));
    }

    #[test]
    fn cli_usage_covers_daemon_and_ops() {
        let u = cli_usage_with(HelpStyle::plain());
        assert!(u.starts_with("VCP storage helper"));
        assert!(u.contains("Usage: vcp-store"));
        assert!(!u.contains("usage:"));
        assert!(u.contains("Commands:"));
        assert!(u.contains("Options:"));
        assert!(u.contains("--spawn-mode"));
        assert!(u.contains("pending-ops"));
        assert!(u.contains("list-keys"));
        assert!(u.contains("approve-key"));
        assert!(u.contains("-h, --help"));
        assert!(u.contains("-V, --version"));
        assert!(!u.contains("Help: -h"));
        assert!(!u.contains('\u{1b}'));
        // Keep usage free of local-dev recipes (same contract as storage
        // invariants on this file). Build the needles so the forbidden
        // literals never appear as contiguous source text here.
        let debug_bin = format!("./{}/{}/{}", "target", "debug", "vcp-store");
        let env_dev = format!("{}_ENVIRONMENT={}", "VCP", "development");
        assert!(!u.contains(&debug_bin) && !u.contains(&env_dev));
    }

    #[test]
    fn cli_usage_option_descriptions_align() {
        let u = cli_usage_with(HelpStyle::plain());
        let print_help = u
            .lines()
            .find(|l| l.contains("Print help"))
            .expect("Print help");
        let helper_toml = u
            .lines()
            .find(|l| l.contains("Helper TOML"))
            .expect("Helper TOML");
        let print_ver = u
            .lines()
            .find(|l| l.contains("Print version"))
            .expect("Print version");
        let blob = u
            .lines()
            .find(|l| l.contains("Absolute blob root"))
            .expect("blob root");
        assert_eq!(
            print_help.find("Print help"),
            helper_toml.find("Helper TOML")
        );
        assert_eq!(
            print_ver.find("Print version"),
            blob.find("Absolute blob root")
        );
    }

    #[test]
    fn cli_usage_color_applies_bold_and_underline() {
        let u = cli_usage_with(HelpStyle::always());
        assert!(u.contains('\u{1b}'));
        assert!(u.contains("\x1b[1;4m"), "headers bold+underline");
        assert!(u.contains("\x1b[1m"), "literals bold");
        assert!(u.contains("\x1b[4m"), "placeholders underline");
    }

    #[test]
    fn ops_cli_usage_matches_clap_style_layout() {
        let u = ops_cli_usage_with(HelpStyle::plain());
        assert!(u.contains("Usage: vcp-store"));
        assert!(!u.contains("usage:"));
        assert!(u.contains("Commands:"));
        assert!(u.contains("Options:"));
        assert!(u.contains("-h, --help"));
        assert!(u.contains("-V, --version"));
        assert!(!u.contains("Help: -h"));
    }

    #[test]
    fn wants_version_recognizes_flags() {
        assert!(wants_version(&["-V".into()]));
        assert!(wants_version(&["--version".into()]));
        assert!(!wants_version(&["--help".into()]));
    }
}
