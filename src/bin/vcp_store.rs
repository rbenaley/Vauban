//! `vcp-store` — sandboxed artifact helper (architecture 1.0).
//!
//! Production: load `vcp-store.conf` (`--config` or default beside portal
//! config). Development spawn: parent passes `--blob-path` / `--listen` /
//! quota flags (same UID, no peercred filter).

use std::env;
use std::path::PathBuf;
use std::process;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use vcp::config::{Config, StorageConfig, StorageIpcMode, StoreHelperConfig};
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
            other => return Err(format!("unknown arg: {other}")),
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
        let cfg = StorageConfig {
            blob_path: blob,
            ipc: StorageIpcMode::Spawn,
            socket_path: listen.clone(),
            helper_path: String::new(),
            max_artifact_bytes: max_artifact_bytes.unwrap_or(defaults.max_artifact_bytes),
            max_image_bytes: max_image_bytes.unwrap_or(defaults.max_image_bytes),
            allowed_image_types: defaults.allowed_image_types,
            max_concurrent_uploads: max_concurrent_uploads
                .unwrap_or(defaults.max_concurrent_uploads),
            max_images_per_org: max_images_per_org.unwrap_or(defaults.max_images_per_org),
            upload_ttl_secs: upload_ttl_secs.unwrap_or(defaults.upload_ttl_secs),
            expected_peer_uid: None,
        };
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

    let blob_root = PathBuf::from(&cfg.blob_path);

    // Process hygiene (best-effort portable).
    #[cfg(unix)]
    {
        // SAFETY: umask is process-global and called before serving.
        #[allow(unsafe_code)]
        unsafe {
            libc::umask(0o077);
        }
    }

    let engine = StorageEngine::open(&blob_root, cfg).map_err(|e| e.to_string())?;
    if spawn_mode {
        warn!("storage helper shares vcp uid (dev mode)");
    }
    capsicum::enter_capability_mode(production);

    // Spawn-mode: parent listens; we connect to --listen path.
    if spawn_mode {
        let stream = std::os::unix::net::UnixStream::connect(&listen_path)
            .map_err(|e| format!("connect parent: {e}"))?;
        info!(path = %listen_path, "vcp-store connected (spawn)");
        serve_connection(&engine, stream);
        return Ok(());
    }

    let listener = bind_socket(&listen_path).map_err(|e| e.to_string())?;
    info!(path = %listen_path, "vcp-store listening");
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "accept failed");
                continue;
            }
        };
        if let Some(want) = expected_uid {
            match peer_uid(&stream) {
                Ok(uid) if uid == want => {}
                Ok(uid) => {
                    warn!(uid, expected = want, "reject peer uid");
                    continue;
                }
                Err(err) => {
                    warn!(error = %err, "peercred failed");
                    continue;
                }
            }
        }
        serve_connection(&engine, stream);
    }
    Ok(())
}
