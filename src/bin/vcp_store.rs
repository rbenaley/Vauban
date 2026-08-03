//! `vcp-store` — sandboxed artifact helper (architecture 1.0).

use std::env;
use std::path::PathBuf;
use std::process;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use vcp::config::{StorageConfig, StorageIpcMode};
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
    let mut blob_path = None;
    let mut listen = None;
    let mut spawn_mode = false;
    let mut production = false;
    let mut expected_uid: Option<u32> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }

    let blob_path = blob_path.ok_or_else(|| "--blob-path required".to_string())?;
    let listen = listen.ok_or_else(|| "--listen required".to_string())?;
    let blob_path = PathBuf::from(blob_path);
    if !blob_path.is_absolute() {
        return Err("blob_path must be absolute".into());
    }

    let cfg = StorageConfig {
        blob_path: blob_path.to_string_lossy().into_owned(),
        ipc: if spawn_mode {
            StorageIpcMode::Spawn
        } else {
            StorageIpcMode::Socket
        },
        socket_path: listen.clone(),
        helper_path: String::new(),
        max_artifact_bytes: 2 * 1024 * 1024 * 1024,
        max_image_bytes: 10 * 1024 * 1024,
        allowed_image_types: vec!["png".into(), "jpeg".into(), "webp".into()],
        max_concurrent_uploads: 4,
        max_images_per_org: 1000,
        upload_ttl_secs: 3600,
        expected_peer_uid: expected_uid,
    };

    // Process hygiene (best-effort portable).
    #[cfg(unix)]
    {
        // SAFETY: umask is process-global and called before serving.
        #[allow(unsafe_code)]
        unsafe {
            libc::umask(0o077);
        }
    }

    let engine = StorageEngine::open(&blob_path, cfg).map_err(|e| e.to_string())?;
    if spawn_mode {
        warn!("storage helper shares vcp uid (dev mode)");
    }
    capsicum::enter_capability_mode(production);

    // Spawn-mode: parent listens; we connect to --listen path.
    if spawn_mode {
        let stream = std::os::unix::net::UnixStream::connect(&listen)
            .map_err(|e| format!("connect parent: {e}"))?;
        info!(path = %listen, "vcp-store connected (spawn)");
        serve_connection(&engine, stream);
        return Ok(());
    }

    let listener = bind_socket(&listen).map_err(|e| e.to_string())?;
    info!(path = %listen, "vcp-store listening");
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
