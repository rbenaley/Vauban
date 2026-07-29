//! Battle pins for config-directory resolution (issue #38).
//!
//! High-signal regressions: a packaged FreeBSD release binary must not load
//! the build-tree `config/vauban.conf` when `/usr/local/etc/vauban` exists,
//! and rc.d / just run must surface an explicit `VAUBAN_CONFIG_DIR`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use shared::config_dir::{ConfigDirError, ConfigDirProfile, SYSTEM_CONFIG_DIR, resolve_config_dir};
use std::path::Path;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read {rel}: {e}");
    })
}

/// Exact scenario from issue #38: release + system present + workspace present
/// -> system wins (never the leftover source-tree config/).
#[test]
fn battle_release_prefers_system_over_leftover_workspace() {
    let system = Path::new(SYSTEM_CONFIG_DIR);
    let workspace = Path::new("/usr/home/builder/Vauban/config");
    let got = resolve_config_dir(
        None,
        (system, true),
        Some((workspace, true)),
        ConfigDirProfile::Release,
    )
    .expect("system must win");
    assert_eq!(got, system);
}

/// Release with no system path and a present workspace must fail closed
/// (operator must set VAUBAN_CONFIG_DIR -- just run does that for staging).
#[test]
fn battle_release_without_system_does_not_use_workspace() {
    let workspace = Path::new("/usr/home/builder/Vauban/config");
    let err = resolve_config_dir(
        None,
        (Path::new(SYSTEM_CONFIG_DIR), false),
        Some((workspace, true)),
        ConfigDirProfile::Release,
    )
    .expect_err("release must not fall back to workspace");
    assert_eq!(
        err,
        ConfigDirError::NotFound {
            profile: ConfigDirProfile::Release
        }
    );
}

/// rc.d must export `vauban_config` as `VAUBAN_CONFIG_DIR` inside prestart
/// so the daemon inherits the packaged path.
#[test]
fn battle_rc_d_exports_in_prestart() {
    let rc = read("pkg/rc.d/vauban");
    let prestart = rc
        .find("vauban_prestart()")
        .expect("vauban_prestart function");
    let body = &rc[prestart..];
    let end = body.find("\nvauban_poststop").unwrap_or(body.len());
    let prestart_body = &body[..end];
    assert!(
        prestart_body.contains("export VAUBAN_CONFIG_DIR=\"${vauban_config}\"")
            || prestart_body.contains("export VAUBAN_CONFIG_DIR=${vauban_config}"),
        "vauban_prestart must export VAUBAN_CONFIG_DIR from vauban_config"
    );
}
