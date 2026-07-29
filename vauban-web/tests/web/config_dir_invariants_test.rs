//! Source-level invariants for configuration directory resolution.
//!
//! Complements the shared unit/proptest suite: pins that web, supervisor,
//! Justfile, and FreeBSD rc.d stay aligned on the issue #38 contract
//! (packaged release never prefers compile-time workspace `config/`).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

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

/// Both services must delegate lookup to `shared::config_dir`.
#[test]
fn web_and_supervisor_delegate_to_shared_config_dir() {
    let web = read("vauban-web/src/config.rs");
    let sup = read("vauban-supervisor/src/config.rs");
    assert!(
        web.contains("shared::config_dir::find_config_dir"),
        "vauban-web must call shared::config_dir::find_config_dir"
    );
    assert!(
        sup.contains("shared::config_dir::find_config_dir"),
        "vauban-supervisor must call shared::config_dir::find_config_dir"
    );
}

/// Release profile must not consult workspace before/instead of the system path.
#[test]
fn shared_release_profile_ignores_workspace() {
    let src = read("shared/src/config_dir.rs");
    assert!(
        src.contains("ConfigDirProfile::Release"),
        "shared::config_dir must define Release profile"
    );
    assert!(
        src.contains("profile == ConfigDirProfile::Debug"),
        "workspace fallback must be gated on Debug profile only"
    );
    assert!(
        src.contains("SYSTEM_CONFIG_DIR"),
        "system path constant must be defined"
    );
    assert!(
        src.contains("/usr/local/etc/vauban"),
        "system path must be /usr/local/etc/vauban"
    );
}

/// FreeBSD rc.d must export `vauban_config` as `VAUBAN_CONFIG_DIR`.
#[test]
fn rc_d_exports_vauban_config_dir() {
    let rc = read("pkg/rc.d/vauban");
    assert!(
        rc.contains("vauban_config"),
        "rc.d must define vauban_config"
    );
    assert!(
        rc.contains("export VAUBAN_CONFIG_DIR="),
        "rc.d must export VAUBAN_CONFIG_DIR for the supervisor process"
    );
    assert!(
        rc.contains("/usr/local/etc/vauban"),
        "default vauban_config must be /usr/local/etc/vauban"
    );
}

/// `just run` / `just validate` must set VAUBAN_CONFIG_DIR to the repo config/.
#[test]
fn justfile_run_and_validate_export_repo_config_dir() {
    let just = read("Justfile");
    assert!(
        just.contains("VAUBAN_CONFIG_DIR"),
        "Justfile must mention VAUBAN_CONFIG_DIR"
    );
    // Localized to run / validate -- not a top-level `export VAUBAN_CONFIG_DIR :=`.
    let top_level_export = just.lines().any(|l| {
        let trimmed = l.trim_start();
        trimmed.starts_with("export VAUBAN_CONFIG_DIR :=")
            || trimmed.starts_with("export VAUBAN_CONFIG_DIR:=")
    });
    assert!(
        !top_level_export,
        "VAUBAN_CONFIG_DIR must not be a top-level Justfile export (pollutes all recipes)"
    );
    for marker in ["validate:", "run *ARGS:"] {
        let idx = just
            .find(marker)
            .unwrap_or_else(|| panic!("missing recipe header `{marker}`"));
        let window = just[idx..].lines().take(20).collect::<Vec<_>>().join("\n");
        assert!(
            window.contains("export VAUBAN_CONFIG_DIR="),
            "recipe `{marker}` must export VAUBAN_CONFIG_DIR locally"
        );
    }
}
