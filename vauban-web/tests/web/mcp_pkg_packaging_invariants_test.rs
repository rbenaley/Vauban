//! Packaging pins for FreeBSD `vb-mcp` / UID 910 (MCP proxy).
//!
//! Mirrors the mailer 909 packaging invariants: production `vauban.conf`,
//! `pkg/+PRE_INSTALL` account creation, ACL list, and `build-pkg.sh` staging.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent")
        .to_path_buf()
}

#[test]
fn inv_production_proxy_mcp_uid_gid_is_910() {
    let conf =
        std::fs::read_to_string(repo_root().join("config/vauban.conf")).expect("vauban.conf");
    let start = conf
        .find("[services.proxy_mcp]")
        .expect("[services.proxy_mcp] in vauban.conf");
    let window = &conf[start..start.saturating_add(220).min(conf.len())];
    assert!(
        window.contains("uid = 910") && window.contains("gid = 910"),
        "production proxy_mcp must run as uid/gid 910"
    );
    assert!(
        window.contains("binary = \"vauban-proxy-mcp\""),
        "production proxy_mcp binary must be vauban-proxy-mcp"
    );
}

#[test]
fn inv_production_mcp_section_opt_in_disabled() {
    let conf =
        std::fs::read_to_string(repo_root().join("config/vauban.conf")).expect("vauban.conf");
    // Prefer a line-start `[mcp]` so comments like `` `[mcp].enabled = true` `` do not match.
    let start = conf
        .find("\n[mcp]\n")
        .map(|i| i + 1)
        .or_else(|| conf.find("[mcp]\n"))
        .expect("[mcp] section in vauban.conf");
    let window = &conf[start..start.saturating_add(900).min(conf.len())];
    assert!(
        window.contains("enabled = false"),
        "production [mcp] must default to enabled = false (opt-in)"
    );
    assert!(
        window.contains("bind_addr = \"127.0.0.1:19443\""),
        "production [mcp] must set bind_addr (same key as iacs_tunnel)"
    );
    assert!(
        !window.contains("listen_addr"),
        "production [mcp] must not keep the retired listen_addr key"
    );
    assert!(
        window.contains("allow_loopback_targets = false"),
        "production [mcp] must keep allow_loopback_targets = false"
    );
    assert!(
        window.contains("session_ttl_seconds = 3600"),
        "production [mcp] must document session_ttl_seconds (appliance default/max)"
    );
    assert!(
        window.contains("hitl_pending_ttl_seconds = 900"),
        "production [mcp] must document hitl_pending_ttl_seconds"
    );
}

#[test]
fn inv_pkg_creates_vb_mcp_910() {
    let pre = std::fs::read_to_string(repo_root().join("pkg/+PRE_INSTALL")).expect("PRE_INSTALL");
    assert!(
        pre.contains("create_group_if_missing vb-mcp 910"),
        "pkg/+PRE_INSTALL must create group vb-mcp 910"
    );
    assert!(
        pre.contains("create_user_if_missing vb-mcp 910 910 vauban-proxy-mcp"),
        "pkg/+PRE_INSTALL must create vb-mcp 910/910"
    );
    assert!(
        pre.contains("set_user_gecos vb-mcp vauban-proxy-mcp"),
        "pkg/+PRE_INSTALL must set GECOS for vb-mcp"
    );

    let apply = std::fs::read_to_string(repo_root().join("pkg/privsep_fs_apply.sh"))
        .expect("privsep apply");
    assert!(
        apply.contains("vb-mcp"),
        "pkg/privsep_fs_apply.sh SVC_USERS must include vb-mcp (ACLs, not POST_INSTALL)"
    );

    let deinstall =
        std::fs::read_to_string(repo_root().join("pkg/+POST_DEINSTALL")).expect("POST_DEINSTALL");
    assert!(
        deinstall.contains("vb-mcp"),
        "pkg/+POST_DEINSTALL must remove vb-mcp"
    );

    let build = std::fs::read_to_string(repo_root().join("pkg/build-pkg.sh")).expect("build-pkg");
    assert!(
        build.contains("vauban-proxy-mcp"),
        "pkg/build-pkg.sh must stage vauban-proxy-mcp binary"
    );
    assert!(
        build.contains("libexec/vauban/vauban-proxy-mcp"),
        "pkg/build-pkg.sh plist must list libexec/vauban/vauban-proxy-mcp"
    );
}
