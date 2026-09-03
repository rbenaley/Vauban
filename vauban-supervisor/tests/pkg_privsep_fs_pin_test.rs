//! Source pins for the privsep filesystem layout catalogue (issue #40).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

const POST_INSTALL: &str = include_str!("../../pkg/+POST_INSTALL");
const APPLY: &str = include_str!("../../pkg/privsep_fs_apply.sh");
const LIST: &str = include_str!("../../pkg/privsep_fs_layout.list");
const PRE_INSTALL: &str = include_str!("../../pkg/+PRE_INSTALL");
const BUILD_PKG: &str = include_str!("../../pkg/build-pkg.sh");
const SUPERVISOR_MAIN: &str = include_str!("../src/main.rs");
const PRIVSEP_FS: &str = include_str!("../src/privsep_fs.rs");

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist in source"));
    let rest = &src[start..];
    let end = rest[1..].find("\nfn ").map(|i| i + 1).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn post_install_sources_apply_and_has_no_raw_mode_tools() {
    assert!(
        POST_INSTALL.contains("privsep_fs_apply.sh")
            && POST_INSTALL.contains("apply_privsep_layout"),
        "+POST_INSTALL must source apply_privsep_layout"
    );
    for line in POST_INSTALL.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        for needle in [
            "chmod ",
            "chown ",
            "setfacl ",
            "set_acl ",
            "set_default_acl ",
            "detect_acl_type ",
        ] {
            assert!(
                !trimmed.starts_with(needle.trim_end()) && !trimmed.contains(&format!(" {needle}")),
                "+POST_INSTALL must not invoke {needle:?}: {line}"
            );
        }
    }
}

#[test]
fn apply_helper_and_catalogue_are_the_mode_source() {
    assert!(APPLY.contains("set_acl"));
    assert!(APPLY.contains("chown"));
    assert!(APPLY.contains("chmod"));
    assert!(LIST.contains("vauban.conf"));
    assert!(LIST.contains("vb-audit,vb-web"));
}

#[test]
fn all_svc_users_exist_in_pre_install() {
    for user in [
        "vb-audit",
        "vb-vault",
        "vb-access",
        "vb-auth",
        "vb-ssh",
        "vb-rdp",
        "vb-web",
        "vb-iacs",
        "vb-mailer",
    ] {
        assert!(
            PRE_INSTALL.contains(&format!("create_user_if_missing {user} ")),
            "+PRE_INSTALL must create {user}"
        );
        assert!(
            PRIVSEP_FS.contains(&format!("\"{user}\"")),
            "SVC_USERS must list {user}"
        );
    }
}

#[test]
fn build_pkg_stages_catalogue_and_apply() {
    assert!(BUILD_PKG.contains("privsep_fs_layout.list"));
    assert!(BUILD_PKG.contains("privsep_fs_apply.sh"));
    assert!(BUILD_PKG.contains("share/vauban/privsep_fs_layout.list"));
}

#[test]
fn apply_and_post_install_parse() {
    for script in ["+POST_INSTALL", "privsep_fs_apply.sh", "build-pkg.sh"] {
        let path = format!("{}/../pkg/{script}", env!("CARGO_MANIFEST_DIR"));
        let status = Command::new("sh")
            .arg("-n")
            .arg(&path)
            .status()
            .expect("sh -n");
        assert!(status.success(), "sh -n failed on pkg/{script}");
    }
}

#[test]
fn supervisor_boot_checks_layout_after_schema_before_spawn() {
    let body = fn_body(SUPERVISOR_MAIN, "fn run_supervisor(");
    let schema = body.find("check_schema_up_to_date(").expect("schema check");
    let layout = body
        .find("check_privsep_fs_layout(")
        .expect("run_supervisor MUST call check_privsep_fs_layout (INV-BOOT)");
    let spawn = body.find("PipeStore::new(").expect("PipeStore::new");
    assert!(
        schema < layout && layout < spawn,
        "layout check MUST run after the schema check and before any pipe spawn"
    );
}

#[test]
fn supervisor_includes_repo_catalogue_and_is_verify_only() {
    assert!(PRIVSEP_FS.contains("include_str!(\"../../pkg/privsep_fs_layout.list\")"));
    assert!(
        !PRIVSEP_FS.contains("setfacl(") && !PRIVSEP_FS.contains("chmod("),
        "privsep_fs.rs must not call setfacl/chmod"
    );
    assert!(PRIVSEP_FS.contains("should_check_layout"));
}

#[test]
fn reap_uses_respawn_decision() {
    let reap = fn_body(SUPERVISOR_MAIN, "fn apply_respawn_policy(");
    assert!(
        reap.contains("respawn_decision("),
        "apply_respawn_policy must call respawn_decision"
    );
    assert!(
        SUPERVISOR_MAIN.contains("ever_ponged = true"),
        "Pong path must set ever_ponged"
    );
}

#[test]
fn catalogue_bytes_are_the_include_str_anchor() {
    assert_eq!(
        LIST,
        include_str!("../../pkg/privsep_fs_layout.list"),
        "pin test and supervisor must see the same catalogue bytes"
    );
}
