//! Source-shape invariants for portal issue tracker.

use std::process::Command;

#[test]
fn inv_check_portal_issues_script() {
    let output = Command::new("bash")
        .arg("scripts/check_portal_issues.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_portal_issues.sh");
    assert!(
        output.status.success(),
        "scripts/check_portal_issues.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_report_issue_persists_details() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(src.contains("details"));
    assert!(src.contains("issues_write"));
    assert!(src.contains("organization_id"));
}

#[test]
fn inv_issue_detail_renders_details() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    assert!(
        src.contains("issue.details"),
        "detail page must render issue.details"
    );
    assert!(
        src.contains("IssueComment"),
        "detail must load IssueComment from DB"
    );
    assert!(src.contains("/reply"), "detail must expose reply POST path");
    assert!(
        src.contains("Vauban Support"),
        "support-side timeline must display Vauban Support"
    );
    assert!(
        !src.contains("max-width: 820px") && !src.contains("max-width: 720px"),
        "issue detail must use full content width"
    );
}

#[test]
fn inv_admin_issues_aggregate_surface() {
    let list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues.rs"
    ));
    let detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    assert!(list.contains("require_staff"));
    assert!(list.contains("issues_read"));
    assert!(
        list.contains("org"),
        "list must support optional org filter"
    );
    assert!(detail.contains("Vauban Support"));
    assert!(detail.contains("ISSUE_ROLE_SUPPORT"));
    assert!(detail.contains("/admin/issues/"));
    assert!(
        !detail.contains("max-width: 820px") && !detail.contains("max-width: 720px"),
        "admin issue detail must use full content width"
    );
}

#[test]
fn inv_dashboard_activity_not_hardcoded_dates() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(
        !src.contains("\"Jun 23\""),
        "dashboard must not hardcode Jun 23"
    );
    assert!(
        !src.contains("\"3h ago\""),
        "dashboard must not hardcode relative fixtures"
    );
    assert!(
        src.contains("format_relative") || src.contains("released_on"),
        "dashboard activity must use DB timestamps"
    );
}
