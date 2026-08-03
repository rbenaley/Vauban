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
fn inv_report_issue_safe_key_allocation() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    let helper = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_key.rs"));
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0009_issue_org_key_unique.sql"
    ));
    assert!(
        src.contains("allocate_issue_key"),
        "report_issue must call allocate_issue_key"
    );
    assert!(
        src.contains("err=create"),
        "failed create must redirect with err=create"
    );
    assert!(
        !src.contains("existing.len() + 200") && !src.contains("len() + 200"),
        "must not forge keys via len() + 200"
    );
    assert!(
        !src.contains("let _ = toasty::create!(Issue"),
        "must not swallow create!(Issue) errors"
    );
    assert!(helper.contains("fn allocate_issue_key"));
    assert!(helper.contains("fn next_issue_key_from_keys"));
    assert!(history.contains("0009_issue_org_key_unique.sql"));
    assert!(migration.contains("index_issues_by_organization_id_and_key"));
    assert!(migration.contains("UNIQUE"));
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
    assert!(src.contains("/close"), "detail must expose close POST path");
    assert!(
        src.contains("/reopen"),
        "detail must expose reopen POST path"
    );
    assert!(
        src.contains("issue_is_closed"),
        "detail must use shared issue_is_closed helper"
    );
    assert!(
        src.contains("close_issue_status") && src.contains("reopen_issue_status"),
        "detail must call close/reopen status helpers"
    );
    assert!(
        !src.contains("<span class=\"vb-btn muted\">\"Close issue\"</span>")
            && !src.contains("<span class=\"vb-btn outline\">\"Reopen issue\"</span>"),
        "Close/Reopen must not remain stub spans"
    );
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
fn inv_issue_status_helpers_exist() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let status = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_status.rs"));
    assert!(models.contains("ISSUE_STATUS_OPEN"));
    assert!(models.contains("ISSUE_STATUS_CLOSED"));
    assert!(models.contains("ISSUE_COMMENT_KIND_STATUS"));
    assert!(status.contains("fn issue_is_closed"));
    assert!(status.contains("ISSUE_TIMELINE_CLOSED"));
    assert!(status.contains("ISSUE_TIMELINE_REOPENED"));
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
    assert!(detail.contains("admin_issue_detail_href"));
    assert!(detail.contains("?org="));
    assert!(detail.contains("/close"));
    assert!(detail.contains("/reopen"));
    assert!(detail.contains("issue_is_closed"));
    let shard = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    assert!(
        shard.contains("admin_issue_detail_href"),
        "admin list shard must use org-disambiguated detail hrefs"
    );
    assert!(
        !detail.contains("<span class=\"vb-btn muted\">\"Close issue\"</span>")
            && !detail.contains("<span class=\"vb-btn outline\">\"Reopen issue\"</span>"),
        "admin Close/Reopen must not remain stub spans"
    );
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
