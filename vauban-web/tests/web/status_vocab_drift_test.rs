//! Drift pins for the closed status vocabularies (July 2026 audit).
//!
//! Three artefacts encode the canonical `proxy_sessions.status`
//! vocabulary: `SessionStatus::ALL` (Rust), the
//! `proxy_sessions_status_chk` DB CHECK (migration) and the
//! `CANONICAL` list of `scripts/check_status_vocabulary.sh` (lint).
//! These tests keep the three in lock-step, pin the select options of
//! every status-filterable page against their `status_vocab`
//! vocabulary (killing dead options like the pre-fix `pending` on
//! `/sessions` and phantoms like `consumed`), and pin the handlers on
//! the shared sanitize/options seam.

use std::path::PathBuf;
use std::process::Command;

use askama::Template;
use vauban_web::models::session::SessionStatus;
use vauban_web::services::status_vocab::{
    APPROVAL, AUDIT_DECISIONS, MY_REQUESTS, session_history_options,
};
use vauban_web::templates::base::{UserContext, VaubanConfig};
use vauban_web::templates::sessions::SessionListTemplate;
use vauban_web::templates::sessions::approval_list::ApprovalListTemplate;
use vauban_web::templates::sessions::my_requests::MyRequestsTemplate;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ===================================================================
// 1. The bash lint passes and stays in lock-step with the enum
// ===================================================================

#[test]
fn check_status_vocabulary_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_status_vocabulary.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_status_vocabulary.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn script_canonical_list_matches_session_status_all() {
    let script = include_str!("../../scripts/check_status_vocabulary.sh");
    let canonical_line = script
        .lines()
        .find(|l| l.starts_with("CANONICAL="))
        .expect("script must define CANONICAL=");
    let list = canonical_line
        .trim_start_matches("CANONICAL=")
        .trim_matches('"');
    let script_values: Vec<&str> = list.split_whitespace().collect();
    let enum_values: Vec<&str> = SessionStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        script_values, enum_values,
        "the CANONICAL list of check_status_vocabulary.sh drifted from SessionStatus::ALL"
    );
}

// ===================================================================
// 2. The DB CHECK constraints stay in lock-step
// ===================================================================

/// Extract the quoted values of a `CHECK (<col> IN (...))` clause.
fn parse_check_values(sql: &str, column: &str) -> Vec<String> {
    let needle = format!("CHECK ({} IN (", column);
    let start = sql
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{needle}` clause found"));
    let rest = &sql[start + needle.len()..];
    let end = rest.find("))").expect("unterminated CHECK IN clause");
    rest[..end]
        .split(',')
        .map(|v| v.trim().trim_matches('\'').to_string())
        .collect()
}

#[test]
fn migration_check_matches_session_status_all() {
    let sql = include_str!(
        "../../../vauban-db/migrations/20260718000000_proxy_sessions_status_chk/up.sql"
    );
    let check_values = parse_check_values(sql, "status");
    let enum_values: Vec<String> = SessionStatus::ALL
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    assert_eq!(
        check_values, enum_values,
        "the proxy_sessions_status_chk CHECK drifted from SessionStatus::ALL"
    );
}

#[test]
fn audit_decisions_match_decision_check_migration() {
    let sql =
        include_str!("../../../vauban-db/migrations/20260705000000_jit_grant_revocation/up.sql");
    let check_values = parse_check_values(sql, "decision");
    assert_eq!(
        check_values,
        AUDIT_DECISIONS
            .values()
            .iter()
            .map(|v| (*v).to_string())
            .collect::<Vec<_>>(),
        "status_vocab::AUDIT_DECISIONS drifted from the approval_audit_log.decision CHECK"
    );
}

// ===================================================================
// 3. Rendered select options == vocabulary (no dead/phantom options)
// ===================================================================

fn admin_user() -> UserContext {
    UserContext {
        uuid: "admin-uuid".to_string(),
        username: "admin".to_string(),
        display_name: "Admin".to_string(),
        is_superuser: true,
        is_staff: true,
    }
}

fn vauban_cfg() -> VaubanConfig {
    VaubanConfig {
        brand_name: "VAUBAN".to_string(),
        brand_logo: None,
        theme: "dark".to_string(),
        ..Default::default()
    }
}

/// Slice the `<select ... name="status" ...>...</select>` block that
/// FOLLOWS the given anchor, so option counting never leaks into the
/// other selects of the page.
fn select_block<'a>(html: &'a str, anchor: &str) -> &'a str {
    let start = html
        .find(anchor)
        .unwrap_or_else(|| panic!("anchor {anchor:?} not found in rendered HTML"));
    let rest = &html[start..];
    let end = rest.find("</select>").expect("unterminated select block");
    &rest[..end]
}

fn count_options(block: &str) -> usize {
    block.matches("<option").count()
}

fn make_session_list(status_filter: Option<String>, industrial: bool) -> SessionListTemplate {
    SessionListTemplate {
        title: "Sessions".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        sessions: Vec::new(),
        status_filter,
        type_filter: None,
        asset_filter: None,
        statuses: session_history_options(industrial),
        show_view_link: true,
        pagination: None,
        ws_enabled: false,
        industrial_enabled: industrial,
        tz: chrono_tz::Tz::UTC,
    }
}

#[test]
fn session_list_select_covers_exactly_the_vocabulary() {
    for industrial in [true, false] {
        let html = make_session_list(None, industrial)
            .render()
            .expect("render");
        let block = select_block(&html, "<select name=\"status\"");
        let vocab = session_history_options(industrial);
        assert_eq!(
            count_options(block),
            vocab.len() + 1,
            "industrial={industrial}: option count must be vocab + the All option"
        );
        for (value, label) in &vocab {
            assert!(
                block.contains(&format!("value=\"{value}\"")),
                "industrial={industrial}: missing option '{value}'"
            );
            assert!(
                block.contains(label.as_str()),
                "industrial={industrial}: missing label '{label}'"
            );
        }
        // Dead / phantom options of the pre-fix template.
        assert!(
            !block.contains("value=\"completed\""),
            "phantom 'completed' option must stay purged"
        );
        assert!(
            !block.contains("value=\"pending\""),
            "'pending' rows are structurally excluded by the handler: dead option"
        );
    }
}

#[test]
fn session_list_select_marks_every_vocab_value_selected() {
    for (value, _) in session_history_options(true) {
        let html = make_session_list(Some(value.clone()), true)
            .render()
            .expect("render");
        let block = select_block(&html, "<select name=\"status\"");
        assert!(
            block.contains(&format!("value=\"{value}\" selected")),
            "'{value}' must render selected"
        );
        assert_eq!(
            block.matches(" selected").count(),
            1,
            "exactly one option may be selected for '{value}'"
        );
    }
}

fn make_approval_list(status_filter: Option<String>) -> ApprovalListTemplate {
    ApprovalListTemplate {
        title: "Approvals".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        approvals: Vec::new(),
        own_pending: Vec::new(),
        pagination: None,
        status_filter,
        statuses: APPROVAL.options(),
    }
}

#[test]
fn approval_list_select_covers_exactly_the_vocabulary() {
    let html = make_approval_list(None).render().expect("render");
    let block = select_block(&html, "<select name=\"status\"");
    assert_eq!(count_options(block), APPROVAL.entries.len() + 1);
    for (value, label) in APPROVAL.entries {
        assert!(block.contains(&format!("value=\"{value}\"")));
        assert!(block.contains(label));
    }
}

#[test]
fn approval_list_select_marks_every_vocab_value_selected() {
    for value in APPROVAL.values() {
        let html = make_approval_list(Some(value.to_string()))
            .render()
            .expect("render");
        let block = select_block(&html, "<select name=\"status\"");
        assert!(block.contains(&format!("value=\"{value}\" selected")));
        assert_eq!(block.matches(" selected").count(), 1);
    }
}

fn make_my_requests(status_filter: Option<String>) -> MyRequestsTemplate {
    MyRequestsTemplate {
        title: "My Requests".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        requests: Vec::new(),
        pagination: None,
        iacs_visible: false,
        iacs_request_allowed: false,
        ews_items: Vec::new(),
        csrf_token: "csrf".to_string(),
        search: None,
        status_filter,
        statuses: MY_REQUESTS.options(),
        ews_search: None,
        ews_state_filter: None,
    }
}

#[test]
fn my_requests_select_covers_exactly_the_vocabulary() {
    let html = make_my_requests(None).render().expect("render");
    let block = select_block(&html, "<select name=\"status\"");
    assert_eq!(count_options(block), MY_REQUESTS.entries.len() + 1);
    for (value, label) in MY_REQUESTS.entries {
        assert!(block.contains(&format!("value=\"{value}\"")));
        assert!(block.contains(label));
    }
    assert!(
        !block.contains("value=\"consumed\""),
        "phantom 'consumed' option must stay purged"
    );
}

#[test]
fn my_requests_select_marks_every_vocab_value_selected() {
    for value in MY_REQUESTS.values() {
        let html = make_my_requests(Some(value.to_string()))
            .render()
            .expect("render");
        let block = select_block(&html, "<select name=\"status\"");
        assert!(block.contains(&format!("value=\"{value}\" selected")));
        assert_eq!(block.matches(" selected").count(), 1);
    }
}

// ===================================================================
// 4. Handlers stay on the shared seam (source pins)
// ===================================================================

#[test]
fn handlers_derive_status_filters_from_status_vocab() {
    let read = |rel: &str| {
        std::fs::read_to_string(manifest_dir().join(rel))
            .unwrap_or_else(|e| panic!("read {rel}: {e}"))
    };

    let sessions = read("src/handlers/web/sessions.rs");
    assert!(
        sessions.contains("session_history_sanitize(opt_filter(&params, \"status\"))"),
        "session_list must sanitize its status filter through status_vocab"
    );
    assert!(
        sessions.contains("session_history_options("),
        "session_list must derive its select options from status_vocab"
    );
    assert!(
        sessions.contains("APPROVAL.sanitize(opt_filter(&params, \"status\"))"),
        "approval_list must sanitize its status filter through status_vocab"
    );
    assert!(
        sessions.contains("MY_REQUESTS.sanitize(opt_filter(&params, \"status\"))"),
        "my_requests must sanitize its status filter through status_vocab"
    );

    let audit = read("src/handlers/web/audit.rs");
    assert!(
        audit.contains("AUDIT_DECISIONS"),
        "approval_audit_list must sanitize its decision filter through status_vocab"
    );

    let assets = read("src/handlers/web/assets.rs");
    let manage = read("src/handlers/web/manage_assets.rs");
    assert!(
        assets.contains("AssetStatus::filter_options()"),
        "/assets must derive its status options from AssetStatus::filter_options"
    );
    assert!(
        manage.contains("AssetStatus::filter_options()"),
        "/assets/manage must derive its status options from AssetStatus::filter_options"
    );
}
