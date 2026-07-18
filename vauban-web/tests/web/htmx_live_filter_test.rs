//! HTMX live-filter regression tests.
//!
//! Issue #28 (live filtering across list pages) introduced HTMX-driven
//! search and filter inputs on:
//!
//! - `/assets`             (`asset_list.html`)
//! - `/assets/manage`      (`assets/manage/list.html`)
//! - `/assets/manage/groups`      (`assets/group_list.html`)
//! - `/accounts/users`     (`accounts/user_list.html`)
//! - `/accounts/groups`    (`accounts/group_list.html`)
//! - `/sessions`           (`sessions/session_list.html`)
//! - `/sessions/recordings`(`sessions/recording_list.html`)
//! - `/sessions/approvals` (`sessions/approval_list.html`)
//!
//! The list-filter factorisation (July 2026) extended the same
//! contract to the four remaining list pages:
//!
//! - `/assets/access`         (`assets/access_list.html`)
//! - `/vault/secrets`         (`secrets/secret_list.html`)
//! - `/vault/secrets/groups`  (`secrets/group_list.html`)
//! - `/vault/secrets/access`  (`secrets/rule_list.html`)
//! - `/assets/manage/deleted` (`assets/asset_deleted_list.html`)
//! - `/sessions/my-requests`  (`sessions/my_requests.html`, one
//!   toolbar per tab: Access [`search`/`status`] and EWS
//!   [`ews_search`/`ews_state`], `hx-include` scoped by toolbar id)
//!
//! Each list shares the same contract:
//!
//! 1. Inputs carry `hx-get="<list_url>"`, `hx-target` + `hx-select`
//!    pointing at a stable container id, `hx-swap="outerHTML"`,
//!    `hx-include` enumerating every filter `name=`, and
//!    `hx-push-url="true"`.
//! 2. The filter form has no `<form method="get">` wrapper and no
//!    `Filter` / `Search` submit button (the contract is implicit:
//!    typing or selecting fires the request).
//! 3. The container id is stable so the WebSocket auto-refresh on
//!    `/sessions`, `/sessions/recordings` and `/sessions/approvals`
//!    keeps targeting the same element across renders.
//! 4. When at least one filter is set and the result is empty, the
//!    page renders a contextual "No matching X" / "No X match your
//!    filters" empty state. The catalogue-empty branch is reserved
//!    for the truly unfiltered case.
//!
//! The tests below render each template with realistic inputs and
//! assert these guarantees. They run in-process (no DB, no HTTP
//! server) so they are fast and deterministic.

use vauban_web::templates::accounts::group_list::{GroupListItem, GroupListTemplate};
use vauban_web::templates::accounts::user_list::{Pagination, UserListItem, UserListTemplate};
use vauban_web::templates::assets::access_list::{AccessListTemplate, AccessRuleListItem};
use vauban_web::templates::assets::asset_list::{AssetListItem, AssetListTemplate};
use vauban_web::templates::assets::group_list::{AssetGroupItem, AssetGroupListTemplate};
use vauban_web::templates::assets::manage::list::{ManageAssetItem, ManageAssetListTemplate};
use vauban_web::templates::assets::{AssetDeletedListTemplate, DeletedAssetItem};
use vauban_web::templates::base::{UserContext, VaubanConfig};
use vauban_web::templates::iacs::{MyEwsItem, MyEwsState};
use vauban_web::templates::secrets::{
    SecretGroupItem, SecretGroupListTemplate, SecretItem, SecretListTemplate, SecretRuleItem,
    SecretRuleListTemplate,
};
use vauban_web::templates::sessions::approval_list::ApprovalListTemplate;
use vauban_web::templates::sessions::my_requests::{MyRequestItem, MyRequestsTemplate};
use vauban_web::templates::sessions::recording_list::RecordingListTemplate;
use vauban_web::templates::sessions::session_list::{SessionListItem, SessionListTemplate};

use askama::Template;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

/// Assert that the rendered HTML carries the full HTMX live-filter
/// contract for one input/select. Panics with a contextual message if
/// any of the required attributes is missing.
fn assert_htmx_live_filter(
    html: &str,
    list_url: &str,
    container_id: &str,
    expected_includes: &[&str],
    label: &str,
) {
    assert!(
        html.contains(&format!("hx-get=\"{}\"", list_url)),
        "[{label}] expected hx-get=\"{list_url}\" to be present"
    );
    assert!(
        html.contains(&format!("hx-target=\"#{}\"", container_id)),
        "[{label}] expected hx-target=\"#{container_id}\" to be present"
    );
    assert!(
        html.contains(&format!("hx-select=\"#{}\"", container_id)),
        "[{label}] expected hx-select=\"#{container_id}\" to be present"
    );
    assert!(
        html.contains("hx-swap=\"outerHTML\""),
        "[{label}] expected hx-swap=\"outerHTML\" to be present"
    );
    assert!(
        html.contains("hx-push-url=\"true\""),
        "[{label}] expected hx-push-url=\"true\" to be present"
    );
    for needle in expected_includes {
        assert!(
            html.contains(needle),
            "[{label}] expected hx-include to mention `{needle}`, got HTML missing this token"
        );
    }
    assert!(
        html.contains(&format!("id=\"{}\"", container_id)),
        "[{label}] expected the container element id=\"{container_id}\" to be rendered"
    );
}

/// Regression guard: the legacy `<form method="get">` wrapper around
/// the filter inputs must NOT come back, and no submit button shaped
/// like `<button type="submit">Filter|Search</button>` should remain.
/// The contract for these list pages is "live filter on input/change",
/// not "submit form".
fn assert_no_legacy_filter_form(html: &str, label: &str) {
    let lowered = html.to_ascii_lowercase();
    assert!(
        !lowered.contains("method=\"get\""),
        "[{label}] rendered HTML must not contain a form with method=\"get\" \
         (live HTMX filter is the only allowed mechanism on this page)"
    );
    // Look only for actual submit buttons, not `<label>Search</label>`
    // texts which are legitimate. The lint scans for `type="submit"`
    // followed within a small window by the `Filter` or `Search`
    // string. A regex would be cleaner but this keeps the suite
    // dependency-free.
    let mut search_from = 0usize;
    while let Some(pos) = lowered[search_from..].find("type=\"submit\"") {
        let abs = search_from + pos;
        let window_end = (abs + 256).min(lowered.len());
        let window = &lowered[abs..window_end];
        for needle in &[">filter<", ">search<"] {
            assert!(
                !window.contains(needle),
                "[{label}] rendered HTML still contains a submit button labelled `{}` \
                 within 256 chars of a type=\"submit\" attribute (live HTMX filter \
                 must have no submit affordance). Window: {window:?}",
                needle.trim_matches(['<', '>'].as_ref())
            );
        }
        search_from = abs + "type=\"submit\"".len();
    }
}

// ---------------------------------------------------------------------------
// /assets - user-facing asset catalogue
// ---------------------------------------------------------------------------

fn make_asset_list(
    assets: Vec<AssetListItem>,
    search: Option<String>,
    type_filter: Option<String>,
    status_filter: Option<String>,
) -> AssetListTemplate {
    AssetListTemplate {
        title: "Assets".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets,
        pagination: None,
        search,
        type_filter,
        status_filter,
        asset_types: vec![("ssh".into(), "SSH".into()), ("rdp".into(), "RDP".into())],
        statuses: vec![
            ("online".into(), "Online".into()),
            ("offline".into(), "Offline".into()),
        ],
        require_justification: true,
        iacs_request_allowed: false,
        iacs_connect_allowed: false,
        user_has_active_ews: false,
    }
}

fn one_asset() -> AssetListItem {
    AssetListItem {
        id: 1,
        uuid: ::uuid::Uuid::new_v4(),
        name: "prod-web-01".to_string(),
        hostname: "prod-web-01.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        status: "online".to_string(),
        group_name: Some("Production".to_string()),
        requires_request: false,
        require_mfa: false,
        is_iacs: false,
        iacs_protocol_label: String::new(),
    }
}

#[test]
fn assets_user_list_has_live_htmx_filter_contract() {
    let html = make_asset_list(vec![one_asset()], None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/assets",
        "asset-list-container",
        &["[name='search']", "[name='type']", "[name='status']"],
        "/assets",
    );
    assert!(
        html.contains("input changed delay:300ms"),
        "/assets search input must debounce input events at 300ms"
    );
    assert_no_legacy_filter_form(&html, "/assets");
}

#[test]
fn assets_user_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_asset_list(vec![], Some("nonexistent".to_string()), None, None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching")
            || lowered.contains("no asset") && lowered.contains("match"),
        "/assets must render a contextual 'no matching' empty state when filter is set"
    );
    assert!(
        lowered.contains("clear") && lowered.contains("filter"),
        "/assets filtered empty state must offer a 'clear filters' affordance"
    );
}

// ---------------------------------------------------------------------------
// /assets/manage - admin asset zone
// ---------------------------------------------------------------------------

fn make_manage_asset_list(
    assets: Vec<ManageAssetItem>,
    search: Option<String>,
    type_filter: Option<String>,
    status_filter: Option<String>,
) -> ManageAssetListTemplate {
    ManageAssetListTemplate {
        title: "Assets".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets,
        pagination: None,
        search,
        type_filter,
        status_filter,
        asset_types: vec![("ssh".into(), "SSH".into()), ("rdp".into(), "RDP".into())],
        statuses: vec![
            ("online".into(), "Online".into()),
            ("offline".into(), "Offline".into()),
        ],
    }
}

fn one_manage_asset() -> ManageAssetItem {
    ManageAssetItem {
        uuid: ::uuid::Uuid::new_v4(),
        name: "db-prod-01".to_string(),
        hostname: "db-prod-01.example.com".to_string(),
        port: 22,
        asset_type: "ssh".to_string(),
        is_iacs: false,
        iacs_protocol_label: String::new(),
        status: "online".to_string(),
        group_name: Some("DB".to_string()),
    }
}

#[test]
fn assets_manage_list_has_live_htmx_filter_contract() {
    let html = make_manage_asset_list(vec![one_manage_asset()], None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/assets/manage",
        "asset-list-container",
        &["[name='search']", "[name='type']", "[name='status']"],
        "/assets/manage",
    );
    assert_no_legacy_filter_form(&html, "/assets/manage");
}

#[test]
fn assets_manage_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_manage_asset_list(vec![], Some("nope".to_string()), None, None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching") || lowered.contains("match"),
        "/assets/manage must render a contextual 'no matching' empty state when filter is set"
    );
}

// ---------------------------------------------------------------------------
// /assets/manage/groups - asset groups (admin)
// ---------------------------------------------------------------------------

fn make_asset_group_list(
    groups: Vec<AssetGroupItem>,
    search: Option<String>,
) -> AssetGroupListTemplate {
    AssetGroupListTemplate {
        title: "Asset Groups".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        groups,
        search,
        pagination: None,
    }
}

#[test]
fn asset_groups_list_has_live_htmx_filter_contract() {
    let html = make_asset_group_list(vec![], None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/assets/manage/groups",
        "group-list-container",
        &["[name='search']"],
        "/assets/manage/groups",
    );
    assert_no_legacy_filter_form(&html, "/assets/manage/groups");
}

#[test]
fn asset_groups_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_asset_group_list(vec![], Some("nope".to_string()))
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching") || (lowered.contains("no") && lowered.contains("group")),
        "/assets/manage/groups must render a contextual 'no matching' empty state when search is set"
    );
}

// ---------------------------------------------------------------------------
// /accounts/users
// ---------------------------------------------------------------------------

fn make_user_list(
    users: Vec<UserListItem>,
    search: Option<String>,
    status_filter: Option<String>,
) -> UserListTemplate {
    UserListTemplate {
        title: "Users".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        users,
        pagination: Option::<Pagination>::None,
        search,
        status_filter,
    }
}

fn one_user() -> UserListItem {
    UserListItem {
        uuid: "user-uuid".to_string(),
        username: "alice".to_string(),
        email: "alice@example.com".to_string(),
        full_name: Some("Alice".to_string()),
        auth_source: "local".to_string(),
        mfa_enabled: true,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        last_login: Some("2026-04-30 10:00:00".to_string()),
    }
}

#[test]
fn users_list_has_live_htmx_filter_contract() {
    let html = make_user_list(vec![one_user()], None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/accounts/users",
        "user-list-container",
        &["[name='search']", "[name='status']"],
        "/accounts/users",
    );
    assert_no_legacy_filter_form(&html, "/accounts/users");
}

#[test]
fn users_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_user_list(vec![], Some("ghost".to_string()), None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/accounts/users must render 'no matching' empty state when search is set"
    );
    assert!(
        lowered.contains("clear") && lowered.contains("filter"),
        "/accounts/users filtered empty state must offer a 'clear filters' affordance"
    );
}

// ---------------------------------------------------------------------------
// /accounts/groups
// ---------------------------------------------------------------------------

fn make_account_group_list(
    groups: Vec<GroupListItem>,
    search: Option<String>,
) -> GroupListTemplate {
    GroupListTemplate {
        title: "Groups".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        groups,
        search,
        pagination: Option::<Pagination>::None,
    }
}

#[test]
fn account_groups_list_has_live_htmx_filter_contract() {
    let html = make_account_group_list(vec![], None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/accounts/groups",
        "group-list-container",
        &["[name='search']"],
        "/accounts/groups",
    );
    assert_no_legacy_filter_form(&html, "/accounts/groups");
}

#[test]
fn account_groups_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_account_group_list(vec![], Some("ghost".to_string()))
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/accounts/groups must render 'no matching' empty state when search is set"
    );
}

// ---------------------------------------------------------------------------
// /sessions  (live filter + WebSocket auto-refresh nested target)
// ---------------------------------------------------------------------------

fn make_session_list(
    sessions: Vec<SessionListItem>,
    asset_filter: Option<String>,
    type_filter: Option<String>,
    status_filter: Option<String>,
    ws_enabled: bool,
) -> SessionListTemplate {
    SessionListTemplate {
        title: "Sessions".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        sessions,
        status_filter,
        type_filter,
        asset_filter,
        statuses: vauban_web::services::status_vocab::session_history_options(true),
        show_view_link: true,
        pagination: None,
        ws_enabled,
        industrial_enabled: true,
        tz: chrono_tz::Tz::UTC,
    }
}

fn one_session() -> SessionListItem {
    SessionListItem {
        id: 1,
        uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        asset_name: "Prod Web 01".to_string(),
        asset_hostname: "prod-web-01".to_string(),
        session_type: "ssh".to_string(),
        status: "active".to_string(),
        credential_id: "local".to_string(),
        credential_username: "alice".to_string(),
        requester_username: "requester".to_string(),
        tunnel_target_addr: None,
        connected_at: Some(
            chrono::DateTime::parse_from_rfc3339("2026-04-30T10:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        disconnected_at: Some(
            chrono::DateTime::parse_from_rfc3339("2026-04-30T10:02:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-04-30T09:55:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        event_at: chrono::DateTime::parse_from_rfc3339("2026-04-30T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        event_label: "Connected".to_string(),
        duration_seconds: Some(120),
        is_recorded: true,
        recording_path: Some("/recordings/test.cast".to_string()),
    }
}

#[test]
fn sessions_list_has_live_htmx_filter_contract() {
    let html = make_session_list(vec![one_session()], None, None, None, false)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/sessions",
        "session-list-container",
        &["[name='asset']", "[name='type']", "[name='status']"],
        "/sessions",
    );
    assert_no_legacy_filter_form(&html, "/sessions");
}

#[test]
fn sessions_list_filter_field_order_is_asset_then_type_then_status() {
    let html = make_session_list(vec![one_session()], None, None, None, false)
        .render()
        .expect("render");
    let asset_pos = html
        .find("name=\"asset\"")
        .expect("asset filter must be rendered");
    let type_pos = html
        .find("name=\"type\"")
        .expect("type filter must be rendered");
    let status_pos = html
        .find("name=\"status\"")
        .expect("status filter must be rendered");
    assert!(
        asset_pos < type_pos && type_pos < status_pos,
        "/sessions: filter order must be Asset -> Type -> Status, got positions \
         asset={asset_pos}, type={type_pos}, status={status_pos}"
    );
}

#[test]
fn sessions_list_filter_target_and_ws_target_coexist() {
    // The HTMX live filter swaps `#session-list-container` (outer);
    // the WebSocket auto-refresh keeps targeting
    // `#ws-session-list-content` (inner). Both ids must be rendered
    // and must be distinct so the swaps do not cancel each other.
    let html = make_session_list(vec![one_session()], None, None, None, true)
        .render()
        .expect("render");
    assert!(
        html.contains("id=\"session-list-container\""),
        "/sessions must render outer #session-list-container for HTMX filter"
    );
    assert!(
        html.contains("id=\"ws-session-list-content\""),
        "/sessions must render inner #ws-session-list-content for WS auto-refresh"
    );
    let outer_pos = html
        .find("id=\"session-list-container\"")
        .expect("outer container id");
    let inner_pos = html
        .find("id=\"ws-session-list-content\"")
        .expect("inner WS target id");
    assert!(
        outer_pos < inner_pos,
        "/sessions outer container must enclose the inner WS target \
         (outer={outer_pos}, inner={inner_pos})"
    );
}

// ---------------------------------------------------------------------------
// /sessions/recordings  (live filter + WebSocket auto-refresh nested target)
// ---------------------------------------------------------------------------

fn make_recording_list(
    asset_filter: Option<String>,
    format_filter: Option<String>,
) -> RecordingListTemplate {
    RecordingListTemplate {
        title: "Recordings".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        recordings: Vec::new(),
        format_filter,
        asset_filter,
        pagination: None,
    }
}

#[test]
fn recordings_list_has_live_htmx_filter_contract() {
    let html = make_recording_list(None, None).render().expect("render");
    assert_htmx_live_filter(
        &html,
        "/sessions/recordings",
        "recordings-list-container",
        &["[name='asset']", "[name='format']"],
        "/sessions/recordings",
    );
    assert_no_legacy_filter_form(&html, "/sessions/recordings");
}

#[test]
fn recordings_list_filter_field_order_is_asset_then_format() {
    let html = make_recording_list(None, None).render().expect("render");
    // Skip the WS auto-refresh trigger lines which also mention the
    // filter names; we want the order of the *visible* fields.
    let asset_pos = html
        .find("name=\"asset\" id=\"asset\"")
        .expect("asset filter (search input) must be rendered");
    let format_pos = html
        .find("name=\"format\" id=\"format\"")
        .expect("format filter (select) must be rendered");
    assert!(
        asset_pos < format_pos,
        "/sessions/recordings: filter order must be Asset -> Format, got \
         asset={asset_pos}, format={format_pos}"
    );
}

#[test]
fn recordings_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_recording_list(Some("nope".to_string()), None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no recordings"),
        "/sessions/recordings empty state must mention 'No recordings' (legacy substring contract)"
    );
    assert!(
        lowered.contains("match") && (lowered.contains("filter") || lowered.contains("clear")),
        "/sessions/recordings must render a contextual filtered empty state when filter is set"
    );
}

// ---------------------------------------------------------------------------
// /sessions/approvals
// ---------------------------------------------------------------------------

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
        statuses: vauban_web::services::status_vocab::APPROVAL.options(),
    }
}

#[test]
fn approvals_list_has_live_htmx_filter_contract() {
    let html = make_approval_list(None).render().expect("render");
    assert_htmx_live_filter(
        &html,
        "/sessions/approvals",
        "approvals-list-container",
        &["[name='status']"],
        "/sessions/approvals",
    );
    assert_no_legacy_filter_form(&html, "/sessions/approvals");
}

#[test]
fn approvals_list_ws_trigger_and_htmx_filter_share_container() {
    // The auto-refresh trigger and the live filter must both point
    // at `#approvals-list-container`. If they ever diverge the WS
    // refresh stops working after a filter change.
    let html = make_approval_list(None).render().expect("render");
    let trigger_count = html.matches("#approvals-list-container").count();
    assert!(
        trigger_count >= 2,
        "/sessions/approvals must reference #approvals-list-container at least twice \
         (filter target + WS auto-refresh target), got {trigger_count}"
    );
}

// ---------------------------------------------------------------------------
// /assets/access - access rules (admin)
// ---------------------------------------------------------------------------

fn make_access_rule_list(
    rules: Vec<AccessRuleListItem>,
    search: Option<String>,
    protocol_filter: Option<String>,
    status_filter: Option<String>,
) -> AccessListTemplate {
    AccessListTemplate {
        title: "Access Rules".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        rules,
        pagination: None,
        search,
        protocol_filter,
        status_filter,
    }
}

fn one_access_rule() -> AccessRuleListItem {
    AccessRuleListItem {
        uuid: "rule-uuid".to_string(),
        name: "Ops to prod".to_string(),
        user_group_name: "Ops".to_string(),
        asset_group_name: "Prod".to_string(),
        allowed_protocols: vec!["ssh".to_string()],
        is_active: true,
        require_mfa: false,
        require_approval: false,
    }
}

#[test]
fn access_rules_list_has_live_htmx_filter_contract() {
    let html = make_access_rule_list(vec![one_access_rule()], None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/assets/access",
        "access-list-container",
        &["[name='search']", "[name='protocol']", "[name='status']"],
        "/assets/access",
    );
    assert!(
        html.contains("input changed delay:300ms"),
        "/assets/access search input must debounce input events at 300ms"
    );
    assert_no_legacy_filter_form(&html, "/assets/access");
}

#[test]
fn access_rules_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_access_rule_list(vec![], Some("ghost".to_string()), None, None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/assets/access must render a 'no matching' empty state when a filter is set"
    );
    assert!(
        lowered.contains("clear") && lowered.contains("filter"),
        "/assets/access filtered empty state must offer a 'clear filters' affordance"
    );
}

#[test]
fn access_rules_list_unfiltered_empty_state_keeps_catalogue_branch() {
    let html = make_access_rule_list(vec![], None, None, None)
        .render()
        .expect("render");
    assert!(
        html.contains("No access rules configured"),
        "/assets/access unfiltered empty state must keep the catalogue-empty wording"
    );
}

// ---------------------------------------------------------------------------
// /vault/secrets
// ---------------------------------------------------------------------------

fn make_secret_list(
    secrets: Vec<SecretItem>,
    search: Option<String>,
    status_filter: Option<String>,
) -> SecretListTemplate {
    SecretListTemplate {
        title: "Vault Secrets".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        secrets,
        pagination: None,
        search,
        status_filter,
    }
}

fn one_secret() -> SecretItem {
    SecretItem {
        uuid: "s1".to_string(),
        name: "db-password".to_string(),
        description: Some("Prod DB".to_string()),
        version: 1,
        is_active: true,
        group_count: 1,
        updated_at: "2026-07-18 10:00 UTC".to_string(),
    }
}

#[test]
fn vault_secrets_list_has_live_htmx_filter_contract() {
    let html = make_secret_list(vec![one_secret()], None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/vault/secrets",
        "secret-list-container",
        &["[name='search']", "[name='status']"],
        "/vault/secrets",
    );
    assert_no_legacy_filter_form(&html, "/vault/secrets");
}

#[test]
fn vault_secrets_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_secret_list(vec![], Some("ghost".to_string()), None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/vault/secrets must render a 'no matching' empty state when a filter is set"
    );
    assert!(
        lowered.contains("clear") && lowered.contains("filter"),
        "/vault/secrets filtered empty state must offer a 'clear filters' affordance"
    );
}

#[test]
fn vault_secrets_list_unfiltered_empty_state_keeps_catalogue_branch() {
    let html = make_secret_list(vec![], None, None)
        .render()
        .expect("render");
    assert!(
        html.contains("No vault secrets yet"),
        "/vault/secrets unfiltered empty state must keep the catalogue-empty wording"
    );
}

// ---------------------------------------------------------------------------
// /vault/secrets/groups
// ---------------------------------------------------------------------------

fn make_secret_group_list(
    groups: Vec<SecretGroupItem>,
    search: Option<String>,
) -> SecretGroupListTemplate {
    SecretGroupListTemplate {
        title: "Secret Groups".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        groups,
        search,
        pagination: None,
    }
}

#[test]
fn secret_groups_list_has_live_htmx_filter_contract() {
    let html = make_secret_group_list(vec![], None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/vault/secrets/groups",
        "secret-group-list-container",
        &["[name='search']"],
        "/vault/secrets/groups",
    );
    assert_no_legacy_filter_form(&html, "/vault/secrets/groups");
}

#[test]
fn secret_groups_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_secret_group_list(vec![], Some("ghost".to_string()))
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/vault/secrets/groups must render a 'no matching' empty state when search is set"
    );
}

// ---------------------------------------------------------------------------
// /vault/secrets/access
// ---------------------------------------------------------------------------

fn make_secret_rule_list(
    rules: Vec<SecretRuleItem>,
    search: Option<String>,
    user_group_filter: Option<String>,
    status_filter: Option<String>,
    eclipsed_filter: Option<String>,
) -> SecretRuleListTemplate {
    SecretRuleListTemplate {
        title: "Secret Access Rules".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        rules,
        pagination: None,
        search,
        user_group_filter,
        secret_group_filter: None,
        asset_group_filter: None,
        status_filter,
        eclipsed_filter,
        user_groups: vec!["Ops".to_string()],
        secret_groups: vec!["Prod credentials".to_string()],
        asset_groups: vec!["All assets".to_string()],
    }
}

fn one_secret_rule() -> SecretRuleItem {
    SecretRuleItem {
        uuid: "r1".to_string(),
        name: "Ops reads prod".to_string(),
        user_group_name: "Ops".to_string(),
        secret_group_name: "Prod credentials".to_string(),
        asset_group_name: "All assets".to_string(),
        is_active: true,
        is_eclipsed: false,
    }
}

#[test]
fn secret_rules_list_has_live_htmx_filter_contract() {
    let html = make_secret_rule_list(vec![one_secret_rule()], None, None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/vault/secrets/access",
        "secret-rule-list-container",
        &[
            "[name='search']",
            "[name='user_group']",
            "[name='secret_group']",
            "[name='asset_group']",
            "[name='status']",
            "[name='eclipsed']",
        ],
        "/vault/secrets/access",
    );
    assert_no_legacy_filter_form(&html, "/vault/secrets/access");
}

#[test]
fn secret_rules_list_select_options_come_from_full_set() {
    // Options are derived from the FULL rule set so they never shrink
    // while filtering: even with an active user_group filter, every
    // option value must stay rendered.
    let html = make_secret_rule_list(
        vec![one_secret_rule()],
        None,
        Some("Ops".to_string()),
        None,
        None,
    )
    .render()
    .expect("render");
    assert!(html.contains("<option value=\"Ops\" selected>"));
    assert!(html.contains("Prod credentials"));
    assert!(html.contains("All assets"));
}

#[test]
fn secret_rules_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_secret_rule_list(
        vec![],
        Some("ghost".to_string()),
        None,
        None,
        Some("yes".to_string()),
    )
    .render()
    .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching"),
        "/vault/secrets/access must render a 'no matching' empty state when a filter is set"
    );
    assert!(
        lowered.contains("clear") && lowered.contains("filter"),
        "/vault/secrets/access filtered empty state must offer a 'clear filters' affordance"
    );
}

#[test]
fn secret_rules_pagination_suffix_carries_filters_encoded() {
    let template = make_secret_rule_list(
        vec![],
        Some("a b".to_string()),
        Some("Ops Team".to_string()),
        Some("active".to_string()),
        Some("yes".to_string()),
    );
    let suffix = template.filter_query_suffix();
    assert_eq!(
        suffix,
        "&search=a%20b&user_group=Ops%20Team&status=active&eclipsed=yes"
    );
}

// ---------------------------------------------------------------------------
// /assets/manage/deleted - tombstone audit page
// ---------------------------------------------------------------------------

fn one_deleted_asset() -> DeletedAssetItem {
    DeletedAssetItem {
        uuid: ::uuid::Uuid::new_v4(),
        name: "Decommissioned host".to_string(),
        hostname: "10.10.10.99".to_string(),
        port: 22,
        connection_username: "root".to_string(),
        asset_type: "ssh".to_string(),
        is_iacs: false,
        type_label: "SSH".to_string(),
        deleted_at: Some(chrono::Utc::now()),
        created_at: chrono::Utc::now(),
        deleted_by: None,
    }
}

fn make_deleted_asset_list(
    assets: Vec<DeletedAssetItem>,
    search: Option<String>,
) -> AssetDeletedListTemplate {
    AssetDeletedListTemplate {
        title: "Deleted Assets".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        assets,
        pagination: None,
        search,
    }
}

#[test]
fn deleted_assets_list_has_live_htmx_filter_contract() {
    let html = make_deleted_asset_list(vec![], None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/assets/manage/deleted",
        "deleted-asset-list-container",
        &["[name='search']"],
        "/assets/manage/deleted",
    );
    assert_no_legacy_filter_form(&html, "/assets/manage/deleted");
}

#[test]
fn deleted_assets_list_filtered_empty_state_shows_no_match_branch() {
    let html = make_deleted_asset_list(vec![], Some("ghost".to_string()))
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no matching deleted assets"),
        "/assets/manage/deleted must render a 'no matching' empty state when search is set"
    );
    assert!(
        !lowered.contains("the audit trail is empty"),
        "/assets/manage/deleted must NOT render the unfiltered empty state while a search is set"
    );
}

#[test]
fn deleted_assets_list_unfiltered_empty_state_keeps_audit_wording() {
    let html = make_deleted_asset_list(vec![], None)
        .render()
        .expect("render");
    let lowered = html.to_ascii_lowercase();
    assert!(
        lowered.contains("no deleted assets"),
        "/assets/manage/deleted must keep the audit-trail empty state when unfiltered"
    );
    assert!(
        !lowered.contains("no matching deleted assets"),
        "/assets/manage/deleted must not render the filtered branch without a search"
    );
}

// ---------------------------------------------------------------------------
// /sessions/my-requests - two-tab self-service page (Access + EWS)
// ---------------------------------------------------------------------------

fn one_my_request() -> MyRequestItem {
    MyRequestItem {
        uuid: "req-1".to_string(),
        asset_name: "prod-db-01".to_string(),
        asset_hostname: "prod-db-01.example.com".to_string(),
        asset_type: "ssh".to_string(),
        session_type: "ssh".to_string(),
        status: "pending".to_string(),
        justification: Some("maintenance".to_string()),
        created_at: "2026-07-18 10:00 UTC".to_string(),
        approved_at: None,
        approved_by: None,
        max_session_duration: None,
    }
}

fn one_my_ews() -> MyEwsItem {
    MyEwsItem {
        uuid: "ews-1".to_string(),
        name: "engineering-laptop".to_string(),
        fingerprint_short: "abcd1234".to_string(),
        key_algo: "ssh-ed25519".to_string(),
        state: MyEwsState::Pending,
        created_at: "2026-07-18 10:00 UTC".to_string(),
        decided_at: None,
        rejection_reason: None,
        justification: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn make_my_requests(
    requests: Vec<MyRequestItem>,
    ews_items: Vec<MyEwsItem>,
    iacs_visible: bool,
    search: Option<String>,
    status_filter: Option<String>,
    ews_search: Option<String>,
    ews_state_filter: Option<String>,
) -> MyRequestsTemplate {
    MyRequestsTemplate {
        title: "My Requests".to_string(),
        user: Some(admin_user()),
        vauban: vauban_cfg(),
        messages: Vec::new(),
        language_code: "en".to_string(),
        sidebar_content: None,
        header_user: None,
        requests,
        pagination: None,
        iacs_visible,
        iacs_request_allowed: iacs_visible,
        ews_items,
        csrf_token: "csrf".to_string(),
        search,
        status_filter,
        statuses: vauban_web::services::status_vocab::MY_REQUESTS.options(),
        ews_search,
        ews_state_filter,
    }
}

#[test]
fn my_requests_access_tab_has_live_htmx_filter_contract() {
    let html = make_my_requests(vec![], vec![], false, None, None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/sessions/my-requests",
        "my-requests-list",
        &["#access-filter-toolbar"],
        "/sessions/my-requests (access)",
    );
    assert_no_legacy_filter_form(&html, "/sessions/my-requests");
}

#[test]
fn my_requests_ews_tab_has_live_htmx_filter_contract() {
    let html = make_my_requests(vec![], vec![one_my_ews()], true, None, None, None, None)
        .render()
        .expect("render");
    assert_htmx_live_filter(
        &html,
        "/sessions/my-requests",
        "my-ews-list",
        &[
            "#ews-filter-toolbar",
            "name=\"ews_search\"",
            "name=\"ews_state\"",
        ],
        "/sessions/my-requests (ews)",
    );
}

#[test]
fn my_requests_toolbars_carry_their_tab_marker() {
    // The hidden `tab` inputs keep the pushed URL opening on the tab
    // that was filtered (Alpine reads ?tab= on load).
    let html = make_my_requests(vec![], vec![], true, None, None, None, None)
        .render()
        .expect("render");
    assert!(
        html.contains("name=\"tab\" value=\"access\""),
        "access toolbar must carry the hidden tab=access marker"
    );
    assert!(
        html.contains("name=\"tab\" value=\"ews\""),
        "ews toolbar must carry the hidden tab=ews marker"
    );
}

#[test]
fn my_requests_access_filtered_empty_state_shows_no_match_branch() {
    let html = make_my_requests(
        vec![],
        vec![],
        false,
        Some("ghost".to_string()),
        Some("approved".to_string()),
        None,
        None,
    )
    .render()
    .expect("render");
    assert!(
        html.contains("No matching access requests"),
        "filtered access empty state must render the 'no match' branch"
    );
    assert!(
        !html.contains("You haven't submitted any access requests yet."),
        "onboarding empty state must not render while access filters are set"
    );
}

#[test]
fn my_requests_ews_filtered_empty_state_shows_no_match_branch() {
    let html = make_my_requests(
        vec![],
        vec![],
        true,
        None,
        None,
        Some("ghost".to_string()),
        None,
    )
    .render()
    .expect("render");
    assert!(
        html.contains("No matching EWS"),
        "filtered EWS empty state must render the 'no match' branch"
    );
    assert!(
        !html.contains("No EWS registered"),
        "onboarding EWS empty state must not render while EWS filters are set"
    );
}

#[test]
fn my_requests_unfiltered_empty_states_keep_onboarding_wording() {
    let html = make_my_requests(vec![], vec![], true, None, None, None, None)
        .render()
        .expect("render");
    assert!(html.contains("No access requests"));
    assert!(html.contains("No EWS registered"));
    assert!(!html.contains("No matching access requests"));
    assert!(!html.contains("No matching EWS"));
}

#[test]
fn my_requests_filter_query_suffix_carries_both_tabs_filters() {
    let template = make_my_requests(
        vec![],
        vec![],
        true,
        Some("a b".to_string()),
        Some("approved".to_string()),
        Some("laptop".to_string()),
        Some("pending".to_string()),
    );
    assert_eq!(
        template.filter_query_suffix(),
        "&search=a%20b&status=approved&ews_search=laptop&ews_state=pending"
    );
}

// ---------------------------------------------------------------------------
// Cross-cutting: indicator wiring
// ---------------------------------------------------------------------------

/// All live filters must reference an `hx-indicator` so users get a
/// discreet feedback while the request is in-flight. The indicator id
/// must exist in the same document.
#[test]
fn every_live_filter_page_renders_an_indicator() {
    let pages: &[(&str, String)] = &[
        (
            "/assets",
            make_asset_list(vec![one_asset()], None, None, None)
                .render()
                .unwrap(),
        ),
        (
            "/assets/manage",
            make_manage_asset_list(vec![one_manage_asset()], None, None, None)
                .render()
                .unwrap(),
        ),
        (
            "/assets/manage/groups",
            make_asset_group_list(vec![], None).render().unwrap(),
        ),
        (
            "/accounts/users",
            make_user_list(vec![one_user()], None, None)
                .render()
                .unwrap(),
        ),
        (
            "/accounts/groups",
            make_account_group_list(vec![], None).render().unwrap(),
        ),
        (
            "/sessions",
            make_session_list(vec![one_session()], None, None, None, false)
                .render()
                .unwrap(),
        ),
        (
            "/sessions/recordings",
            make_recording_list(None, None).render().unwrap(),
        ),
        (
            "/sessions/approvals",
            make_approval_list(None).render().unwrap(),
        ),
        (
            "/assets/access",
            make_access_rule_list(vec![one_access_rule()], None, None, None)
                .render()
                .unwrap(),
        ),
        (
            "/vault/secrets",
            make_secret_list(vec![one_secret()], None, None)
                .render()
                .unwrap(),
        ),
        (
            "/vault/secrets/groups",
            make_secret_group_list(vec![], None).render().unwrap(),
        ),
        (
            "/vault/secrets/access",
            make_secret_rule_list(vec![one_secret_rule()], None, None, None, None)
                .render()
                .unwrap(),
        ),
        (
            "/assets/manage/deleted",
            make_deleted_asset_list(vec![one_deleted_asset()], None)
                .render()
                .unwrap(),
        ),
        (
            "/sessions/my-requests",
            make_my_requests(
                vec![one_my_request()],
                vec![one_my_ews()],
                true,
                None,
                None,
                None,
                None,
            )
            .render()
            .unwrap(),
        ),
    ];

    for (label, html) in pages {
        let indicator_attr = "hx-indicator=\"#";
        let indicator_pos = html
            .find(indicator_attr)
            .unwrap_or_else(|| panic!("[{label}] expected at least one hx-indicator reference"));
        // Extract the indicator id between the quotes after the `#`.
        let after = &html[indicator_pos + indicator_attr.len()..];
        let id_end = after
            .find('"')
            .unwrap_or_else(|| panic!("[{label}] hx-indicator value must be quoted"));
        let indicator_id = &after[..id_end];
        assert!(
            !indicator_id.is_empty(),
            "[{label}] hx-indicator id must not be empty"
        );
        assert!(
            html.contains(&format!("id=\"{}\"", indicator_id)),
            "[{label}] hx-indicator references #{indicator_id} but no element with that id is rendered"
        );
        assert!(
            html.contains("htmx-indicator"),
            "[{label}] indicator element must carry the `htmx-indicator` class"
        );
    }
}
