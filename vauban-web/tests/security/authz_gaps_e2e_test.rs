//! End-to-end attack tests for the three authorization fences closed by
//! `docs/remediation/authz_shadowing_and_api_gaps.md`.
//!
//! Every `attack_*` / `*_is_rejected` test below performs the abuse
//! through the real router (auth middleware, Casbin `PermissionContext`,
//! in-process `vauban-access`, Postgres) and expects a refusal; the
//! companion non-regression tests prove the legitimate path still works.
//!
//! 1. Interactive WebSocket data plane (`/ws/terminal`, `/ws/rdp`) is
//!    owner-only; `sessions:supervise` no longer opens it.
//! 2. `PUT /api/v1/accounts/{uuid}` on a superuser needs
//!    `users:manage_admins`.
//! 3. `POST /api/v1/sessions` records the same bounded `pending` request
//!    as the web form.

use axum::http::header::{self, COOKIE};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_admin_user, create_simple_rdp_asset, create_simple_ssh_asset,
    create_staff_only_user, create_test_access_rule_with_constraints, create_test_asset_group,
    create_test_session_with_access, create_test_user, create_test_vauban_group, get_asset_uuid,
    unique_name,
};
use vauban_web::models::session::SessionType;
use vauban_web::schema::{proxy_sessions, users};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Plain GET on a WebSocket route (no upgrade headers). A guard refusal
/// answers 401/403/404; when the guard passes, the handler's
/// `WebSocketUpgrade` extractor fails with 400/426.
pub(crate) async fn ws_get(app: &TestApp, path: &str, token: &str) -> u16 {
    app.server
        .get(path)
        .add_header(header::AUTHORIZATION, app.auth_header(token))
        .await
        .status_code()
        .as_u16()
}

fn guard_passed(status: u16) -> bool {
    !matches!(status, 401 | 403 | 404 | 410)
}

/// `(status, connected_at, expires_at, disconnected_at)` of a session.
pub(crate) type SessionLiveness = (
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

pub(crate) async fn session_liveness(
    conn: &mut AsyncPgConnection,
    session_uuid: Uuid,
) -> SessionLiveness {
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::connected_at,
                proxy_sessions::expires_at,
                proxy_sessions::disconnected_at,
            ))
            .first(conn)
            .await
    )
}

/// Insert a bare SSH session row in `status` with a duration cap.
async fn insert_ssh_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    status: &str,
    max_session_duration: Option<i32>,
) -> Uuid {
    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("local"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(SessionType::Ssh),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::metadata.eq(serde_json::json!({})),
                proxy_sessions::max_session_duration.eq(max_session_duration),
            ))
            .execute(conn)
            .await
    );
    session_uuid
}

/// `(is_active, email, is_deleted)` of a user row.
pub(crate) async fn user_row(conn: &mut AsyncPgConnection, user_id: i32) -> (bool, String, bool) {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select((users::is_active, users::email, users::is_deleted))
            .first(conn)
            .await
    )
}

/// Wire `user_id` and `asset_id` through fresh groups and an active
/// access rule with `require_approval = true` and the given duration cap.
pub(crate) async fn grant_with_approval(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    max_duration: Option<i32>,
) {
    use vauban_web::schema::{asset_asset_groups, asset_groups};

    let ug = create_test_vauban_group(conn, &unique_name("authz-ug")).await;
    add_user_to_vauban_group(conn, user_id, &ug).await;
    let ag = create_test_asset_group(conn, &unique_name("authz-ag")).await;
    let ag_id: i32 = unwrap_ok!(
        asset_groups::table
            .filter(asset_groups::uuid.eq(ag))
            .select(asset_groups::id)
            .first(conn)
            .await
    );
    unwrap_ok!(
        diesel::insert_into(asset_asset_groups::table)
            .values((
                asset_asset_groups::asset_id.eq(asset_id),
                asset_asset_groups::asset_group_id.eq(ag_id),
            ))
            .on_conflict_do_nothing()
            .execute(conn)
            .await
    );
    create_test_access_rule_with_constraints(
        conn,
        &ug,
        &ag,
        &["ssh", "rdp"],
        false,
        true,
        max_duration,
    )
    .await;
}

type StoredRequestRow = (
    String,
    String,
    String,
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// The stored shape of an access request.
#[derive(Debug)]
pub(crate) struct StoredRequest {
    pub status: String,
    pub credential_id: String,
    pub credential_username: String,
    pub max_session_duration: Option<i32>,
    pub justification: Option<String>,
    pub client_user_agent: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub(crate) async fn stored_request(
    conn: &mut AsyncPgConnection,
    session_uuid: Uuid,
) -> StoredRequest {
    let row: StoredRequestRow = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::credential_id,
                proxy_sessions::credential_username,
                proxy_sessions::max_session_duration,
                proxy_sessions::justification,
                proxy_sessions::client_user_agent,
                proxy_sessions::expires_at,
            ))
            .first(conn)
            .await
    );
    StoredRequest {
        status: row.0,
        credential_id: row.1,
        credential_username: row.2,
        max_session_duration: row.3,
        justification: row.4,
        client_user_agent: row.5,
        expires_at: row.6,
    }
}

async fn pending_count_for(conn: &mut AsyncPgConnection, user_id: i32) -> i64 {
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user_id))
            .filter(proxy_sessions::status.eq("pending"))
            .count()
            .get_result(conn)
            .await
    )
}

// =====================================================================
// 1. Interactive WebSocket data plane is owner-only
// =====================================================================

/// A staff user (`sessions:supervise`, not the owner) probes the SSH
/// terminal data plane of someone else's live session.
#[tokio::test]
#[serial]
async fn attack_staff_supervisor_on_terminal_ws_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own1")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff1")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset1"), owner.user.id).await;
    let (_id, session_uuid, _rule) =
        create_test_session_with_access(&mut conn, owner.user.id, asset_id, "ssh", "active").await;
    let before = session_liveness(&mut conn, session_uuid).await;
    drop(conn);

    let status = ws_get(app, &format!("/ws/terminal/{session_uuid}"), &staff.token).await;
    assert_eq!(
        status, 404,
        "a non-owner supervisor must get the collapsed 404 on /ws/terminal"
    );

    // The refusal happened before the handler: the row is untouched.
    let mut conn = app.get_conn().await;
    assert_eq!(session_liveness(&mut conn, session_uuid).await, before);
}

/// Same probe on the RDP data plane.
#[tokio::test]
#[serial]
async fn attack_staff_supervisor_on_rdp_ws_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own2")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff2")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("azg-asset2"), owner.user.id).await;
    let (_id, session_uuid, _rule) =
        create_test_session_with_access(&mut conn, owner.user.id, asset_id, "rdp", "active").await;
    let before = session_liveness(&mut conn, session_uuid).await;
    drop(conn);

    let status = ws_get(app, &format!("/ws/rdp/{session_uuid}"), &staff.token).await;
    assert_eq!(
        status, 404,
        "a non-owner supervisor must get the collapsed 404 on /ws/rdp"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(session_liveness(&mut conn, session_uuid).await, before);
}

/// A superuser who is not the owner is refused too: the fence is about
/// ownership, not about rank.
#[tokio::test]
#[serial]
async fn attack_superuser_non_owner_on_rdp_ws_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own3")).await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_adm3")).await;
    let asset_id =
        create_simple_rdp_asset(&mut conn, &unique_name("azg-asset3"), owner.user.id).await;
    let (_id, session_uuid, _rule) =
        create_test_session_with_access(&mut conn, owner.user.id, asset_id, "rdp", "active").await;
    drop(conn);

    let status = ws_get(app, &format!("/ws/rdp/{session_uuid}"), &admin.token).await;
    assert_eq!(
        status, 404,
        "a non-owner superuser must be refused on /ws/rdp"
    );
}

/// The owner-only refusal is indistinguishable from "no such session":
/// the interactive routes are not an existence oracle for supervisors.
#[tokio::test]
#[serial]
async fn supervisor_probe_matches_unknown_session_on_data_plane() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own4")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff4")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset4"), owner.user.id).await;
    let (_id, session_uuid, _rule) =
        create_test_session_with_access(&mut conn, owner.user.id, asset_id, "ssh", "active").await;
    drop(conn);

    let existing = ws_get(app, &format!("/ws/terminal/{session_uuid}"), &staff.token).await;
    let unknown = ws_get(
        app,
        &format!("/ws/terminal/{}", Uuid::new_v4()),
        &staff.token,
    )
    .await;
    assert_eq!(existing, unknown, "existing vs unknown session must match");
    assert_eq!(existing, 404);
}

/// Non-regression: the owner still passes the guard on both interactive
/// routes, and a supervisor still reaches the read-only push feed.
#[tokio::test]
#[serial]
async fn owner_keeps_data_plane_and_supervisor_keeps_push_feed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own5")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff5")).await;
    let ssh_asset =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset5s"), owner.user.id).await;
    let rdp_asset =
        create_simple_rdp_asset(&mut conn, &unique_name("azg-asset5r"), owner.user.id).await;
    let (_i, ssh_session, _r) =
        create_test_session_with_access(&mut conn, owner.user.id, ssh_asset, "ssh", "active").await;
    let (_i, rdp_session, _r) =
        create_test_session_with_access(&mut conn, owner.user.id, rdp_asset, "rdp", "active").await;
    drop(conn);

    let owner_ssh = ws_get(app, &format!("/ws/terminal/{ssh_session}"), &owner.token).await;
    assert!(
        guard_passed(owner_ssh),
        "owner must pass the terminal guard, got {owner_ssh}"
    );
    let owner_rdp = ws_get(app, &format!("/ws/rdp/{rdp_session}"), &owner.token).await;
    assert!(
        guard_passed(owner_rdp),
        "owner must pass the RDP guard, got {owner_rdp}"
    );

    let staff_feed = ws_get(app, &format!("/ws/session/{ssh_session}"), &staff.token).await;
    assert!(
        guard_passed(staff_feed),
        "a supervisor must still reach /ws/session/{{id}}, got {staff_feed}"
    );
}

/// `activate_proxy_session` transitions a `connecting` row exactly once.
/// A second call on the now-`active` row leaves `connected_at` and
/// `expires_at` untouched, so reconnecting does not push the duration
/// horizon back.
#[tokio::test]
#[serial]
async fn attack_reconnect_to_extend_session_expiry_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own6")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset6"), owner.user.id).await;
    let session_uuid =
        insert_ssh_session(&mut conn, owner.user.id, asset_id, "connecting", Some(600)).await;
    let sid = session_uuid.to_string();

    vauban_web::handlers::websocket::activate_proxy_session(&app.app_state, &sid).await;
    let first = session_liveness(&mut conn, session_uuid).await;
    assert_eq!(first.0, "active", "first activation must flip to active");
    let connected_at = first.1.expect("connected_at set on activation");
    let expires_at = first
        .2
        .expect("expires_at derived from max_session_duration");
    assert_eq!(
        (expires_at - connected_at).num_seconds(),
        600,
        "expires_at must be connected_at + max_session_duration"
    );

    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    vauban_web::handlers::websocket::activate_proxy_session(&app.app_state, &sid).await;
    let second = session_liveness(&mut conn, session_uuid).await;
    assert_eq!(
        second, first,
        "a second activation must not move connected_at / expires_at"
    );
}

/// A row that is not `connecting` (already terminal) is never revived.
#[tokio::test]
#[serial]
async fn activation_never_revives_a_terminal_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let owner = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_own7")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset7"), owner.user.id).await;

    for status in [
        "terminated",
        "disconnected",
        "expired",
        "pending",
        "approved",
    ] {
        let session_uuid =
            insert_ssh_session(&mut conn, owner.user.id, asset_id, status, Some(600)).await;
        let before = session_liveness(&mut conn, session_uuid).await;
        vauban_web::handlers::websocket::activate_proxy_session(
            &app.app_state,
            &session_uuid.to_string(),
        )
        .await;
        assert_eq!(
            session_liveness(&mut conn, session_uuid).await,
            before,
            "status `{status}` must not be activated"
        );
    }
}

// =====================================================================
// 2. API account update: superuser-target fence
// =====================================================================

async fn put_account(
    app: &TestApp,
    target_uuid: Uuid,
    api_key: &str,
    body: serde_json::Value,
) -> axum_test::TestResponse {
    app.server
        .put(&format!("/api/v1/accounts/{target_uuid}"))
        .add_header(header::AUTHORIZATION, app.api_key_header(api_key))
        .json(&body)
        .await
}

/// Staff (`users:write`, no `users:manage_admins`) tries to deactivate a
/// superuser through the M2M API.
#[tokio::test]
#[serial]
async fn attack_staff_deactivating_superuser_via_api_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff8")).await;
    let target = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_sup8")).await;
    let before = user_row(&mut conn, target.user.id).await;
    drop(conn);

    let response = put_account(
        app,
        target.user.uuid,
        &staff.api_key,
        json!({ "is_active": false }),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 403);
    assert!(
        response.text().contains("users:manage_admins"),
        "the refusal must name the missing capability"
    );

    let mut conn = app.get_conn().await;
    assert_eq!(
        user_row(&mut conn, target.user.id).await,
        before,
        "the superuser row must be untouched"
    );
}

/// Staff tries to redirect a superuser's email (notification hijack).
#[tokio::test]
#[serial]
async fn attack_staff_changing_superuser_email_via_api_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff9")).await;
    let target = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_sup9")).await;
    let before = user_row(&mut conn, target.user.id).await;
    drop(conn);

    let response = put_account(
        app,
        target.user.uuid,
        &staff.api_key,
        json!({ "email": "hijack@attacker.test", "first_name": "Owned" }),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 403);

    let mut conn = app.get_conn().await;
    assert_eq!(user_row(&mut conn, target.user.id).await, before);
}

/// Non-regression: a superuser edits another superuser, and staff still
/// edits a regular user.
#[tokio::test]
#[serial]
async fn legitimate_account_updates_still_succeed() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let operator = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_op10")).await;
    let peer = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_sup10")).await;
    let staff =
        create_staff_only_user(&mut conn, &app.auth_service, &unique_name("azg_staff10")).await;
    let regular = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_usr10")).await;
    drop(conn);

    let response = put_account(
        app,
        peer.user.uuid,
        &operator.api_key,
        json!({ "first_name": "Edited" }),
    )
    .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "a superuser must still edit another superuser: {}",
        response.text()
    );

    let response = put_account(
        app,
        regular.user.uuid,
        &staff.api_key,
        json!({ "first_name": "Edited" }),
    )
    .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "staff must still edit a regular user: {}",
        response.text()
    );
}

/// A soft-deleted account is invisible to the update: 404, and the row
/// is neither edited nor reactivated.
#[tokio::test]
#[serial]
async fn attack_updating_soft_deleted_account_via_api_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let operator = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_op11")).await;
    let ghost = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_del11")).await;
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(ghost.user.id)))
            .set((users::is_deleted.eq(true), users::is_active.eq(false)))
            .execute(&mut conn)
            .await
    );
    let before = user_row(&mut conn, ghost.user.id).await;
    drop(conn);

    let response = put_account(
        app,
        ghost.user.uuid,
        &operator.api_key,
        json!({ "is_active": true, "email": "revived@attacker.test" }),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 404);

    let mut conn = app.get_conn().await;
    assert_eq!(user_row(&mut conn, ghost.user.id).await, before);
}

// =====================================================================
// 3. API access request: same bounded `pending` row as the web form
// =====================================================================

pub(crate) async fn post_session(
    app: &TestApp,
    api_key: &str,
    body: serde_json::Value,
) -> axum_test::TestResponse {
    app.server
        .post("/api/v1/sessions")
        .add_header(header::AUTHORIZATION, app.api_key_header(api_key))
        .add_header(header::USER_AGENT, "authz-gaps-e2e/1.0")
        .json(&body)
        .await
}

pub(crate) fn created_uuid(response: &axum_test::TestResponse) -> Uuid {
    let body: serde_json::Value = response.json();
    let raw = body
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("response must carry a uuid: {body}"));
    unwrap_ok!(Uuid::parse_str(raw))
}

/// The caller tries to smuggle a credential and to omit the duration
/// cap. The stored request carries the rule's cap and the placeholder.
#[tokio::test]
#[serial]
async fn attack_api_request_with_smuggled_credential_is_neutralized() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_req12")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset12"), user.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    grant_with_approval(&mut conn, user.user.id, asset_id, Some(1800)).await;
    drop(conn);

    let response = post_session(
        app,
        &user.api_key,
        json!({
            "asset_id": asset_uuid,
            "session_type": "ssh",
            "credential_id": "root-forever",
            "justification": "<b>Routine</b> maintenance window"
        }),
    )
    .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "request must be recorded: {}",
        response.text()
    );
    let session_uuid = created_uuid(&response);

    let mut conn = app.get_conn().await;
    let stored = stored_request(&mut conn, session_uuid).await;
    assert_eq!(stored.status, "pending");
    assert_eq!(
        stored.credential_id, "pending",
        "credential must be ignored"
    );
    assert_eq!(stored.credential_username, "pending");
    assert_eq!(
        stored.max_session_duration,
        Some(1800),
        "the access rule's cap must be copied on the request"
    );
    assert_eq!(
        stored.justification.as_deref(),
        Some("Routine maintenance window"),
        "the justification must be tag-stripped"
    );
    assert_eq!(
        stored.client_user_agent.as_deref(),
        Some("authz-gaps-e2e/1.0"),
        "request metadata must describe the real caller"
    );
}

/// Full chain: a request created through the API, approved WITHOUT a
/// duration override, ends up with an `expires_at` horizon. Before the
/// fix the row had no cap and the approval was permanent.
#[tokio::test]
#[serial]
async fn attack_api_request_approved_without_override_is_time_bounded() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_req13")).await;
    let approver = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_apr13")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset13"), approver.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    grant_with_approval(&mut conn, user.user.id, asset_id, Some(900)).await;
    drop(conn);

    let response = post_session(
        app,
        &user.api_key,
        json!({
            "asset_id": asset_uuid,
            "session_type": "ssh",
            "justification": "Quarterly patching of the jump host"
        }),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 200, "{}", response.text());
    let session_uuid = created_uuid(&response);

    let csrf_token = app.generate_csrf_token();
    let before_approval = chrono::Utc::now();
    let approve = app
        .server
        .post(&format!("/sessions/approvals/{session_uuid}/approve"))
        .add_header(
            COOKIE,
            format!(
                "access_token={}; __vauban_csrf={}",
                approver.token, csrf_token
            ),
        )
        .form(&[("csrf_token", csrf_token.as_str())])
        .await;
    let status = approve.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "approve should redirect, got {status}"
    );

    let mut conn = app.get_conn().await;
    let stored = stored_request(&mut conn, session_uuid).await;
    assert_eq!(stored.status, "approved");
    let expires_at = stored
        .expires_at
        .expect("an approved API request must carry an expires_at horizon");
    let horizon = (expires_at - before_approval).num_seconds();
    assert!(
        (890..=910).contains(&horizon),
        "expires_at must sit ~900 s after the approval, got {horizon} s"
    );
}

/// A request without a reviewable justification is refused and leaves
/// no row behind.
#[tokio::test]
#[serial]
async fn api_request_without_justification_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_req14")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset14"), user.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    grant_with_approval(&mut conn, user.user.id, asset_id, Some(1800)).await;
    drop(conn);

    for justification in [
        serde_json::Value::Null,
        json!(""),
        json!("too short"),
        json!("            "),
        json!("<script></script><b></b><i></i>"),
    ] {
        let response = post_session(
            app,
            &user.api_key,
            json!({
                "asset_id": asset_uuid,
                "session_type": "ssh",
                "justification": justification
            }),
        )
        .await;
        assert_eq!(
            response.status_code().as_u16(),
            400,
            "justification {justification:?} must be refused"
        );
    }

    let mut conn = app.get_conn().await;
    assert_eq!(
        pending_count_for(&mut conn, user.user.id).await,
        0,
        "a refused request must not leave a pending row"
    );
}

/// Without any access rule the request is still refused (the rule
/// evaluation was moved, not removed).
#[tokio::test]
#[serial]
async fn api_request_without_access_rule_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_req15")).await;
    let owner = create_admin_user(&mut conn, &app.auth_service, &unique_name("azg_own15")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset15"), owner.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    drop(conn);

    let response = post_session(
        app,
        &user.api_key,
        json!({
            "asset_id": asset_uuid,
            "session_type": "ssh",
            "justification": "Routine maintenance window"
        }),
    )
    .await;
    assert_eq!(response.status_code().as_u16(), 403);

    let mut conn = app.get_conn().await;
    assert_eq!(pending_count_for(&mut conn, user.user.id).await, 0);
}

// =====================================================================
// 3b. Web form: protocol coherence (found by the adversarial review)
// =====================================================================

async fn post_web_request(app: &TestApp, token: &str, asset_uuid: Uuid, session_type: &str) -> u16 {
    let csrf_token = app.generate_csrf_token();
    let asset = asset_uuid.to_string();
    app.server
        .post("/sessions/request")
        .add_header(
            COOKIE,
            format!("access_token={token}; __vauban_csrf={csrf_token}"),
        )
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("asset_uuid", asset.as_str()),
            ("session_type", session_type),
            ("justification", "Routine maintenance window"),
        ])
        .await
        .status_code()
        .as_u16()
}

/// The caller holds a rule covering both `ssh` and `rdp`, and asks for
/// `rdp` (or garbage) on an SSH asset through the web form. Without the
/// guard the request would be stored under a protocol the asset does
/// not speak, carrying the constraints of whichever rule matched it.
#[tokio::test]
#[serial]
async fn attack_web_request_with_mismatched_protocol_is_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let user = create_test_user(&mut conn, &app.auth_service, &unique_name("azg_req16")).await;
    let asset_id =
        create_simple_ssh_asset(&mut conn, &unique_name("azg-asset16"), user.user.id).await;
    let asset_uuid = get_asset_uuid(&mut conn, asset_id).await;
    grant_with_approval(&mut conn, user.user.id, asset_id, Some(900)).await;
    drop(conn);

    for session_type in ["rdp", "iacs_tunnel", "mcp", "telnet", ""] {
        let status = post_web_request(app, &user.token, asset_uuid, session_type).await;
        assert!(
            status == 302 || status == 303,
            "the form answers with a flash redirect, got {status} for {session_type:?}"
        );
        let mut conn = app.get_conn().await;
        assert_eq!(
            pending_count_for(&mut conn, user.user.id).await,
            0,
            "session_type {session_type:?} on an SSH asset must not record a request"
        );
    }

    // Non-regression: the matching protocol is still recorded, bounded.
    let status = post_web_request(app, &user.token, asset_uuid, "ssh").await;
    assert!(status == 302 || status == 303, "got {status}");
    let mut conn = app.get_conn().await;
    assert_eq!(pending_count_for(&mut conn, user.user.id).await, 1);
    let (stored_type, cap): (SessionType, Option<i32>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::user_id.eq(user.user.id))
            .filter(proxy_sessions::status.eq("pending"))
            .select((
                proxy_sessions::session_type,
                proxy_sessions::max_session_duration
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(stored_type, SessionType::Ssh);
    assert_eq!(cap, Some(900));
}
