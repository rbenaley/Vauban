// VAUBAN Web - JIT grant revocation & duration-update E2E tests.
//
// End-to-end coverage of the post-approval verbs (issue: instant
// revocation + adjustable duration of approved JIT grants):
//
//   * revoke  -> grant flips to `revoked`, connect lookups are blocked,
//                live sessions of the (user, asset) couple are
//                cascade-terminated, an append-only audit row lands.
//   * extend  -> `expires_at = approved_at + D` recomputed forward,
//                reconnects keep working.
//   * reduce  -> grant horizon shrinks AND live sessions are clamped
//                (never extended).
//   * reduce below the already-elapsed time -> connects are blocked
//                instantly (expires_at in the past).
//   * fences  -> non-admin denied, CSRF enforced, pending grant denied.
//   * UI      -> approval_detail exposes revoke/duration controls on
//                approved grants, my_requests shows the revoked badge
//                and no Connect button, approval_list filter knows
//                `revoked`.

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    create_approval_request, create_approved_session, create_simple_admin_user,
    create_simple_ssh_asset, create_simple_user, setup_approval_rule, unique_name,
};
use axum::http::header::COOKIE;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;
use vauban_web::schema::{approval_audit_log, proxy_sessions, users};

type Ts = chrono::DateTime<chrono::Utc>;

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Seed a LIVE proxy session (the row a running SSH/RDP/IACS bridge
/// owns) for the (user, asset) couple, with a controlled status and
/// optional expiry.
async fn seed_live_session(
    conn: &mut AsyncPgConnection,
    user_id: i32,
    asset_id: i32,
    session_type: &str,
    status: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Uuid {
    let session_uuid = Uuid::new_v4();
    let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
    unwrap_ok!(
        diesel::insert_into(proxy_sessions::table)
            .values((
                proxy_sessions::uuid.eq(session_uuid),
                proxy_sessions::user_id.eq(user_id),
                proxy_sessions::asset_id.eq(asset_id),
                proxy_sessions::credential_id.eq("cred-123"),
                proxy_sessions::credential_username.eq("testuser"),
                proxy_sessions::session_type.eq(session_type),
                proxy_sessions::status.eq(status),
                proxy_sessions::client_ip.eq(ip),
                proxy_sessions::is_recorded.eq(false),
                proxy_sessions::metadata.eq(serde_json::json!({})),
                proxy_sessions::connected_at.eq(Some(chrono::Utc::now())),
                proxy_sessions::expires_at.eq(expires_at),
            ))
            .execute(conn)
            .await
    );
    session_uuid
}

/// The exact lookup every connect path (SSH page, RDP page, assets
/// Connect button) runs: an unexpired APPROVED grant for the couple.
async fn connect_lookup(conn: &mut AsyncPgConnection, user_id: i32, asset_id: i32) -> Option<Uuid> {
    let now = chrono::Utc::now();
    proxy_sessions::table
        .filter(proxy_sessions::user_id.eq(user_id))
        .filter(proxy_sessions::asset_id.eq(asset_id))
        .filter(proxy_sessions::status.eq("approved"))
        .filter(
            proxy_sessions::expires_at
                .is_null()
                .or(proxy_sessions::expires_at.gt(now)),
        )
        .select(proxy_sessions::uuid)
        .first(conn)
        .await
        .ok()
}

async fn expiry_of(
    conn: &mut AsyncPgConnection,
    session_uuid: Uuid,
) -> Option<chrono::DateTime<chrono::Utc>> {
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::expires_at)
            .first(conn)
            .await
    )
}

async fn session_status(conn: &mut AsyncPgConnection, session_uuid: Uuid) -> String {
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(conn)
            .await
    )
}

fn admin_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={}; __vauban_csrf={}", token, csrf)
}

// =====================================================================
// Revocation
// =====================================================================

/// Full revoke flow: approved grant + live SSH and RDP sessions ->
/// POST revoke -> grant revoked (with actor + timestamp), connect
/// lookup blocked, both live sessions terminated, audit row written.
#[tokio::test]
async fn e2e_revoke_blocks_new_sessions_and_terminates_live() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rvk_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_name = unique_name("rvk_usr");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let asset_name = unique_name("rvk_ast");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;

    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;
    let live_ssh = seed_live_session(&mut conn, user_id, asset_id, "ssh", "active", None).await;
    let live_rdp = seed_live_session(&mut conn, user_id, asset_id, "rdp", "connecting", None).await;

    assert!(
        connect_lookup(&mut conn, user_id, asset_id).await.is_some(),
        "sanity: connect lookup must succeed before revocation"
    );

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("reason", "contractor engagement ended"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "revoke should redirect, got {status}"
    );

    // Grant: terminal `revoked` state with actor + timestamp.
    let (grant_status, revoked_by, revoked_at, reason): (
        String,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    ) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::revoked_by_id,
                proxy_sessions::revoked_at,
                proxy_sessions::decision_reason,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(grant_status, "revoked");
    assert_eq!(revoked_by, Some(admin_id), "revoker must be recorded");
    assert!(revoked_at.is_some(), "revoked_at must be stamped");
    assert_eq!(reason.as_deref(), Some("contractor engagement ended"));

    // Layer 1: connect lookup blocked instantly.
    assert!(
        connect_lookup(&mut conn, user_id, asset_id).await.is_none(),
        "connect lookup must find nothing after revocation"
    );

    // Layer 2: the cascade terminated every live session of the couple.
    assert_eq!(
        session_status(&mut conn, live_ssh).await,
        "terminated",
        "live SSH session must be cascade-terminated"
    );
    assert_eq!(
        session_status(&mut conn, live_rdp).await,
        "terminated",
        "live RDP session must be cascade-terminated"
    );

    // Audit: an append-only `revoke` row landed.
    let audit_count: i64 = unwrap_ok!(
        approval_audit_log::table
            .filter(approval_audit_log::session_uuid.eq(grant_uuid))
            .filter(approval_audit_log::decision.eq("revoke"))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(audit_count, 1, "revoke must write exactly one audit row");
}

/// A revoked grant is terminal: a second revoke is denied and the
/// original actor/timestamp are untouched.
#[tokio::test]
async fn e2e_revoke_is_terminal_second_revoke_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rv2_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_name = unique_name("rv2_usr");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rv2_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;

    let csrf = app.generate_csrf_token();
    let first = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(first.status_code().as_u16(), 302 | 303));
    let revoked_at_1: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::revoked_at)
            .first(&mut conn)
            .await
    );

    let csrf2 = app.generate_csrf_token();
    let second = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf2))
        .form(&[("csrf_token", csrf2.as_str())])
        .await;
    // The IPC denies with SessionNotApproved; the handler surfaces a
    // flash redirect (not a 5xx).
    let status = second.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "second revoke must flash-redirect, got {status}"
    );

    let (grant_status, revoked_at_2): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select((proxy_sessions::status, proxy_sessions::revoked_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(grant_status, "revoked");
    assert_eq!(
        revoked_at_1, revoked_at_2,
        "second revoke must not overwrite the original revocation stamp"
    );
    let audit_count: i64 = unwrap_ok!(
        approval_audit_log::table
            .filter(approval_audit_log::session_uuid.eq(grant_uuid))
            .filter(approval_audit_log::decision.eq("revoke"))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(
        audit_count, 1,
        "denied second revoke must not add audit rows"
    );
}

/// Revoking a PENDING request is denied (`SessionNotApproved`): the
/// pending path already has reject.
#[tokio::test]
async fn e2e_revoke_pending_request_denied() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("rvp_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("rvp_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("rvp_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let pending_uuid = create_approval_request(&mut conn, user_id, asset_id).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", pending_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));
    assert_eq!(
        session_status(&mut conn, pending_uuid).await,
        "pending",
        "pending request must stay pending after a revoke attempt"
    );
}

// =====================================================================
// Duration updates
// =====================================================================

/// Extend: `expires_at` moves to `approved_at + D`, the grant stays
/// approved and reconnects keep working.
#[tokio::test]
async fn e2e_extend_duration_moves_expiry_and_keeps_connects_working() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("ext_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("ext_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("ext_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    // 15-minute grant, extended to 2 hours.
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(900)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("duration_value", "2"),
            ("duration_unit", "hours"),
        ])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let (status, approved_at, expires_at, max_dur): (String, Option<Ts>, Option<Ts>, Option<i32>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select((
                proxy_sessions::status,
                proxy_sessions::approved_at,
                proxy_sessions::expires_at,
                proxy_sessions::max_session_duration,
            ))
            .first(&mut conn)
            .await
    );
    assert_eq!(status, "approved", "extension must not change the status");
    assert_eq!(max_dur, Some(7200));
    let expected = unwrap_ok!(approved_at.ok_or("approved_at")) + chrono::Duration::seconds(7200);
    let drift = (unwrap_ok!(expires_at.ok_or("expires_at")) - expected)
        .num_seconds()
        .abs();
    assert!(
        drift < 2,
        "expires_at must be approved_at + 7200s, drift {drift}s"
    );

    assert!(
        connect_lookup(&mut conn, user_id, asset_id).await.is_some(),
        "connects must keep working after an extension"
    );

    let audit_override: Option<i32> = unwrap_ok!(
        approval_audit_log::table
            .filter(approval_audit_log::session_uuid.eq(grant_uuid))
            .filter(approval_audit_log::decision.eq("update_duration"))
            .select(approval_audit_log::duration_override_seconds)
            .first(&mut conn)
            .await
    );
    assert_eq!(
        audit_override,
        Some(7200),
        "audit row must carry the new duration"
    );
}

/// Reduce: the grant horizon shrinks AND live sessions are clamped to
/// the new horizon; a session already expiring EARLIER is left alone.
#[tokio::test]
async fn e2e_reduce_duration_clamps_grant_and_live_sessions() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("red_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("red_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("red_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    // 4-hour grant reduced to 30 minutes.
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(14400)).await;

    let now = chrono::Utc::now();
    // Live session expiring at the ORIGINAL horizon (4 h): must clamp.
    let live_late = seed_live_session(
        &mut conn,
        user_id,
        asset_id,
        "ssh",
        "active",
        Some(now + chrono::Duration::hours(4)),
    )
    .await;
    // Live session without any horizon (NULL): must clamp too.
    let live_null = seed_live_session(&mut conn, user_id, asset_id, "ssh", "active", None).await;
    // Live session already expiring in 5 min: must be LEFT ALONE
    // (clamping never extends).
    let early_expiry = now + chrono::Duration::minutes(5);
    let live_early = seed_live_session(
        &mut conn,
        user_id,
        asset_id,
        "rdp",
        "active",
        Some(early_expiry),
    )
    .await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("duration_value", "30"),
            ("duration_unit", "minutes"),
        ])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let new_horizon: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::expires_at)
            .first(&mut conn)
            .await
    );
    let new_horizon = unwrap_ok!(new_horizon.ok_or("grant must keep an expiry"));
    assert!(
        new_horizon < now + chrono::Duration::minutes(31),
        "grant horizon must have shrunk to ~30 min"
    );

    assert_eq!(
        expiry_of(&mut conn, live_late).await,
        Some(new_horizon),
        "live session with a LATER horizon must be clamped"
    );
    assert_eq!(
        expiry_of(&mut conn, live_null).await,
        Some(new_horizon),
        "live session with NULL horizon must be clamped"
    );
    let early = unwrap_ok!(expiry_of(&mut conn, live_early).await.ok_or("early expiry"));
    assert!(
        (early - early_expiry).num_seconds().abs() < 2,
        "live session already expiring earlier must NOT be touched"
    );

    // Live sessions stay live: the clamp reduces the horizon, it does
    // not terminate anything.
    assert_eq!(session_status(&mut conn, live_late).await, "active");
    assert_eq!(session_status(&mut conn, live_null).await, "active");
}

/// Reduce below the already-elapsed time: `expires_at` lands in the
/// past and connects are blocked instantly, while the grant stays in
/// `approved` status (the cleanup task will expire it).
#[tokio::test]
async fn e2e_reduce_below_elapsed_blocks_connects_instantly() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("shr_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("shr_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("shr_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(14400)).await;

    // Backdate the approval by 2 hours so a 1-minute window is already
    // fully consumed.
    let backdated = chrono::Utc::now() - chrono::Duration::hours(2);
    unwrap_ok!(
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(grant_uuid)))
            .set(proxy_sessions::approved_at.eq(Some(backdated)))
            .execute(&mut conn)
            .await
    );
    assert!(
        connect_lookup(&mut conn, user_id, asset_id).await.is_some(),
        "sanity: grant must be connectable before the reduction"
    );

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("duration_value", "1"),
            ("duration_unit", "minutes"),
        ])
        .await;
    assert!(matches!(response.status_code().as_u16(), 302 | 303));

    let (status, expires_at): (String, Option<chrono::DateTime<chrono::Utc>>) = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select((proxy_sessions::status, proxy_sessions::expires_at))
            .first(&mut conn)
            .await
    );
    assert_eq!(status, "approved", "shrink-below-elapsed keeps the status");
    assert!(
        unwrap_ok!(expires_at.ok_or("expires_at")) < chrono::Utc::now(),
        "expires_at must land in the past"
    );
    assert!(
        connect_lookup(&mut conn, user_id, asset_id).await.is_none(),
        "connects must be blocked instantly after the reduction"
    );
}

/// The duration form is mandatory: omitting it flash-redirects with an
/// error and leaves the grant untouched.
#[tokio::test]
async fn e2e_duration_update_without_duration_rejected() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("nod_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("nod_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("nod_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;
    let before: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::expires_at)
            .first(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "missing duration must flash-redirect"
    );

    let after: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::expires_at)
            .first(&mut conn)
            .await
    );
    assert_eq!(before, after, "grant expiry must be untouched");
}

// =====================================================================
// Fences: permissions + CSRF
// =====================================================================

#[tokio::test]
async fn e2e_revoke_denied_for_non_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("prm_adm")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("prm_usr")).await;
    let outsider_name = unique_name("prm_out");
    let outsider_id = create_simple_user(&mut conn, &outsider_name).await;
    let outsider_uuid = get_user_uuid(&mut conn, outsider_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("prm_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&outsider_uuid.to_string(), &outsider_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "non-admin revoke must be denied, got {status}"
    );
    assert_eq!(
        session_status(&mut conn, grant_uuid).await,
        "approved",
        "grant must stay approved after a denied revoke"
    );
}

#[tokio::test]
async fn e2e_duration_update_denied_for_non_admin() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("prd_adm")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("prd_usr")).await;
    let outsider_name = unique_name("prd_out");
    let outsider_id = create_simple_user(&mut conn, &outsider_name).await;
    let outsider_uuid = get_user_uuid(&mut conn, outsider_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("prd_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;
    let before: Option<i32> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::max_session_duration)
            .first(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&outsider_uuid.to_string(), &outsider_name, false, false)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("duration_value", "8"),
            ("duration_unit", "hours"),
        ])
        .await;
    let status = response.status_code().as_u16();
    assert!(
        status == 403 || status == 303,
        "non-admin duration update must be denied, got {status}"
    );
    let after: Option<i32> = unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(grant_uuid))
            .select(proxy_sessions::max_session_duration)
            .first(&mut conn)
            .await
    );
    assert_eq!(before, after, "duration must be untouched");
}

#[tokio::test]
async fn e2e_revoke_rejects_invalid_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("csr_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("csr_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("csr_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", "forged-token")])
        .await;
    assert_status(&response, 400);
    assert_eq!(
        session_status(&mut conn, grant_uuid).await,
        "approved",
        "grant must stay approved after a CSRF-rejected revoke"
    );
}

#[tokio::test]
async fn e2e_duration_update_rejects_invalid_csrf() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("csd_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("csd_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("csd_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let response = app
        .server
        .post(&format!("/sessions/approvals/{}/duration", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[
            ("csrf_token", "forged-token"),
            ("duration_value", "2"),
            ("duration_unit", "hours"),
        ])
        .await;
    assert_status(&response, 400);
}

// =====================================================================
// UI surfaces
// =====================================================================

/// The detail page of an APPROVED grant (viewed by an admin who is not
/// the requester) exposes both the revoke and the duration controls.
#[tokio::test]
async fn e2e_approval_detail_shows_revoke_and_duration_controls() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("uid_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("uid_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("uid_ast"), admin_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get(&format!("/sessions/approvals/{}", grant_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains(&format!("/sessions/approvals/{}/revoke", grant_uuid)),
        "approved detail must expose the revoke form"
    );
    assert!(
        body.contains(&format!("/sessions/approvals/{}/duration", grant_uuid)),
        "approved detail must expose the duration form"
    );
}

/// After revocation the detail page shows the read-only banner, the
/// revoker identity, and no revoke/duration controls.
#[tokio::test]
async fn e2e_approval_detail_revoked_read_only() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("uir_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("uir_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("uir_ast"), admin_id).await;
    setup_approval_rule(&mut conn, user_id, asset_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let csrf = app.generate_csrf_token();
    let revoke = app
        .server
        .post(&format!("/sessions/approvals/{}/revoke", grant_uuid))
        .add_header(COOKIE, admin_cookie(&token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert!(matches!(revoke.status_code().as_u16(), 302 | 303));

    let response = app
        .server
        .get(&format!("/sessions/approvals/{}", grant_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("This grant has been revoked"),
        "revoked detail must show the revocation banner"
    );
    assert!(
        body.contains("Revoked by") && body.contains(&admin_name),
        "revoked detail must show the revoker"
    );
    assert!(
        !body.contains(&format!("/sessions/approvals/{}/revoke", grant_uuid)),
        "revoked detail must not re-expose the revoke form"
    );
    assert!(
        !body.contains(&format!("/sessions/approvals/{}/duration", grant_uuid)),
        "revoked detail must not expose the duration form"
    );
}

/// My-requests shows the `Revoked` badge and hides the Connect button
/// for a revoked grant.
#[tokio::test]
async fn e2e_my_requests_revoked_badge_no_connect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("mrq_adm")).await;
    let user_name = unique_name("mrq_usr");
    let user_id = create_simple_user(&mut conn, &user_name).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("mrq_ast"), admin_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;

    // Flip to revoked directly (the HTTP path is covered above).
    unwrap_ok!(
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(grant_uuid)))
            .set((
                proxy_sessions::status.eq("revoked"),
                proxy_sessions::revoked_by_id.eq(Some(admin_id)),
                proxy_sessions::revoked_at.eq(Some(chrono::Utc::now())),
            ))
            .execute(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&user_uuid.to_string(), &user_name, false, false)
        .await;
    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("Revoked"),
        "my-requests must show the Revoked badge"
    );
    assert!(
        !body.contains(&format!("/assets/{}", grant_uuid)),
        "my-requests must not offer a Connect link for a revoked grant"
    );
}

/// The approval list accepts `status=revoked` as a filter and lists
/// the revoked grant with its badge.
#[tokio::test]
async fn e2e_approval_list_filters_revoked() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("lst_adm");
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let user_id = create_simple_user(&mut conn, &unique_name("lst_usr")).await;
    let asset_name = unique_name("lst_ast");
    let asset_id = create_simple_ssh_asset(&mut conn, &asset_name, admin_id).await;
    let grant_uuid = create_approved_session(&mut conn, user_id, asset_id, Some(3600)).await;
    unwrap_ok!(
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(grant_uuid)))
            .set((
                proxy_sessions::status.eq("revoked"),
                proxy_sessions::revoked_by_id.eq(Some(admin_id)),
                proxy_sessions::revoked_at.eq(Some(chrono::Utc::now())),
            ))
            .execute(&mut conn)
            .await
    );

    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    let response = app
        .server
        .get("/sessions/approvals?status=revoked")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains(&asset_name),
        "revoked filter must list the revoked grant"
    );
    assert!(
        body.contains("Revoked"),
        "list must render the Revoked badge"
    );
}

// =====================================================================
// Drift pins
// =====================================================================

/// `is_proxy_session_live` (the WS backstop probe) under every state:
/// live for connecting/active before expiry, dead for terminated /
/// revoked-then-terminated / expired horizons.
#[tokio::test]
async fn e2e_probe_is_proxy_session_live_state_matrix() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_id = create_simple_admin_user(&mut conn, &unique_name("prb_adm")).await;
    let user_id = create_simple_user(&mut conn, &unique_name("prb_usr")).await;
    let asset_id = create_simple_ssh_asset(&mut conn, &unique_name("prb_ast"), admin_id).await;

    let now = chrono::Utc::now();
    let cases: [(&str, Option<chrono::DateTime<chrono::Utc>>, bool); 6] = [
        ("connecting", None, true),
        ("active", None, true),
        ("active", Some(now + chrono::Duration::hours(1)), true),
        ("active", Some(now - chrono::Duration::minutes(1)), false),
        ("terminated", None, false),
        ("disconnected", None, false),
    ];
    for (status, expires_at, expected) in cases {
        let session_uuid =
            seed_live_session(&mut conn, user_id, asset_id, "ssh", status, expires_at).await;
        let live = vauban_web::services::session_activity::is_proxy_session_live(
            &app.app_state,
            &session_uuid.to_string(),
        )
        .await;
        assert_eq!(
            live, expected,
            "probe mismatch for status={status} expires_at={expires_at:?}"
        );
    }

    // Malformed uuid: fail-closed (not live).
    assert!(
        !vauban_web::services::session_activity::is_proxy_session_live(
            &app.app_state,
            "not-a-uuid"
        )
        .await,
        "malformed session id must not be considered live"
    );

    // Unknown uuid: not live.
    assert!(
        !vauban_web::services::session_activity::is_proxy_session_live(
            &app.app_state,
            &Uuid::new_v4().to_string()
        )
        .await,
        "unknown session must not be considered live"
    );
}

/// Drift pin: `APPROVAL_STATUSES` (list filter) and the status badge
/// classifier both know `revoked`; a grant in `revoked` status renders
/// with the red badge everywhere.
#[tokio::test]
async fn e2e_revoked_status_is_wired_in_ui_helpers() {
    // Badge classifier.
    let class = vauban_web::templates::sessions::session_status_class("revoked");
    assert!(
        class.contains("red"),
        "revoked badge must use the red scheme, got {class}"
    );
    // The approval list page itself proves APPROVAL_STATUSES contains
    // `revoked` (covered by e2e_approval_list_filters_revoked); here we
    // additionally pin the label used by my_requests.
    let item = vauban_web::templates::sessions::my_requests::MyRequestItem {
        uuid: "u".into(),
        asset_name: "a".into(),
        asset_hostname: "h".into(),
        asset_type: "linux".into(),
        session_type: "ssh".into(),
        status: "revoked".into(),
        justification: None,
        created_at: "now".into(),
        approved_at: None,
        approved_by: None,
        max_session_duration: None,
    };
    assert_eq!(item.status_label(), "Revoked");
    assert!(!item.is_approved(), "revoked grant must not be connectable");
}
