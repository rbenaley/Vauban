//! Access Posture (Bastion Watch) -- MFA-enabled counting perimeter.
//!
//! Regression coverage for the operator-reported bug where the
//! "MFA enabled" guardrail on `/` (Access Posture quadrant) reported
//! a population inconsistent with `/users`:
//!
//! - PROD: "6/6" while only 2 users exist -- soft-deleted users were
//!   still counted because the soft-delete handler leaves
//!   `is_active = true` and `load_access_posture` only filtered on
//!   `is_active`, never on `is_deleted`.
//! - INTEGRATION: "10/21" while 24 users exist -- inactive (non-deleted)
//!   users were silently dropped from the denominator.
//!
//! The fix scopes the two MFA counts in
//! `services::dashboard::snapshot::load_access_posture` to
//! `is_deleted = false` AND `is_service_account = false` (active AND
//! inactive), mirroring the convention already used by
//! `services::anomalies::mfa_stale_users`.
//!
//! Two layers, because `TestApp` is a `&'static` singleton over a
//! SHARED, non-reset DB and the count is GLOBAL (unscoped): an
//! absolute count would be polluted by every other test's fixtures.
//!
//! 1. Structural pin (deterministic) -- the query filters cannot drift.
//! 2. E2E delta (robust to pre-existing rows) -- seed one user at a
//!    time and assert how the rendered `mfa_on/total` moves. Serialised
//!    by `--test-threads=1`, so the deltas are exact.

use crate::common::{TestApp, unwrap_ok};
use crate::fixtures::{create_simple_admin_user, unique_name};
use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;
use vauban_web::models::user::{AuthSource, NewUser, User};
use vauban_web::schema::users;

// =====================================================================
// Layer 1 -- structural pin
// =====================================================================

fn snapshot_src() -> &'static str {
    include_str!("../../src/services/dashboard/snapshot.rs")
}

/// The body of `load_access_posture` is bounded by its signature and
/// the first top-level closing brace (a `}` at column 0).
fn load_access_posture_body() -> &'static str {
    let src = snapshot_src();
    let idx = src
        .find("pub(crate) async fn load_access_posture(")
        .expect("load_access_posture must exist in snapshot.rs");
    let end = src[idx..]
        .find("\n}\n")
        .map(|i| idx + i + 3)
        .unwrap_or(src.len());
    &src[idx..end]
}

/// Pin: the MFA posture counts MUST exclude soft-deleted users and
/// service accounts, and MUST NOT re-introduce the `is_active` filter
/// on the user counts (which was the original bug: deleted users stay
/// `is_active = true`, and inactive users were dropped from the
/// denominator).
#[test]
fn load_access_posture_scopes_out_deleted_and_service_accounts() {
    let body = load_access_posture_body();

    let deleted = body.matches("users::is_deleted.eq(false)").count();
    assert!(
        deleted >= 2,
        "load_access_posture MUST filter `users::is_deleted.eq(false)` on \
         BOTH the mfa_on and mfa_off counts (found {deleted}). Soft-deleted \
         users keep `is_active = true` (the delete handler does not reset \
         it), so without this filter they inflate the MFA posture -- the \
         '6/6 while only 2 users' production bug."
    );

    let service = body.matches("users::is_service_account.eq(false)").count();
    assert!(
        service >= 2,
        "load_access_posture MUST filter `users::is_service_account.eq(false)` \
         on BOTH MFA counts (found {service}). Service accounts authenticate \
         via API keys, never MFA, and must not dilute the posture."
    );

    assert!(
        !body.contains("users::is_active.eq(true)"),
        "load_access_posture MUST NOT scope the MFA counts on \
         `users::is_active.eq(true)`. The denominator counts every \
         non-deleted, non-service user (active AND inactive) so it matches \
         the /users total; gating on is_active dropped inactive users from \
         the denominator (the '10/21 while 24 users' integration bug)."
    );
}

// =====================================================================
// Layer 2 -- E2E delta
// =====================================================================

async fn user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Insert a fully-specified user row directly (the fixtures do not
/// expose every flag combination we need here).
async fn insert_user(
    conn: &mut AsyncPgConnection,
    username: &str,
    is_active: bool,
    is_service_account: bool,
    mfa_enabled: bool,
) -> User {
    let new_user = NewUser {
        uuid: Uuid::new_v4(),
        username: username.to_string(),
        email: format!("{}@test.vauban.io", username),
        password_hash: "!test-no-login".to_string(),
        first_name: None,
        last_name: None,
        phone: None,
        is_active,
        is_staff: false,
        is_superuser: false,
        is_service_account,
        mfa_enabled,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .await
    )
}

/// Soft-delete a user the same way the production handler does: set
/// `is_deleted = true` / `deleted_at` WITHOUT touching `is_active`.
async fn soft_delete(conn: &mut AsyncPgConnection, user_id: i32) {
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::is_deleted.eq(true),
                users::deleted_at.eq(chrono::Utc::now()),
            ))
            .execute(conn)
            .await
    );
}

/// Extract `(mfa_on, total)` from the rendered "MFA enabled" bar inside
/// the Access Posture tile (`id="dash-access-posture"`). The template
/// renders the bar label then a `font-mono` span carrying the
/// `mfa_on/total` value label.
fn parse_posture(body: &str) -> (i64, i64) {
    let tile = body
        .find("id=\"dash-access-posture\"")
        .expect("Access Posture tile (id=dash-access-posture) MUST render for a supervisor");
    let region = &body[tile..];
    let label = region
        .find("MFA enabled")
        .expect("Access Posture MUST render the 'MFA enabled' bar");
    let after = &region[label..];
    let fm = after
        .find("font-mono")
        .expect("MFA enabled bar MUST carry a font-mono value label span");
    let after_fm = &after[fm..];
    let gt = after_fm.find('>').expect("value label span open");
    let close = after_fm.find("</span>").expect("value label span close");
    let value = after_fm[gt + 1..close].trim();
    let mut parts = value.split('/');
    let on: i64 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse mfa_on from value label `{value}`"));
    let total: i64 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse total from value label `{value}`"));
    (on, total)
}

async fn read_posture(app: &TestApp, token: &str) -> (i64, i64) {
    let response = app
        .server
        .get("/")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "/ must load with supervisor credentials"
    );
    parse_posture(&response.text())
}

/// E2E: seed users one at a time and assert how the rendered MFA
/// posture (`mfa_on/total`) moves. Deltas are immune to the rows other
/// tests left in the shared singleton DB.
#[tokio::test]
async fn mfa_posture_counts_non_deleted_non_service_users() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_username = unique_name("ap_admin");
    let admin_id = create_simple_admin_user(&mut conn, &admin_username).await;
    let admin_uuid = user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_username, true, true)
        .await;

    // Baseline.
    let (on0, total0) = read_posture(app, &token).await;

    // 1. INACTIVE + MFA-on, non-deleted, non-service. The denominator
    //    counts active AND inactive, so both numerator and denominator
    //    must grow by one (the integration "10/21 vs 24" case).
    insert_user(
        &mut conn,
        &unique_name("ap_inactive_mfa"),
        false, // is_active
        false, // is_service_account
        true,  // mfa_enabled
    )
    .await;
    let (on1, total1) = read_posture(app, &token).await;
    assert_eq!(
        (on1, total1),
        (on0 + 1, total0 + 1),
        "an INACTIVE non-deleted MFA user MUST count in BOTH the numerator \
         and the denominator (active+inactive perimeter)"
    );

    // 2. Soft-deleted + MFA-on. The delete handler leaves is_active=true,
    //    so this is exactly the production inflation case; it MUST NOT
    //    move either count.
    let doomed = insert_user(
        &mut conn,
        &unique_name("ap_deleted_mfa"),
        true, // is_active (stays true through soft-delete, like prod)
        false,
        true,
    )
    .await;
    soft_delete(&mut conn, doomed.id).await;
    let (on2, total2) = read_posture(app, &token).await;
    assert_eq!(
        (on2, total2),
        (on1, total1),
        "a SOFT-DELETED user MUST NOT be counted (this is the '6/6 while \
         only 2 users' production bug: deleted users keep is_active=true)"
    );

    // 3. Service account + MFA-on. Excluded from the posture.
    insert_user(
        &mut conn,
        &unique_name("ap_service_mfa"),
        true,
        true, // is_service_account
        true,
    )
    .await;
    let (on3, total3) = read_posture(app, &token).await;
    assert_eq!(
        (on3, total3),
        (on2, total2),
        "a SERVICE ACCOUNT MUST NOT be counted in the MFA posture"
    );
}
