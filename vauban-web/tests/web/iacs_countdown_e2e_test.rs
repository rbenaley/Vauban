//! E2E -- IACS `waiting_client` countdown on the tunnel status page.
//!
//! Pins the countdown contract end-to-end through the real HTTP
//! surface:
//!
//! 1. Right after `POST /assets/{uuid}/connect-iacs`, the status
//!    page seeds the Alpine component with (approximately) the full
//!    `waiting_client_ttl_seconds` window and renders the countdown
//!    slot plus its server-side initial label.
//! 2. The countdown is anchored on `proxy_sessions.created_at` (the
//!    revocation watchdog's reference), NOT on the page-load
//!    instant: refreshing the page against a backdated row resumes
//!    the true remaining window.
//! 3. A row past the deadline renders a zero seed -- and the
//!    revocation watchdog agrees: the very same row is the one it
//!    flips to `expired` on the next tick (lock-step pin between
//!    the UX hint and the enforcement layer).
//! 4. Non-`waiting_client` rows (e.g. `tunnel_active`) render NO
//!    countdown slot and seed the `-1` sentinel so the client never
//!    starts the timer.

use axum::http::header::COOKIE;
use diesel::ExpressionMethods;
use diesel::QueryDsl;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vauban_web::config::IacsTunnelConfig;
use vauban_web::models::asset::AssetType;
use vauban_web::services::iacs_tunnel::{format_countdown_label, watchdog_run_once};

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{
    add_user_to_vauban_group, create_simple_admin_user, create_simple_user,
    create_test_access_rule, create_test_asset_group, create_test_asset_in_group_with_type,
    create_test_vauban_group, unique_name,
};

// ===================================================================
// Helpers
// ===================================================================

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

async fn get_asset_uuid(conn: &mut AsyncPgConnection, asset_id: i32) -> Uuid {
    use vauban_web::schema::assets;
    unwrap_ok!(
        assets::table
            .filter(assets::id.eq(asset_id))
            .select(assets::uuid)
            .first(conn)
            .await
    )
}

/// Active EWS row owned by `user_id` (same shortcut as the connect
/// button suite; the submit -> approve UI flow is covered by
/// `iacs_test`).
async fn seed_active_ews(conn: &mut AsyncPgConnection, user_id: i32, label: &str) {
    use chrono::Utc;
    let key_seed = Sha256::digest(format!("{}-{}", label, Uuid::new_v4()).as_bytes());
    let fp_hex = hex::encode(key_seed);
    let request_uuid = Uuid::new_v4();
    let ews_uuid = Uuid::new_v4();
    let now = Utc::now();

    diesel::sql_query(
        "INSERT INTO ews_onboarding_requests \
         (uuid, user_id, name, public_key, public_key_fingerprint, key_algo, \
          status, justification, decided_by_id, decided_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'ssh-ed25519 placeholder', $4, 'ed25519', \
                 'approved', 'seed-justification', $2, $5, $5, $5)",
    )
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &request_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews_onboarding_requests");

    diesel::sql_query(
        "INSERT INTO ews \
         (uuid, request_uuid, user_id, name, public_key, public_key_fingerprint, \
          key_algo, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'ssh-ed25519 placeholder', $5, 'ed25519', $6, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Uuid, _>(request_uuid)
    .bind::<diesel::sql_types::Integer, _>(user_id)
    .bind::<diesel::sql_types::Text, _>(format!("ews_{}", &ews_uuid.to_string()[..8]))
    .bind::<diesel::sql_types::Text, _>(&fp_hex)
    .bind::<diesel::sql_types::Timestamptz, _>(now)
    .execute(conn)
    .await
    .expect("insert seed ews");
}

/// IACS asset + access chain (user group + asset group + rule with
/// the applicative IACS protocol).
async fn seed_iacs_asset_with_access(
    conn: &mut AsyncPgConnection,
    admin_id: i32,
    user_id: i32,
    label: &str,
) -> Uuid {
    let suffix = unique_name(label);
    let asset_group_uuid = create_test_asset_group(conn, &format!("{}-ag", suffix)).await;
    let user_group_uuid = create_test_vauban_group(conn, &format!("{}-ug", suffix)).await;
    add_user_to_vauban_group(conn, user_id, &user_group_uuid).await;

    let asset_id = create_test_asset_in_group_with_type(
        conn,
        &format!("{}-asset", suffix),
        admin_id,
        &asset_group_uuid,
        AssetType::IacsModbus,
    )
    .await;

    let _ = create_test_access_rule(
        conn,
        &user_group_uuid,
        &asset_group_uuid,
        &[AssetType::IacsModbus.as_str()],
    )
    .await;

    get_asset_uuid(conn, asset_id).await
}

/// Full connect flow: seed user/asset/EWS, POST connect-iacs, return
/// `(session_uuid, access_token)` for follow-up status-page GETs.
async fn open_waiting_session(app: &TestApp, label: &str) -> (Uuid, String) {
    let mut conn = app.get_conn().await;
    let admin_id = create_simple_admin_user(&mut conn, &unique_name(&format!("{label}_adm"))).await;
    let username = unique_name(&format!("{label}_usr"));
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let asset_uuid = seed_iacs_asset_with_access(&mut conn, admin_id, user_id, label).await;
    seed_active_ews(&mut conn, user_id, label).await;
    drop(conn);

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/{}/connect-iacs", asset_uuid))
        .add_header(
            COOKIE,
            format!("access_token={}; __vauban_csrf={}", token, csrf),
        )
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .expect("connect-iacs must set Location");
    let session_uuid: Uuid = location
        .strip_prefix("/sessions/")
        .and_then(|tail| tail.split('/').next())
        .expect("Location format /sessions/{uuid}/iacs/status")
        .parse()
        .expect("session uuid parses");

    (session_uuid, token)
}

async fn get_status_page(app: &TestApp, session_uuid: Uuid, token: &str) -> String {
    let resp = app
        .server
        .get(&format!("/sessions/{}/iacs/status", session_uuid))
        .add_header(COOKIE, format!("access_token={}", token))
        .await;
    assert_status(&resp, 200);
    resp.text()
}

/// Extract the numeric `remainingSeconds:` Alpine seed from the
/// rendered page.
fn extract_seed(body: &str) -> i64 {
    let idx = body
        .find("remainingSeconds: ")
        .expect("page must carry the remainingSeconds Alpine seed");
    let tail = &body[idx + "remainingSeconds: ".len()..];
    let end = tail
        .find([',', '\n'])
        .expect("seed must be comma/newline terminated");
    tail[..end]
        .trim()
        .parse()
        .expect("remainingSeconds seed must be an integer")
}

async fn backdate_session(app: &TestApp, session_uuid: Uuid, seconds: i64) {
    let mut conn = app.get_conn().await;
    diesel::sql_query(
        "UPDATE proxy_sessions \
         SET created_at = NOW() - make_interval(secs => $1) \
         WHERE uuid = $2",
    )
    .bind::<diesel::sql_types::Double, _>(seconds as f64)
    .bind::<diesel::sql_types::Uuid, _>(session_uuid)
    .execute(&mut conn)
    .await
    .expect("backdate proxy_sessions.created_at");
}

async fn session_status(app: &TestApp, session_uuid: Uuid) -> String {
    use vauban_web::schema::proxy_sessions;
    let mut conn = app.get_conn().await;
    unwrap_ok!(
        proxy_sessions::table
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select(proxy_sessions::status)
            .first(&mut conn)
            .await
    )
}

/// The `[industrial.iacs_tunnel]` block from `config/testing.toml`
/// pins the TTL every assertion below is calibrated against.
const TESTING_TTL_SECONDS: i64 = 300;

fn watchdog_cfg() -> IacsTunnelConfig {
    IacsTunnelConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        advertise_hostname: "127.0.0.1".to_string(),
        host_key_path: "/tmp/never_used_countdown".to_string(),
        max_concurrent_per_user: 0,
        max_concurrent_per_ews: 0,
        max_concurrent_channels_per_session: 16,
        waiting_client_ttl_seconds: TESTING_TTL_SECONDS as u32,
        revocation_poll_interval_seconds: 2,
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn countdown_seeds_full_ttl_right_after_connect() {
    let app = TestApp::spawn().await;
    let (session_uuid, token) = open_waiting_session(app, "cd_full").await;

    let body = get_status_page(app, session_uuid, &token).await;

    assert!(
        body.contains("data-testid=\"iacs-tunnel-countdown\""),
        "waiting_client page must render the countdown slot"
    );
    let seed = extract_seed(&body);
    assert!(
        (TESTING_TTL_SECONDS - 5..=TESTING_TTL_SECONDS).contains(&seed),
        "seed right after connect must be ~ the full TTL window \
         ({TESTING_TTL_SECONDS}s from config/testing.toml), got {seed}"
    );
    // The server-side initial label matches the seed (twin of the
    // Alpine formatCountdown; a drift here means the first paint
    // lies until the first client tick).
    assert!(
        body.contains(&format_countdown_label(seed)),
        "initial label must be the server-rendered format of the \
         seed {seed} (expected '{}')",
        format_countdown_label(seed)
    );
}

#[tokio::test]
async fn countdown_resumes_from_created_at_on_refresh() {
    let app = TestApp::spawn().await;
    let (session_uuid, token) = open_waiting_session(app, "cd_resume").await;

    // Simulate an operator coming back to the page 290 s after the
    // Connect click: the countdown must resume at ~10 s, NOT restart
    // at the full TTL.
    backdate_session(app, session_uuid, TESTING_TTL_SECONDS - 10).await;
    let body = get_status_page(app, session_uuid, &token).await;

    let seed = extract_seed(&body);
    assert!(
        (5..=10).contains(&seed),
        "countdown must be anchored on created_at (expected ~10s \
         left after backdating by TTL-10), got {seed}"
    );
}

#[tokio::test]
async fn countdown_is_zero_past_deadline_and_watchdog_reaps_the_same_row() {
    let app = TestApp::spawn().await;
    let (session_uuid, token) = open_waiting_session(app, "cd_zero").await;

    // Way past the deadline. The page must clamp at zero (never
    // negative) and still render 200 for forensic display.
    backdate_session(app, session_uuid, TESTING_TTL_SECONDS + 700).await;
    let body = get_status_page(app, session_uuid, &token).await;
    assert_eq!(
        extract_seed(&body),
        0,
        "a row past the waiting_client deadline must seed a zero countdown"
    );

    // Lock-step with the enforcement layer: the SAME row is reaped
    // by the revocation watchdog on its next tick.
    let (_closed, transitions) = watchdog_run_once(&app.db_pool, &watchdog_cfg(), None).await;
    assert!(
        transitions >= 1,
        "watchdog must transition at least the backdated row (got {transitions})"
    );
    assert_eq!(
        session_status(app, session_uuid).await,
        "expired",
        "the zero-countdown row must be the one the watchdog expires"
    );

    // After the DB flip the page renders the expired pill and no
    // countdown at all (status is no longer waiting_client).
    let body_after = get_status_page(app, session_uuid, &token).await;
    assert!(
        !body_after.contains("data-testid=\"iacs-tunnel-countdown\""),
        "an expired session must not render the countdown slot"
    );
    assert!(
        body_after.contains("remainingSeconds: -1"),
        "an expired session must seed the -1 sentinel"
    );
}

#[tokio::test]
async fn countdown_absent_for_tunnel_active_row() {
    let app = TestApp::spawn().await;
    let (session_uuid, token) = open_waiting_session(app, "cd_active").await;

    {
        use vauban_web::schema::proxy_sessions;
        let mut conn = app.get_conn().await;
        diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(session_uuid)))
            .set(proxy_sessions::status.eq("tunnel_active"))
            .execute(&mut conn)
            .await
            .expect("flip to tunnel_active");
    }

    let body = get_status_page(app, session_uuid, &token).await;
    assert!(
        !body.contains("data-testid=\"iacs-tunnel-countdown\""),
        "tunnel_active must not render the countdown slot (the TTL \
         only governs the waiting_client window)"
    );
    assert!(
        body.contains("remainingSeconds: -1"),
        "tunnel_active must seed the -1 sentinel so the Alpine \
         component never starts the countdown timer"
    );
}
