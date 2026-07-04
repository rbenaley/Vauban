//! Tests for the SSH/RDP login-session re-validation that tears down a
//! live WebSocket once the auth token expires (idle timeout /
//! max-duration / reaped row).
//!
//! Layered, no live-socket harness (axum-test cannot drive a real WS, and
//! ssh_proxy/rdp_proxy are None in tests):
//! 1. DB integration of `is_login_session_live` under each expiry mode,
//!    including the access-token-lifetime clamp (an idle session must
//!    die at the same horizon over WS as over HTTP);
//! 2. pure unit tests + shipped-config invariants of
//!    `effective_idle_timeout_secs` (WS horizon never laxer than the
//!    JWT lifetime, and always leaving the activity throttle a wide
//!    safety margin so active users are never cut);
//! 3. structural pins that both WS loops wire the re-validation arm
//!    (close code 4401 + cause auth_expired) and keep the 4 lifecycle
//!    logs intact.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, test_db};
use crate::fixtures::{create_test_user, unique_name};
use vauban_web::config::{Config, Environment};
use vauban_web::schema::auth_sessions;
use vauban_web::services::auth::AuthService;
use vauban_web::services::session_activity::{
    ACTIVITY_REFRESH_MIN_INTERVAL_SECS, effective_idle_timeout_secs, is_login_session_live,
};

const WEBSOCKET_SRC: &str = include_str!("../../src/handlers/websocket.rs");
const SESSION_ACTIVITY_SRC: &str = include_str!("../../src/services/session_activity.rs");
const AUTH_SERVICE_SRC: &str = include_str!("../../src/services/auth.rs");

/// Workspace root config/ directory (same derivation as `TestApp`).
fn config_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("config")
}

/// Testing-environment config (default.toml + testing.toml), the same
/// shape `TestApp` runs with: idle 1800 s, access token 15 min.
fn testing_config() -> Config {
    Config::load_with_environment(config_dir(), Environment::Testing).expect("load testing config")
}

async fn fresh_session(
    auth_service: &AuthService,
    conn: &mut diesel_async::AsyncPgConnection,
    label: &str,
) -> Uuid {
    let username = unique_name(label);
    let test_user = create_test_user(conn, auth_service, &username).await;
    let claims = auth_service
        .verify_token(&test_user.token)
        .expect("valid fixture token");
    Uuid::parse_str(claims.jti.as_ref().expect("fixture jti")).unwrap()
}

/// A freshly-created session is live.
#[tokio::test]
#[serial]
async fn is_live_true_for_fresh_session() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_fresh").await;

    assert!(
        is_login_session_live(&app.app_state, session_uuid).await,
        "a fresh session must be considered live"
    );

    test_db::cleanup(&mut conn).await;
}

/// A session idle past `session_idle_timeout_secs` (30 min default) is dead.
#[tokio::test]
#[serial]
async fn is_live_false_when_idle_past_timeout() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_idle").await;

    // 2h ago >> 30 min default idle timeout; created_at stays recent so
    // only the idle predicate trips.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(Utc::now() - Duration::hours(2)))
        .execute(&mut conn)
        .await
        .expect("seed idle last_activity");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "an idle session must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// A session older than `session_max_duration_secs` (8h default) is dead,
/// even with recent activity.
#[tokio::test]
#[serial]
async fn is_live_false_when_past_max_duration() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_maxdur").await;

    // created 9h ago (> 8h max-duration), but active right now so only the
    // max-duration predicate trips.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set((
            auth_sessions::created_at.eq(Utc::now() - Duration::hours(9)),
            auth_sessions::last_activity.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("seed old created_at");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "a session past max-duration must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// A reaped (deleted) session row is dead.
#[tokio::test]
#[serial]
async fn is_live_false_when_row_reaped() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_reaped").await;

    diesel::delete(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .execute(&mut conn)
        .await
        .expect("delete session row");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "a reaped session must be considered dead"
    );

    test_db::cleanup(&mut conn).await;
}

/// THE regression test for the idle-tab bug: a session whose
/// `last_activity` is past the ACCESS-TOKEN lifetime (15 min) but still
/// within the configured idle timeout (30 min in default/testing) must
/// be dead for the WS probe too. Before the clamp, this row was
/// (wrongly) considered live and an idle SSH/RDP tab survived up to 15
/// extra minutes after every HTTP request had started bouncing to
/// /login.
#[tokio::test]
#[serial]
async fn is_live_false_when_idle_past_token_lifetime() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_clamp").await;

    // Sanity: this test only means something if the configured idle
    // timeout is laxer than the token lifetime (the bug's precondition).
    let idle = app.app_state.config.security.session_idle_timeout_secs;
    let token_secs = app.app_state.config.jwt.access_token_lifetime_minutes * 60;
    assert!(
        idle > token_secs,
        "testing config must keep idle ({idle}s) > token lifetime ({token_secs}s) \
         so this regression test exercises the clamp"
    );

    // 16 min ago: past the 15-min token lifetime, but NOT past the
    // 30-min configured idle timeout.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(Utc::now() - Duration::minutes(16)))
        .execute(&mut conn)
        .await
        .expect("seed last_activity past token lifetime");

    assert!(
        !is_login_session_live(&app.app_state, session_uuid).await,
        "a session idle past the access-token lifetime must be dead for the WS \
         probe (its JWT is dead for HTTP, the horizons must match)"
    );

    test_db::cleanup(&mut conn).await;
}

/// Non-regression (active user): recent activity keeps the session live.
#[tokio::test]
#[serial]
async fn is_live_true_for_recent_activity_within_all_horizons() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_active").await;

    // 5 min ago: within the clamped horizon (15 min).
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set(auth_sessions::last_activity.eq(Utc::now() - Duration::minutes(5)))
        .execute(&mut conn)
        .await
        .expect("seed recent last_activity");

    assert!(
        is_login_session_live(&app.app_state, session_uuid).await,
        "a recently-active session must stay live"
    );

    test_db::cleanup(&mut conn).await;
}

/// Non-regression (active user): the clamp applies to the INACTIVITY
/// cutoff only, never to `created_at`. A session older than the token
/// lifetime but with fresh activity stays live (its cookie keeps
/// rotating via the front-end heartbeat, its `last_activity` via the
/// throttled WS touches).
#[tokio::test]
#[serial]
async fn is_live_true_when_session_older_than_token_but_recently_active() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let session_uuid = fresh_session(&app.auth_service, &mut conn, "reval_oldactive").await;

    // Created 20 min ago (> 15-min token lifetime, << 8h max-duration),
    // active right now.
    diesel::update(auth_sessions::table.filter(auth_sessions::uuid.eq(session_uuid)))
        .set((
            auth_sessions::created_at.eq(Utc::now() - Duration::minutes(20)),
            auth_sessions::last_activity.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await
        .expect("seed old created_at with fresh activity");

    assert!(
        is_login_session_live(&app.app_state, session_uuid).await,
        "an ACTIVE session older than the token lifetime must stay live \
         (the clamp must never apply to created_at / max-duration)"
    );

    test_db::cleanup(&mut conn).await;
}

// ===================== effective_idle_timeout_secs (pure) =====================

/// The effective WS idle horizon is the min of the configured idle
/// timeout and the access-token lifetime, in both orders and at
/// equality.
#[test]
fn effective_idle_timeout_is_min_of_idle_and_token_lifetime() {
    let mut config = testing_config();

    // idle > token lifetime -> clamped to the token lifetime.
    config.security.session_idle_timeout_secs = 1800;
    config.jwt.access_token_lifetime_minutes = 15;
    assert_eq!(effective_idle_timeout_secs(&config), 900);

    // idle < token lifetime -> the configured idle wins.
    config.security.session_idle_timeout_secs = 600;
    assert_eq!(effective_idle_timeout_secs(&config), 600);

    // Equality (the production shape: 900 s = 15 min).
    config.security.session_idle_timeout_secs = 900;
    assert_eq!(effective_idle_timeout_secs(&config), 900);
}

/// Read `(session_idle_timeout_secs, access_token_lifetime_minutes)`
/// from a layered set of shipped config files, without running the
/// environment-specific validators (mailer/CORS) that a full
/// `Config::load_with_environment` would apply.
fn shipped_timeout_pair(files: &[&str]) -> (u64, u64) {
    let mut builder = config::Config::builder();
    for file in files {
        // Explicit TOML format: `vauban.conf` has no .toml extension, so
        // the config crate cannot infer it (same reason the production
        // loader in src/config.rs goes through File::from_str).
        builder = builder.add_source(
            config::File::from(config_dir().join(file)).format(config::FileFormat::Toml),
        );
    }
    let settings = builder
        .build()
        .unwrap_or_else(|e| panic!("parse shipped config {files:?}: {e}"));
    let idle = settings
        .get_int("security.session_idle_timeout_secs")
        .unwrap_or_else(|e| panic!("{files:?} must define security.session_idle_timeout_secs: {e}"))
        as u64;
    let token_minutes = settings
        .get_int("jwt.access_token_lifetime_minutes")
        .unwrap_or_else(|e| panic!("{files:?} must define jwt.access_token_lifetime_minutes: {e}"))
        as u64;
    (idle, token_minutes)
}

/// Invariant over every shipped configuration (default+testing,
/// default+development, vauban.conf):
/// 1. the effective WS idle horizon never exceeds the access-token
///    lifetime (WS is never laxer than HTTP for an idle user);
/// 2. the horizon keeps at least a 4x safety margin over the activity
///    throttle window, so an ACTIVE user -- whose `last_activity` may
///    lag by up to one throttle interval -- can never be classified
///    idle.
#[test]
fn shipped_configs_keep_ws_horizon_tight_and_active_users_safe() {
    let shipped: [(&str, &[&str]); 3] = [
        ("default+testing", &["default.toml", "testing.toml"]),
        ("default+development", &["default.toml", "development.toml"]),
        ("vauban.conf", &["vauban.conf"]),
    ];

    for (label, files) in shipped {
        let (idle, token_minutes) = shipped_timeout_pair(files);
        let mut config = testing_config();
        config.security.session_idle_timeout_secs = idle;
        config.jwt.access_token_lifetime_minutes = token_minutes;

        let effective = effective_idle_timeout_secs(&config);
        assert!(
            effective <= token_minutes * 60,
            "{label}: effective WS idle horizon ({effective}s) must never exceed \
             the access-token lifetime ({}s)",
            token_minutes * 60
        );
        assert!(
            effective <= idle,
            "{label}: effective WS idle horizon ({effective}s) must never exceed \
             the configured idle timeout ({idle}s)"
        );
        assert!(
            effective >= 4 * ACTIVITY_REFRESH_MIN_INTERVAL_SECS,
            "{label}: effective WS idle horizon ({effective}s) must keep at least \
             a 4x margin over the activity throttle ({ACTIVITY_REFRESH_MIN_INTERVAL_SECS}s), \
             or genuinely active SSH/RDP users could be disconnected"
        );
    }
}

// ============================ structural pins ============================

/// `is_login_session_live` must derive its inactivity cutoff from the
/// clamped helper -- not from the raw `session_idle_timeout_secs` --
/// and the helper must clamp with the access-token lifetime.
#[test]
fn liveness_probe_uses_clamped_idle_horizon() {
    assert!(
        SESSION_ACTIVITY_SRC.contains("effective_idle_timeout_secs(&state.config)"),
        "is_login_session_live must compute idle_cutoff via effective_idle_timeout_secs"
    );
    assert!(
        SESSION_ACTIVITY_SRC.contains(".min(config.jwt.access_token_lifetime_minutes * 60)"),
        "effective_idle_timeout_secs must clamp the idle timeout by the access-token lifetime"
    );
    assert!(
        !SESSION_ACTIVITY_SRC.contains("security.session_idle_timeout_secs as i64"),
        "is_login_session_live must not fall back to the raw (unclamped) idle timeout"
    );
}

/// Parity pin: the HTTP side enforces JWT `exp` (idle users stop
/// rotating their cookie, so their token dies at the lifetime horizon).
/// Combined with `shipped_configs_keep_ws_horizon_tight_and_active_users_safe`
/// (WS horizon <= token lifetime) this guarantees both paths cut an
/// idle user at the same horizon.
#[test]
fn http_path_still_enforces_jwt_expiry() {
    assert!(
        AUTH_SERVICE_SRC.contains("validation.validate_exp = true"),
        "AuthService::verify_token must keep validating the JWT exp claim"
    );
}

/// Both SSH/RDP loops must drive their activity throttle from the
/// shared ACTIVITY_REFRESH_MIN_INTERVAL_SECS constant, so the margin
/// invariant above actually governs the running code.
#[test]
fn ws_loops_use_shared_activity_refresh_interval() {
    let uses = WEBSOCKET_SRC
        .matches("ACTIVITY_REFRESH_MIN_INTERVAL_SECS")
        .count();
    assert!(
        uses >= 2,
        "both the SSH and RDP loops must build their ActivityThrottle from \
         session_activity::ACTIVITY_REFRESH_MIN_INTERVAL_SECS; found {uses}"
    );
}

/// Both WS loops must wire the periodic re-validation arm: query liveness,
/// and on expiry close with code 4401 + cause auth_expired.
#[test]
fn ws_loops_wire_revalidation_arm() {
    assert!(
        WEBSOCKET_SRC.contains("const REVALIDATE_INTERVAL_SECS"),
        "websocket.rs must define REVALIDATE_INTERVAL_SECS"
    );
    let checks = WEBSOCKET_SRC
        .matches("is_login_session_live(&state, auth_session.0)")
        .count();
    assert!(
        checks >= 2,
        "both the SSH and RDP loops must re-validate via is_login_session_live; found {checks}"
    );
    let expiries = WEBSOCKET_SRC
        .matches("close_cause = \"auth_expired\"")
        .count();
    assert!(
        expiries >= 2,
        "both loops must set close_cause = auth_expired on expiry; found {expiries}"
    );
    assert!(
        WEBSOCKET_SRC.contains("code: WS_CLOSE_AUTH_EXPIRED")
            && WEBSOCKET_SRC.contains("const WS_CLOSE_AUTH_EXPIRED: u16 = 4401"),
        "the expiry close must use the dedicated 4401 close code"
    );
}

/// The re-validation additions must not disturb the canonical lifecycle
/// log literals.
#[test]
fn ws_lifecycle_logs_preserved_after_revalidation() {
    for literal in [
        "WebSocket connection requested",
        "WebSocket connected",
        "WebSocket closed",
        "WebSocket disconnected",
    ] {
        assert!(
            WEBSOCKET_SRC.contains(literal),
            "lifecycle log literal `{literal}` must remain present"
        );
    }
}
