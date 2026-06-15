//! VAU-012 - Integration tests for session-creation rate limits and
//! concurrency quotas.
//!
//! These drive the real production code path
//! ([`vauban_web::services::session_limits::enforce_session_creation`]) against
//! the test Postgres database. The handlers (`connect_ssh`, `connect_rdp`,
//! `connect_iacs`) all funnel through this single seam right before the
//! `proxy_sessions` INSERT (pinned structurally by
//! `session_creation_limits_invariants_test`), so exercising the seam with
//! seeded rows covers all three protocols deterministically without standing
//! up SSH/RDP/IACS proxy backends.
//!
//! Each test uses its OWN fresh in-memory rate limiter and tailored thresholds
//! so neither the shared `TestApp` singleton nor sibling tests can pollute the
//! `session:global` / `session:user:*` buckets.

use std::net::IpAddr;

use vauban_web::AppState;
use vauban_web::services::rate_limit::RateLimiter;
use vauban_web::services::session_limits::{
    count_live_for_asset, count_live_for_user, enforce_session_creation,
};

use crate::common::TestApp;
use crate::fixtures::{
    create_iacs_test_session_with_uuid, create_test_asset_group, create_test_asset_in_group,
    create_test_session, create_test_user, unique_name,
};

/// Build an `AppState` with a fresh, isolated rate limiter and the given
/// VAU-012 thresholds. Everything else is inherited from the shared TestApp.
fn limited_state(
    app: &TestApp,
    per_user_rate: u32,
    global_rate: u32,
    per_user_conc: i64,
    per_asset_conc: i64,
) -> AppState {
    let mut state = app.app_state.clone();
    state.rate_limiter = RateLimiter::in_memory();
    state.config.security.session_create_rate_per_minute = per_user_rate;
    state.config.security.session_create_rate_global_per_minute = global_rate;
    state.config.security.max_concurrent_sessions_per_user = per_user_conc;
    state.config.security.max_concurrent_sessions_per_asset = per_asset_conc;
    state
}

fn ip() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// Create a fresh (user_id, asset_id) pair backed by real DB rows.
async fn fresh_user_and_asset(app: &TestApp, tag: &str) -> (i32, i32) {
    let mut conn = app.get_conn().await;
    let user = create_test_user(&mut conn, &app.auth_service, &unique_name(tag)).await;
    let group_uuid = create_test_asset_group(&mut conn, &unique_name(&format!("{tag}-grp"))).await;
    let asset_id =
        create_test_asset_in_group(&mut conn, &unique_name(tag), user.user.id, &group_uuid).await;
    (user.user.id, asset_id)
}

// ==================== Per-user rate limit ====================

#[tokio::test]
async fn per_user_rate_limit_denies_after_threshold() {
    let app = TestApp::spawn().await;
    let (user_id, asset_id) = fresh_user_and_asset(app, "vau012_user_rate").await;
    // Only the per-user rate control is active (2/min); everything else off.
    let state = limited_state(app, 2, 0, 0, 0);
    let mut conn = app.get_conn().await;

    for i in 1..=2 {
        let res = enforce_session_creation(&state, &mut conn, user_id, asset_id, ip())
            .await
            .expect("DB ok");
        assert!(
            res.is_ok(),
            "request {i} within the per-user limit must pass"
        );
    }
    let denied = enforce_session_creation(&state, &mut conn, user_id, asset_id, ip())
        .await
        .expect("DB ok");
    assert!(
        denied.is_err(),
        "the 3rd request must be denied by the per-user rate limit"
    );
}

// ==================== Global rate limit ====================

#[tokio::test]
async fn global_rate_limit_denies_across_users() {
    let app = TestApp::spawn().await;
    let (user_a, asset_a) = fresh_user_and_asset(app, "vau012_glob_a").await;
    let (user_b, asset_b) = fresh_user_and_asset(app, "vau012_glob_b").await;
    // Only the global control is active (2/min); per-user rate is off so the
    // denial can only come from the shared global bucket.
    let state = limited_state(app, 0, 2, 0, 0);
    let mut conn = app.get_conn().await;

    assert!(
        enforce_session_creation(&state, &mut conn, user_a, asset_a, ip())
            .await
            .expect("DB ok")
            .is_ok()
    );
    assert!(
        enforce_session_creation(&state, &mut conn, user_b, asset_b, ip())
            .await
            .expect("DB ok")
            .is_ok()
    );
    // A different user still trips the global limit.
    let denied = enforce_session_creation(&state, &mut conn, user_a, asset_a, ip())
        .await
        .expect("DB ok");
    assert!(
        denied.is_err(),
        "the global rate limit must deny regardless of which user submits"
    );
}

// ==================== Per-user concurrency quota ====================

#[tokio::test]
async fn per_user_concurrency_denies_when_full() {
    let app = TestApp::spawn().await;
    let (user_id, asset_id) = fresh_user_and_asset(app, "vau012_uconc").await;
    let mut conn = app.get_conn().await;

    // Cap is 2 concurrent live sessions per user; all rate controls off.
    let state = limited_state(app, 0, 0, 2, 0);

    // One live SSH session: still under the cap.
    create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;
    assert!(
        enforce_session_creation(&state, &mut conn, user_id, asset_id, ip())
            .await
            .expect("DB ok")
            .is_ok(),
        "1 live session with a cap of 2 must be allowed"
    );

    // A second live session (different protocol) reaches the cap.
    create_test_session(&mut conn, user_id, asset_id, "rdp", "active").await;
    assert!(
        enforce_session_creation(&state, &mut conn, user_id, asset_id, ip())
            .await
            .expect("DB ok")
            .is_err(),
        "2 live sessions with a cap of 2 must deny the next session"
    );
}

// ==================== Per-asset concurrency quota ====================

#[tokio::test]
async fn per_asset_concurrency_denies_when_full() {
    let app = TestApp::spawn().await;
    let (owner_id, asset_id) = fresh_user_and_asset(app, "vau012_aconc").await;
    let mut conn = app.get_conn().await;
    // A second, distinct user also targets the same asset.
    let other =
        create_test_user(&mut conn, &app.auth_service, &unique_name("vau012_aconc_o")).await;

    // Cap is 2 concurrent live sessions per asset; all rate controls off and
    // per-user concurrency off so only the per-asset quota can deny.
    let state = limited_state(app, 0, 0, 0, 2);

    // Two live sessions on the asset, from two different users, reach the cap.
    create_test_session(&mut conn, owner_id, asset_id, "ssh", "active").await;
    create_test_session(&mut conn, other.user.id, asset_id, "rdp", "active").await;

    let denied = enforce_session_creation(&state, &mut conn, owner_id, asset_id, ip())
        .await
        .expect("DB ok");
    assert!(
        denied.is_err(),
        "2 live sessions on the asset with a cap of 2 must deny the next session"
    );
}

// ==================== Threshold 0 disables the control (INV-12-3) ====

#[tokio::test]
async fn zero_thresholds_disable_all_controls() {
    let app = TestApp::spawn().await;
    let (user_id, asset_id) = fresh_user_and_asset(app, "vau012_off").await;
    let mut conn = app.get_conn().await;

    // Seed several live sessions to make sure concurrency would otherwise trip.
    for _ in 0..5 {
        create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;
    }

    // Everything disabled.
    let state = limited_state(app, 0, 0, 0, 0);

    // Many calls, all allowed (no rate, no concurrency control active).
    for i in 1..=20 {
        assert!(
            enforce_session_creation(&state, &mut conn, user_id, asset_id, ip())
                .await
                .expect("DB ok")
                .is_ok(),
            "with all thresholds at 0, request {i} must be allowed"
        );
    }
}

// ==================== Live-session counting alignment ====================

#[tokio::test]
async fn counts_only_live_statuses() {
    let app = TestApp::spawn().await;
    let (user_id, asset_id) = fresh_user_and_asset(app, "vau012_count").await;
    let mut conn = app.get_conn().await;

    // Live statuses (is_live == true): connecting, active, waiting_client,
    // tunnel_active. Non-live: pending, terminated, disconnected, failed, ...
    // SSH/RDP rows for connecting/active; the IACS-only statuses
    // (waiting_client, tunnel_active) go through the IACS fixture which
    // satisfies the proxy_sessions_iacs_consistency check constraint.
    create_test_session(&mut conn, user_id, asset_id, "ssh", "active").await;
    create_test_session(&mut conn, user_id, asset_id, "ssh", "connecting").await;
    create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "waiting_client").await;
    create_iacs_test_session_with_uuid(&mut conn, user_id, asset_id, "tunnel_active").await;
    // Non-live rows must NOT be counted.
    create_test_session(&mut conn, user_id, asset_id, "ssh", "terminated").await;
    create_test_session(&mut conn, user_id, asset_id, "ssh", "disconnected").await;
    create_test_session(&mut conn, user_id, asset_id, "ssh", "failed").await;

    let by_user = count_live_for_user(&mut conn, user_id)
        .await
        .expect("DB ok");
    assert_eq!(
        by_user, 4,
        "exactly the 4 live rows must be counted per user"
    );

    let by_asset = count_live_for_asset(&mut conn, asset_id)
        .await
        .expect("DB ok");
    assert_eq!(
        by_asset, 4,
        "exactly the 4 live rows must be counted per asset"
    );
}
