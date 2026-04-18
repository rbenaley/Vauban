/// VAUBAN Web - Battle tests for the Casbin-backed PermissionContext.
///
/// These tests exercise the full pipeline:
///
///   auth_middleware -> permission_context_middleware -> handler -> template
///
/// in dev fallback mode (no IPC client). They verify that:
///
/// 1. `PermissionContext::default` is fail-closed: a route reached without
///    going through the middleware (or with an unauthenticated request) sees
///    every permission denied.
/// 2. The middleware correctly maps `is_staff` / `is_superuser` to the
///    expected fallback Casbin policy for every tracked permission.
/// 3. Web handlers consume `perms.*` instead of `is_staff || is_superuser`:
///    a non-admin user is denied access to admin pages even though their JWT
///    is valid (and conversely an admin is granted access).
/// 4. Non-regression for issue #1: an authenticated regular user must NOT
///    see an "Edit" button on their own profile, but an admin user must see
///    it (UI must mirror the server gate exactly).
/// 5. Performance: loading the full `PermissionContext` (15 parallel
///    `check_rbac` calls in fallback mode) stays well under any reasonable
///    request budget.
use std::time::Instant;

use axum::http::header::COOKIE;
use serial_test::serial;

use vauban_web::auth::{PermissionContext, check_rbac};
use vauban_web::middleware::auth::AuthUser;

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{create_simple_user, unique_name};

// ---------------------------------------------------------------------------
// Pure fail-closed contract
// ---------------------------------------------------------------------------

#[test]
fn permission_context_default_denies_every_resource() {
    let ctx = PermissionContext::default();
    assert!(!ctx.users_read);
    assert!(!ctx.users_write);
    assert!(!ctx.assets_read);
    assert!(!ctx.assets_write);
    assert!(!ctx.groups_read);
    assert!(!ctx.groups_write);
    assert!(!ctx.access_rules_read);
    assert!(!ctx.access_rules_write);
    assert!(!ctx.auth_sessions_read);
    assert!(!ctx.auth_sessions_write);
    assert!(!ctx.sessions_read);
    assert!(!ctx.sessions_write);
    assert!(!ctx.admin_view);
    assert!(!ctx.profile_read);
    assert!(!ctx.profile_write);
}

// ---------------------------------------------------------------------------
// Real Casbin policy matrix (default_policy.csv loaded in the in-process
// vauban-access service spawned by TestApp::spawn()).
// ---------------------------------------------------------------------------

fn make_user(is_superuser: bool, is_staff: bool) -> AuthUser {
    AuthUser {
        uuid: "test-uuid".to_string(),
        username: "tester".to_string(),
        mfa_verified: true,
        is_superuser,
        is_staff,
    }
}

#[tokio::test]
#[serial]
async fn check_rbac_superuser_grants_everything() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app);
    let user = make_user(true, true);

    for (resource, action) in TRACKED_PERMS {
        assert!(
            check_rbac(&state, &user, resource, action).await,
            "superuser must be granted {}:{}",
            resource,
            action
        );
    }
}

#[tokio::test]
#[serial]
async fn check_rbac_staff_grants_admin_set_only() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app);
    let user = make_user(false, true);

    let staff_allowed: &[(&str, &str)] = &[
        ("users", "read"),
        ("users", "write"),
        ("assets", "read"),
        ("assets", "write"),
        ("sessions", "read"),
        ("sessions", "write"),
        ("groups", "read"),
        ("groups", "write"),
        ("access_rules", "read"),
        ("access_rules", "write"),
        ("auth_sessions", "read"),
        ("auth_sessions", "write"),
        ("admin", "view"),
    ];

    for (resource, action) in TRACKED_PERMS {
        let expected = staff_allowed.contains(&(resource, action));
        assert_eq!(
            check_rbac(&state, &user, resource, action).await,
            expected,
            "staff fallback mismatch for {}:{}",
            resource,
            action
        );
    }
}

#[tokio::test]
#[serial]
async fn check_rbac_user_grants_only_self_serve_set() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app);
    let user = make_user(false, false);

    // Matches `config/access/default_policy.csv` for role:user.
    let user_allowed: &[(&str, &str)] = &[
        ("assets", "read"),
        ("profile", "read"),
        ("profile", "write"),
    ];

    for (resource, action) in TRACKED_PERMS {
        let expected = user_allowed.contains(&(resource, action));
        assert_eq!(
            check_rbac(&state, &user, resource, action).await,
            expected,
            "regular-user fallback mismatch for {}:{}",
            resource,
            action
        );
    }
}

#[tokio::test]
#[serial]
async fn permission_context_load_matches_per_check_rbac() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app);

    for (label, user) in [
        ("superuser", make_user(true, false)),
        ("staff", make_user(false, true)),
        ("user", make_user(false, false)),
    ] {
        let bulk = PermissionContext::load(&state, &user).await;
        let manual = manual_load(&state, &user).await;
        assert_eq!(
            bulk, manual,
            "PermissionContext::load disagrees with per-call check_rbac for {label}"
        );
    }
}

// ---------------------------------------------------------------------------
// End-to-end: handlers reject via PermissionContext, not is_staff shortcut
// ---------------------------------------------------------------------------

/// Regular user must be denied the admin-only "All sessions" page even though
/// their JWT is valid (this is a structural gate via PermissionContext).
#[tokio::test]
#[serial]
async fn admin_route_denied_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("plain_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: uuid::Uuid = {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(user_id))
                .select(users::uuid)
                .first(&mut conn)
                .await
        )
    };

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/admin/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    // Authorization error -> 403 (handler returns AppError::Authorization).
    assert_status(&response, 403);
}

/// Same route, admin user, must succeed.
#[tokio::test]
#[serial]
async fn admin_route_allowed_for_admin_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("admin_user");
    let user_id = create_simple_user(&mut conn, &username).await;

    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .set((users::is_superuser.eq(true), users::is_staff.eq(true),))
                .execute(&mut conn)
                .await
        );
    }

    let user_uuid: uuid::Uuid = {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(user_id))
                .select(users::uuid)
                .first(&mut conn)
                .await
        )
    };

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/admin/sessions")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
}

// ---------------------------------------------------------------------------
// Non-regression: Issue #1 - profile "Edit" button visibility
// ---------------------------------------------------------------------------

/// Regular user visits their own profile: the rendered HTML MUST NOT contain
/// an Edit button (Casbin denies `users:write` to `role:user`).
#[tokio::test]
#[serial]
async fn profile_edit_button_hidden_for_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("plain_profile");
    let user_id = create_simple_user(&mut conn, &username).await;

    let user_uuid: uuid::Uuid = {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(user_id))
                .select(users::uuid)
                .first(&mut conn)
                .await
        )
    };

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    let edit_href = format!("/accounts/users/{}/edit", user_uuid);
    assert!(
        !body.contains(&edit_href),
        "regular user profile MUST NOT expose the edit button (Casbin denies users:write); body contained {edit_href}"
    );
}

/// Admin user visits their own profile: the rendered HTML MUST contain the
/// Edit button (Casbin grants `users:write` to `role:superuser`/`role:staff`).
#[tokio::test]
#[serial]
async fn profile_edit_button_shown_for_admin_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("admin_profile");
    let user_id = create_simple_user(&mut conn, &username).await;

    {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .set((users::is_superuser.eq(true), users::is_staff.eq(true),))
                .execute(&mut conn)
                .await
        );
    }

    let user_uuid: uuid::Uuid = {
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::RunQueryDsl;
        use vauban_web::schema::users;
        unwrap_ok!(
            users::table
                .filter(users::id.eq(user_id))
                .select(users::uuid)
                .first(&mut conn)
                .await
        )
    };

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, true, true)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    let edit_href = format!("/accounts/users/{}/edit", user_uuid);
    assert!(
        body.contains(&edit_href),
        "admin profile MUST expose the edit button (Casbin grants users:write); missing {edit_href}"
    );
}

// ---------------------------------------------------------------------------
// Performance budget
// ---------------------------------------------------------------------------

/// `PermissionContext::load` performs 15 Casbin checks in parallel via
/// `tokio::join!`. Even in fallback mode (pure in-memory match) we want to
/// confirm the parallel join is dirt-cheap and is not a per-request hotspot.
/// Threshold is intentionally generous (20 ms) so the test stays stable on
/// slow CI hardware while still catching multi-millisecond regressions.
#[tokio::test]
#[serial]
async fn permission_context_load_perf_budget() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app);
    let user = make_user(true, true);

    // Warm-up
    let _ = PermissionContext::load(&state, &user).await;

    let iterations = 100;
    let started = Instant::now();
    for _ in 0..iterations {
        let _ = PermissionContext::load(&state, &user).await;
    }
    let elapsed = started.elapsed();
    let per_call_us = elapsed.as_micros() / iterations as u128;

    println!(
        "PermissionContext::load fallback: {iterations} iters in {elapsed:?} \
         (~{per_call_us}us/call)"
    );

    assert!(
        elapsed.as_millis() < 200,
        "PermissionContext::load is regressing: {iterations} fallback loads took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Re-create the 15 (resource, action) couples loaded by
/// [`PermissionContext::load`] so the matrix tests stay aligned with the
/// loader implementation. If the loader gains a new permission the const
/// below MUST be updated, and a matching grant must be added to one of the
/// fallback role sets above.
const TRACKED_PERMS: &[(&str, &str)] = &[
    ("users", "read"),
    ("users", "write"),
    ("assets", "read"),
    ("assets", "write"),
    ("groups", "read"),
    ("groups", "write"),
    ("access_rules", "read"),
    ("access_rules", "write"),
    ("auth_sessions", "read"),
    ("auth_sessions", "write"),
    ("sessions", "read"),
    ("sessions", "write"),
    ("admin", "view"),
    ("profile", "read"),
    ("profile", "write"),
];

async fn manual_load(state: &vauban_web::AppState, user: &AuthUser) -> PermissionContext {
    PermissionContext {
        users_read: check_rbac(state, user, "users", "read").await,
        users_write: check_rbac(state, user, "users", "write").await,
        assets_read: check_rbac(state, user, "assets", "read").await,
        assets_write: check_rbac(state, user, "assets", "write").await,
        groups_read: check_rbac(state, user, "groups", "read").await,
        groups_write: check_rbac(state, user, "groups", "write").await,
        access_rules_read: check_rbac(state, user, "access_rules", "read").await,
        access_rules_write: check_rbac(state, user, "access_rules", "write").await,
        auth_sessions_read: check_rbac(state, user, "auth_sessions", "read").await,
        auth_sessions_write: check_rbac(state, user, "auth_sessions", "write").await,
        sessions_read: check_rbac(state, user, "sessions", "read").await,
        sessions_write: check_rbac(state, user, "sessions", "write").await,
        admin_view: check_rbac(state, user, "admin", "view").await,
        profile_read: check_rbac(state, user, "profile", "read").await,
        profile_write: check_rbac(state, user, "profile", "write").await,
    }
}

/// Build a minimal `AppState` from the shared `TestApp`. The shared app
/// spawns a real in-process vauban-access service with a real Casbin
/// enforcer; we reuse its `access_client` so the matrix tests exercise
/// the exact same authorization logic as production.
fn build_state_from(app: &TestApp) -> vauban_web::AppState {
    use vauban_web::AppState;
    use vauban_web::cache::CacheConnection;
    use vauban_web::services::rate_limit::RateLimiter;

    AppState {
        config: app.config.clone(),
        db_pool: app.db_pool.clone(),
        cache: CacheConnection::Mock(std::sync::Arc::new(vauban_web::cache::MockCache::new())),
        auth_service: app.auth_service.clone(),
        broadcast: app.broadcast.clone(),
        user_connections: app.user_connections.clone(),
        ws_counter: app.ws_counter.clone(),
        rate_limiter: unwrap_ok!(RateLimiter::new(false, None, 1000)),
        ssh_proxy: None,
        rdp_proxy: None,
        supervisor: None,
        vault_client: None,
        access_client: std::sync::Arc::clone(&app._access_service.access_client),
        auth_ipc_client: None,
    }
}
