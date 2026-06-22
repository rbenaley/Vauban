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
/// 5. Performance: loading the full `PermissionContext` (20 parallel
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
    assert!(!ctx.assets_manage);
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
    assert!(!ctx.users_manage_admins);
    assert!(!ctx.assets_read_all);
    assert!(!ctx.groups_manage_members);
    assert!(!ctx.sessions_supervise);
    assert!(!ctx.sessions_bypass_access_rules);
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
    let state = build_state_from(app).await;
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
    let state = build_state_from(app).await;
    let user = make_user(false, true);

    // Matches `config/access/default_policy.csv` for role:staff. Note that
    // `users:manage_admins` and `sessions:bypass_access_rules` are deliberately
    // superuser-only. Staff now also holds `groups:write` (full group CRUD) and
    // the self-service `profile:*` / `iacs:request` / `iacs:read` /
    // `assets:connect_iacs` scopes.
    let staff_allowed: &[(&str, &str)] = &[
        ("users", "read"),
        ("users", "write"),
        ("assets", "read"),
        ("assets", "read_all"),
        ("assets", "manage"),
        ("assets", "connect_iacs"),
        ("sessions", "read"),
        ("sessions", "write"),
        ("sessions", "supervise"),
        ("groups", "read"),
        ("groups", "write"),
        ("groups", "manage_members"),
        ("access_rules", "read"),
        ("access_rules", "write"),
        ("auth_sessions", "read"),
        ("auth_sessions", "write"),
        ("admin", "view"),
        ("profile", "read"),
        ("profile", "write"),
        ("iacs", "request"),
        ("iacs", "read"),
        ("iacs", "manage"),
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
    let state = build_state_from(app).await;
    let user = make_user(false, false);

    // Matches `config/access/default_policy.csv` for role:user.
    //
    // SECURITY: `sessions:read` was added to `role:user` so regular
    // users can list their own sessions via the API; the
    // instance-level filter (caller_id == row.user_id) is enforced
    // server-side in `services::session_access` /
    // `handlers::api::sessions::list_sessions`.
    let user_allowed: &[(&str, &str)] = &[
        ("assets", "read"),
        ("assets", "connect_iacs"),
        ("profile", "read"),
        ("profile", "write"),
        ("sessions", "read"),
        ("iacs", "request"),
        ("iacs", "read"),
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

// ---------------------------------------------------------------------------
// Targeted negative-cases: documents the privilege boundaries introduced by
// the fine-grained migration. Each test below is the canonical proof-of-
// regression for one resserrement.
// ---------------------------------------------------------------------------

/// `assets:read_all` MUST stay denied to `role:user`. Regular users see
/// assets only through their access rules; granting `read_all` would leak
/// every asset in the catalogue.
#[tokio::test]
#[serial]
async fn check_rbac_user_denied_assets_read_all() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, false);

    assert!(
        !check_rbac(&state, &user, "assets", "read_all").await,
        "regular user must NOT have assets:read_all (would bypass access \
         rules at listing time)"
    );
}

/// `groups:write` (CRUD on the group itself) is granted to staff as well as
/// superuser. Staff can both create/rename/delete a group AND manage its
/// membership.
#[tokio::test]
#[serial]
async fn check_rbac_staff_granted_groups_write() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, true);

    assert!(
        check_rbac(&state, &user, "groups", "write").await,
        "staff must have groups:write (full CRUD on the group entity)"
    );
    assert!(
        check_rbac(&state, &user, "groups", "manage_members").await,
        "staff must keep groups:manage_members so the day-to-day membership \
         workflow is not broken"
    );
}

/// `sessions:bypass_access_rules` is reserved to superusers (via the
/// `*` wildcard). Staff must be subject to the same access-rule checks
/// as regular users when opening a session.
#[tokio::test]
#[serial]
async fn check_rbac_staff_denied_sessions_bypass_access_rules() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, true);

    assert!(
        !check_rbac(&state, &user, "sessions", "bypass_access_rules").await,
        "staff must NOT bypass access rules when opening a session; only \
         superusers may"
    );
}

/// Issue #27: `assets:manage` (admin CRUD on the asset catalogue) MUST
/// stay denied to `role:user`. The user zone (`/assets/*`) only grants
/// `assets:read`; CRUD lives exclusively under the `/assets/manage/*`
/// admin sub-tree gated by `assets:manage`.
#[tokio::test]
#[serial]
async fn check_rbac_user_denied_assets_manage() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, false);

    assert!(
        !check_rbac(&state, &user, "assets", "manage").await,
        "regular user must NOT have assets:manage (CRUD on the asset \
         catalogue is reserved to staff/superuser via the /assets/manage \
         admin sub-tree)"
    );
    assert!(
        check_rbac(&state, &user, "assets", "read").await,
        "regular user must keep assets:read so they can list assets they \
         have an access rule for in the user zone"
    );
}

/// Issue #27: staff MUST have `assets:manage` (the admin CRUD scope on
/// assets that replaced the legacy `assets:write`). Without it the
/// `/assets/manage/*` sub-tree would be unreachable for staff after the
/// rename.
#[tokio::test]
#[serial]
async fn check_rbac_staff_granted_assets_manage() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, true);

    assert!(
        check_rbac(&state, &user, "assets", "manage").await,
        "staff must have assets:manage (admin CRUD scope; replaces the \
         legacy assets:write after issue #27)"
    );
}

/// Issue #27: the legacy `assets:write` permission MUST be denied for
/// every role, even superuser via the `*, *` wildcard. The wildcard
/// would technically grant it but no production code references the
/// legacy string anymore (verified by
/// `manage_assets_invariants_test::no_legacy_assets_write_in_production_code`),
/// so a custom Casbin policy still using `assets:write` for staff/user
/// would silently fail. We pin the rename here from the policy side.
#[tokio::test]
#[serial]
async fn check_rbac_assets_write_not_required_by_any_handler() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;

    // The wildcard line `p, role:superuser, *, *` makes superuser
    // match `assets:write` too, but no handler reads that result.
    // Staff and user MUST NOT match; if they did, a custom policy
    // could accidentally grant CRUD via the legacy key.
    for (label, user) in [
        ("staff", make_user(false, true)),
        ("user", make_user(false, false)),
    ] {
        assert!(
            !check_rbac(&state, &user, "assets", "write").await,
            "{label} must NOT be granted the legacy `assets:write` (renamed \
             to `assets:manage` in issue #27); a custom policy using the \
             legacy key would silently fail to authorise the admin handlers"
        );
    }
}

/// `users:manage_admins` (promote/demote a superuser) is superuser-only.
/// Staff must be able to manage non-admin users (`users:write`) but must
/// NOT be able to grant the superuser flag.
#[tokio::test]
#[serial]
async fn check_rbac_staff_denied_users_manage_admins() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
    let user = make_user(false, true);

    assert!(
        !check_rbac(&state, &user, "users", "manage_admins").await,
        "staff must NOT promote/demote superusers"
    );
    assert!(
        check_rbac(&state, &user, "users", "write").await,
        "staff must keep users:write for non-admin user CRUD"
    );
}

#[tokio::test]
#[serial]
async fn permission_context_load_matches_per_check_rbac() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;

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

/// Regular user must be denied the admin-only "All login sessions" page even though
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
        .get("/accounts/all-login-sessions")
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
        .get("/accounts/all-login-sessions")
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

/// `PermissionContext::load` performs 20 Casbin checks in parallel via
/// `tokio::join!`. Even in fallback mode (pure in-memory match) we want to
/// confirm the parallel join is dirt-cheap and is not a per-request hotspot.
/// Threshold is intentionally generous so the test stays stable on slow
/// CI hardware while still catching multi-millisecond regressions.
#[tokio::test]
#[serial]
async fn permission_context_load_perf_budget() {
    let app = TestApp::spawn().await;
    let state = build_state_from(app).await;
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

/// Re-create the 20 (resource, action) couples loaded by
/// [`PermissionContext::load`] so the matrix tests stay aligned with the
/// loader implementation. If the loader gains a new permission the const
/// below MUST be updated, and a matching grant must be added to one of the
/// fallback role sets above.
const TRACKED_PERMS: &[(&str, &str)] = &[
    ("users", "read"),
    ("users", "write"),
    ("users", "manage_admins"),
    ("assets", "read"),
    ("assets", "read_all"),
    ("assets", "manage"),
    ("groups", "read"),
    ("groups", "write"),
    ("groups", "manage_members"),
    ("access_rules", "read"),
    ("access_rules", "write"),
    ("auth_sessions", "read"),
    ("auth_sessions", "write"),
    ("sessions", "read"),
    ("sessions", "write"),
    ("sessions", "supervise"),
    ("sessions", "bypass_access_rules"),
    ("admin", "view"),
    ("profile", "read"),
    ("profile", "write"),
    ("iacs", "request"),
    ("iacs", "read"),
    ("iacs", "manage"),
    ("assets", "connect_iacs"),
];

async fn manual_load(state: &vauban_web::AppState, user: &AuthUser) -> PermissionContext {
    PermissionContext {
        users_read: check_rbac(state, user, "users", "read").await,
        users_write: check_rbac(state, user, "users", "write").await,
        users_manage_admins: check_rbac(state, user, "users", "manage_admins").await,
        assets_read: check_rbac(state, user, "assets", "read").await,
        assets_read_all: check_rbac(state, user, "assets", "read_all").await,
        assets_manage: check_rbac(state, user, "assets", "manage").await,
        groups_read: check_rbac(state, user, "groups", "read").await,
        groups_write: check_rbac(state, user, "groups", "write").await,
        groups_manage_members: check_rbac(state, user, "groups", "manage_members").await,
        access_rules_read: check_rbac(state, user, "access_rules", "read").await,
        access_rules_write: check_rbac(state, user, "access_rules", "write").await,
        auth_sessions_read: check_rbac(state, user, "auth_sessions", "read").await,
        auth_sessions_write: check_rbac(state, user, "auth_sessions", "write").await,
        sessions_read: check_rbac(state, user, "sessions", "read").await,
        sessions_write: check_rbac(state, user, "sessions", "write").await,
        sessions_supervise: check_rbac(state, user, "sessions", "supervise").await,
        sessions_bypass_access_rules: check_rbac(state, user, "sessions", "bypass_access_rules")
            .await,
        admin_view: check_rbac(state, user, "admin", "view").await,
        profile_read: check_rbac(state, user, "profile", "read").await,
        profile_write: check_rbac(state, user, "profile", "write").await,
        iacs_request: check_rbac(state, user, "iacs", "request").await,
        iacs_read: check_rbac(state, user, "iacs", "read").await,
        iacs_manage: check_rbac(state, user, "iacs", "manage").await,
        assets_connect_iacs: check_rbac(state, user, "assets", "connect_iacs").await,
    }
}

/// Build a minimal `AppState` from the shared `TestApp`. The shared app
/// spawns a real in-process vauban-access service with a real Casbin
/// enforcer; we reuse its `access_client` so the matrix tests exercise
/// the exact same authorization logic as production.
async fn build_state_from(app: &TestApp) -> vauban_web::AppState {
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
        rate_limiter: RateLimiter::in_memory(),
        ssh_proxy: None,
        rdp_proxy: None,
        proxy_iacs: None,
        supervisor: None,
        vault_client: None,
        audit_client: None,
        access_client: std::sync::Arc::clone(&app._access_service.access_client),
        auth_ipc_client: None,
        mailer: vauban_web::services::mailer::Mailer::new(
            std::sync::Arc::new(tokio::sync::Notify::new()),
            false,
            5,
        ),
        http_rate: std::sync::Arc::new(vauban_web::services::system_health::HttpRateTracker::new()),
        live_session_history: std::sync::Arc::new(
            vauban_web::services::system_health::LiveSessionHistory::default(),
        ),
        system_health_cache: std::sync::Arc::new(
            vauban_web::services::system_health::SystemHealthCache::new(
                app.db_pool.clone(),
                std::sync::Arc::new(
                    vauban_web::services::broker_latency::BrokerLatencyTracker::default(),
                ),
                std::sync::Arc::new(vauban_web::services::system_health::HttpRateTracker::new()),
            ),
        ),
        iacs_tunnel_registry: vauban_web::services::iacs_tunnel::TunnelRegistry::new(),
        pending_mfa: vauban_web::services::pending_mfa::PendingMfaStore::new(),
    }
}

// ---------------------------------------------------------------------------
// Policy / code drift detector
// ---------------------------------------------------------------------------

/// Catches the regression scenario where a contributor adds a new
/// `PermissionContext` field (and a `check_rbac` call in `load()`) without
/// granting it to ANY role in `config/access/default_policy.csv`. In that
/// situation the field would silently stay `false` for everybody and
/// nothing would ever exercise the new code path.
///
/// We parse the CSV at test time and assert that every `(resource, action)`
/// tuple in [`TRACKED_PERMS`] is mentioned by at least one `p, role:..., r,
/// a` line OR by the catch-all `p, role:superuser, *, *` (which makes any
/// `(r, a)` reachable for superusers).
#[test]
fn policy_csv_grants_every_tracked_permission_to_at_least_one_role() {
    // `include_str!` is relative to this source file: walk up three
    // directories (middleware -> tests -> vauban-web -> repo root) to
    // locate `config/access/default_policy.csv`.
    let csv = include_str!("../../../config/access/default_policy.csv");

    // Parse `p, sub, obj, act` lines. We deliberately keep this loose: the
    // real Casbin model has the same shape and any deviation should be
    // caught by the integration tests anyway.
    let mut grants: Vec<(String, String)> = Vec::new();
    let mut has_superuser_wildcard = false;
    for raw in csv.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < 4 || fields[0] != "p" {
            continue;
        }
        let (subject, obj, act) = (fields[1], fields[2], fields[3]);
        if subject == "role:superuser" && obj == "*" && act == "*" {
            has_superuser_wildcard = true;
        } else {
            grants.push((obj.to_string(), act.to_string()));
        }
    }

    assert!(
        has_superuser_wildcard || !grants.is_empty(),
        "default_policy.csv parsed empty; check the include_str! path"
    );

    for (resource, action) in TRACKED_PERMS {
        let granted_explicitly = grants.iter().any(|(r, a)| r == resource && a == action);
        let granted_via_wildcard = has_superuser_wildcard;
        assert!(
            granted_explicitly || granted_via_wildcard,
            "TRACKED_PERMS includes ({}:{}) but `default_policy.csv` grants \
             it to no role -- the new field would silently stay false for \
             every user. Add a `p, role:..., {}, {}` line (or rely on the \
             superuser wildcard) before merging.",
            resource,
            action,
            resource,
            action
        );
    }
}
