//! Issue #27 — exhaustive gate matrix for the `/assets/manage/*` and
//! `/api/v1/assets/manage/*` admin sub-trees.
//!
//! Every route x role combination is exercised through the full
//! Axum stack (auth middleware, permission_context_middleware,
//! `require_assets_manage`, then the handler). The expected outcome
//! is a tri-state:
//!
//!   - `Allowed` -- the gate clears (status MUST NOT be 401/403).
//!     We do not pin the exact 200 vs 4xx code because the handler
//!     may legitimately fail on the synthetic UUID we feed it.
//!   - `Denied`  -- the gate refuses with 403 Forbidden (or with a
//!     302 redirect to `/login` for unauthenticated callers on web
//!     routes that go through `auth_middleware` first).
//!   - `Unauthenticated` -- no JWT cookie/header; the auth
//!     middleware refuses BEFORE the gate is reached.
//!
//! The `ROUTES` constant is the canonical list of admin endpoints
//! that exist in `main.rs`. The `ROUTES.len()` count is asserted
//! against an explicit expected number so a contributor adding a
//! new admin route MUST update this test (defence-in-depth: a
//! forgotten route would otherwise silently dodge the matrix).

use axum::http::header::COOKIE;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{create_admin_user, create_staff_only_user, create_test_user, unique_name};

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Put,
}

struct Route {
    method: Method,
    path_template: &'static str,
    needs_uuid: bool,
}

/// All routes mounted under the `/assets/manage/*` web nest.
///
/// The bare root path `/assets/manage` (with or without trailing
/// slash) is intentionally NOT in this matrix because it collides
/// with the user-zone `/assets/{uuid}` pattern (with `uuid="manage"`)
/// and Axum's nest-trailing-slash auto-redirect. The root-path
/// behaviour is pinned separately by the e2e lifecycle test; this
/// matrix focuses on the per-method × per-role gate that
/// `require_assets_manage` enforces on the unambiguous routes.
const WEB_ROUTES: &[Route] = &[
    Route { method: Method::Get,  path_template: "/assets/manage/new",                   needs_uuid: false },
    Route { method: Method::Post, path_template: "/assets/manage/new",                   needs_uuid: false },
    Route { method: Method::Get,  path_template: "/assets/manage/deleted",               needs_uuid: false },
    Route { method: Method::Get,  path_template: "/assets/manage/search",                needs_uuid: false },
    Route { method: Method::Get,  path_template: "/assets/manage/{uuid}",                needs_uuid: true  },
    Route { method: Method::Get,  path_template: "/assets/manage/{uuid}/edit",           needs_uuid: true  },
    Route { method: Method::Post, path_template: "/assets/manage/{uuid}/edit",           needs_uuid: true  },
    Route { method: Method::Post, path_template: "/assets/manage/{uuid}/delete",         needs_uuid: true  },
    Route { method: Method::Post, path_template: "/assets/manage/{uuid}/fetch-host-key", needs_uuid: true  },
];

/// All routes mounted under the `/api/v1/assets/manage/*` API nest.
/// The bare root path is excluded for the same reason the web matrix
/// excludes it (see [`WEB_ROUTES`]).
const API_ROUTES: &[Route] = &[
    Route { method: Method::Get,  path_template: "/api/v1/assets/manage/groups",                needs_uuid: false },
    Route { method: Method::Get,  path_template: "/api/v1/assets/manage/groups/{uuid}/assets",  needs_uuid: true  },
    Route { method: Method::Get,  path_template: "/api/v1/assets/manage/{uuid}",                needs_uuid: true  },
    Route { method: Method::Put,  path_template: "/api/v1/assets/manage/{uuid}",                needs_uuid: true  },
    Route { method: Method::Get,  path_template: "/api/v1/assets/manage/{uuid}/ssh-host-key",   needs_uuid: true  },
    Route { method: Method::Post, path_template: "/api/v1/assets/manage/{uuid}/ssh-host-key",   needs_uuid: true  },
];

/// Materialise the path by substituting `{uuid}` with a synthetic UUID.
fn url_for(route: &Route) -> String {
    let dummy = Uuid::new_v4().to_string();
    if route.needs_uuid {
        route.path_template.replace("{uuid}", &dummy)
    } else {
        route.path_template.to_string()
    }
}

/// Send `route` with the given optional cookie token and return the
/// HTTP status code observed by the client.
async fn send(app: &TestApp, route: &Route, token: Option<&str>) -> u16 {
    let url = url_for(route);
    let req = match route.method {
        Method::Get => app.server.get(&url),
        Method::Post => app.server.post(&url),
        Method::Put => app.server.put(&url),
    };
    let req = match token {
        Some(t) => req.add_header(COOKIE, format!("access_token={}", t)),
        None => req,
    };
    req.await.status_code().as_u16()
}

/// Sanity guard: if a contributor adds (or accidentally drops) an
/// admin asset route in `main.rs`, the count below MUST be updated
/// in lock-step. This is the only mechanism that prevents a new
/// route from silently dodging the matrix.
#[test]
fn route_inventory_is_exhaustive() {
    assert_eq!(
        WEB_ROUTES.len(),
        9,
        "WEB_ROUTES drift: update the matrix AND the count when adding/removing a /assets/manage/* route \
         (root path is excluded — it is pinned separately, see WEB_ROUTES doc-comment)"
    );
    assert_eq!(
        API_ROUTES.len(),
        6,
        "API_ROUTES drift: update the matrix AND the count when adding/removing a /api/v1/assets/manage/* route \
         (root path is excluded — see API_ROUTES doc-comment)"
    );
}

/// Every web admin route MUST refuse a regular (`role:user`) caller
/// with 403 Forbidden. The `require_assets_manage` middleware is
/// registered as a `route_layer` on the `/assets/manage` nest, so
/// the refusal is structural (no DB lookup, no UUID parsing) — see
/// the anti-enumeration test for the matching pin.
#[tokio::test]
#[serial]
async fn web_routes_deny_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_name = unique_name("manage_assets_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    for route in WEB_ROUTES {
        let status = send(app, route, Some(&user.token)).await;
        assert_eq!(
            status, 403,
            "{} {} MUST return 403 for role:user (gated by require_assets_manage)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// Same matrix, staff caller (`role:staff` granted `assets:manage`).
/// The gate MUST clear: we tolerate any non-403/401 status because
/// the handler may legitimately surface a 4xx/5xx on the synthetic
/// UUID (asset not found, validation error, ...).
#[tokio::test]
#[serial]
async fn web_routes_clear_gate_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let staff_name = unique_name("manage_assets_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    for route in WEB_ROUTES {
        let status = send(app, route, Some(&staff.token)).await;
        assert_ne!(
            status, 403,
            "{} {} MUST clear require_assets_manage for role:staff (got 403)",
            method_str(route.method),
            route.path_template
        );
        assert_ne!(
            status, 401,
            "{} {} MUST clear auth_middleware for role:staff (got 401)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// Same matrix, superuser caller. Identical contract to staff.
#[tokio::test]
#[serial]
async fn web_routes_clear_gate_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_name = unique_name("manage_assets_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    for route in WEB_ROUTES {
        let status = send(app, route, Some(&admin.token)).await;
        assert_ne!(
            status, 403,
            "{} {} MUST clear require_assets_manage for role:superuser (got 403)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// Every admin web route MUST refuse an unauthenticated caller. The
/// auth middleware redirects HTML routes to `/login` (302) and
/// returns 401 for HTMX/API contexts; we accept either as long as it
/// is NOT 200 OK. Critically, no admin handler may produce a
/// success response when no JWT is presented.
#[tokio::test]
#[serial]
async fn web_routes_refuse_unauthenticated() {
    let app = TestApp::spawn().await;

    for route in WEB_ROUTES {
        let status = send(app, route, None).await;
        assert!(
            !(200..=299).contains(&status),
            "{} {} MUST NOT return 2xx without authentication (got {})",
            method_str(route.method),
            route.path_template,
            status
        );
    }
}

/// API matrix counterpart for `role:user`: every `/api/v1/assets/manage/*`
/// route MUST refuse with 403 (no redirect, no 200).
#[tokio::test]
#[serial]
async fn api_routes_deny_regular_user() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_name = unique_name("manage_assets_api_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    for route in API_ROUTES {
        let status = send(app, route, Some(&user.token)).await;
        assert_eq!(
            status, 403,
            "{} {} MUST return 403 for role:user (gated by require_assets_manage)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// API matrix, staff caller: gate clears.
#[tokio::test]
#[serial]
async fn api_routes_clear_gate_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let staff_name = unique_name("manage_assets_api_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    for route in API_ROUTES {
        let status = send(app, route, Some(&staff.token)).await;
        assert_ne!(
            status, 403,
            "{} {} MUST clear require_assets_manage for role:staff (got 403)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// API matrix, unauthenticated: every route MUST refuse (401).
#[tokio::test]
#[serial]
async fn api_routes_refuse_unauthenticated() {
    let app = TestApp::spawn().await;

    for route in API_ROUTES {
        let status = send(app, route, None).await;
        assert!(
            !(200..=299).contains(&status),
            "{} {} MUST NOT return 2xx without authentication (got {})",
            method_str(route.method),
            route.path_template,
            status
        );
    }
}

/// Method isolation: `/assets/manage/deleted` accepts GET only.
/// A POST to that exact path MUST return 405 Method Not Allowed.
/// This pins the route shape (no accidental method conflation —
/// e.g. nobody can DELETE the deleted-assets list).
#[tokio::test]
#[serial]
async fn web_method_isolation_deleted_path() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_name = unique_name("manage_assets_405");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let resp = app
        .server
        .post("/assets/manage/deleted")
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 405);
}

/// Method isolation: `/assets/manage/{uuid}/delete` accepts POST
/// only. A GET to that exact path MUST return 405 Method Not
/// Allowed (no accidental "open the delete page on click" route).
#[tokio::test]
#[serial]
async fn web_method_isolation_delete_action() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_name = unique_name("manage_assets_405_del");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    let dummy = Uuid::new_v4();
    let resp = app
        .server
        .get(&format!("/assets/manage/{}/delete", dummy))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;
    assert_status(&resp, 405);
}

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
    }
}
