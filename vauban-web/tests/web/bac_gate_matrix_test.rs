//! BAC hardening — exhaustive gate matrix for every ADMIN web
//! sub-tree outside `/assets/manage/*` (which has its own matrix in
//! `manage_assets_gate_matrix_test.rs`).
//!
//! Production incident (July 2026): a customer discovered that a
//! regular `role:user` could load `/assets/groups`, `/accounts/users`,
//! `/accounts/groups` and `/assets/access` by typing the URL — the
//! handlers carried no Casbin gate (Broken Access Control, OWASP
//! A01:2021). The fix fences each sub-tree with a `route_layer`
//! (`require_users_read`, `require_groups_read`,
//! `require_access_rules_read`, `require_assets_manage`) AND
//! re-checks the permission inside every handler.
//!
//! This matrix drives every route × role combination through the full
//! Axum stack and pins the tri-state outcome:
//!
//! - anonymous     -> 303 `/login` (HTML zone), never 2xx;
//! - `role:user`   -> 403 systématique (the nest gate fires BEFORE
//!   any handler / DB access);
//! - `role:staff`  -> the gate clears (never 401/403 — staff holds
//!   every permission exercised here per `default_policy.csv`);
//! - superuser     -> the gate clears.
//!
//! The inventory count is pinned so a contributor adding an admin
//! route MUST add it to the matrix (drift detector, same mechanism
//! as `manage_assets_gate_matrix_test::route_inventory_is_exhaustive`).

use axum::http::header::COOKIE;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status};
use crate::fixtures::{
    create_admin_user, create_staff_only_user, create_test_asset_group, create_test_ssh_asset,
    create_test_user, unique_name,
};

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
}

struct Route {
    method: Method,
    path_template: &'static str,
    /// Minimum Casbin permission fencing the route (documentation +
    /// failure-message value; the matrix itself only observes HTTP
    /// outcomes).
    min_perm: &'static str,
}

/// Every admin web route that must be denied to `role:user`.
///
/// `{uuid}` and `{user_uuid}` are substituted with synthetic UUIDs so
/// the gate is exercised BEFORE any handler-level parsing.
const ADMIN_ROUTES: &[Route] = &[
    // ---- /admin (dashboard admin, gated admin:view) ----
    Route {
        method: Method::Get,
        path_template: "/admin",
        min_perm: "admin:view",
    },
    // ---- /accounts/users nest (require_users_read) ----
    Route {
        method: Method::Get,
        path_template: "/accounts/users",
        min_perm: "users:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/users/new",
        min_perm: "users:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/users",
        min_perm: "users:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/users/{uuid}",
        min_perm: "users:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/users/{uuid}",
        min_perm: "users:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/users/{uuid}/edit",
        min_perm: "users:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/users/{uuid}/delete",
        min_perm: "users:read",
    },
    // ---- /accounts/groups nest (require_groups_read) ----
    Route {
        method: Method::Get,
        path_template: "/accounts/groups",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/groups",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/groups/new",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/groups/{uuid}",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/groups/{uuid}",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/groups/{uuid}/edit",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/groups/{uuid}/members/add",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Get,
        path_template: "/accounts/groups/{uuid}/members/search",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/groups/{uuid}/members",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/groups/{uuid}/members/{user_uuid}/remove",
        min_perm: "groups:read",
    },
    Route {
        method: Method::Post,
        path_template: "/accounts/groups/{uuid}/delete",
        min_perm: "groups:read",
    },
    // ---- /assets/access nest (require_access_rules_read) ----
    Route {
        method: Method::Get,
        path_template: "/assets/access",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Post,
        path_template: "/assets/access",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Get,
        path_template: "/assets/access/new",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Get,
        path_template: "/assets/access/{uuid}",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Get,
        path_template: "/assets/access/{uuid}/edit",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Post,
        path_template: "/assets/access/{uuid}/edit",
        min_perm: "access_rules:read",
    },
    Route {
        method: Method::Post,
        path_template: "/assets/access/{uuid}/delete",
        min_perm: "access_rules:read",
    },
];

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
    }
}

fn url_for(route: &Route) -> String {
    route
        .path_template
        .replace("{uuid}", &Uuid::new_v4().to_string())
        .replace("{user_uuid}", &Uuid::new_v4().to_string())
}

async fn send(app: &TestApp, route: &Route, token: Option<&str>) -> (u16, Option<String>) {
    let url = url_for(route);
    let req = match route.method {
        Method::Get => app.server.get(&url),
        Method::Post => app.server.post(&url),
    };
    let req = match token {
        Some(t) => req.add_header(COOKIE, format!("access_token={}", t)),
        None => req,
    };
    let resp = req.await;
    let status = resp.status_code().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, location)
}

/// Drift detector: adding/removing an admin route in `main.rs` MUST
/// update this matrix in lock-step.
#[test]
fn route_inventory_is_exhaustive() {
    assert_eq!(
        ADMIN_ROUTES.len(),
        26,
        "ADMIN_ROUTES drift: update the matrix AND this count when \
         adding/removing an admin route under /admin, /accounts/users, \
         /accounts/groups or /assets/access."
    );
}

/// `role:user` MUST be refused with 403 on EVERY admin route. The
/// nest `route_layer` fires before any handler / DB access, so the
/// refusal is structural.
#[tokio::test]
#[serial]
async fn admin_routes_deny_regular_user_with_403() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let user_name = unique_name("bac_matrix_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    for route in ADMIN_ROUTES {
        let (status, _) = send(app, route, Some(&user.token)).await;
        assert_eq!(
            status,
            403,
            "{} {} MUST return 403 for role:user (min permission {})",
            method_str(route.method),
            route.path_template,
            route.min_perm
        );
    }
}

/// Staff (granted every permission exercised by this matrix in
/// `default_policy.csv`) MUST clear every gate: no 401, no 403. The
/// handler may still answer 4xx/5xx on the synthetic UUID.
#[tokio::test]
#[serial]
async fn admin_routes_clear_gate_for_staff() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let staff_name = unique_name("bac_matrix_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;

    for route in ADMIN_ROUTES {
        let (status, _) = send(app, route, Some(&staff.token)).await;
        assert_ne!(
            status,
            403,
            "{} {} MUST clear the gate for role:staff (got 403)",
            method_str(route.method),
            route.path_template
        );
        assert_ne!(
            status,
            401,
            "{} {} MUST clear auth for role:staff (got 401)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// Superuser: identical contract to staff.
#[tokio::test]
#[serial]
async fn admin_routes_clear_gate_for_superuser() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin_name = unique_name("bac_matrix_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;

    for route in ADMIN_ROUTES {
        let (status, _) = send(app, route, Some(&admin.token)).await;
        assert_ne!(
            status,
            403,
            "{} {} MUST clear the gate for role:superuser (got 403)",
            method_str(route.method),
            route.path_template
        );
    }
}

/// Anonymous callers MUST be redirected to `/login` (303) on every
/// admin HTML route — never a 2xx, never a JSON 403.
#[tokio::test]
#[serial]
async fn admin_routes_redirect_anonymous_to_login() {
    let app = TestApp::spawn().await;

    for route in ADMIN_ROUTES {
        let (status, location) = send(app, route, None).await;
        assert!(
            !(200..=299).contains(&status),
            "{} {} MUST NOT return 2xx without authentication (got {})",
            method_str(route.method),
            route.path_template,
            status
        );
        // Routes under a require_* nest go through
        // `unauthenticated_response_for` -> 303 /login. Non-nested
        // routes (e.g. /admin) rely on the WebAuthUser extractor,
        // which also redirects. Either way: 303 to /login.
        assert_eq!(
            status,
            303,
            "{} {} MUST redirect anonymous callers (got {})",
            method_str(route.method),
            route.path_template,
            status
        );
        assert_eq!(
            location.as_deref(),
            Some("/login"),
            "{} {} Location must be /login",
            method_str(route.method),
            route.path_template
        );
    }
}

// ===================================================================
// Anti-enumeration probes (existing vs random UUID -> same status,
// same body). `/assets/manage/groups/{uuid}` is covered by
// `manage_assets_anti_enumeration_test.rs`; here we pin the
// `/accounts/groups/{uuid}` nest.
// ===================================================================

#[tokio::test]
#[serial]
async fn accounts_groups_do_not_leak_group_existence_to_role_user() {
    use crate::fixtures::create_test_vauban_group;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let real_uuid = create_test_vauban_group(&mut conn, &unique_name("bac-antienum-ug")).await;
    let random = Uuid::new_v4();
    let user_name = unique_name("bac_antienum_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    let probes = [
        format!("/accounts/groups/{}", real_uuid),
        format!("/accounts/groups/{}", random),
        format!("/accounts/groups/{}/edit", real_uuid),
        format!("/accounts/groups/{}/edit", random),
    ];

    let mut bodies: Vec<(String, String)> = Vec::with_capacity(probes.len());
    for url in probes {
        let resp = app
            .server
            .get(&url)
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        assert_status(&resp, 403);
        bodies.push((url, resp.text()));
    }

    let baseline = &bodies[0].1;
    for (url, body) in &bodies[1..] {
        assert_eq!(
            body, baseline,
            "{}: anti-enumeration leak — a role:user could distinguish \
             'group exists' from 'group does not exist' by the body.",
            url
        );
    }
}

// ===================================================================
// Navigation flow (QA rule « web navigation flow tests ») : the full
// asset-group lifecycle under the NEW `/assets/manage/groups` URLs.
// Every PRG / HTMX redirect emitted along the way MUST point inside
// `/assets/manage/groups` and MUST resolve to a live route.
// ===================================================================

#[tokio::test]
#[serial]
async fn asset_group_full_lifecycle_navigates_under_manage_urls() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let staff_name = unique_name("bac_flow_staff");
    let staff = create_staff_only_user(&mut conn, &app.auth_service, &staff_name).await;
    let csrf = app.generate_csrf_token();
    let cookies = format!("access_token={}; __vauban_csrf={}", staff.token, csrf);

    // Step 1: the list page loads.
    let resp = app
        .server
        .get("/assets/manage/groups")
        .add_header(COOKIE, cookies.clone())
        .await;
    assert_status(&resp, 200);

    // Step 2: create a group; the PRG redirect must stay under
    // /assets/manage/groups and resolve.
    let group_name = unique_name("bac-flow-grp");
    let group_slug = unique_name("bac-flow-slug");
    let resp = app
        .server
        .post("/assets/manage/groups")
        .add_header(COOKIE, cookies.clone())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("name", &group_name),
            ("slug", &group_slug),
            ("color", "#6366f1"),
            ("icon", "server"),
        ])
        .await;
    assert_status(&resp, 303);
    let detail_url = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("create must redirect")
        .to_string();
    assert!(
        detail_url.starts_with("/assets/manage/groups"),
        "create redirect must stay under /assets/manage/groups, was {detail_url}"
    );

    // Step 3: follow the redirect — the detail page must resolve.
    let resp = app
        .server
        .get(&detail_url)
        .add_header(COOKIE, cookies.clone())
        .await;
    assert_status(&resp, 200);
    let group_uuid = detail_url
        .rsplit('/')
        .next()
        .expect("detail url ends with uuid")
        .to_string();

    // Step 4: add an asset to the group; redirect must resolve.
    let asset = create_test_ssh_asset(&mut conn, &unique_name("bac_flow_asset")).await;
    let resp = app
        .server
        .post(&format!("/assets/manage/groups/{}/add-asset", group_uuid))
        .add_header(COOKIE, cookies.clone())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuids", &asset.asset.uuid.to_string()),
        ])
        .await;
    assert_status(&resp, 303);
    let after_add = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("add-asset must redirect")
        .to_string();
    assert!(
        after_add.starts_with("/assets/manage/groups"),
        "add-asset redirect must stay under /assets/manage/groups, was {after_add}"
    );
    let resp = app
        .server
        .get(&after_add)
        .add_header(COOKIE, cookies.clone())
        .await;
    assert_status(&resp, 200);

    // Step 5: remove the asset; redirect must resolve.
    let resp = app
        .server
        .post(&format!(
            "/assets/manage/groups/{}/remove-asset",
            group_uuid
        ))
        .add_header(COOKIE, cookies.clone())
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("asset_uuid", &asset.asset.uuid.to_string()),
        ])
        .await;
    assert_status(&resp, 303);
    let after_remove = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("remove-asset must redirect")
        .to_string();
    assert!(
        after_remove.starts_with("/assets/manage/groups"),
        "remove-asset redirect must stay under /assets/manage/groups, was {after_remove}"
    );

    // Step 6: delete the group; final redirect must land on the list.
    let resp = app
        .server
        .post(&format!("/assets/manage/groups/{}/delete", group_uuid))
        .add_header(COOKIE, cookies.clone())
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_status(&resp, 303);
    let after_delete = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("delete must redirect")
        .to_string();
    assert!(
        after_delete.starts_with("/assets/manage/groups"),
        "delete redirect must stay under /assets/manage/groups, was {after_delete}"
    );
    let resp = app
        .server
        .get(&after_delete)
        .add_header(COOKIE, cookies)
        .await;
    assert_status(&resp, 200);
}

/// A group seeded in DB MUST NOT be reachable by role:user through
/// the OLD flat URL family (`/assets/groups/...`). The paths are
/// unrouted now — the pin protects against an accidental re-mount.
#[tokio::test]
#[serial]
async fn legacy_flat_asset_group_urls_stay_unrouted() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let group_uuid = create_test_asset_group(&mut conn, &unique_name("bac-legacy-grp")).await;
    let user_name = unique_name("bac_legacy_user");
    let user = create_test_user(&mut conn, &app.auth_service, &user_name).await;

    // NOTE: `/assets/groups` (no extra segment) matches the user-zone
    // `/assets/{uuid}` route with uuid="groups" and serves the 410
    // tombstone — that is fine (it discloses nothing). What must NOT
    // happen is the old LIST/DETAIL rendering with real group data.
    for probe in [
        format!("/assets/groups/{}", group_uuid),
        format!("/assets/groups/{}/edit", group_uuid),
    ] {
        let resp = app
            .server
            .get(&probe)
            .add_header(COOKIE, format!("access_token={}", user.token))
            .await;
        let status = resp.status_code().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Unrouted paths land on the global `fallback_handler`
        // (303 -> "/"); a hard 404/410 would be equally fine. What
        // must NEVER happen is a 2xx rendering or a redirect back
        // into an asset-group page.
        let unrouted = status == 404 || status == 410 || (status == 303 && location == "/");
        assert!(
            unrouted,
            "{} must be unrouted (404/410 or fallback 303 to /), got {} \
             (Location: {:?}) — the flat asset-group surface must never \
             come back outside the manage nest",
            probe, status, location
        );
    }
}
