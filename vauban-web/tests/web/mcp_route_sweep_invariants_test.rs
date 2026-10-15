//! Sweep of every MCP web POST route (MCP Arch §11, §13.2).
//!
//! Each MCP mutation is a human action: `WebAuthUser` (JWT cookie + TOTP),
//! CSRF double-submit before any side effect, and a `PermissionContext`
//! gate. An API key is never a human on these routes. The route table is
//! read from `main.rs`, so a new MCP POST route fails here until it is
//! added to `ROUTES` with its gates.
use crate::common::{TestApp, build_test_router};
use crate::fixtures::{create_admin_user, unique_name};
use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION};
use axum_test::TestServer;
use serial_test::serial;
use std::collections::BTreeSet;

const MAIN: &str = include_str!("../../src/main.rs");
const MCP_ACCESS: &str = include_str!("../../src/handlers/web/mcp_access.rs");
const MCP_HITL: &str = include_str!("../../src/handlers/web/mcp_hitl.rs");
const MCP_CONNECT: &str = include_str!("../../src/handlers/web/mcp.rs");
const MCP_DISCOVER: &str = include_str!("../../src/handlers/web/mcp_discover.rs");
const CONTESTATION: &str = include_str!("../../src/handlers/web/access_contestation.rs");

struct Route {
    path: &'static str,
    handler: &'static str,
    src: &'static str,
    /// `PermissionContext` field the handler re-asserts.
    perm: &'static str,
}

const U: &str = "00000000-0000-4000-8000-000000000001";

const ROUTES: &[Route] = &[
    Route {
        path: "/sessions/mcp/access",
        handler: "create_mcp_access_rule_web",
        src: MCP_ACCESS,
        perm: "access_rules_write",
    },
    Route {
        path: "/sessions/mcp/access/{U}/edit",
        handler: "update_mcp_access_rule_web",
        src: MCP_ACCESS,
        perm: "access_rules_write",
    },
    Route {
        path: "/sessions/mcp/access/{U}/delete",
        handler: "delete_mcp_access_rule_web",
        src: MCP_ACCESS,
        perm: "access_rules_write",
    },
    Route {
        path: "/sessions/mcp/contestations/{U}/claim",
        handler: "contestation_claim_web",
        src: CONTESTATION,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/mcp/contestations/{U}/uphold",
        handler: "contestation_uphold_web",
        src: CONTESTATION,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/mcp/contestations/{U}/overturn",
        handler: "contestation_overturn_web",
        src: CONTESTATION,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/mcp/{U}/p1/approve",
        handler: "mcp_hitl_approve_web",
        src: MCP_HITL,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/mcp/{U}/p1/deny",
        handler: "mcp_hitl_deny_web",
        src: MCP_HITL,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/mcp-hitl/{U}/p1/approve",
        handler: "mcp_hitl_approve_web",
        src: MCP_HITL,
        perm: "sessions_supervise",
    },
    Route {
        path: "/sessions/{U}/contest",
        handler: "contestation_open_web",
        src: CONTESTATION,
        perm: "sessions_supervise",
    },
    Route {
        path: "/assets/{U}/connect-mcp",
        handler: "connect_mcp",
        src: MCP_CONNECT,
        perm: "assets_connect_mcp",
    },
    Route {
        path: "/assets/manage/{U}/discover-mcp-tools",
        handler: "discover_mcp_tools_web",
        src: MCP_DISCOVER,
        perm: "assets_manage",
    },
    Route {
        path: "/assets/manage/{U}/approve-mcp-tools",
        handler: "approve_mcp_tools_web",
        src: MCP_DISCOVER,
        perm: "assets_manage",
    },
];

fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(&format!("pub async fn {name}("))
        .or_else(|| src.find(&format!("\nasync fn {name}(")))
        .unwrap_or_else(|| panic!("handler {name} not found"));
    let rest = &src[start + 1..];
    let end = [
        "\npub async fn ",
        "\nasync fn ",
        "\nfn ",
        "\npub fn ",
        "\n#[cfg(test)]",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    &src[start..start + 1 + end]
}

/// The handler (or the private helper it delegates to) that holds the gates.
fn gated_body(r: &Route) -> &'static str {
    let body = fn_body(r.src, r.handler);
    if body.contains("decide_web(") {
        fn_body(r.src, "decide_web")
    } else {
        body
    }
}

#[test]
fn every_mcp_post_route_is_in_the_sweep() {
    let routed: BTreeSet<&str> = MAIN
        .match_indices("post(handlers::web::")
        .filter_map(|(i, m)| {
            let name = &MAIN[i + m.len()..];
            let name = &name[..name.find(')')?];
            (name.contains("mcp") || name.contains("contestation")).then_some(name)
        })
        .collect();
    let swept: BTreeSet<&str> = ROUTES.iter().map(|r| r.handler).collect();
    assert_eq!(
        routed, swept,
        "add the new MCP POST route to ROUTES with its gates"
    );
}

#[test]
fn every_mcp_post_handler_is_human_csrf_and_permission_gated() {
    for r in ROUTES {
        let sig = fn_body(r.src, r.handler);
        assert!(
            sig.contains("WebAuthUser"),
            "{}: human session only",
            r.handler
        );
        assert!(
            sig.contains("PermissionContext"),
            "{}: PermissionContext",
            r.handler
        );
        let body = gated_body(r);
        let csrf = body
            .find("csrf_ok(")
            .or_else(|| body.find("validate_double_submit("))
            .unwrap_or_else(|| panic!("{}: no CSRF double-submit", r.handler));
        assert!(
            body.contains(&format!("perms.{}", r.perm)),
            "{}: must re-assert perms.{}",
            r.handler,
            r.perm
        );
        for effect in ["db_pool", "proxy_mcp", "access_client", "mcp_control::"] {
            if let Some(at) = body.find(effect) {
                assert!(
                    csrf < at,
                    "{}: CSRF must be checked before {effect}",
                    r.handler
                );
            }
        }
        for forbidden in ["is_staff", "is_superuser"] {
            assert!(
                !body.contains(forbidden),
                "{}: {forbidden} is not authz",
                r.handler
            );
        }
    }
}

fn refused_like_anonymous(resp: &axum_test::TestResponse) -> bool {
    let code = resp.status_code().as_u16();
    let to_login = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|l| l.starts_with("/login"));
    code == 401 || code == 403 || ((300..400).contains(&code) && to_login)
}

/// Live router: anonymous and an API key (Bearer or `X-API-Key`) are refused
/// before any handler. (The human JWT itself may come as cookie or Bearer.)
#[tokio::test]
#[serial]
async fn mcp_post_routes_refuse_anonymous_and_api_keys() {
    let app = TestApp::spawn().await;
    let server = TestServer::new(build_test_router(app.app_state.clone())).unwrap();
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("test_sweep")).await;
    let csrf = app.generate_csrf_token();
    for r in ROUTES {
        let path = r.path.replace("{U}", U);
        let form = [
            ("csrf_token", csrf.as_str()),
            ("justification", "sweep test only"),
        ];
        let cookie = format!("__vauban_csrf={csrf}");
        let attempts = [
            (
                "anonymous",
                server.post(&path).add_header(COOKIE, cookie.clone()),
            ),
            (
                "api key bearer",
                server
                    .post(&path)
                    .add_header(COOKIE, cookie.clone())
                    .add_header(AUTHORIZATION, format!("Bearer {}", admin.api_key)),
            ),
            (
                "api key header",
                server
                    .post(&path)
                    .add_header(COOKIE, cookie.clone())
                    .add_header("x-api-key", admin.api_key.clone()),
            ),
        ];
        for (who, req) in attempts {
            let resp = req.form(&form).await;
            assert!(
                refused_like_anonymous(&resp),
                "{path} as {who}: got {} {:?}",
                resp.status_code(),
                resp.headers().get(LOCATION)
            );
        }
    }
}
