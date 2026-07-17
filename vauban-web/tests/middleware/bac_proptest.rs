//! BAC hardening — property-based invariants on the `require_*`
//! route-layer gates (proptest).
//!
//! The E2E matrix (`tests/web/bac_gate_matrix_test.rs`) pins the
//! deterministic outcomes for the three concrete roles; the
//! properties below fuzz the WHOLE `PermissionContext` space (2^26
//! combinations) and arbitrary URL suffixes to pin the invariants
//! that make the gates safe by construction:
//!
//! 1. **Fail-closed / flag-isolation**: for every gate, the decision
//!    depends on its OWN flag and nothing else. `flag == false` =>
//!    403 whatever the other 25 booleans say; `flag == true` => the
//!    request reaches the handler.
//! 2. **Anti-oracle**: under a fenced nest, a caller without the
//!    permission receives ONE stable 403 (same status, same body)
//!    for every conceivable path suffix — no existence
//!    differential.
//! 3. **Deny-all default**: `PermissionContext::default()` refuses
//!    every gate (the fallback taken when the extension is missing).

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use axum::routing::get;
use proptest::prelude::*;
use tower::ServiceExt;

use vauban_web::auth::PermissionContext;
use vauban_web::middleware::AuthUser;

/// Map a 26-bit mask onto the 26 boolean fields of
/// [`PermissionContext`]. The mapping is arbitrary but FIXED; the
/// properties only rely on being able to reach any combination.
fn perms_from_bits(bits: u32) -> PermissionContext {
    let b = |i: u32| bits & (1 << i) != 0;
    PermissionContext {
        users_read: b(0),
        users_write: b(1),
        users_manage_admins: b(2),
        assets_read: b(3),
        assets_read_all: b(4),
        assets_manage: b(5),
        groups_read: b(6),
        groups_write: b(7),
        groups_manage_members: b(8),
        access_rules_read: b(9),
        access_rules_write: b(10),
        auth_sessions_read: b(11),
        auth_sessions_write: b(12),
        sessions_read: b(13),
        sessions_write: b(14),
        sessions_supervise: b(15),
        sessions_bypass_access_rules: b(16),
        admin_view: b(17),
        profile_read: b(18),
        profile_write: b(19),
        iacs_request: b(20),
        iacs_read: b(21),
        iacs_manage: b(22),
        assets_connect_iacs: b(23),
        vault_secrets_read: b(24),
        vault_secrets_manage: b(25),
    }
}

type GateFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;
type GateFn = fn(Request, Next) -> GateFuture;

fn users_gate(req: Request, next: Next) -> GateFuture {
    Box::pin(vauban_web::middleware::require_permission::require_users_read(req, next))
}
fn groups_gate(req: Request, next: Next) -> GateFuture {
    Box::pin(vauban_web::middleware::require_permission::require_groups_read(req, next))
}
fn access_gate(req: Request, next: Next) -> GateFuture {
    Box::pin(vauban_web::middleware::require_permission::require_access_rules_read(req, next))
}
fn assets_manage_gate(req: Request, next: Next) -> GateFuture {
    Box::pin(vauban_web::middleware::require_assets_manage::require_assets_manage(req, next))
}

type FlagFn = fn(&PermissionContext) -> bool;
type GateCase = (&'static str, GateFn, FlagFn);

/// The four production gates with the flag extractor each one is
/// supposed to (and ONLY supposed to) observe.
fn gates() -> Vec<GateCase> {
    vec![
        ("require_users_read", users_gate as GateFn, |p| p.users_read),
        ("require_groups_read", groups_gate as GateFn, |p| {
            p.groups_read
        }),
        ("require_access_rules_read", access_gate as GateFn, |p| {
            p.access_rules_read
        }),
        ("require_assets_manage", assets_manage_gate as GateFn, |p| {
            p.assets_manage
        }),
    ]
}

fn test_auth_user() -> AuthUser {
    AuthUser {
        uuid: "00000000-0000-0000-0000-00000000abcd".into(),
        username: "prop-user".into(),
        mfa_verified: true,
        is_superuser: false,
        is_staff: false,
    }
}

/// Minimal router: `gate` fences a catch-all probe route; the outer
/// layer injects a synthetic `AuthUser` + the given
/// `PermissionContext`, mirroring what `auth_middleware` +
/// `permission_context_middleware` do in production.
fn router_with(gate: GateFn, perms: PermissionContext) -> Router {
    let auth_user = test_auth_user();
    Router::new()
        .route("/probe", get(|| async { (StatusCode::OK, "downstream") }))
        .route(
            "/probe/{*rest}",
            get(|| async { (StatusCode::OK, "downstream") }),
        )
        .layer(from_fn(gate))
        .layer(from_fn(move |mut req: Request, next: Next| {
            let perms = perms.clone();
            let auth_user = auth_user.clone();
            async move {
                req.extensions_mut().insert(auth_user);
                req.extensions_mut().insert(perms);
                next.run(req).await
            }
        }))
}

async fn probe(router: Router, path: &str) -> (StatusCode, Vec<u8>) {
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router service");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, body.to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Property 1 — fail-closed / flag-isolation. For an ARBITRARY
    /// permission context, each gate lets the request through IFF
    /// its own flag is set. No combination of the other 25 flags can
    /// flip the decision (a `role:user` granted a bag of unrelated
    /// permissions still cannot cross a fence it does not hold).
    #[test]
    fn gate_decision_depends_only_on_its_flag(bits in any::<u32>()) {
        let rt = runtime();
        for (name, gate, flag) in gates() {
            let perms = perms_from_bits(bits);
            let expected_pass = flag(&perms);
            let (status, _) = rt.block_on(probe(router_with(gate, perms), "/probe"));
            if expected_pass {
                prop_assert_eq!(
                    status, StatusCode::OK,
                    "{}: flag=true must pass whatever the other flags (bits={:#028b})",
                    name, bits
                );
            } else {
                prop_assert_eq!(
                    status, StatusCode::FORBIDDEN,
                    "{}: flag=false must yield 403 whatever the other flags (bits={:#028b})",
                    name, bits
                );
            }
        }
    }

    /// Property 2 — anti-oracle. A denied caller observes ONE stable
    /// (status, body) pair for every path suffix under the fenced
    /// nest: UUID-shaped, garbage, nested, dotted... nothing about
    /// the path leaks through the 403.
    #[test]
    fn denied_response_is_path_independent(
        bits in any::<u32>(),
        segments in prop::collection::vec("[a-zA-Z0-9._~-]{1,24}", 1..4),
    ) {
        let rt = runtime();
        for (name, gate, flag) in gates() {
            // Force the gate's own flag OFF, keep the rest arbitrary.
            let mut perms = perms_from_bits(bits);
            match name {
                "require_users_read" => perms.users_read = false,
                "require_groups_read" => perms.groups_read = false,
                "require_access_rules_read" => perms.access_rules_read = false,
                "require_assets_manage" => perms.assets_manage = false,
                _ => unreachable!(),
            }
            let _ = flag;

            let (baseline_status, baseline_body) =
                rt.block_on(probe(router_with(gate, perms.clone()), "/probe"));
            prop_assert_eq!(baseline_status, StatusCode::FORBIDDEN, "{}", name);

            let path = format!("/probe/{}", segments.join("/"));
            let (status, body) = rt.block_on(probe(router_with(gate, perms), &path));
            prop_assert_eq!(
                status, StatusCode::FORBIDDEN,
                "{}: probe {} must be refused", name, path
            );
            prop_assert_eq!(
                body, baseline_body,
                "{}: 403 body for {} differs from the baseline — path oracle",
                name, path
            );
        }
    }
}

/// Property 3 — deny-all default (deterministic pin, kept next to the
/// properties it underpins). `PermissionContext::default()` is the
/// value the gates fall back to when the extension is missing; every
/// gate MUST refuse it.
#[tokio::test]
async fn default_permission_context_is_deny_all() {
    for (name, gate, flag) in gates() {
        let perms = PermissionContext::default();
        assert!(
            !flag(&perms),
            "{}: PermissionContext::default() must not grant the flag",
            name
        );
        let (status, _) = probe(router_with(gate, perms), "/probe").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{}: the deny-all default context must be refused",
            name
        );
    }
}

/// The 26-bit mapping in `perms_from_bits` must stay exhaustive: if a
/// field is added to `PermissionContext`, this pin fails and the
/// mapping (plus the properties) must be extended.
#[test]
fn perms_from_bits_covers_every_field() {
    // All bits set -> every field true. A newly added field would
    // stay at its `Default::default()` (false) and trip the debug
    // formatting comparison below.
    let all = perms_from_bits(u32::MAX);
    let dump = format!("{:?}", all);
    assert!(
        !dump.contains("false"),
        "perms_from_bits(u32::MAX) left at least one field false — a new \
         PermissionContext field was added without extending the proptest \
         mapping: {}",
        dump
    );
}
