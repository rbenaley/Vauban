//! Structural pins for the global client IP ACL
//! (`[security] allowed_client_networks`).
//!
//! Pure source-greps that freeze the load-bearing wiring decisions so a
//! future refactor cannot silently unhook the guarantee:
//!
//! 1. `ip_acl_middleware` runs BEFORE `auth_middleware` in BOTH routers
//!    (production `common_layers` and the test router), so a denied IP's
//!    credentials are stripped before any of them is evaluated.
//! 2. The middleware resolves the client IP through `resolve_client_ip`
//!    only (raw XFF/X-Real-IP reads are the classic spoofing regression).
//! 3. ACME stays exempt BY CONSTRUCTION: the resolver lives below the
//!    HTTP layer, so neither side may reference the other.
//! 4. The login timing equalizer is wired in BOTH places that skip the
//!    real Argon2 verification: the ACL short-circuit and the
//!    unknown-username branch (pre-existing enumeration oracle).
//! 5. Boot is fail-closed: `load_with_environment` validates the CIDR
//!    list, and the sacrifice hash is minted at boot.

const MAIN_RS: &str = include_str!("../../src/main.rs");
const TEST_ROUTER_RS: &str = include_str!("../common/mod.rs");
const IP_ACL_RS: &str = include_str!("../../src/middleware/ip_acl.rs");
const AUTH_HANDLER_RS: &str = include_str!("../../src/handlers/auth.rs");
const CONFIG_RS: &str = include_str!("../../src/config.rs");
const ACME_MOD_RS: &str = include_str!("../../src/acme/mod.rs");
const ACME_RESOLVER_RS: &str = include_str!("../../src/acme/resolver.rs");

// =============================================================================
// 1. Mounting order: ip_acl BEFORE auth, in both routers
// =============================================================================

/// In `main.rs`, `ServiceBuilder::layer` order IS execution order: the
/// ip_acl layer must be added before the auth layer.
#[test]
fn main_rs_mounts_ip_acl_before_auth_middleware() {
    let ip_acl_pos = MAIN_RS
        .find("middleware::ip_acl::ip_acl_middleware")
        .expect("main.rs must mount middleware::ip_acl::ip_acl_middleware in common_layers");
    let auth_pos = MAIN_RS
        .find("middleware::auth::auth_middleware")
        .expect("main.rs must mount middleware::auth::auth_middleware in common_layers");
    assert!(
        ip_acl_pos < auth_pos,
        "INVARIANT BROKEN: in ServiceBuilder, layers execute in add order; \
         ip_acl (byte {ip_acl_pos}) must be added BEFORE auth (byte {auth_pos}) \
         so a denied IP's credentials are stripped before evaluation."
    );
}

/// In the test router, `.layer()` on `Router` wraps in REVERSE order
/// (last added = outermost = runs first): ip_acl must be added AFTER
/// auth in the source so it executes BEFORE it, mirroring production.
#[test]
fn test_router_mounts_ip_acl_outermost_before_auth() {
    let ip_acl_pos = TEST_ROUTER_RS
        .find("middleware::ip_acl::ip_acl_middleware")
        .expect("tests/common/mod.rs must mount ip_acl_middleware in build_test_router");
    let auth_pos = TEST_ROUTER_RS
        .find("middleware::auth::auth_middleware,\n        ))")
        .expect("tests/common/mod.rs must mount auth_middleware in build_test_router");
    assert!(
        ip_acl_pos > auth_pos,
        "INVARIANT BROKEN: on Router, the LAST .layer() added is the \
         OUTERMOST (runs first); ip_acl (byte {ip_acl_pos}) must be added \
         AFTER auth (byte {auth_pos}) in build_test_router so the E2E tests \
         exercise the same execution order as production."
    );
}

// =============================================================================
// 2. IP resolution goes through resolve_client_ip only
// =============================================================================

/// The middleware must use the shared trusted-proxy-aware resolver and
/// never read the spoofable headers directly.
#[test]
fn ip_acl_uses_resolve_client_ip_never_raw_headers() {
    assert!(
        IP_ACL_RS.contains("resolve_client_ip("),
        "ip_acl.rs must resolve the client IP via resolve_client_ip \
         (trusted-proxy aware; the single seam shared with audit/api_key)."
    );
    // Forbid the CALL PATTERN (comments may mention the header names).
    assert!(
        !IP_ACL_RS.contains(r#".get("X-Forwarded-For""#)
            && !IP_ACL_RS.contains(r#".get("x-forwarded-for""#)
            && !IP_ACL_RS.contains(r#".get("X-Real-IP""#)
            && !IP_ACL_RS.contains(r#".get("x-real-ip""#),
        "ip_acl.rs must NOT read X-Forwarded-For / X-Real-IP directly: \
         raw header reads bypass the trusted_proxies gate and reopen \
         IP spoofing."
    );
}

/// The decision must go through the shared matcher (`AppState.client_acl`
/// -> `shared::client_acl`), not a local CIDR reimplementation.
#[test]
fn ip_acl_delegates_to_the_shared_matcher() {
    assert!(
        IP_ACL_RS.contains(".client_acl.permits(") || IP_ACL_RS.contains("client_acl.permits("),
        "ip_acl.rs must call AppState.client_acl.permits(...) -- the \
         single matcher shared with vauban-proxy-iacs."
    );
    assert!(
        !IP_ACL_RS.contains("IpNetwork::"),
        "ip_acl.rs must not parse/match CIDRs itself; that logic lives in \
         shared::client_acl (grammar drift between services is the risk)."
    );
}

// =============================================================================
// 3. ACME exemption is structural (below the HTTP layer)
// =============================================================================

/// Neither ACME source file may reference the client ACL, and the
/// middleware may not reach into ALPN/rustls: the exemption holds
/// because the two layers never meet.
#[test]
fn acme_and_ip_acl_never_reference_each_other() {
    for (name, src) in [
        ("acme/mod.rs", ACME_MOD_RS),
        ("acme/resolver.rs", ACME_RESOLVER_RS),
    ] {
        assert!(
            !src.contains("client_acl") && !src.contains("allowed_client_networks"),
            "{name} must NOT reference the client ACL: the ACME TLS-ALPN-01 \
             challenge is exempt because it lives BELOW the HTTP layer, not \
             because of an explicit carve-out."
        );
    }
    // Forbid CODE-LEVEL reaches into the TLS layer (doc comments may
    // legitimately explain the TLS-ALPN-01 exemption).
    assert!(
        !IP_ACL_RS.contains("rustls::")
            && !IP_ACL_RS.contains("alpn_protocols")
            && !IP_ACL_RS.contains("use rustls"),
        "ip_acl.rs must NOT reach into the TLS/ALPN layer; the ACL is a \
         pure HTTP-layer concern."
    );
}

// =============================================================================
// 4. Timing equalizer wiring (anti-enumeration)
// =============================================================================

/// The ACL login short-circuit must equalize timing BEFORE responding.
#[test]
fn ip_acl_login_short_circuit_equalizes_timing() {
    let equalize_pos = IP_ACL_RS
        .find("equalize_login_timing(&state).await")
        .expect("ip_acl.rs must call equalize_login_timing in the login short-circuit");
    let response_pos = IP_ACL_RS
        .find("login_invalid_credentials_response(")
        .expect("ip_acl.rs must reuse handlers::auth::login_invalid_credentials_response");
    assert!(
        equalize_pos < response_pos,
        "the dummy Argon2 verification must run BEFORE the generic response \
         is produced, so an ACL denial costs the same wall-clock time as a \
         wrong-password failure."
    );
}

/// The pre-existing unknown-username branch of `login` must also call
/// the equalizer (that branch used to return without any Argon2 work --
/// a username-enumeration timing oracle).
#[test]
fn login_unknown_username_branch_equalizes_timing() {
    let unknown_user_pos = AUTH_HANDLER_RS
        .find(r#""reason":"unknown_user""#)
        .expect("handlers/auth.rs must audit the unknown_user login failure");
    let window_start = unknown_user_pos.saturating_sub(800);
    let window = &AUTH_HANDLER_RS[window_start..unknown_user_pos];
    assert!(
        window.contains("equalize_login_timing"),
        "the unknown-username branch of login() must call \
         equalize_login_timing right before the generic failure, so \
         response timing cannot reveal whether a username exists."
    );
}

/// The sacrifice hash must be minted at boot in `main.rs` (production
/// parameters, random password) -- never lazily on the request path.
#[test]
fn sacrifice_hash_is_minted_at_boot() {
    assert!(
        MAIN_RS.contains("login_timing_sacrifice_hash"),
        "main.rs must mint the login timing sacrifice hash at boot and \
         store it in AppState."
    );
    assert!(
        !IP_ACL_RS.contains("hash_password("),
        "ip_acl.rs must never hash on the request path; it only verifies \
         against the boot-minted sacrifice hash."
    );
}

// =============================================================================
// 5. Fail-closed boot validation
// =============================================================================

/// `Config::load_with_environment` must validate the security block
/// (CIDR list) so a typo stops the boot instead of altering the policy.
#[test]
fn load_with_environment_validates_security_config() {
    let load_pos = CONFIG_RS
        .find("pub fn load_with_environment")
        .expect("config.rs must define load_with_environment");
    let body = &CONFIG_RS[load_pos..];
    let validate_pos = body
        .find(".security\n            .validate()")
        .expect("load_with_environment must call config.security.validate()");
    // The call must live inside load_with_environment, i.e. before the
    // next `pub fn` after it.
    let next_fn = body[10..]
        .find("pub fn ")
        .map(|p| p + 10)
        .unwrap_or(usize::MAX);
    assert!(
        validate_pos < next_fn,
        "security.validate() must be called INSIDE load_with_environment \
         (fail-closed at boot), not in some optional helper."
    );
}

/// The `SecurityConfig::validate` seam itself must delegate to the
/// shared fail-closed parser.
#[test]
fn security_config_validate_uses_shared_parser() {
    assert!(
        CONFIG_RS.contains("shared::client_acl::ClientAcl::parse(&self.allowed_client_networks)"),
        "SecurityConfig::validate must parse allowed_client_networks via \
         shared::client_acl::ClientAcl::parse (single grammar across services)."
    );
}
