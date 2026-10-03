//! Source pins for the bare hop-2 router and the no-OAuth decision.

#[test]
fn bare_mcp_branch_has_ip_acl_body_cap_and_no_auth_stack() {
    let src = include_str!("../../src/handlers/mcp_relay.rs");
    let start = src.find("fn mcp_bare_router").expect("bare /mcp router");
    let block = &src[start..];
    assert!(block.contains("ip_acl_middleware"));
    assert!(block.contains("DefaultBodyLimit"));
    assert!(block.contains("ConcurrencyLimitLayer"));
    assert!(block.contains("TimeoutLayer"));
    assert!(block.contains("/mcp/tunnel"));
    assert!(block.contains("mcp_tunnel_gate"));
    assert!(src.contains("client_acl.permits("));
    for forbidden in [
        "csrf",
        "auth_middleware",
        "permission_context",
        "audit_middleware",
    ] {
        assert!(
            !block.contains(forbidden),
            "bare hop-2 router must not include {forbidden}"
        );
    }
}

#[test]
fn relay_does_not_parse_the_body_or_log_the_ticket() {
    let src = include_str!("../../src/handlers/mcp_relay.rs");
    let start = src.find("pub async fn relay_mcp").expect("relay_mcp");
    let body = &src[start..];
    assert!(
        !body.contains("serde_json::from_"),
        "the relay must not parse JSON-RPC"
    );
    assert!(
        !body.contains("authorization =") && !body.contains("body ="),
        "logs must not carry the ticket or the body"
    );
    assert!(!body.contains("COOKIE") && !body.contains("header::COOKIE"));
}

#[test]
fn no_oauth_discovery_routes() {
    let src = include_str!("../../src/main.rs");
    assert!(!src.contains("oauth-authorization-server"));
    assert!(!src.contains("oauth-protected-resource"));
    assert!(!src.contains("VAUBAN_MCP_PROXY_URL"));
}

#[test]
fn hop1_url_comes_from_the_public_origin() {
    let api = include_str!("../../src/handlers/api/mcp_sessions.rs");
    let web = include_str!("../../src/handlers/web/mcp.rs");
    assert!(api.contains("public_mcp_url()"));
    assert!(web.contains("public_mcp_url()"));
    assert!(!api.contains("http://"));
    assert!(!web.contains("http://127.0.0.1:19443"));
}
