//! Source pins for the bare hop-2 router and the no-OAuth decision.

#[test]
fn bare_mcp_branch_has_ip_acl_body_cap_and_no_auth_stack() {
    let src = include_str!("../../src/handlers/mcp_relay.rs");
    let start = src.find("fn mcp_bare_router").expect("bare /mcp router");
    let block = &src[start..];
    assert!(block.contains("ip_acl_middleware"));
    assert!(block.contains("DefaultBodyLimit"));
    assert!(block.contains("relay_inflight_gate"));
    assert!(src.contains("permits.try_acquire_owned()"));
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

fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src.find(signature).expect(signature);
    let tail = &src[start..];
    let open = tail.find('{').expect("body");
    let mut depth = 0i32;
    for (i, ch) in tail[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..open + i + 1];
                }
            }
            _ => {}
        }
    }
    tail
}

const WS_SRC: &str = include_str!("../../src/handlers/websocket.rs");
const RELAY_SRC: &str = include_str!("../../src/handlers/mcp_relay.rs");

#[test]
fn tunnel_frames_are_capped_at_the_pipe_chunk() {
    let wrapper = fn_body(WS_SRC, "pub async fn mcp_tunnel_ws(");
    assert!(wrapper.contains("max_message_size(chunk)"));
    assert!(wrapper.contains("max_frame_size(chunk)"));
    assert!(wrapper.contains("MCP_PIPE_CHUNK_BYTES"));
    assert!(RELAY_SRC.contains("REQUEST_HEADER_FIELDS_TOO_LARGE"));
}

#[test]
fn open_tunnel_runs_only_after_the_upgrade() {
    let socket = fn_body(WS_SRC, "async fn handle_mcp_tunnel_socket(");
    assert!(socket.contains("data.open_tunnel("));
    assert_eq!(
        WS_SRC.matches(".open_tunnel(").count(),
        1,
        "open_tunnel must only be called from handle_mcp_tunnel_socket"
    );
    let wrapper = fn_body(WS_SRC, "pub async fn mcp_tunnel_ws(");
    assert!(!wrapper.contains("open_tunnel("));
}

#[test]
fn hop2_paths_resolve_the_client_ip_through_trusted_proxies() {
    for (src, sig) in [
        (RELAY_SRC, "pub async fn relay_mcp("),
        (RELAY_SRC, "async fn mcp_tunnel_gate("),
        (WS_SRC, "pub async fn mcp_tunnel_ws("),
    ] {
        let body = fn_body(src, sig);
        assert!(body.contains("hop2_client_ip("), "{sig}");
        assert!(!body.contains("peer.ip()"), "{sig}");
        assert!(!body.contains("client_addr.0.ip()"), "{sig}");
    }
    assert!(!RELAY_SRC.contains("peer.ip()"));
    assert!(!RELAY_SRC.contains("client_addr.0.ip()"));
    let helper = fn_body(RELAY_SRC, "pub fn hop2_client_ip(");
    assert!(helper.contains("parsed_trusted_proxies()"));
    assert!(helper.contains("resolve_client_ip("));
}

#[test]
fn per_ip_tunnel_cap_is_checked_in_the_gate_and_at_registration() {
    let gate = fn_body(RELAY_SRC, "async fn mcp_tunnel_gate(");
    assert!(gate.contains("tunnels_for_ip("));
    assert!(gate.contains("max_per_ip"));
    let data = include_str!("../../src/ipc/proxy_mcp_data.rs");
    let open = fn_body(data, "pub fn open_tunnel(");
    assert!(open.contains("TunnelRefused::PerIp"));
    assert!(open.contains("TunnelRefused::Total"));
}
