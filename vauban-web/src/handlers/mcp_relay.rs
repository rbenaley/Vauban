//! Bare `POST /mcp`. No cookie, session, CSRF or Casbin.
//!
//! The body is not parsed. An allow-list of headers is forwarded on the
//! data pipe; the leaf authenticates the `vbw_` ticket.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::sync::Semaphore;
use tower_http::timeout::TimeoutLayer;

use crate::ipc::proxy_mcp_data::TunnelLimits;
use crate::middleware::client_addr::ClientAddr;
use crate::middleware::resolve_client_ip;

const FALLBACK_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

const MAX_BODY: usize = 1_048_576;

/// A `vbw_` ticket is ~70 bytes; 8 KiB leaves room for any bearer.
pub const MAX_AUTHORIZATION_BYTES: usize = 8 * 1024;
pub const MAX_OTHER_HEADER_BYTES: usize = 1024;

const MCP_SESSION_ID: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION: &str = "mcp-protocol-version";

fn header_safe(value: &str) -> bool {
    value
        .chars()
        .all(|c| c == '\t' || (c >= ' ' && c != '\u{7f}'))
}

fn one(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|s| header_safe(s))
}

/// `true` when a forwarded header would not fit the relay message.
pub fn forwarded_headers_too_large(headers: &HeaderMap) -> bool {
    let over = |name: &str, cap: usize| headers.get_all(name).iter().any(|v| v.len() > cap);
    over(header::AUTHORIZATION.as_str(), MAX_AUTHORIZATION_BYTES)
        || [
            header::CONTENT_TYPE.as_str(),
            header::ACCEPT.as_str(),
            MCP_SESSION_ID,
            MCP_PROTOCOL_VERSION,
        ]
        .into_iter()
        .any(|name| over(name, MAX_OTHER_HEADER_BYTES))
}

/// Client address for the hop-2 rate keys, the per-IP tunnel cap and
/// the leaf's `client_ip`. `X-Forwarded-For` counts only when the TCP
/// peer is a trusted proxy.
pub fn hop2_client_ip(state: &crate::AppState, headers: &HeaderMap, connect: SocketAddr) -> IpAddr {
    let trusted = state.config.security.parsed_trusted_proxies();
    resolve_client_ip(headers, connect.ip(), &trusted)
}

pub async fn relay_mcp(
    State(state): State<crate::AppState>,
    client_addr: ClientAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if forwarded_headers_too_large(&headers) {
        return StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.into_response();
    }
    let client_ip = hop2_client_ip(&state, &headers, client_addr.0);
    let limit = state.config.mcp.relay_rate_limit_per_minute;
    let key = format!("mcp:{client_ip}");
    match state.rate_limiter.check(&key, limit).await {
        Ok(result) if !result.allowed => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let Some(proxy) = state.proxy_mcp.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(data) = proxy.data() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(authorization) = one(&headers, header::AUTHORIZATION) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let content_type = one(&headers, header::CONTENT_TYPE).unwrap_or_default();
    let accept = one(&headers, header::ACCEPT).unwrap_or_default();
    let mcp_session_id = one(&headers, header::HeaderName::from_static(MCP_SESSION_ID));
    let mcp_protocol_version = one(
        &headers,
        header::HeaderName::from_static(MCP_PROTOCOL_VERSION),
    );
    match data
        .relay(crate::ipc::proxy_mcp_data::RelayRequest {
            client_ip: client_ip.to_string(),
            authorization,
            content_type,
            accept,
            mcp_session_id,
            mcp_protocol_version,
            body: body.to_vec(),
        })
        .await
    {
        Ok(relayed) => {
            let mut response = Response::builder().status(relayed.status);
            if !relayed.content_type.is_empty()
                && let Ok(value) = relayed.content_type.parse::<header::HeaderValue>()
            {
                response = response.header(header::CONTENT_TYPE, value);
            }
            if let Some(sid) = relayed.mcp_session_id.filter(|s| header_safe(s))
                && let Ok(value) = sid.parse::<header::HeaderValue>()
            {
                response = response.header(MCP_SESSION_ID, value);
            }
            response
                .body(axum::body::Body::from(relayed.body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn peer_addr(request: &Request) -> SocketAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(FALLBACK_PEER, |info| info.0)
}

/// Tunnel caps from `[mcp]`.
pub fn tunnel_limits(state: &crate::AppState) -> TunnelLimits {
    TunnelLimits {
        max_total: state.config.mcp.max_tunnels as usize,
        max_per_ip: state.config.mcp.max_tunnels_per_ip as usize,
    }
}

/// `GET /mcp/tunnel` has no outer credential to strip. A denied client
/// IP is refused here, before the upgrade opens a leaf tunnel.
async fn mcp_tunnel_gate(
    State(state): State<crate::AppState>,
    request: Request,
    next: Next,
) -> Response {
    let client_ip = hop2_client_ip(&state, request.headers(), peer_addr(&request));
    if state.client_acl.is_enabled() && !state.client_acl.permits(client_ip) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let limit = state.config.mcp.relay_rate_limit_per_minute;
    let key = format!("mcp-tunnel:{client_ip}");
    match state.rate_limiter.check(&key, limit).await {
        Ok(result) if !result.allowed => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let limits = tunnel_limits(&state);
    if let Some(data) = state.proxy_mcp.as_ref().and_then(|proxy| proxy.data())
        && (data.tunnel_count() >= limits.max_total
            || data.tunnels_for_ip(&client_ip.to_string()) >= limits.max_per_ip)
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(request).await
}

/// `relay_max_inflight` relays at once. One more gets 503, it does not queue.
async fn relay_inflight_gate(permits: Arc<Semaphore>, request: Request, next: Next) -> Response {
    let Ok(_permit) = permits.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    next.run(request).await
}

/// Hop-2 routes outside the cookie, CSRF, auth and Casbin layers.
/// `ip_acl` is the outermost layer. The WebSocket has no timeout.
pub fn mcp_bare_router(state: &crate::AppState) -> Router<crate::AppState> {
    let permits = Arc::new(Semaphore::new(state.config.mcp.relay_max_inflight as usize));
    let mcp_http = Router::new()
        .route("/mcp", post(relay_mcp))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            std::time::Duration::from_secs(state.config.mcp.relay_timeout_seconds),
        ))
        .layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                relay_inflight_gate(Arc::clone(&permits), request, next)
            },
        ));
    let mcp_ws = Router::new()
        .route(
            "/mcp/tunnel",
            get(crate::handlers::websocket::mcp_tunnel_ws),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            mcp_tunnel_gate,
        ));
    mcp_http
        .merge(mcp_ws)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::ip_acl::ip_acl_middleware,
        ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with(name: &'static str, len: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(&"a".repeat(len)).unwrap());
        headers
    }

    #[test]
    fn authorization_cap_is_eight_kib() {
        assert!(!forwarded_headers_too_large(&with("authorization", 8192)));
        assert!(forwarded_headers_too_large(&with("authorization", 8193)));
    }

    #[test]
    fn other_forwarded_headers_cap_is_one_kib() {
        for name in [
            "content-type",
            "accept",
            MCP_SESSION_ID,
            MCP_PROTOCOL_VERSION,
        ] {
            assert!(!forwarded_headers_too_large(&with(name, 1024)), "{name}");
            assert!(forwarded_headers_too_large(&with(name, 1025)), "{name}");
        }
    }

    #[test]
    fn unforwarded_headers_are_not_capped_here() {
        assert!(!forwarded_headers_too_large(&with("x-unrelated", 4096)));
    }

    proptest::proptest! {
        #[test]
        fn header_cap_matches_length(len in 0usize..20_000) {
            proptest::prop_assert_eq!(
                forwarded_headers_too_large(&with("authorization", len)),
                len > MAX_AUTHORIZATION_BYTES
            );
            proptest::prop_assert_eq!(
                forwarded_headers_too_large(&with("accept", len)),
                len > MAX_OTHER_HEADER_BYTES
            );
        }
    }
}
