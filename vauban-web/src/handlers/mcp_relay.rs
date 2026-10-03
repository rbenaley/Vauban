//! Bare `POST /mcp`. No cookie, session, CSRF or Casbin.
//!
//! The body is not parsed. An allow-list of headers is forwarded on the
//! data pipe; the leaf authenticates the `vbw_` ticket.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tower_http::timeout::TimeoutLayer;

use crate::middleware::client_addr::ClientAddr;
use crate::middleware::resolve_client_ip;

const FALLBACK_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

const MAX_BODY: usize = 1_048_576;

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

pub async fn relay_mcp(
    State(state): State<crate::AppState>,
    ClientAddr(peer): ClientAddr,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_BODY {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let limit = state.config.mcp.relay_rate_limit_per_minute;
    let key = format!("mcp:{}", peer.ip());
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
    let mcp_session_id = one(&headers, header::HeaderName::from_static("mcp-session-id"));
    let mcp_protocol_version = one(
        &headers,
        header::HeaderName::from_static("mcp-protocol-version"),
    );
    match data
        .relay(crate::ipc::proxy_mcp_data::RelayRequest {
            client_ip: peer.ip().to_string(),
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
                response = response.header("mcp-session-id", value);
            }
            response
                .body(axum::body::Body::from(relayed.body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn peer_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(FALLBACK_PEER, |info| info.0.ip())
}

/// `GET /mcp/tunnel` has no outer credential to strip. A denied client
/// IP is refused here, before the upgrade opens a leaf tunnel.
async fn mcp_tunnel_gate(
    State(state): State<crate::AppState>,
    request: Request,
    next: Next,
) -> Response {
    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip = resolve_client_ip(request.headers(), peer_ip(&request), &trusted);
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
    let cap = state.config.mcp.max_tunnels as usize;
    if let Some(data) = state.proxy_mcp.as_ref().and_then(|proxy| proxy.data())
        && data.tunnel_count() >= cap
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(request).await
}

/// Hop-2 routes outside the cookie, CSRF, auth and Casbin layers.
/// `ip_acl` is the outermost layer. The WebSocket has no timeout.
pub fn mcp_bare_router(state: &crate::AppState) -> Router<crate::AppState> {
    let mcp_http = Router::new()
        .route("/mcp", post(relay_mcp))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            state.config.mcp.relay_max_inflight as usize,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(state.config.mcp.relay_timeout_seconds),
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
