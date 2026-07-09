//! VAUBAN Web - Global client IP ACL middleware
//! (`[security] allowed_client_networks`).
//!
//! Mounted in `common_layers` BEFORE `auth_middleware` so it covers every
//! HTTP, API, and WebSocket route. The ACME TLS-ALPN-01 challenge is
//! answered below the HTTP layer (`AcmeResolver`, rustls) and is therefore
//! exempt by construction -- no CA allowlist to maintain.
//!
//! Stealth-deny contract (SEC-04/05): a denied IP must NEVER receive a
//! response shape that reveals the ACL exists.
//!
//! - Login endpoints (`POST /auth/login`, `POST /api/v1/auth/login`) are
//!   short-circuited with the exact generic "Invalid credentials" failure,
//!   AFTER a dummy Argon2 verification so the response costs the same
//!   wall-clock time as a real wrong-password attempt (no timing oracle).
//! - Every other request is DOWNGRADED to anonymous: the `access_token`
//!   cookie, `Authorization` header, and `X-API-Key` header are stripped
//!   before the auth middleware runs. The observable behaviour is exactly
//!   that of a logged-out visitor (login page served, 303 to `/login` on
//!   protected pages, 401 on the API, WS refused as unauthenticated) --
//!   even with a valid stolen cookie or API key.
//!
//! Loopback is always permitted by the shared matcher (anti-lockout) and
//! an empty configured list disables the ACL entirely (allow all).

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, header},
    middleware::Next,
    response::Response,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::AppState;
use crate::error::{AppError, is_htmx_request};
use crate::ipc::AuditEvent;
use crate::middleware::resolve_client_ip;
use crate::services::emit_audit;
use shared::messages::AuditEventType;

/// Fallback peer when `ConnectInfo` is absent (in-process tests drive the
/// router without a TCP socket). Loopback is always permitted, which is
/// exactly the anti-lockout semantic we want for a peer we cannot see.
const FALLBACK_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Login endpoints that must be short-circuited with the generic
/// credential failure instead of the anonymous downgrade (an anonymous
/// downgrade would still run the real credential check and succeed).
fn is_login_path(method: &Method, path: &str) -> bool {
    *method == Method::POST && (path == "/auth/login" || path == "/api/v1/auth/login")
}

/// Global client IP ACL enforcement. See the module docs for the contract.
pub async fn ip_acl_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !state.client_acl.is_enabled() {
        return Ok(next.run(request).await);
    }

    // Same resolution seam as every other consumer: raw TCP peer, then
    // X-Forwarded-For / X-Real-IP ONLY when the peer is a trusted proxy.
    let connect_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(FALLBACK_PEER, |ci| ci.0.ip());
    let trusted = state.config.security.parsed_trusted_proxies();
    let client_ip = resolve_client_ip(request.headers(), connect_ip, &trusted);

    if state.client_acl.permits(client_ip) {
        return Ok(next.run(request).await);
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();

    if is_login_path(&method, &path) {
        // Short-circuit: never let a denied IP reach the credential check.
        // Equalize timing first so the response costs the same as a real
        // wrong-password failure, then reply with the byte-identical
        // generic error. Audited in the WORM log (internal only).
        crate::services::auth::equalize_login_timing(&state).await;
        emit_audit(
            &state,
            AuditEvent::new(
                AuditEventType::AuthFailure,
                r#"{"reason":"client_ip_denied"}"#,
            )
            .ip(Some(client_ip)),
        );
        let htmx = is_htmx_request(request.headers());
        return crate::handlers::auth::login_invalid_credentials_response(htmx);
    }

    // Anonymous downgrade: strip every credential carrier so the request
    // proceeds exactly like a logged-out visitor's. debug! only -- a port
    // scan or crawler from a denied range must not flood the operator's
    // terminal at INFO.
    tracing::debug!(
        client_ip = %client_ip,
        method = %method,
        path = %path,
        "client IP outside allowed_client_networks; downgrading request to anonymous"
    );
    strip_credentials(&mut request);
    Ok(next.run(request).await)
}

/// Remove the `Authorization` header, the `X-API-Key` header, and the
/// `access_token` cookie from the request. Other cookies (CSRF, flash,
/// browser timezone) are preserved so the request stays indistinguishable
/// from a genuine anonymous visitor carrying the same browser state.
fn strip_credentials(request: &mut Request) {
    let headers = request.headers_mut();
    headers.remove(header::AUTHORIZATION);
    headers.remove("X-API-Key");

    let filtered_cookies: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| {
            pair.split_once('=')
                .is_none_or(|(name, _)| name.trim() != "access_token")
        })
        .map(str::to_string)
        .collect();

    headers.remove(header::COOKIE);
    if !filtered_cookies.is_empty()
        && let Ok(rebuilt) = HeaderValue::from_str(&filtered_cookies.join("; "))
    {
        headers.insert(header::COOKIE, rebuilt);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request_with_headers(pairs: &[(&str, &str)]) -> Request {
        let mut builder = axum::http::Request::builder().uri("/dashboard");
        for (name, value) in pairs {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).expect("request")
    }

    // ==================== is_login_path ====================

    #[test]
    fn login_paths_are_matched_on_post_only() {
        assert!(is_login_path(&Method::POST, "/auth/login"));
        assert!(is_login_path(&Method::POST, "/api/v1/auth/login"));
        assert!(!is_login_path(&Method::GET, "/auth/login"));
        assert!(!is_login_path(&Method::POST, "/login"));
        assert!(!is_login_path(&Method::POST, "/auth/login/extra"));
    }

    // ==================== strip_credentials ====================

    #[test]
    fn strip_removes_authorization_and_api_key_headers() {
        let mut req = request_with_headers(&[
            ("Authorization", "Bearer abc"),
            ("X-API-Key", "vbn_secret"),
            ("User-Agent", "test"),
        ]);
        strip_credentials(&mut req);
        assert!(req.headers().get("Authorization").is_none());
        assert!(req.headers().get("X-API-Key").is_none());
        assert!(req.headers().get("User-Agent").is_some());
    }

    #[test]
    fn strip_removes_only_the_access_token_cookie() {
        let mut req = request_with_headers(&[(
            "Cookie",
            "csrf_token=keepme; access_token=steal.me.jwt; vauban_tz=Europe%2FParis",
        )]);
        strip_credentials(&mut req);
        let cookie = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cookie.contains("csrf_token=keepme"));
        assert!(cookie.contains("vauban_tz=Europe%2FParis"));
        assert!(!cookie.contains("access_token"));
    }

    #[test]
    fn strip_removes_cookie_header_when_only_access_token() {
        let mut req = request_with_headers(&[("Cookie", "access_token=steal.me.jwt")]);
        strip_credentials(&mut req);
        assert!(req.headers().get(header::COOKIE).is_none());
    }

    #[test]
    fn strip_handles_requests_without_credentials() {
        let mut req = request_with_headers(&[("User-Agent", "test")]);
        strip_credentials(&mut req);
        assert!(req.headers().get(header::COOKIE).is_none());
        assert!(req.headers().get("Authorization").is_none());
    }

    #[test]
    fn strip_merges_multiple_cookie_headers() {
        let mut req = request_with_headers(&[
            ("Cookie", "csrf_token=a; access_token=jwt1"),
            ("Cookie", "flash=b"),
        ]);
        strip_credentials(&mut req);
        let cookie = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cookie.contains("csrf_token=a"));
        assert!(cookie.contains("flash=b"));
        assert!(!cookie.contains("access_token"));
    }
}
