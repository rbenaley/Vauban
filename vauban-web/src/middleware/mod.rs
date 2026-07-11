pub mod api_key;
pub mod audit;
/// VAUBAN Web - Middleware module.
pub mod auth;
pub mod browser_tz;
pub mod client_addr;
pub mod csrf;
pub mod flash;
pub mod ip_acl;
pub mod permissions;
pub mod require_assets_manage;
pub mod require_iacs_manage;
pub mod require_vault_secrets_manage;
pub mod security;

pub use audit::*;
pub use auth::*;
pub use browser_tz::*;
pub use client_addr::*;
pub use flash::*;
pub use security::*;

use axum::extract::OriginalUri;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;

use crate::error::AppError;

/// Build the response a route-layer permission gate must return when
/// the caller is **not authenticated** (no `AuthUser` in the request
/// extensions: cookie missing, JWT expired, session revoked, ...).
///
/// The shape is content-negotiated by URL family so it matches the
/// shape of the `AuthUser` / `WebAuthUser` extractor rejections that
/// downstream API and HTML handlers already produce:
///
/// - `/api/...`  -> 401 JSON `{"error":"Authentication required",...}`,
///   identical to what `AuthUser::from_request_parts` returns. API
///   clients (curl, IaC, M2M) MUST get a JSON 401, not a 303 to
///   `/login`, otherwise they cannot tell auth-expired apart from
///   forbidden, and they cannot follow an HTML redirect.
/// - everything else  -> 303 redirect to `/login`, identical to what
///   `WebAuthUser::from_request_parts` returns. Browsers naturally
///   follow the redirect and the user lands on the login form, the
///   same UX as every other admin page.
///
/// Without this branching, a route_layer like `require_assets_manage`
/// (mounted on BOTH the `/assets/manage` HTML nest AND the
/// `/api/v1/assets/manage` JSON nest) would either redirect API
/// callers to `/login` (breaks M2M) or serve a JSON 403 to a
/// browser that just had its session expire (the symptom this
/// helper fixes).
///
/// # Why we read `OriginalUri`, not `request.uri()`
///
/// When a `Router::nest("/api/v1/assets/manage", ...)` mounts a
/// nested router carrying this middleware as a `route_layer`,
/// axum strips the nest prefix from `request.uri()` before
/// invoking inner middlewares -- the layer sees `/groups` instead
/// of `/api/v1/assets/manage/groups`. The `OriginalUri` extension
/// preserves the full path that the client requested. Without
/// reading it, every API caller would fall through to the HTML
/// branch and be redirected to `/login` (regression).
pub fn unauthenticated_response_for(request: &Request) -> Response {
    let original_path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    if original_path.starts_with("/api/") {
        AppError::Auth("Authentication required".to_string()).into_response()
    } else {
        AppError::AuthRedirect.into_response()
    }
}

/// Resolve the real client IP address.
///
/// Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are only trusted when the
/// direct TCP connection originates from an address listed in `trusted_proxies`.
/// If the list is empty or the connection does not come from a trusted proxy,
/// the raw TCP peer address is returned.  This prevents clients from spoofing
/// their source IP by injecting these headers directly.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    connect_ip: IpAddr,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    // Only trust proxy headers when the direct connection is from a trusted proxy
    if !trusted_proxies.is_empty() && trusted_proxies.contains(&connect_ip) {
        // Try X-Forwarded-For first (comma-separated list, first is original client)
        if let Some(xff) = headers.get("X-Forwarded-For")
            && let Ok(xff_str) = xff.to_str()
            && let Some(first_ip) = xff_str.split(',').next()
            && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
        {
            return ip;
        }

        // Try X-Real-IP
        if let Some(real_ip) = headers.get("X-Real-IP")
            && let Ok(ip_str) = real_ip.to_str()
            && let Ok(ip) = ip_str.parse::<IpAddr>()
        {
            return ip;
        }
    }

    // Default: use the actual TCP connection address
    connect_ip
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_ignores_xff_when_no_trusted_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());

        let connect_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec![];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_resolve_ignores_xff_when_not_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());

        let connect_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_resolve_trusts_xff_when_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.50".parse().unwrap());

        let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "203.0.113.50");
    }

    #[test]
    fn test_resolve_trusts_x_real_ip_when_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "8.8.8.8".parse().unwrap());

        let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "8.8.8.8");
    }

    #[test]
    fn test_resolve_xff_takes_priority_over_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.1.1.1".parse().unwrap());
        headers.insert("X-Real-IP", "2.2.2.2".parse().unwrap());

        let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "1.1.1.1");
    }

    #[test]
    fn test_resolve_fallback_on_invalid_xff_from_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "not-an-ip".parse().unwrap());

        let connect_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_resolve_first_ip_from_xff_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "203.0.113.50, 70.41.3.18, 150.172.238.178".parse().unwrap(),
        );

        let connect_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "203.0.113.50");
    }

    #[test]
    fn test_resolve_ipv6_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "2001:db8::1".parse().unwrap());

        let connect_ip: IpAddr = "::1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["::1".parse().unwrap()];

        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "2001:db8::1");
    }

    // ------------------------------------------------------------------
    // unauthenticated_response_for: content-negotiation by URL family.
    //
    // The function reads `OriginalUri` from the request extensions to
    // see the full URL the client requested (axum strips the nest
    // prefix from `request.uri()` for inner middlewares). Each test
    // builds a fresh `Request` and inserts an `OriginalUri` so the
    // helper sees the path a real production caller would carry.
    // ------------------------------------------------------------------

    use axum::body::Body;
    use axum::extract::OriginalUri;
    use axum::extract::Request;
    use axum::http::{StatusCode, Uri};

    fn req_with_original_uri(path: &str) -> Request {
        let uri: Uri = path.parse().expect("valid uri");
        let mut req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("request builder");
        req.extensions_mut().insert(OriginalUri(uri));
        req
    }

    #[test]
    fn unauthenticated_response_redirects_for_html_pages() {
        let req = req_with_original_uri("/assets/manage");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "HTML route must yield a 303 redirect to /login (matches WebAuthUser)"
        );
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(location, "/login");
    }

    #[test]
    fn unauthenticated_response_redirects_for_iacs_admin() {
        // Pin: the IACS admin sub-tree must keep the redirect contract
        // (regression-proof against future helper rewrites).
        let req = req_with_original_uri("/iacs/admin");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[test]
    fn unauthenticated_response_redirects_for_root_html() {
        let req = req_with_original_uri("/groups/new");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[test]
    fn unauthenticated_response_returns_401_json_for_api_routes() {
        let req = req_with_original_uri("/api/v1/assets/manage/abc");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "API route must yield 401 JSON, not a redirect (matches AuthUser)"
        );
        let location = resp.headers().get("location");
        assert!(
            location.is_none(),
            "API 401 must NOT carry a Location header (clients should not follow a redirect)"
        );
    }

    #[test]
    fn unauthenticated_response_api_root_is_json_too() {
        let req = req_with_original_uri("/api/anything");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unauthenticated_response_api_lookalikes_are_html() {
        // A path that *contains* "/api" but doesn't START with "/api/"
        // must still be treated as an HTML page (defence against
        // accidental URL-family confusion).
        let req = req_with_original_uri("/something/api/probe");
        let resp = unauthenticated_response_for(&req);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    /// Defensive: when no `OriginalUri` extension is present (the
    /// middleware is somehow invoked outside of a nested router), the
    /// helper falls back to `request.uri().path()` so the contract
    /// still applies. This is the path used by unit tests that drive
    /// the middleware in isolation (no Router::nest).
    #[test]
    fn unauthenticated_response_falls_back_to_request_uri() {
        let req = axum::http::Request::builder()
            .uri("/api/v1/foo")
            .body(Body::empty())
            .expect("req");
        // No OriginalUri extension inserted.
        let resp = unauthenticated_response_for(&req);
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "fallback to request.uri() must keep API path -> 401 contract"
        );
    }
}
