pub mod api_key;
pub mod audit;
/// VAUBAN Web - Middleware module.
pub mod auth;
pub mod browser_tz;
pub mod client_addr;
pub mod cors;
pub mod csrf;
pub mod flash;
pub mod ip_acl;
pub mod permissions;
pub mod require_assets_manage;
pub mod require_iacs_manage;
pub mod require_permission;
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
/// Proxy headers are read only when the TCP peer is one of
/// `trusted_proxies`. Otherwise the peer address is the answer: a client
/// that connects directly cannot choose its address with a header.
///
/// `X-Forwarded-For` is read from the right. Each proxy appends the
/// address it received the request from, so the rightmost entries are
/// the ones our own proxies wrote, and everything to their left came
/// from the client. The answer is the first entry, walking leftward,
/// that is not a trusted proxy: the address the outermost trusted proxy
/// saw. Taking the leftmost entry, as this function once did, let a
/// client behind an appending proxy send `X-Forwarded-For: <any address>`
/// and be taken for that address by the rate limiter, the lockout, the
/// client ACL and the audit trail.
///
/// Consequence for operators: with several proxies in a row, each must be
/// listed in `trusted_proxies`, or the walk stops at the first unlisted
/// one and that proxy's address is used.
///
/// The header is untrusted input. An entry that is not an address (with
/// an optional port) ends the walk and the peer address is returned:
/// what lies to the left of a hop we cannot read is not evidence.
///
/// `X-Real-IP` is read only when no `X-Forwarded-For` header is present.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    connect_ip: IpAddr,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    if trusted_proxies.is_empty() || !trusted_proxies.contains(&connect_ip) {
        return connect_ip;
    }

    let mut forwarded = headers.get_all("X-Forwarded-For").iter().peekable();
    if forwarded.peek().is_some() {
        // Several header lines are one list, in order (RFC 9110, 5.3).
        let mut hops: Vec<&str> = Vec::new();
        for value in forwarded {
            let Ok(text) = value.to_str() else {
                return connect_ip;
            };
            hops.extend(text.split(','));
        }
        for hop in hops.into_iter().rev() {
            let Some(ip) = parse_forwarded_hop(hop) else {
                return connect_ip;
            };
            if !trusted_proxies.contains(&ip) {
                return ip;
            }
        }
        // Every hop is one of our proxies: the request started there.
        return connect_ip;
    }

    if let Some(real_ip) = headers.get("X-Real-IP")
        && let Ok(text) = real_ip.to_str()
        && let Some(ip) = parse_forwarded_hop(text)
    {
        return ip;
    }

    connect_ip
}

/// One `X-Forwarded-For` entry: an address, optionally with a port
/// (`203.0.113.7`, `203.0.113.7:4711`, `2001:db8::1`, `[2001:db8::1]`,
/// `[2001:db8::1]:4711`). Anything else is `None`.
fn parse_forwarded_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = hop.parse::<std::net::SocketAddr>() {
        return Some(addr.ip());
    }
    hop.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<std::net::Ipv6Addr>().ok())
        .map(IpAddr::V6)
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
    fn test_resolve_rightmost_untrusted_ip_from_xff_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "203.0.113.50, 70.41.3.18, 150.172.238.178".parse().unwrap(),
        );

        let connect_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];

        // The proxy at 10.0.0.1 appended 150.172.238.178: that is the
        // address it saw. The two entries to its left came from there.
        let result = resolve_client_ip(&headers, connect_ip, &trusted);
        assert_eq!(result.to_string(), "150.172.238.178");
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("X-Forwarded-For", value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn attack_spoofed_leftmost_xff_is_ignored() {
        // The client sends its own header; the proxy appends the truth.
        let headers = xff(&["10.9.9.9, 198.51.100.7"]);
        let trusted = [ip("10.0.0.1")];
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("198.51.100.7"),
            "the address the proxy appended wins over the one the client sent"
        );

        // Claiming to be a trusted proxy on the left changes nothing.
        let headers = xff(&["10.0.0.1, 198.51.100.7"]);
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("198.51.100.7")
        );

        // Nor does a long forged chain.
        let headers = xff(&["1.1.1.1, 2.2.2.2, 3.3.3.3, 198.51.100.7"]);
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn attack_xff_from_untrusted_peer_is_ignored() {
        let headers = xff(&["203.0.113.50"]);
        for trusted in [&[][..], &[ip("192.168.1.1")][..]] {
            assert_eq!(
                resolve_client_ip(&headers, ip("198.51.100.7"), trusted),
                ip("198.51.100.7")
            );
        }
    }

    #[test]
    fn attack_spoofed_xff_in_a_second_header_line_is_ignored() {
        // Two lines are one list. The proxy's line comes last.
        let headers = xff(&["10.9.9.9", "198.51.100.7"]);
        let trusted = [ip("10.0.0.1")];
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn attack_x_real_ip_does_not_override_xff() {
        let mut headers = xff(&["198.51.100.7"]);
        headers.insert("X-Real-IP", "10.9.9.9".parse().unwrap());
        let trusted = [ip("10.0.0.1")];
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("198.51.100.7")
        );

        // An unreadable XFF does not make X-Real-IP the fallback either.
        let mut headers = xff(&["garbage"]);
        headers.insert("X-Real-IP", "10.9.9.9".parse().unwrap());
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn attack_unreadable_hop_stops_the_walk() {
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        // The hop between our proxy and the claimed client is not an
        // address: what is to its left is not believed.
        for value in [
            "203.0.113.50, garbage, 10.0.0.2",
            "203.0.113.50, , 10.0.0.2",
            "203.0.113.50, 999.1.1.1, 10.0.0.2",
            "203.0.113.50, 198.51.100.7 extra, 10.0.0.2",
            "203.0.113.50, unknown, 10.0.0.2",
        ] {
            assert_eq!(
                resolve_client_ip(&xff(&[value]), ip("10.0.0.1"), &trusted),
                ip("10.0.0.1"),
                "{value:?}"
            );
        }
    }

    #[test]
    fn test_chain_of_trusted_proxies_is_skipped() {
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        let headers = xff(&["203.0.113.50, 10.0.0.2"]);
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("203.0.113.50")
        );
        // An inner proxy that is not listed is where the walk stops.
        let headers = xff(&["203.0.113.50, 10.0.0.3"]);
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("10.0.0.3")
        );
        // Only trusted hops: the request started at a proxy.
        let headers = xff(&["10.0.0.2"]);
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn test_hop_with_port_or_brackets_is_read() {
        let trusted = [ip("10.0.0.1")];
        for (value, expected) in [
            ("198.51.100.7:4711", "198.51.100.7"),
            ("[2001:db8::1]:4711", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("  198.51.100.7  ", "198.51.100.7"),
        ] {
            assert_eq!(
                resolve_client_ip(&xff(&[value]), ip("10.0.0.1"), &trusted),
                ip(expected),
                "{value:?}"
            );
        }
    }

    use proptest::prelude::*;

    proptest::proptest! {
        /// Whatever the header says, the answer is the TCP peer or an
        /// entry of the list that is an address and not one of our
        /// proxies. A client can never make the function return a
        /// trusted proxy's address other than the peer, nor an address
        /// that is not in the header.
        #[test]
        fn prop_answer_is_the_peer_or_an_untrusted_hop(
            hops in proptest::collection::vec(
                proptest::prop_oneof![
                    (0u8..4, 0u8..4).prop_map(|(a, b)| format!("10.0.{a}.{b}")),
                    (1u8..255).prop_map(|a| format!("198.51.100.{a}")),
                    "[a-z ,:\\[\\]0-9.]{0,12}",
                ],
                0..6,
            ),
            peer_is_trusted in proptest::bool::ANY,
        ) {
            let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
            let peer = if peer_is_trusted { ip("10.0.0.1") } else { ip("198.51.100.250") };
            let mut headers = HeaderMap::new();
            let line = hops.join(",");
            if let Ok(value) = line.parse() {
                headers.insert("X-Forwarded-For", value);
            }
            let answer = resolve_client_ip(&headers, peer, &trusted);
            if !peer_is_trusted {
                prop_assert_eq!(answer, peer);
            } else if answer != peer {
                prop_assert!(!trusted.contains(&answer));
                prop_assert!(
                    line.split(',').any(|h| parse_forwarded_hop(h) == Some(answer)),
                    "{answer} is not a hop of {line:?}"
                );
            }
        }
    }

    #[test]
    fn attack_non_ascii_xff_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            axum::http::HeaderValue::from_bytes(b"198.51.100.7\xff").unwrap(),
        );
        let trusted = [ip("10.0.0.1")];
        assert_eq!(
            resolve_client_ip(&headers, ip("10.0.0.1"), &trusted),
            ip("10.0.0.1")
        );
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
