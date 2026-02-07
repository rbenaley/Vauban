pub mod audit;
/// VAUBAN Web - Middleware module.
pub mod auth;
pub mod client_addr;
pub mod csrf;
pub mod flash;
pub mod security;

pub use audit::*;
pub use auth::*;
pub use client_addr::*;
pub use flash::*;
pub use security::*;

use axum::http::HeaderMap;
use std::net::IpAddr;

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
            "203.0.113.50, 70.41.3.18, 150.172.238.178"
                .parse()
                .unwrap(),
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
}
