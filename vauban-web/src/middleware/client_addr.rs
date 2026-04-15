/// VAUBAN Web - Client address extractor.
///
/// Provides a robust way to extract the client's IP address that works
/// both in production (with ConnectInfo) and in tests (without it).
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use ipnetwork::IpNetwork;
use std::net::SocketAddr;

/// Default address used when ConnectInfo is not available (e.g., in tests).
const DEFAULT_ADDR: &str = "127.0.0.1:0";

/// Extractor for the client's socket address.
///
/// This extractor tries to get the real client address from `ConnectInfo`,
/// but falls back to a default localhost address if not available.
/// This allows the same handler code to work both in production
/// (with `into_make_service_with_connect_info`) and in tests.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

impl ClientAddr {
    /// Get the socket address.
    pub fn addr(&self) -> SocketAddr {
        self.0
    }
}

/// Extract the client IP as an `IpNetwork`, resolving proxy headers
/// (`X-Forwarded-For`, `X-Real-IP`) when the connection originates from
/// a trusted proxy.  Falls back to the raw TCP peer address otherwise.
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    connect_addr: SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) -> IpNetwork {
    let resolved =
        super::resolve_client_ip(headers, connect_addr.ip(), trusted_proxies);
    IpNetwork::from(resolved)
}

impl<S> FromRequestParts<S> for ClientAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    #[allow(clippy::unwrap_used)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract ConnectInfo if available
        match ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await {
            Ok(ConnectInfo(addr)) => Ok(ClientAddr(addr)),
            Err(_) => {
                // ConnectInfo not available (e.g., in tests), use default
                // SAFETY: DEFAULT_ADDR is a compile-time constant, parsing cannot fail
                #[allow(clippy::unwrap_used)]
                Ok(ClientAddr(DEFAULT_ADDR.parse().unwrap()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== DEFAULT_ADDR Constant Tests ====================

    #[test]
    fn test_default_addr_constant() {
        assert_eq!(DEFAULT_ADDR, "127.0.0.1:0");
    }

    #[test]
    fn test_default_addr_is_parseable() {
        let result: Result<SocketAddr, _> = DEFAULT_ADDR.parse();
        assert!(result.is_ok());
    }

    // ==================== ClientAddr Tests ====================

    #[test]
    fn test_client_addr_default() {
        let addr: SocketAddr = unwrap_ok!(DEFAULT_ADDR.parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_client_addr_custom() {
        let addr: SocketAddr = unwrap_ok!("192.168.1.100:12345".parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "192.168.1.100");
        assert_eq!(client_addr.addr().port(), 12345);
    }

    #[test]
    fn test_client_addr_ipv6() {
        let addr: SocketAddr = unwrap_ok!("[2001:db8::1]:443".parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn test_client_addr_debug() {
        let addr: SocketAddr = unwrap_ok!("10.0.0.1:8080".parse());
        let client_addr = ClientAddr(addr);
        let debug_str = format!("{:?}", client_addr);
        assert!(debug_str.contains("ClientAddr"));
        assert!(debug_str.contains("10.0.0.1"));
    }

    #[test]
    fn test_client_addr_clone() {
        let addr: SocketAddr = unwrap_ok!("172.16.0.1:9000".parse());
        let client_addr = ClientAddr(addr);
        let cloned = client_addr;
        assert_eq!(client_addr.addr(), cloned.addr());
    }

    #[test]
    fn test_client_addr_copy() {
        let addr: SocketAddr = unwrap_ok!("192.168.0.1:443".parse());
        let client_addr = ClientAddr(addr);
        let copied = client_addr;
        assert_eq!(client_addr.addr(), copied.addr());
    }

    #[test]
    fn test_client_addr_port_zero() {
        let addr: SocketAddr = unwrap_ok!("127.0.0.1:0".parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().port(), 0);
    }

    #[test]
    fn test_client_addr_high_port() {
        let addr: SocketAddr = unwrap_ok!("127.0.0.1:65535".parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().port(), 65535);
    }

    #[test]
    fn test_client_addr_ipv6_localhost() {
        let addr: SocketAddr = unwrap_ok!("[::1]:8443".parse());
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "::1");
    }

    #[test]
    fn test_client_addr_ipv6_full() {
        let addr: SocketAddr = unwrap_ok!("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:80".parse());
        let client_addr = ClientAddr(addr);
        assert!(client_addr.addr().ip().is_ipv6());
    }

    // ==================== extract_client_ip Tests ====================

    #[test]
    fn test_extract_client_ip_returns_peer_addr_without_proxy() {
        let headers = axum::http::HeaderMap::new();
        let addr: SocketAddr = unwrap_ok!("203.0.113.50:12345".parse());
        let ip = extract_client_ip(&headers, addr, &[]);
        assert_eq!(ip.ip().to_string(), "203.0.113.50");
    }

    #[test]
    fn test_extract_client_ip_resolves_xff_from_trusted_proxy() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("198.51.100.1".parse()));
        let addr: SocketAddr = unwrap_ok!("127.0.0.1:1234".parse());
        let trusted = vec![unwrap_ok!("127.0.0.1".parse())];
        let ip = extract_client_ip(&headers, addr, &trusted);
        assert_eq!(ip.ip().to_string(), "198.51.100.1");
    }

    #[test]
    fn test_extract_client_ip_ignores_xff_from_untrusted() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Forwarded-For", unwrap_ok!("198.51.100.1".parse()));
        let addr: SocketAddr = unwrap_ok!("10.0.0.1:1234".parse());
        let ip = extract_client_ip(&headers, addr, &[]);
        assert_eq!(ip.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_returns_ipnetwork() {
        let headers = axum::http::HeaderMap::new();
        let addr: SocketAddr = unwrap_ok!("192.168.1.1:443".parse());
        let ip = extract_client_ip(&headers, addr, &[]);
        assert_eq!(ip.prefix(), 32);
    }
}
