/// VAUBAN Web - Client address extractor.
///
/// Provides a robust way to extract the client's IP address that works
/// both in production (with ConnectInfo) and in tests (without it).
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
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

impl<S> FromRequestParts<S> for ClientAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract ConnectInfo if available
        match ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await {
            Ok(ConnectInfo(addr)) => Ok(ClientAddr(addr)),
            Err(_) => {
                // ConnectInfo not available (e.g., in tests), use default
                Ok(ClientAddr(DEFAULT_ADDR.parse().unwrap()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_addr_default() {
        let addr: SocketAddr = DEFAULT_ADDR.parse().unwrap();
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_client_addr_custom() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "192.168.1.100");
        assert_eq!(client_addr.addr().port(), 12345);
    }

    #[test]
    fn test_client_addr_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let client_addr = ClientAddr(addr);
        assert_eq!(client_addr.addr().ip().to_string(), "2001:db8::1");
    }
}
