/// VAUBAN Web - Audit logging middleware.
///
/// Logs security events and user actions.
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use std::net::SocketAddr;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::AppState;
use crate::middleware::auth::AuthUser;

/// Audit log entry.
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub event_type: String,
    pub duration_ms: u64,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub request_id: String,
}

/// Format log in Apache Combined Log extended format.
/// Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D %{X-Request-ID}o
/// Example: 192.168.1.1 - john [04/Jan/2026:12:34:56 +0000] "GET /api/v1/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 45ms req-abc123
pub fn format_apache_combined(log: &AuditLog) -> String {
    format!(
        "{} - {} [{}] \"{} {} HTTP/1.1\" {} - \"{}\" \"{}\" {}ms {}",
        log.ip_address.as_deref().unwrap_or("-"),
        log.user_id.as_deref().unwrap_or("-"),
        Utc::now().format("%d/%b/%Y:%H:%M:%S %z"),
        log.method,
        log.path,
        log.status_code,
        log.referer.as_deref().unwrap_or("-"),
        log.user_agent.as_deref().unwrap_or("-"),
        log.duration_ms,
        log.request_id,
    )
}

/// Audit middleware that logs requests.
///
/// Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are only trusted when the
/// TCP connection originates from an address in `config.security.trusted_proxies`.
pub async fn audit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Resolve client IP using trusted proxy validation
    let trusted = state.config.security.parsed_trusted_proxies();
    let connect_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let ip = if let Some(peer_ip) = connect_ip {
        Some(
            super::resolve_client_ip(request.headers(), peer_ip, &trusted).to_string(),
        )
    } else {
        // ConnectInfo not available (e.g. in tests) – fall back to
        // peer address only; never trust proxy headers without a known peer.
        None
    };

    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let referer = request
        .headers()
        .get("referer")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Generate request ID
    let request_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    let user = request.extensions().get::<AuthUser>().cloned();

    let response = next.run(request).await;

    let duration_ms = start.elapsed().as_millis() as u64;
    let status_code = response.status().as_u16();
    let event_type = if status_code >= 400 {
        "error"
    } else if status_code >= 300 {
        "redirect"
    } else {
        "success"
    };

    let audit_log = AuditLog {
        user_id: user.map(|u| u.uuid),
        ip_address: ip,
        method: method.to_string(),
        path,
        status_code,
        event_type: event_type.to_string(),
        duration_ms,
        user_agent,
        referer,
        request_id,
    };

    // Log in Apache Combined format for text mode (structured logging for JSON mode)
    let apache_log = format_apache_combined(&audit_log);

    // Log based on severity
    match status_code {
        500..=599 => error!(
            audit_log = ?audit_log,
            apache_format = %apache_log,
            "Server error"
        ),
        400..=499 => warn!(
            audit_log = ?audit_log,
            apache_format = %apache_log,
            "Client error"
        ),
        _ => info!(
            audit_log = ?audit_log,
            apache_format = %apache_log,
            "Request processed"
        ),
    }

    response
}

/// Determine event type from status code.
pub fn get_event_type(status_code: u16) -> &'static str {
    if status_code >= 400 {
        "error"
    } else if status_code >= 300 {
        "redirect"
    } else {
        "success"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== AuditLog Tests ====================

    fn create_test_audit_log() -> AuditLog {
        AuditLog {
            user_id: Some("user-123".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: 45,
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: Some("https://example.com".to_string()),
            request_id: "abc12345".to_string(),
        }
    }

    #[test]
    fn test_audit_log_clone() {
        let log = create_test_audit_log();
        let cloned = log.clone();

        assert_eq!(log.user_id, cloned.user_id);
        assert_eq!(log.ip_address, cloned.ip_address);
        assert_eq!(log.method, cloned.method);
        assert_eq!(log.path, cloned.path);
        assert_eq!(log.status_code, cloned.status_code);
        assert_eq!(log.event_type, cloned.event_type);
    }

    #[test]
    fn test_audit_log_debug() {
        let log = create_test_audit_log();
        let debug_str = format!("{:?}", log);

        assert!(debug_str.contains("AuditLog"));
        assert!(debug_str.contains("user-123"));
        assert!(debug_str.contains("192.168.1.1"));
        assert!(debug_str.contains("GET"));
    }

    #[test]
    fn test_audit_log_anonymous_user() {
        let log = AuditLog {
            user_id: None,
            ip_address: Some("10.0.0.1".to_string()),
            method: "POST".to_string(),
            path: "/login".to_string(),
            status_code: 401,
            event_type: "error".to_string(),
            duration_ms: 10,
            user_agent: None,
            referer: None,
            request_id: "def67890".to_string(),
        };

        assert!(log.user_id.is_none());
        assert_eq!(log.status_code, 401);
    }

    #[test]
    fn test_audit_log_no_ip() {
        let log = AuditLog {
            user_id: Some("user-456".to_string()),
            ip_address: None,
            method: "DELETE".to_string(),
            path: "/api/items/1".to_string(),
            status_code: 204,
            event_type: "success".to_string(),
            duration_ms: 5,
            user_agent: Some("curl/7.68.0".to_string()),
            referer: None,
            request_id: "ghi11223".to_string(),
        };

        assert!(log.ip_address.is_none());
    }

    // ==================== Event Type Tests ====================

    #[test]
    fn test_get_event_type_success_200() {
        assert_eq!(get_event_type(200), "success");
    }

    #[test]
    fn test_get_event_type_success_201() {
        assert_eq!(get_event_type(201), "success");
    }

    #[test]
    fn test_get_event_type_success_204() {
        assert_eq!(get_event_type(204), "success");
    }

    #[test]
    fn test_get_event_type_redirect_301() {
        assert_eq!(get_event_type(301), "redirect");
    }

    #[test]
    fn test_get_event_type_redirect_302() {
        assert_eq!(get_event_type(302), "redirect");
    }

    #[test]
    fn test_get_event_type_redirect_304() {
        assert_eq!(get_event_type(304), "redirect");
    }

    #[test]
    fn test_get_event_type_error_400() {
        assert_eq!(get_event_type(400), "error");
    }

    #[test]
    fn test_get_event_type_error_401() {
        assert_eq!(get_event_type(401), "error");
    }

    #[test]
    fn test_get_event_type_error_403() {
        assert_eq!(get_event_type(403), "error");
    }

    #[test]
    fn test_get_event_type_error_404() {
        assert_eq!(get_event_type(404), "error");
    }

    #[test]
    fn test_get_event_type_error_500() {
        assert_eq!(get_event_type(500), "error");
    }

    #[test]
    fn test_get_event_type_error_503() {
        assert_eq!(get_event_type(503), "error");
    }

    // ==================== Boundary Tests ====================

    #[test]
    fn test_get_event_type_boundary_299() {
        assert_eq!(get_event_type(299), "success");
    }

    #[test]
    fn test_get_event_type_boundary_300() {
        assert_eq!(get_event_type(300), "redirect");
    }

    #[test]
    fn test_get_event_type_boundary_399() {
        assert_eq!(get_event_type(399), "redirect");
    }

    #[test]
    fn test_get_event_type_boundary_400() {
        assert_eq!(get_event_type(400), "error");
    }

    // ==================== Apache Combined Log Format Tests ====================

    #[test]
    fn test_format_apache_combined_full() {
        let log = create_test_audit_log();
        let formatted = format_apache_combined(&log);

        // Verify the format contains expected parts
        assert!(formatted.contains("192.168.1.1"));
        assert!(formatted.contains("user-123"));
        assert!(formatted.contains("GET /api/users HTTP/1.1"));
        assert!(formatted.contains("200"));
        assert!(formatted.contains("https://example.com"));
        assert!(formatted.contains("Mozilla/5.0"));
        assert!(formatted.contains("45ms"));
        assert!(formatted.contains("abc12345"));
    }

    #[test]
    fn test_format_apache_combined_anonymous() {
        let log = AuditLog {
            user_id: None,
            ip_address: None,
            method: "POST".to_string(),
            path: "/login".to_string(),
            status_code: 401,
            event_type: "error".to_string(),
            duration_ms: 10,
            user_agent: None,
            referer: None,
            request_id: "xyz99999".to_string(),
        };
        let formatted = format_apache_combined(&log);

        // Anonymous user and missing fields should show "-"
        assert!(formatted.contains("- - -"));
        assert!(formatted.contains("POST /login HTTP/1.1"));
        assert!(formatted.contains("401"));
        assert!(formatted.contains("\"-\" \"-\""));
        assert!(formatted.contains("10ms"));
    }

    #[test]
    fn test_format_apache_combined_partial() {
        let log = AuditLog {
            user_id: Some("admin".to_string()),
            ip_address: Some("10.0.0.1".to_string()),
            method: "PUT".to_string(),
            path: "/api/settings".to_string(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: 150,
            user_agent: Some("curl/8.0".to_string()),
            referer: None,
            request_id: "req-abc".to_string(),
        };
        let formatted = format_apache_combined(&log);

        assert!(formatted.contains("10.0.0.1"));
        assert!(formatted.contains("admin"));
        assert!(formatted.contains("PUT /api/settings HTTP/1.1"));
        assert!(formatted.contains("\"-\"")); // No referer
        assert!(formatted.contains("curl/8.0"));
        assert!(formatted.contains("150ms"));
    }

    // ==================== AuditLog Additional Tests ====================

    #[test]
    fn test_audit_log_all_fields_none() {
        let log = AuditLog {
            user_id: None,
            ip_address: None,
            method: "OPTIONS".to_string(),
            path: "/".to_string(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: 0,
            user_agent: None,
            referer: None,
            request_id: "".to_string(),
        };

        assert!(log.user_id.is_none());
        assert!(log.ip_address.is_none());
        assert!(log.user_agent.is_none());
        assert!(log.referer.is_none());
    }

    #[test]
    fn test_audit_log_long_path() {
        let long_path = "/api/".to_string() + &"a".repeat(1000);
        let log = AuditLog {
            user_id: Some("user".to_string()),
            ip_address: Some("1.2.3.4".to_string()),
            method: "GET".to_string(),
            path: long_path.clone(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: 100,
            user_agent: None,
            referer: None,
            request_id: "req-1".to_string(),
        };

        assert_eq!(log.path, long_path);
    }

    #[test]
    fn test_audit_log_high_duration() {
        let log = AuditLog {
            user_id: None,
            ip_address: None,
            method: "POST".to_string(),
            path: "/slow".to_string(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: u64::MAX,
            user_agent: None,
            referer: None,
            request_id: "slow-req".to_string(),
        };

        assert_eq!(log.duration_ms, u64::MAX);
    }

    // ==================== get_event_type Additional Tests ====================

    #[test]
    fn test_get_event_type_100_series() {
        assert_eq!(get_event_type(100), "success");
        assert_eq!(get_event_type(101), "success");
    }

    #[test]
    fn test_get_event_type_200_series() {
        assert_eq!(get_event_type(201), "success");
        assert_eq!(get_event_type(202), "success");
        assert_eq!(get_event_type(204), "success");
    }

    #[test]
    fn test_get_event_type_300_series() {
        assert_eq!(get_event_type(307), "redirect");
        assert_eq!(get_event_type(308), "redirect");
    }

    #[test]
    fn test_get_event_type_400_series() {
        assert_eq!(get_event_type(405), "error");
        assert_eq!(get_event_type(429), "error");
        assert_eq!(get_event_type(499), "error");
    }

    #[test]
    fn test_get_event_type_500_series() {
        assert_eq!(get_event_type(501), "error");
        assert_eq!(get_event_type(502), "error");
        assert_eq!(get_event_type(504), "error");
    }

    // ==================== format_apache_combined Additional Tests ====================

    #[test]
    fn test_format_apache_combined_contains_http_version() {
        let log = create_test_audit_log();
        let formatted = format_apache_combined(&log);
        assert!(formatted.contains("HTTP/1.1"));
    }

    #[test]
    fn test_format_apache_combined_timestamp_format() {
        let log = create_test_audit_log();
        let formatted = format_apache_combined(&log);
        // Should contain date in Apache format like [10/Jan/2026:12:34:56 +0000]
        assert!(formatted.contains("["));
        assert!(formatted.contains("]"));
    }

    #[test]
    fn test_format_apache_combined_request_id_included() {
        let log = AuditLog {
            user_id: None,
            ip_address: None,
            method: "GET".to_string(),
            path: "/".to_string(),
            status_code: 200,
            event_type: "success".to_string(),
            duration_ms: 1,
            user_agent: None,
            referer: None,
            request_id: "unique-req-id-12345".to_string(),
        };
        let formatted = format_apache_combined(&log);
        assert!(formatted.contains("unique-req-id-12345"));
    }
}
