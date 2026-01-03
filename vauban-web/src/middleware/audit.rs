/// VAUBAN Web - Audit logging middleware.
///
/// Logs security events and user actions.

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use tracing::{error, info, warn};

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
}

/// Audit middleware that logs requests.
pub async fn audit_middleware(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
        })
        .map(|s| s.to_string());

    let user = request.extensions().get::<AuthUser>().cloned();

    let response = next.run(request).await;

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
    };

    // Log based on severity
    match status_code {
        500..=599 => error!(?audit_log, "Server error"),
        400..=499 => warn!(?audit_log, "Client error"),
        _ => info!(?audit_log, "Request processed"),
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
}

