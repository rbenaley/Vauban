/// VAUBAN Web - Audit logging middleware.
///
/// Logs security events and user actions.

use axum::{
    extract::Request,
    http::StatusCode,
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

