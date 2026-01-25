/// VAUBAN Web - Custom error types.
///
/// All errors use `thiserror` for proper error handling without `unwrap()`.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;
use thiserror::Error;

/// Main application error type.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Authentication required - redirect to login")]
    AuthRedirect,

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Cache error: {0}")]
    Cache(#[from] redis::RedisError),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Special case: AuthRedirect returns a redirect to login page
        if matches!(self, AppError::AuthRedirect) {
            return Redirect::to("/login").into_response();
        }

        let (status, error_message) = match self {
            AppError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database operation failed".to_string(),
                )
            }
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::AuthRedirect => unreachable!(), // Handled above
            AppError::Authorization(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Internal(e) => {
                tracing::error!("Internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::Ipc(e) => {
                tracing::error!("IPC error: {}", e);
                (StatusCode::BAD_GATEWAY, "Service unavailable".to_string())
            }
            AppError::Cache(e) => {
                tracing::warn!("Cache error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cache operation failed".to_string(),
                )
            }
            AppError::Config(msg) => {
                tracing::error!("Configuration error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Configuration error".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Result type alias for convenience.
pub type AppResult<T> = Result<T, AppError>;

// =============================================================================
// HTMX Error Response Helpers
// =============================================================================

/// Translate technical error messages to user-friendly messages.
///
/// Returns a human-readable error message suitable for display to end users.
pub fn user_friendly_message(error: &str) -> &str {
    match error {
        // Validation errors
        "Invalid IP address format" => {
            "The IP address is not valid. Please use a format like 192.168.1.1 or 2001:db8::1"
        }
        msg if msg == "Validation failed" || msg.starts_with("Validation failed:") => {
            "Please check the form fields and try again"
        }

        // Authentication errors
        "Invalid credentials" => "Incorrect username or password",
        "Session expired" => "Your session has expired. Please sign in again",
        "Authentication required" => "Please sign in to continue",
        "Account is locked" => "Your account has been locked. Please contact an administrator",
        "Invalid MFA code" => "The MFA code is incorrect. Please try again",

        // Authorization errors
        "Unauthorized" | "Access denied" => {
            "You do not have permission to perform this action"
        }

        // Not found errors
        "Asset not found" => "The requested asset was not found or has been deleted",
        "User not found" => "The requested user was not found",
        "Session not found" => "The requested session was not found",
        msg if msg.contains("not found") => "The requested resource was not found",

        // Server errors
        "Database operation failed" => "A server error occurred. Please try again later",
        "Internal server error" => "An unexpected error occurred. Please try again later",
        "Service unavailable" => "The service is temporarily unavailable. Please try again later",

        // Default: return original message
        _ => error,
    }
}

/// Generate an HTML error fragment for HTMX responses.
///
/// This returns a styled error alert that can be directly swapped into the DOM by HTMX.
pub fn html_error_fragment(message: &str) -> String {
    let friendly_message = user_friendly_message(message);
    format!(
        r#"<div class="flex">
    <div class="flex-shrink-0">
        <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd"/>
        </svg>
    </div>
    <div class="ml-3">
        <p class="text-sm font-medium text-red-800 dark:text-red-200">{}</p>
    </div>
</div>"#,
        friendly_message
    )
}

/// Check if a request is an HTMX request by looking for the HX-Request header.
pub fn is_htmx_request(headers: &axum::http::HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

/// Create an HTML error response for HTMX requests.
///
/// Returns an HTML fragment with the appropriate status code.
pub fn htmx_error_response(
    status: StatusCode,
    message: &str,
) -> (StatusCode, axum::response::Html<String>) {
    (
        status,
        axum::response::Html(html_error_fragment(message)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    

    // ==================== AppError Display Tests ====================

    #[test]
    fn test_app_error_display_auth() {
        let error = AppError::Auth("Invalid credentials".to_string());
        assert_eq!(
            error.to_string(),
            "Authentication error: Invalid credentials"
        );
    }

    #[test]
    fn test_app_error_display_authorization() {
        let error = AppError::Authorization("Access denied".to_string());
        assert_eq!(error.to_string(), "Authorization error: Access denied");
    }

    #[test]
    fn test_app_error_display_validation() {
        let error = AppError::Validation("Invalid input".to_string());
        assert_eq!(error.to_string(), "Validation error: Invalid input");
    }

    #[test]
    fn test_app_error_display_not_found() {
        let error = AppError::NotFound("User not found".to_string());
        assert_eq!(error.to_string(), "Not found: User not found");
    }

    #[test]
    fn test_app_error_display_config() {
        let error = AppError::Config("Missing SECRET_KEY".to_string());
        assert_eq!(error.to_string(), "Configuration error: Missing SECRET_KEY");
    }

    // ==================== IntoResponse Tests ====================
    // Note: We test status code only - body extraction requires additional dependencies.

    #[test]
    fn test_app_error_into_response_auth_status() {
        let error = AppError::Auth("Invalid token".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_app_error_into_response_auth_redirect_status() {
        let error = AppError::AuthRedirect;
        let response = error.into_response();
        // AuthRedirect returns a 303 See Other redirect
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[test]
    fn test_app_error_into_response_auth_redirect_has_location_header() {
        let error = AppError::AuthRedirect;
        let response = error.into_response();
        let location = response.headers().get("location");
        assert!(location.is_some());
        assert_eq!(unwrap_ok!(unwrap_some!(location).to_str()), "/login");
    }

    #[test]
    fn test_app_error_display_auth_redirect() {
        let error = AppError::AuthRedirect;
        assert_eq!(
            error.to_string(),
            "Authentication required - redirect to login"
        );
    }

    #[test]
    fn test_app_error_debug_auth_redirect() {
        let error = AppError::AuthRedirect;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("AuthRedirect"));
    }

    #[test]
    fn test_app_error_into_response_authorization_status() {
        let error = AppError::Authorization("Forbidden".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_app_error_into_response_validation_status() {
        let error = AppError::Validation("Invalid email".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_app_error_into_response_not_found_status() {
        let error = AppError::NotFound("Resource not found".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_app_error_into_response_internal_status() {
        let error = AppError::Internal(anyhow::anyhow!("Something went wrong"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_app_error_into_response_config_status() {
        let error = AppError::Config("Bad config".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ==================== Error From Trait Tests ====================

    #[test]
    fn test_app_error_from_anyhow() {
        let anyhow_error = anyhow::anyhow!("Something failed");
        let app_error: AppError = anyhow_error.into();

        match app_error {
            AppError::Internal(_) => (), // Expected
            _ => panic!("Expected Internal error"),
        }
    }

    // ==================== AppResult Tests ====================

    #[test]
    fn test_app_result_ok() {
        let result: AppResult<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(unwrap_ok!(result), 42);
    }

    #[test]
    fn test_app_result_err() {
        let result: AppResult<i32> = Err(AppError::NotFound("Not found".to_string()));
        assert!(result.is_err());
    }

    // ==================== AppError Debug Tests ====================

    #[test]
    fn test_app_error_debug_auth() {
        let error = AppError::Auth("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Auth"));
    }

    #[test]
    fn test_app_error_debug_authorization() {
        let error = AppError::Authorization("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Authorization"));
    }

    #[test]
    fn test_app_error_debug_validation() {
        let error = AppError::Validation("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Validation"));
    }

    #[test]
    fn test_app_error_debug_not_found() {
        let error = AppError::NotFound("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("NotFound"));
    }

    #[test]
    fn test_app_error_debug_config() {
        let error = AppError::Config("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Config"));
    }

    #[test]
    fn test_app_error_debug_internal() {
        let error = AppError::Internal(anyhow::anyhow!("test"));
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Internal"));
    }

    // ==================== Response Body Tests ====================

    #[test]
    fn test_app_error_into_response_ipc_status() {
        let error = AppError::Ipc("service unavailable".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_app_error_display_internal() {
        let error = AppError::Internal(anyhow::anyhow!("inner error"));
        let display = error.to_string();
        assert!(display.contains("Internal server error"));
    }

    #[test]
    fn test_app_error_display_ipc() {
        let error = AppError::Ipc("connection closed".to_string());
        let display = error.to_string();
        assert!(display.contains("IPC error"));
    }

    // ==================== User-Friendly Message Tests ====================

    #[test]
    fn test_user_friendly_message_ip_address() {
        let msg = user_friendly_message("Invalid IP address format");
        assert!(msg.contains("192.168.1.1"));
        assert!(msg.contains("2001:db8::1"));
    }

    #[test]
    fn test_user_friendly_message_validation() {
        let msg = user_friendly_message("Validation failed");
        assert!(msg.contains("check the form fields"));
    }

    #[test]
    fn test_user_friendly_message_credentials() {
        let msg = user_friendly_message("Invalid credentials");
        assert_eq!(msg, "Incorrect username or password");
    }

    #[test]
    fn test_user_friendly_message_session_expired() {
        let msg = user_friendly_message("Session expired");
        assert!(msg.contains("sign in again"));
    }

    #[test]
    fn test_user_friendly_message_unauthorized() {
        let msg = user_friendly_message("Unauthorized");
        assert!(msg.contains("permission"));
    }

    #[test]
    fn test_user_friendly_message_asset_not_found() {
        let msg = user_friendly_message("Asset not found");
        assert!(msg.contains("asset"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_user_friendly_message_generic_not_found() {
        let msg = user_friendly_message("Something not found");
        assert!(msg.contains("resource was not found"));
    }

    #[test]
    fn test_user_friendly_message_database_error() {
        let msg = user_friendly_message("Database operation failed");
        assert!(msg.contains("server error"));
    }

    #[test]
    fn test_user_friendly_message_unknown_passthrough() {
        let msg = user_friendly_message("Some unknown error");
        assert_eq!(msg, "Some unknown error");
    }

    // ==================== HTML Error Fragment Tests ====================

    #[test]
    fn test_html_error_fragment_contains_message() {
        let html = html_error_fragment("Invalid IP address format");
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("text-red-"));
        assert!(html.contains("<svg"));
    }

    #[test]
    fn test_html_error_fragment_structure() {
        let html = html_error_fragment("Test error");
        assert!(html.contains("<div class=\"flex\">"));
        assert!(html.contains("</div>"));
        assert!(html.contains("<p class="));
    }

    // ==================== HTMX Helper Tests ====================

    #[test]
    fn test_is_htmx_request_with_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("HX-Request", unwrap_ok!("true".parse()));
        assert!(is_htmx_request(&headers));
    }

    #[test]
    fn test_is_htmx_request_without_header() {
        let headers = axum::http::HeaderMap::new();
        assert!(!is_htmx_request(&headers));
    }

    #[test]
    fn test_htmx_error_response_status() {
        let (status, _html) = htmx_error_response(StatusCode::BAD_REQUEST, "Test error");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_htmx_error_response_content() {
        let (_status, html) = htmx_error_response(StatusCode::BAD_REQUEST, "Invalid IP address format");
        let body = html.0;
        assert!(body.contains("192.168.1.1"));
    }
}
