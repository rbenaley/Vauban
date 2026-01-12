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

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

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
            AppError::Grpc(e) => {
                tracing::error!("gRPC error: {}", e);
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
        assert_eq!(location.unwrap().to_str().unwrap(), "/login");
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
        assert_eq!(result.unwrap(), 42);
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
    fn test_app_error_into_response_grpc_status() {
        let error = AppError::Grpc(tonic::Status::unavailable("service down"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    // ==================== Error Source Tests ====================

    #[test]
    fn test_app_error_from_tonic_status() {
        let status = tonic::Status::not_found("resource not found");
        let app_error: AppError = status.into();

        match app_error {
            AppError::Grpc(_) => (),
            _ => panic!("Expected Grpc error"),
        }
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_app_error_display_internal() {
        let error = AppError::Internal(anyhow::anyhow!("inner error"));
        let display = error.to_string();
        assert!(display.contains("Internal server error"));
    }

    #[test]
    fn test_app_error_display_grpc() {
        let error = AppError::Grpc(tonic::Status::unknown("unknown"));
        let display = error.to_string();
        assert!(display.contains("gRPC error"));
    }
}
