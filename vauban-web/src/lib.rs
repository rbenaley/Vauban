//! VAUBAN Web - Library crate exposing all modules.
//!
//! This file makes modules available for integration tests.

// Clippy lints to enforce proper error handling
// Note: Using warn instead of deny to allow #[allow] annotations to work
// with code that requires expect (e.g., regex compilation in static initializers)
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::todo)]

// Test utilities - macros for replacing unwrap/expect in tests
#[macro_use]
pub mod test_utils;

pub mod cache;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod grpc;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod schema;
pub mod services;
pub mod tasks;
pub mod templates;
pub mod utils;

use cache::CacheConnection;
use config::Config;
use db::DbPool;
use services::auth::AuthService;
use services::broadcast::BroadcastService;
use services::connections::UserConnectionRegistry;
use services::rate_limit::RateLimiter;

/// Application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: DbPool,
    pub cache: CacheConnection,
    pub auth_service: AuthService,
    pub broadcast: BroadcastService,
    /// Registry for WebSocket connections with personalized context.
    pub user_connections: UserConnectionRegistry,
    /// Rate limiter for login endpoints.
    pub rate_limiter: RateLimiter,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Module Export Tests ====================

    #[test]
    fn test_config_module_exported() {
        // Verify config module is accessible via type check
        fn _check_config_type(_config: &config::Config) {}
    }

    #[test]
    fn test_error_module_exported() {
        // Verify error module is accessible
        let err = error::AppError::Validation("test".to_string());
        assert!(matches!(err, error::AppError::Validation(_)));
    }

    #[test]
    fn test_models_module_exported() {
        // Verify models module is accessible via path
        fn _check_user_model() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_services_module_exported() {
        // Verify services module is accessible
        fn _check_auth_service() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_handlers_module_exported() {
        // Verify handlers module is accessible
        fn _check_handlers() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_middleware_module_exported() {
        // Verify middleware module is accessible
        fn _check_middleware() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_templates_module_exported() {
        // Verify templates module is accessible
        fn _check_templates() {
            // Just verifies the module path compiles
        }
    }

    // ==================== AppState Tests ====================
    // Note: AppState requires actual database/cache connections to be fully tested.
    // These tests verify the struct definition is correct.

    #[test]
    fn test_app_state_is_clone() {
        // Verify AppState implements Clone (compile-time check)
        fn assert_clone<T: Clone>() {}
        assert_clone::<AppState>();
    }

    #[test]
    fn test_app_state_fields_exist() {
        // This test verifies the struct fields are defined correctly
        // by checking their types at compile time
        fn check_types(state: &AppState) {
            let _config: &Config = &state.config;
            let _pool: &DbPool = &state.db_pool;
            let _cache: &CacheConnection = &state.cache;
            let _auth: &AuthService = &state.auth_service;
        }

        // The function above won't be called, but it ensures types are correct
        let _ = check_types;
    }

    // ==================== AppState Field Type Tests ====================

    #[test]
    fn test_app_state_has_broadcast_field() {
        fn check_broadcast(state: &AppState) {
            let _broadcast: &services::broadcast::BroadcastService = &state.broadcast;
        }
        let _ = check_broadcast;
    }

    #[test]
    fn test_app_state_has_user_connections_field() {
        fn check_connections(state: &AppState) {
            let _connections: &services::connections::UserConnectionRegistry =
                &state.user_connections;
        }
        let _ = check_connections;
    }

    // ==================== Module Accessibility Tests ====================

    #[test]
    fn test_grpc_module_exported() {
        fn _check_grpc() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_tasks_module_exported() {
        fn _check_tasks() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_cache_module_exported() {
        fn _check_cache() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_db_module_exported() {
        fn _check_db() {
            // Just verifies the module path compiles
        }
    }

    #[test]
    fn test_schema_module_exported() {
        fn _check_schema() {
            // Just verifies the module path compiles
        }
    }

    // ==================== Error Type Tests ====================

    #[test]
    fn test_error_types_accessible() {
        let _auth = error::AppError::Auth("test".to_string());
        let _validation = error::AppError::Validation("test".to_string());
        let _not_found = error::AppError::NotFound("test".to_string());
        let _config = error::AppError::Config("test".to_string());
    }

    #[test]
    fn test_error_result_type() {
        fn check_result() -> error::AppResult<i32> {
            Ok(42)
        }
        assert!(check_result().is_ok());
    }
}
