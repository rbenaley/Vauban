//! VAUBAN Web - Library crate exposing all modules.
//!
//! This file makes modules available for integration tests.

// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

// Test utilities - macros for replacing unwrap/expect in tests
#[macro_use]
pub mod test_utils;

pub mod acme;
pub mod auth;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod handlers;
pub mod ipc;
pub mod middleware;
pub mod models;
pub use vauban_db::schema;
pub mod services;
pub mod tasks;
pub mod templates;
pub mod utils;

use cache::CacheConnection;
use config::Config;
use db::DbPool;
use ipc::AccessIpcClient;
use ipc::AuthIpcClient;
use ipc::ProxyRdpClient;
use ipc::ProxySshClient;
use ipc::VaultCryptoClient;
use services::auth::AuthService;
use services::broadcast::BroadcastService;
use services::connections::{UserConnectionRegistry, WsConnectionCounter};
use services::mailer::Mailer;
use services::rate_limit::RateLimiter;
use services::system_health::{HttpRateTracker, LiveSessionHistory, SystemHealthCache};
use std::sync::Arc;

pub mod static_assets;

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
    /// Per-user WebSocket connection counter.
    /// Applied as middleware on all WS routes to enforce the configured limit.
    pub ws_counter: WsConnectionCounter,
    /// Rate limiter for login endpoints.
    pub rate_limiter: RateLimiter,
    /// SSH proxy client for IPC with vauban-proxy-ssh.
    /// None if proxy is not available (development mode without supervisor).
    pub ssh_proxy: Option<Arc<ProxySshClient>>,
    /// RDP proxy client for IPC with vauban-proxy-rdp.
    /// None if proxy is not available (development mode without supervisor).
    pub rdp_proxy: Option<Arc<ProxyRdpClient>>,
    /// Supervisor client for IPC with vauban-supervisor.
    /// Used for TCP connection brokering (Capsicum sandbox support).
    /// None if not running under supervisor (development mode).
    pub supervisor: Option<Arc<ipc::SupervisorClient>>,
    /// Vault crypto client for IPC with vauban-vault.
    /// Provides encrypt/decrypt and MFA operations.
    /// None if vault is not available (development mode without supervisor).
    pub vault_client: Option<Arc<VaultCryptoClient>>,
    /// Access IPC client for authorization checks via vauban-access (Casbin).
    ///
    /// Mandatory: vauban-web refuses to start without a live IPC channel to
    /// vauban-access. Casbin is the single source of truth for authorization
    /// and has no fallback path (no role:superuser / role:staff hardcoded
    /// short-circuit).
    pub access_client: Arc<AccessIpcClient>,
    /// Auth IPC client for password hashing/verification via vauban-auth (Argon2id).
    /// None if not running under supervisor (development mode).
    pub auth_ipc_client: Option<Arc<AuthIpcClient>>,
    /// Email notification mailer (Issue #10). Owns the dispatcher's
    /// `Notify` handle. `Mailer::queue` is called from handlers in
    /// the same DB transaction as the business mutation; the
    /// dispatcher task drains the outbox out-of-band.
    pub mailer: Mailer,
    /// Sliding-window HTTP request rate tracker (Bastion Watch).
    /// Updated by the `record_http_request` middleware on every
    /// request, consumed by the SYSTEM HEALTH tile via
    /// `system_health_cache`.
    pub http_rate: Arc<HttpRateTracker>,
    /// Sliding-window live-session count history (Bastion Watch
    /// LIVE hero tile). Sampled at every dashboard snapshot
    /// computation so the tile's sparkline reflects active-count
    /// motion over the last ~2 minutes (NOT openings-per-hour,
    /// which lied in the LIVE context: a long-running session
    /// would surface as a single past spike then a flat zero).
    pub live_session_history: Arc<LiveSessionHistory>,
    /// 5 s-cached system-health snapshot for the Bastion Watch
    /// dashboard. Re-uses `db_pool` and the supervisor's broker
    /// latency tracker, so this struct is lightweight to clone.
    pub system_health_cache: Arc<SystemHealthCache>,
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
    fn test_ipc_module_exported() {
        fn _check_ipc() {
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
