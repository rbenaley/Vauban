/// VAUBAN Web - Test infrastructure.
///
/// Common utilities for integration tests.
use axum::{Router, http::HeaderValue};
use axum_test::TestServer;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use tokio::sync::OnceCell;

use vauban_web::{
    AppState,
    cache::CacheConnection,
    config::{Config, Environment},
    db::DbPool,
    services::auth::AuthService,
    services::broadcast::BroadcastService,
};

/// Test application wrapper.
pub struct TestApp {
    pub server: TestServer,
    pub db_pool: DbPool,
    pub auth_service: AuthService,
    pub config: Config,
}

/// Global test app instance (lazy initialization).
static TEST_APP: OnceCell<TestApp> = OnceCell::const_new();

impl TestApp {
    /// Create a new test application.
    pub async fn spawn() -> &'static TestApp {
        TEST_APP
            .get_or_init(|| async { Self::create().await })
            .await
    }

    /// Create test app (internal).
    async fn create() -> Self {
        // Load test configuration from config/testing.toml
        let config = Config::load_with_environment("config", Environment::Testing)
            .expect("Failed to load test config from config/testing.toml");

        // Create database pool
        let manager = ConnectionManager::<diesel::PgConnection>::new(&config.database.url);
        let db_pool = Pool::builder()
            .max_size(config.database.max_connections)
            .build(manager)
            .expect("Failed to create test database pool");

        // Create auth service
        let auth_service = AuthService::new(config.clone()).expect("Failed to create auth service");

        // Create cache (mock for tests since cache.enabled = false in testing.toml)
        let cache = CacheConnection::Mock(std::sync::Arc::new(vauban_web::cache::MockCache::new()));

        // Create broadcast service
        let broadcast = BroadcastService::new();

        // Create app state
        let state = AppState {
            config: config.clone(),
            db_pool: db_pool.clone(),
            cache,
            auth_service: auth_service.clone(),
            broadcast,
        };

        // Build router
        let app = build_test_router(state);

        // Create test server
        let server = TestServer::new(app).expect("Failed to create test server");

        Self {
            server,
            db_pool,
            auth_service,
            config,
        }
    }

    /// Generate authorization header with JWT token.
    pub fn auth_header(&self, token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
    }

    /// Generate a valid JWT for a test user.
    pub fn generate_test_token(
        &self,
        user_uuid: &str,
        username: &str,
        is_superuser: bool,
        is_staff: bool,
    ) -> String {
        self.auth_service
            .generate_access_token(user_uuid, username, true, is_superuser, is_staff)
            .expect("Failed to generate test token")
    }

    /// Get a database connection.
    pub fn get_conn(
        &self,
    ) -> diesel::r2d2::PooledConnection<ConnectionManager<diesel::PgConnection>> {
        self.db_pool.get().expect("Failed to get DB connection")
    }
}

/// Build the test router with all routes.
fn build_test_router(state: AppState) -> Router {
    use axum::routing::{get, post, put};
    use vauban_web::handlers;
    use vauban_web::middleware;

    Router::new()
        // WebSocket routes
        .route("/ws/dashboard", get(handlers::websocket::dashboard_ws))
        .route("/ws/session/{id}", get(handlers::websocket::session_ws))
        .route(
            "/ws/notifications",
            get(handlers::websocket::notifications_ws),
        )
        // Auth routes
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/logout", post(handlers::auth::logout))
        .route("/api/auth/mfa/setup", post(handlers::auth::setup_mfa))
        // Accounts routes
        .route("/api/v1/accounts", get(handlers::accounts::list_users))
        .route("/api/v1/accounts", post(handlers::accounts::create_user))
        .route("/api/v1/accounts/{uuid}", get(handlers::accounts::get_user))
        .route(
            "/api/v1/accounts/{uuid}",
            put(handlers::accounts::update_user),
        )
        // Assets routes
        .route("/api/v1/assets", get(handlers::assets::list_assets))
        .route("/api/v1/assets", post(handlers::assets::create_asset))
        .route("/api/v1/assets/{uuid}", get(handlers::assets::get_asset))
        .route("/api/v1/assets/{uuid}", put(handlers::assets::update_asset))
        // Asset groups routes
        .route(
            "/api/v1/assets/groups/{uuid}",
            post(handlers::web::update_asset_group),
        )
        // Sessions routes
        .route("/api/v1/sessions", get(handlers::sessions::list_sessions))
        .route("/api/v1/sessions", post(handlers::sessions::create_session))
        .route(
            "/api/v1/sessions/{uuid}",
            get(handlers::sessions::get_session),
        )
        // Web pages (HTML) - for testing raw SQL queries
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route("/sessions/recordings/{id}/play", get(handlers::web::recording_play))
        .route("/sessions/approvals", get(handlers::web::approval_list))
        .route("/sessions/approvals/{uuid}", get(handlers::web::approval_detail))
        .route("/sessions/active", get(handlers::web::active_sessions))
        .route("/assets/{id}", get(handlers::web::asset_detail))
        .route("/assets/groups", get(handlers::web::asset_group_list))
        .route("/assets/groups/{uuid}", get(handlers::web::asset_group_detail))
        .route("/assets/groups/{uuid}/edit", get(handlers::web::asset_group_edit))
        .route("/accounts/groups", get(handlers::web::group_list))
        .route("/accounts/groups/{uuid}", get(handlers::web::group_detail))
        // Account pages (sessions and API keys)
        .route("/accounts/sessions", get(handlers::web::user_sessions))
        .route(
            "/accounts/sessions/{uuid}/revoke",
            post(handlers::web::revoke_session),
        )
        .route("/accounts/apikeys", get(handlers::web::api_keys))
        .route(
            "/accounts/apikeys/create",
            get(handlers::web::create_api_key_form).post(handlers::web::create_api_key),
        )
        .route(
            "/accounts/apikeys/{uuid}/revoke",
            post(handlers::web::revoke_api_key),
        )
        // Health check
        .route("/health", get(|| async { "OK" }))
        // Add auth middleware
        .layer(axum::middleware::from_fn_with_state(
            state.auth_service.clone(),
            middleware::auth::auth_middleware,
        ))
        .with_state(state)
}

/// Test database utilities.
pub mod test_db {
    use super::*;
    use diesel::sql_query;

    /// Clean up test data (run before/after tests).
    pub fn cleanup(conn: &mut diesel::PgConnection) {
        // Delete in reverse order of foreign key dependencies
        sql_query("DELETE FROM session_recordings")
            .execute(conn)
            .ok();
        sql_query("DELETE FROM proxy_sessions").execute(conn).ok();
        sql_query("DELETE FROM approval_requests")
            .execute(conn)
            .ok();
        sql_query("DELETE FROM assets WHERE name LIKE 'test-%'")
            .execute(conn)
            .ok();
        sql_query("DELETE FROM asset_groups WHERE name LIKE 'test-%'")
            .execute(conn)
            .ok();
        sql_query("DELETE FROM user_groups WHERE name LIKE 'test-%'")
            .execute(conn)
            .ok();
        sql_query("DELETE FROM users WHERE username LIKE 'test_%'")
            .execute(conn)
            .ok();
    }
}

/// Response assertion helpers.
pub mod assertions {
    use axum_test::TestResponse;
    use serde_json::Value;

    /// Assert response status code.
    pub fn assert_status(response: &TestResponse, expected: u16) {
        assert_eq!(
            response.status_code().as_u16(),
            expected,
            "Expected status {}, got {}",
            expected,
            response.status_code()
        );
    }

    /// Assert response is JSON and contains a field.
    pub fn assert_json_has_field(response: &TestResponse, field: &str) {
        let json: Value = response.json();
        assert!(
            json.get(field).is_some(),
            "Expected JSON to have field '{}', got: {}",
            field,
            json
        );
    }

    /// Assert response JSON field equals value.
    pub fn assert_json_field_eq(response: &TestResponse, field: &str, expected: &str) {
        let json: Value = response.json();
        let actual = json.get(field).and_then(|v| v.as_str());
        assert_eq!(
            actual,
            Some(expected),
            "Expected field '{}' to be '{}', got: {:?}",
            field,
            expected,
            actual
        );
    }
}
