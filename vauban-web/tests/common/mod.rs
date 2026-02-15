/// VAUBAN Web - Test infrastructure.
///
/// Common utilities for integration tests.
// Re-export test macros for all test files
pub use vauban_web::{assert_err, assert_none, assert_ok, assert_some, unwrap_ok, unwrap_some};

use axum::{Router, http::HeaderValue};
use axum_test::TestServer;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use secrecy::ExposeSecret;
use tokio::sync::OnceCell;

use vauban_web::{
    AppState,
    cache::CacheConnection,
    config::{Config, Environment},
    db::DbPool,
    models::user::AuthSource,
    services::auth::AuthService,
    services::broadcast::BroadcastService,
    services::rate_limit::RateLimiter,
};

/// Test application wrapper.
pub struct TestApp {
    pub server: TestServer,
    pub db_pool: DbPool,
    pub auth_service: AuthService,
    pub config: Config,
    pub broadcast: BroadcastService,
    pub user_connections: vauban_web::services::connections::UserConnectionRegistry,
    pub ws_counter: vauban_web::services::connections::WsConnectionCounter,
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

    /// Get the path to the workspace root config/ directory.
    fn config_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .join("config")
    }

    /// Create test app (internal).
    async fn create() -> Self {
        // Load test configuration from workspace root config/testing.toml
        let config = unwrap_ok!(Config::load_with_environment(
            Self::config_dir(),
            Environment::Testing
        ));

        // Create async database pool
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            config.database.url.expose_secret(),
        );
        let db_pool = unwrap_ok!(
            Pool::builder(manager)
                .max_size(config.database.max_connections as usize)
                .build()
        );

        // Create auth service
        let auth_service = unwrap_ok!(AuthService::new(config.clone()));

        // Create cache (mock for tests since cache.enabled = false in testing.toml)
        let cache = CacheConnection::Mock(std::sync::Arc::new(vauban_web::cache::MockCache::new()));

        // Create broadcast service
        let broadcast = BroadcastService::new();

        // Create user connection registry + WS counter
        let user_connections = vauban_web::services::connections::UserConnectionRegistry::new();
        let ws_counter = vauban_web::services::connections::WsConnectionCounter::new(
            config.websocket.max_connections_per_user,
        );

        // Create rate limiter (in-memory for tests, with higher limit)
        // Use 1000 requests per minute in tests to avoid rate limiting interference
        let rate_limiter = unwrap_ok!(RateLimiter::new(
            false, // Don't use Redis in tests
            None, 1000, // High limit for tests
        ));

        // Create app state
        let state = AppState {
            config: config.clone(),
            db_pool: db_pool.clone(),
            cache,
            auth_service: auth_service.clone(),
            broadcast: broadcast.clone(),
            user_connections: user_connections.clone(),
            ws_counter: ws_counter.clone(),
            rate_limiter,
            ssh_proxy: None,      // No SSH proxy in tests
            supervisor: None,     // No supervisor in tests
            vault_client: None,   // No vault in tests (dev mode fallback)
        };

        // Build router
        let app = build_test_router(state);

        // Create test server
        let server = unwrap_ok!(TestServer::new(app));

        Self {
            server,
            db_pool,
            auth_service,
            config,
            broadcast,
            user_connections,
            ws_counter,
        }
    }

    /// Generate authorization header with JWT token.
    pub fn auth_header(&self, token: &str) -> HeaderValue {
        unwrap_ok!(HeaderValue::from_str(&format!("Bearer {}", token)))
    }

    /// Generate a valid JWT for a test user and create a session in database.
    /// This is required because the middleware now validates sessions exist in DB.
    pub async fn generate_test_token(
        &self,
        user_uuid: &str,
        username: &str,
        is_superuser: bool,
        is_staff: bool,
    ) -> String {
        use chrono::{Duration, Utc};
        use diesel::OptionalExtension;
        use sha3::{Digest, Sha3_256};
        use vauban_web::models::NewAuthSession;
        use vauban_web::schema::{auth_sessions, users};

        let token = unwrap_ok!(self.auth_service.generate_access_token(
            user_uuid,
            username,
            true,
            is_superuser,
            is_staff
        ));

        // Create session in database for this token
        let mut conn = self.get_conn().await;

        // Try to find user by UUID or username, or create one
        let user_id: i32 = if let Ok(uuid_val) = uuid::Uuid::parse_str(user_uuid) {
            let existing: Option<i32> = users::table
                .filter(users::uuid.eq(uuid_val))
                .select(users::id)
                .first(&mut conn)
                .await
                .optional()
                .unwrap_or(None);

            match existing {
                Some(id) => id,
                None => {
                    // User doesn't exist, create minimal user
                    diesel::insert_into(users::table)
                        .values((
                            users::uuid.eq(uuid_val),
                            users::username.eq(username),
                            users::email.eq(format!("{}@test.local", username)),
                            users::password_hash.eq("test_hash"),
                            users::is_active.eq(true),
                            users::is_staff.eq(is_staff),
                            users::is_superuser.eq(is_superuser),
                            users::auth_source.eq(AuthSource::Local),
                            users::preferences.eq(serde_json::json!({})),
                        ))
                        .returning(users::id)
                        .get_result(&mut conn)
                        .await
                        .unwrap_or(1)
                }
            }
        } else {
            // No valid UUID, use placeholder ID
            1
        };

        // Hash the token using SHA3-256
        let mut hasher = Sha3_256::new();
        hasher.update(token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());

        let ip: ipnetwork::IpNetwork = unwrap_ok!("127.0.0.1".parse());
        let new_session = NewAuthSession {
            uuid: uuid::Uuid::new_v4(),
            user_id,
            token_hash,
            ip_address: ip,
            user_agent: Some("Test Client".to_string()),
            device_info: Some("Test".to_string()),
            expires_at: Utc::now() + Duration::hours(24),
            is_current: true,
        };

        // Insert session (ignore errors if duplicate)
        diesel::insert_into(auth_sessions::table)
            .values(&new_session)
            .execute(&mut conn)
            .await
            .ok();

        token
    }

    /// Generate a signed CSRF token for tests.
    pub fn generate_csrf_token(&self) -> String {
        vauban_web::middleware::csrf::generate_csrf_token(
            self.config.secret_key.expose_secret().as_bytes(),
        )
    }

    /// Get a database connection.
    pub async fn get_conn(&self) -> vauban_web::db::DbConnection {
        unwrap_ok!(self.db_pool.get().await)
    }
}

/// Serve static files from the compiled-in asset registry (test version).
///
/// Mirrors the production `serve_static` handler in main.rs.
async fn serve_static_test(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    use axum::body::Body;
    use axum::http::{Response, header};

    if path.contains("..") || path.contains('\0') {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    let asset = vauban_web::static_assets::lookup(&path)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(asset.content))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

/// Build the test router with all routes.
fn build_test_router(state: AppState) -> Router {
    use axum::routing::{get, post};
    use vauban_web::handlers;
    use vauban_web::middleware;

    // Session ownership middleware for WS routes
    let session_guard = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_session_guard,
    );

    // L-8: Per-user WS connection limit middleware
    let ws_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_connection_limit,
    );

    // WebSocket routes with connection limit middleware
    let ws_routes = Router::new()
        .route("/ws/dashboard", get(handlers::websocket::dashboard_ws))
        .route(
            "/ws/session/{id}",
            get(handlers::websocket::session_ws).layer(session_guard.clone()),
        )
        .route(
            "/ws/notifications",
            get(handlers::websocket::notifications_ws),
        )
        .route(
            "/ws/sessions/active",
            get(handlers::websocket::active_sessions_ws),
        )
        .layer(ws_limit_layer);

    Router::new()
        // Login page (for redirect tests)
        .route("/login", get(handlers::web::login_page))
        // WebSocket routes (with L-8 connection limit layer)
        .merge(ws_routes)
        // Auth routes
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/auth/login", post(handlers::auth::login_web))
        .route("/auth/logout", post(handlers::auth::logout_web))
        // MFA routes (web only, no API endpoint)
        .route(
            "/mfa/setup",
            get(handlers::auth::mfa_setup_page).post(handlers::auth::mfa_setup_submit),
        )
        .route(
            "/mfa/verify",
            get(handlers::auth::mfa_verify_page).post(handlers::auth::mfa_verify_submit),
        )
        // Accounts routes
        .route("/api/v1/accounts", get(handlers::api::list_users))
        .route("/api/v1/accounts", post(handlers::api::create_user))
        // L-2: DELETE stub returns 501 Not Implemented (not 200 OK)
        .route(
            "/api/v1/accounts/{uuid}",
            get(handlers::api::get_user)
                .put(handlers::api::update_user)
                .delete(|| async {
                    (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                }),
        )
        // Assets routes
        .route("/api/v1/assets", get(handlers::api::list_assets))
        .route("/api/v1/assets", post(handlers::api::create_asset))
        // L-2: DELETE stub returns 501 Not Implemented (not 200 OK)
        .route(
            "/api/v1/assets/{uuid}",
            get(handlers::api::get_asset)
                .put(handlers::api::update_asset)
                .delete(|| async {
                    (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                }),
        )
        // Asset Groups API
        .route(
            "/api/v1/assets/groups",
            get(handlers::api::list_asset_groups),
        )
        .route(
            "/api/v1/assets/groups/{uuid}/assets",
            get(handlers::api::list_group_assets),
        )
        // Asset groups routes
        .route(
            "/api/v1/assets/groups/{uuid}",
            post(handlers::web::update_asset_group),
        )
        // Sessions routes
        .route("/api/v1/sessions", get(handlers::api::list_sessions))
        .route("/api/v1/sessions", post(handlers::api::create_session))
        // L-2: DELETE stub returns 501 Not Implemented (not 200 OK)
        .route(
            "/api/v1/sessions/{uuid}",
            get(handlers::api::get_session)
                .delete(|| async {
                    (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                }),
        )
        // Web pages (HTML) - for testing raw SQL queries
        .route("/sessions", get(handlers::web::session_list))
        .route("/sessions/recordings", get(handlers::web::recording_list))
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route(
            "/sessions/recordings/{id}/play",
            get(handlers::web::recording_play),
        )
        .route("/sessions/approvals", get(handlers::web::approval_list))
        .route(
            "/sessions/approvals/{uuid}",
            get(handlers::web::approval_detail),
        )
        .route("/sessions/active", get(handlers::web::active_sessions))
        .route(
            "/sessions/{id}/terminate",
            post(handlers::web::terminate_session_web),
        )
        .route(
            "/assets/{uuid}/edit",
            get(handlers::web::asset_edit).post(handlers::web::update_asset_web),
        )
        .route(
            "/assets/{uuid}/delete",
            post(handlers::web::delete_asset_web),
        )
        .route("/assets/new", get(handlers::web::asset_create_form))
        .route(
            "/assets",
            get(handlers::web::asset_list).post(handlers::web::create_asset_web),
        )
        .route("/assets/{uuid}", get(handlers::web::asset_detail))
        .route("/assets/search", get(handlers::web::asset_search))
        // Asset groups - literal routes MUST come before parameterized routes
        .route(
            "/assets/groups/new",
            get(handlers::web::asset_group_create_form),
        )
        .route(
            "/assets/groups",
            get(handlers::web::asset_group_list).post(handlers::web::create_asset_group_web),
        )
        .route(
            "/assets/groups/{uuid}",
            get(handlers::web::asset_group_detail),
        )
        .route(
            "/assets/groups/{uuid}/edit",
            get(handlers::web::asset_group_edit).post(handlers::web::update_asset_group),
        )
        .route(
            "/assets/groups/{uuid}/delete",
            post(handlers::web::delete_asset_group_web),
        )
        .route(
            "/assets/groups/{uuid}/add-asset",
            get(handlers::web::asset_group_add_asset_form)
                .post(handlers::web::asset_group_add_asset),
        )
        .route(
            "/assets/groups/{uuid}/remove-asset",
            post(handlers::web::asset_group_remove_asset),
        )
        .route(
            "/accounts/groups",
            get(handlers::web::group_list).post(handlers::web::create_vauban_group_web),
        )
        // Group management routes (literal paths before parameterized)
        .route(
            "/accounts/groups/new",
            get(handlers::web::vauban_group_create_form),
        )
        .route(
            "/accounts/groups/{uuid}/edit",
            get(handlers::web::vauban_group_edit_form),
        )
        .route(
            "/accounts/groups/{uuid}/members/add",
            get(handlers::web::group_add_member_form),
        )
        .route(
            "/accounts/groups/{uuid}/members/search",
            get(handlers::web::group_member_search),
        )
        .route(
            "/accounts/groups/{uuid}/members",
            post(handlers::web::add_group_member_web),
        )
        .route(
            "/accounts/groups/{uuid}/members/{user_uuid}/remove",
            post(handlers::web::remove_group_member_web),
        )
        .route(
            "/accounts/groups/{uuid}/delete",
            post(handlers::web::delete_vauban_group_web),
        )
        .route(
            "/accounts/groups/{uuid}",
            get(handlers::web::group_detail).post(handlers::web::update_vauban_group_web),
        )
        // Groups API (read-only)
        .route(
            "/api/v1/groups/{uuid}/members",
            get(handlers::api::list_group_members),
        )
        // User management pages (literal paths before parameterized)
        .route("/accounts/users/new", get(handlers::web::user_create_form))
        .route(
            "/accounts/users",
            get(handlers::web::user_list).post(handlers::web::create_user_web),
        )
        .route(
            "/accounts/users/{uuid}/edit",
            get(handlers::web::user_edit_form),
        )
        .route(
            "/accounts/users/{uuid}/delete",
            post(handlers::web::delete_user_web),
        )
        .route(
            "/accounts/users/{uuid}",
            get(handlers::web::user_detail).post(handlers::web::update_user_web),
        )
        // Account pages (profile, sessions and API keys)
        .route("/accounts/profile", get(handlers::web::profile))
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
        // SSH connection endpoints
        .route(
            "/assets/{uuid}/connect",
            post(handlers::web::connect_ssh),
        )
        // SSH host key management (H-9)
        .route(
            "/assets/{uuid}/fetch-host-key",
            post(handlers::web::fetch_ssh_host_key),
        )
        .route(
            "/assets/{uuid}/verify-host-key",
            get(handlers::web::verify_ssh_host_key),
        )
        .route(
            "/api/v1/assets/{uuid}/ssh-host-key",
            get(handlers::api::get_ssh_host_key_status)
                .post(handlers::api::fetch_ssh_host_key_api),
        )
        .route(
            "/sessions/terminal/{session_id}",
            get(handlers::web::terminal_page),
        )
        // Terminal WebSocket (with session ownership guard)
        .route(
            "/ws/terminal/{session_id}",
            get(handlers::websocket::terminal_ws).layer(session_guard),
        )
        // Static file serving
        .route("/static/{*path}", get(serve_static_test))
        // Health check
        .route("/health", get(|| async { "OK" }))
        // Dashboard home
        .route("/", get(handlers::web::dashboard_home))
        // Fallback handler for unmatched routes
        .fallback(handlers::web::fallback_handler)
        // Security headers middleware
        .layer(axum::middleware::from_fn(
            middleware::security::security_headers_middleware,
        ))
        // CSRF cookie middleware
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf::csrf_cookie_middleware,
        ))
        // Add flash middleware
        .layer(axum::middleware::from_fn_with_state(
            middleware::flash::FlashSecretKey(
                state.config.secret_key.expose_secret().as_bytes().to_vec(),
            ),
            middleware::flash::flash_middleware,
        ))
        // Add auth middleware
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ))
        .with_state(state)
}

/// Test database utilities.
pub mod test_db {
    use super::*;
    use diesel_async::AsyncPgConnection;

    /// Clean up test data (run before/after tests).
    pub async fn cleanup(conn: &mut AsyncPgConnection) {
        // Delete in reverse order of foreign key dependencies
        diesel::sql_query("DELETE FROM session_recordings")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM proxy_sessions")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM approval_requests")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM assets WHERE name LIKE 'test-%'")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM asset_groups WHERE name LIKE 'test-%'")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM user_groups WHERE name LIKE 'test-%'")
            .execute(conn)
            .await
            .ok();
        diesel::sql_query("DELETE FROM users WHERE username LIKE 'test_%'")
            .execute(conn)
            .await
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
