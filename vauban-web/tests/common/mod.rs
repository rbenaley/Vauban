/// VAUBAN Web - Test infrastructure.
///
/// Common utilities for integration tests.
// Re-export test macros for all test files
pub use vauban_web::{assert_err, assert_none, assert_ok, assert_some, unwrap_ok, unwrap_some};

use axum::{Router, extract::Path, http::HeaderValue, response::Redirect};
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
    /// Cloned AppState exposed for tests that need to call functions
    /// taking `&AppState` (e.g. `services::recording_hydrator::enqueue_hydration`).
    /// `supervisor` is `None` here -- exactly the development-mode shape
    /// `enqueue_hydration` must short-circuit on (issue #29 v1.4).
    pub app_state: AppState,
    /// Handle to the in-process vauban-access service backing the test
    /// AppState's `access_client`. Kept alive for the lifetime of the app
    /// so the background threads (and their Casbin enforcer) stay up.
    pub _access_service: &'static ipc_test_service::InProcessAccessService,
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

        // Initialize vauban-web's virtual-group OnceLock so the
        // web-side resolver in `services::access` knows the virtual
        // "All assets" id. Without this call,
        // `list_accessible_asset_ids` and `can_access_asset` would
        // never recognize the special-case row in tests.
        {
            let mut conn = unwrap_ok!(db_pool.get().await);
            if let Err(e) = vauban_web::services::virtual_group::init_or_die(&mut conn).await {
                eprintln!("test app: failed to init vauban-web virtual_group OnceLock: {e:?}");
            }
        }

        // Spawn the in-process vauban-access service (real Casbin enforcer
        // + real IPC pipes). vauban-web requires a live `access_client` now
        // that the standalone fallback has been removed.
        let access_service: &'static ipc_test_service::InProcessAccessService = {
            static ACCESS_SERVICE: OnceCell<ipc_test_service::InProcessAccessService> =
                OnceCell::const_new();
            ACCESS_SERVICE
                .get_or_init(|| async {
                    ipc_test_service::spawn(config.database.url.expose_secret())
                })
                .await
        };
        // The `ipc_test_service::spawn` helper already owns a dedicated
        // thread that drives `AccessIpcClient::process_incoming`, so here we
        // only need to clone the `Arc` and hand it to the app state.
        let access_client = std::sync::Arc::clone(&access_service.access_client);

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
            ssh_proxy: None,       // No SSH proxy in tests
            rdp_proxy: None,       // No RDP proxy in tests
            supervisor: None,      // No supervisor in tests
            vault_client: None,    // No vault in tests (dev mode fallback)
            access_client,         // Real Casbin-backed IPC client
            auth_ipc_client: None, // No Auth IPC in tests (dev mode fallback)
        };

        // Build router
        let app_state = state.clone();
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
            app_state,
            _access_service: access_service,
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
        // Issue #8: per-token `device_info` so two `generate_test_token`
        // calls for the same user (different `mfa_verified`/`is_superuser`
        // combinations) can coexist without tripping the
        // `uniq_auth_sessions_per_device` UNIQUE index.
        let new_session = NewAuthSession {
            uuid: uuid::Uuid::new_v4(),
            user_id,
            token_hash: token_hash.clone(),
            ip_address: ip,
            user_agent: Some("Test Client".to_string()),
            device_info: format!("Test/{}", &token_hash[..8]),
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

    let asset =
        vauban_web::static_assets::lookup(&path).ok_or(axum::http::StatusCode::NOT_FOUND)?;

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
    let session_guard =
        axum::middleware::from_fn_with_state(state.clone(), handlers::websocket::ws_session_guard);

    // Per-user WS connection limit middleware
    let ws_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_connection_limit,
    );

    // SECURITY: mirror the production routing of `/ws/sessions/list`
    // and `/ws/sessions/active` (see `vauban-web/src/main.rs`):
    // both are gated by `admin:view` BEFORE the WS upgrade extractor
    // so unauthorised users get a 403 instead of a 400 (extractor
    // rejection on missing upgrade headers).
    let ws_admin_view_layer = axum::middleware::from_fn(handlers::websocket::ws_admin_view_guard);

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
            get(handlers::websocket::active_sessions_ws).layer(ws_admin_view_layer.clone()),
        )
        .route(
            "/ws/sessions/list",
            get(handlers::websocket::session_list_ws).layer(ws_admin_view_layer),
        )
        .layer(ws_limit_layer);

    Router::new()
        // Login page (for redirect tests)
        .route("/login", get(handlers::web::login_page))
        // WebSocket routes
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
        // DELETE stub returns 501 Not Implemented (not 200 OK)
        .route(
            "/api/v1/accounts/{uuid}",
            get(handlers::api::get_user)
                .put(handlers::api::update_user)
                .delete(|| async { (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented") }),
        )
        // Assets routes -- USER ZONE only.
        // Issue #27: every write / detail / SSH host-key endpoint moved
        // under `/api/v1/assets/manage/*` (mounted further down with
        // the require_assets_manage middleware). The DELETE stub at
        // the legacy path mirrors production: an unsupported verb
        // returns 501 Not Implemented instead of falling through to a
        // generic 404.
        .route("/api/v1/assets", get(handlers::api::list_assets))
        .route(
            "/api/v1/assets/{uuid}",
            axum::routing::delete(|| async {
                (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
            }),
        )
        // Asset groups POST -- this endpoint does not exist in
        // production (asset groups are managed via the web routes
        // under /assets/groups/*). Kept as a test-only fixture for
        // pre-existing tests in `tests/api/asset_groups_test.rs`.
        .route(
            "/api/v1/assets/groups/{uuid}",
            post(handlers::web::update_asset_group),
        )
        // Access Rules API
        .route(
            "/api/v1/access-rules",
            get(handlers::api::list_access_rules).post(handlers::api::create_access_rule),
        )
        .route(
            "/api/v1/access-rules/{uuid}",
            get(handlers::api::get_access_rule)
                .put(handlers::api::update_access_rule)
                .delete(handlers::api::delete_access_rule),
        )
        // Sessions routes
        .route("/api/v1/sessions", get(handlers::api::list_sessions))
        .route("/api/v1/sessions", post(handlers::api::create_session))
        // DELETE stub returns 501 Not Implemented (not 200 OK)
        .route(
            "/api/v1/sessions/{uuid}",
            get(handlers::api::get_session)
                .delete(|| async { (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented") }),
        )
        // Web pages (HTML) - for testing raw SQL queries
        .route("/sessions", get(handlers::web::session_list))
        .route("/sessions/recordings", get(handlers::web::recording_list))
        // Issue #29 / UX-28: recording-centric detail page (UUID-keyed)
        // and download endpoint. Registered BEFORE `/sessions/{id}` to
        // ensure `/sessions/recordings/...` always wins routing.
        .route(
            "/sessions/recordings/{uuid}",
            get(handlers::web::recording_detail),
        )
        .route(
            "/sessions/recordings/{uuid}/download",
            get(handlers::web::download_recording),
        )
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
        .route(
            "/sessions/approvals/{uuid}/approve",
            post(handlers::web::approve_access_request),
        )
        .route(
            "/sessions/approvals/{uuid}/reject",
            post(handlers::web::reject_access_request),
        )
        .route("/sessions/my-requests", get(handlers::web::my_requests))
        .route(
            "/sessions/my-requests/{uuid}/cancel",
            post(handlers::web::cancel_access_request),
        )
        .route("/sessions/active", get(handlers::web::active_sessions))
        .route(
            "/sessions/{uuid}/terminate",
            post(handlers::web::terminate_session_web),
        )
        .route(
            "/api/v1/sessions/{uuid}/terminate",
            post(handlers::api::terminate_session),
        )
        // ----------------------------------------------------------------
        // Issue #27: USER zone -- `/assets` (list filtered by access
        // rules) + `/assets/{uuid}` (connect / request-access page).
        // Every other verb on `/assets/*` lives in the admin nest
        // below and is gated by `require_assets_manage`. v1.0 has not
        // shipped, so there are NO legacy admin routes mounted here:
        // tests targeting CRUD MUST use `/assets/manage/*`.
        // ----------------------------------------------------------------
        .route("/assets", get(handlers::web::asset_list))
        .route("/assets/{uuid}", get(handlers::web::asset_user_view))
        // ----------------------------------------------------------------
        // Issue #27: admin asset CRUD nest, mirrored from main.rs so
        // gate-matrix and anti-enumeration tests exercise the same
        // route_layer middleware as production.
        // ----------------------------------------------------------------
        .nest(
            "/assets/manage",
            Router::new()
                .route("/", get(handlers::web::manage_asset_list))
                .route(
                    "/new",
                    get(handlers::web::asset_create_form)
                        .post(handlers::web::create_asset_web),
                )
                .route("/deleted", get(handlers::web::asset_deleted_list))
                .route("/search", get(handlers::web::asset_search))
                .route("/{uuid}", get(handlers::web::asset_detail))
                .route(
                    "/{uuid}/edit",
                    get(handlers::web::asset_edit)
                        .post(handlers::web::update_asset_web),
                )
                .route(
                    "/{uuid}/delete",
                    post(handlers::web::delete_asset_web),
                )
                .route(
                    "/{uuid}/fetch-host-key",
                    post(handlers::web::fetch_ssh_host_key),
                )
                .route_layer(axum::middleware::from_fn(
                    middleware::require_assets_manage::require_assets_manage,
                )),
        )
        // ----------------------------------------------------------------
        // Issue #27: API admin nest, same defence-in-depth as the web nest.
        // ----------------------------------------------------------------
        .nest(
            "/api/v1/assets/manage",
            Router::new()
                .route("/", post(handlers::api::create_asset))
                .route("/groups", get(handlers::api::list_asset_groups))
                .route(
                    "/groups/{uuid}/assets",
                    get(handlers::api::list_group_assets),
                )
                .route(
                    "/{uuid}",
                    get(handlers::api::get_asset)
                        .put(handlers::api::update_asset),
                )
                .route(
                    "/{uuid}/ssh-host-key",
                    get(handlers::api::get_ssh_host_key_status)
                        .post(handlers::api::fetch_ssh_host_key_api),
                )
                .route_layer(axum::middleware::from_fn(
                    middleware::require_assets_manage::require_assets_manage,
                )),
        )
        // Access rules - literal routes MUST come before parameterized routes
        .route(
            "/assets/access/new",
            get(handlers::web::access_rule_create_form),
        )
        .route(
            "/assets/access",
            get(handlers::web::access_rules_list).post(handlers::web::create_access_rule_web),
        )
        .route(
            "/assets/access/{uuid}",
            get(handlers::web::access_rule_detail),
        )
        .route(
            "/assets/access/{uuid}/edit",
            get(handlers::web::access_rule_edit).post(handlers::web::update_access_rule_web),
        )
        .route(
            "/assets/access/{uuid}/delete",
            post(handlers::web::delete_access_rule_web),
        )
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
        // Account pages (profile, login sessions and API keys)
        .route("/accounts/profile", get(handlers::web::profile))
        // Self-service password rotation modal handler (mirror production
        // main.rs). POST-only on purpose: the form is rendered inline on
        // /accounts/profile via Alpine.js modal.
        .route(
            "/accounts/profile/password",
            post(handlers::web::change_own_password_web),
        )
        // Issue #8: renamed routes (mirror production main.rs).
        .route(
            "/accounts/login-sessions",
            get(handlers::web::user_sessions),
        )
        .route(
            "/accounts/login-sessions/{uuid}/revoke",
            post(handlers::web::revoke_session),
        )
        .route(
            "/accounts/all-login-sessions",
            get(handlers::web::admin_user_sessions),
        )
        .route(
            "/accounts/all-login-sessions/{uuid}/revoke",
            post(handlers::web::admin_revoke_session),
        )
        // Legacy 301 redirects (Issue #8 backward compatibility).
        .route(
            "/accounts/sessions",
            get(|| async { Redirect::permanent("/accounts/login-sessions") }),
        )
        .route(
            "/accounts/sessions/{uuid}/revoke",
            post(|Path(uuid): Path<String>| async move {
                Redirect::permanent(&format!("/accounts/login-sessions/{uuid}/revoke"))
            }),
        )
        .route(
            "/admin/sessions",
            get(|| async { Redirect::permanent("/accounts/all-login-sessions") }),
        )
        .route(
            "/admin/sessions/{uuid}/revoke",
            post(|Path(uuid): Path<String>| async move {
                Redirect::permanent(&format!("/accounts/all-login-sessions/{uuid}/revoke"))
            }),
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
        // SSH/RDP connection endpoints
        .route("/assets/{uuid}/connect", post(handlers::web::connect_ssh))
        .route(
            "/assets/{uuid}/connect-rdp",
            post(handlers::web::connect_rdp),
        )
        .route("/sessions/rdp/{session_id}", get(handlers::web::rdp_page))
        // SSH host key management
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
            get(handlers::api::get_ssh_host_key_status).post(handlers::api::fetch_ssh_host_key_api),
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
        // Audit middleware (injects RequestId extension required by
        // approve/reject handlers)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::audit::audit_middleware,
        ))
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
        // Add Casbin PermissionContext middleware BEFORE auth in the `.layer()`
        // chain so that after Router's reverse-order wrapping it ends up INSIDE
        // the auth layer (i.e. runs AFTER auth populates `AuthUser`). This
        // mirrors the ServiceBuilder-based layering in main.rs where auth is
        // added first (outermost) and perms second (innermost).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::permissions::permission_context_middleware,
        ))
        // Add auth middleware (outermost here so it runs first and populates
        // AuthUser before the PermissionContext middleware).
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
        diesel::sql_query("DELETE FROM access_rules")
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

/// In-process access service for IPC integration tests.
///
/// Spawns a background thread running the vauban-access handler logic,
/// connected via a pipe pair. Returns the `AccessIpcClient` and a handle
/// to the background service thread.
///
/// The service uses a **real Casbin enforcer** loaded from the workspace
/// `config/model.conf` and `config/default_policy.csv`, mirroring the
/// production policy. This means tests exercise the same authorization
/// logic as production, with no hardcoded "allow all" shortcut.
pub mod ipc_test_service {
    use std::os::unix::io::IntoRawFd;
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use casbin::prelude::*;
    use shared::ipc::{IpcChannel, IpcError};
    use shared::messages::{AccessResponse, Message, RbacResult};
    use vauban_web::ipc::AccessIpcClient;

    pub struct InProcessAccessService {
        pub access_client: Arc<AccessIpcClient>,
        _service_thread: JoinHandle<()>,
        _reader_thread: JoinHandle<()>,
    }

    pub fn spawn(database_url: &str) -> InProcessAccessService {
        let (p2c_read, p2c_write) = nix::unistd::pipe().expect("pipe p2c");
        let (c2p_read, c2p_write) = nix::unistd::pipe().expect("pipe c2p");

        let web_read_fd = c2p_read.into_raw_fd();
        let web_write_fd = p2c_write.into_raw_fd();
        let svc_read_fd = p2c_read.into_raw_fd();
        let svc_write_fd = c2p_write.into_raw_fd();

        let svc_channel = unsafe { IpcChannel::from_raw_fds(svc_read_fd, svc_write_fd) };

        let db_url = database_url.to_string();
        let service_thread = std::thread::spawn(move || {
            run_access_service_loop(svc_channel, &db_url);
        });

        let (client_tx, client_rx) = std::sync::mpsc::channel::<Arc<AccessIpcClient>>();

        let reader_thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("reader tokio runtime");

            rt.block_on(async move {
                let client =
                    AccessIpcClient::new(web_read_fd, web_write_fd).expect("AccessIpcClient::new");
                client_tx.send(Arc::clone(&client)).expect("send client");
                let _ = client.process_incoming().await;
            });
        });

        let access_client = client_rx.recv().expect("receive client Arc");

        InProcessAccessService {
            access_client,
            _service_thread: service_thread,
            _reader_thread: reader_thread,
        }
    }

    fn load_test_enforcer(rt: &tokio::runtime::Runtime) -> Enforcer {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("config")
            .join("access");
        let model_path = root.join("model.conf");
        let policy_path = root.join("default_policy.csv");
        assert!(
            model_path.exists(),
            "model.conf not found at {}",
            model_path.display()
        );
        assert!(
            policy_path.exists(),
            "default_policy.csv not found at {}",
            policy_path.display()
        );

        let model = rt
            .block_on(DefaultModel::from_file(
                model_path.to_str().unwrap().to_string(),
            ))
            .expect("load Casbin model");
        let adapter = FileAdapter::new(policy_path.to_str().unwrap().to_string());
        rt.block_on(Enforcer::new(model, adapter))
            .expect("build Casbin enforcer")
    }

    fn run_access_service_loop(channel: IpcChannel, database_url: &str) {
        use diesel_async::AsyncPgConnection;
        use diesel_async::pooled_connection::AsyncDieselConnectionManager;
        use diesel_async::pooled_connection::deadpool::Pool;

        // Multi-thread runtime: deadpool + block_on on current_thread can deadlock
        // when connection setup needs other tasks to run on the same runtime.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime for access service");

        let pool = {
            let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
            Pool::builder(manager).max_size(2).build().expect("DB pool")
        };

        let enforcer = load_test_enforcer(&rt);

        // Initialize vauban-access's virtual-group OnceLock from the test
        // database. The handlers that special-case the "All assets"
        // virtual group rely on this resolved id, so without this call
        // policy-resolution tests would silently fall back to the
        // UNINITIALIZED_VIRTUAL_ID sentinel and miss every virtual rule.
        if let Err(e) = rt.block_on(vauban_access::virtual_group::init_or_die(&pool)) {
            eprintln!("test access service: failed to init virtual_group OnceLock: {e:?}");
        }

        loop {
            match channel.recv() {
                Ok(Message::AccessRequest {
                    request_id,
                    request,
                }) => {
                    let response = rt.block_on(vauban_access::handlers::handle_access_request(
                        &pool, request,
                    ));
                    let msg = Message::AccessResponse {
                        request_id,
                        response,
                    };
                    match channel.send(&msg) {
                        Ok(()) => {}
                        Err(IpcError::MessageTooLarge { .. }) => {
                            let fallback = Message::AccessResponse {
                                request_id,
                                response: AccessResponse::Error(
                                    "IPC response exceeds maximum message size".to_string(),
                                ),
                            };
                            if channel.send(&fallback).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Ok(Message::RbacCheck {
                    request_id,
                    subject,
                    object,
                    action,
                }) => {
                    let allowed = enforcer
                        .enforce(vec![subject.clone(), object.clone(), action.clone()])
                        .unwrap_or(false);
                    let result = RbacResult {
                        allowed,
                        reason: if allowed {
                            None
                        } else {
                            Some("Policy denied".to_string())
                        },
                    };
                    let msg = Message::RbacResponse { request_id, result };
                    if channel.send(&msg).is_err() {
                        break;
                    }
                }
                Ok(Message::Control(shared::messages::ControlMessage::Shutdown)) => break,
                Err(shared::ipc::IpcError::ConnectionClosed) => break,
                Err(_) => continue,
                _ => {}
            }
        }
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
