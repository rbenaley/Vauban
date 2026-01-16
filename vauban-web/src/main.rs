/// VAUBAN Web - Main application entry point.
///
/// Rust web application using Axum, Diesel, and Askama.
/// Runs exclusively over HTTPS with TLS 1.3.
use axum::{
    Router,
    http::Method,
    routing::{get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vauban_web::{
    AppState,
    cache::create_cache_client,
    config::{Config, LogFormat},
    db::create_pool,
    error::AppError,
    handlers, middleware,
    services::auth::AuthService,
    services::broadcast::BroadcastService,
    tasks::{start_cleanup_tasks, start_dashboard_tasks},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the default crypto provider for rustls (aws-lc-rs)
    // This must be done before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load configuration from TOML files
    let config = Config::load().map_err(|e| {
        eprintln!("Failed to load configuration: {}", e);
        e
    })?;

    // Initialize tracing based on configuration
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("vauban_web={},tower_http=info", config.logging.level).into());

    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }

    tracing::info!(
        environment = %config.environment.as_str(),
        "Starting VAUBAN Web"
    );

    // Create database pool
    let db_pool = create_pool(&config).map_err(|e| {
        eprintln!("Failed to create database pool: {}", e);
        e
    })?;

    // Create cache client (will use mock if disabled or unavailable)
    let cache = create_cache_client(&config).await.map_err(|e| {
        eprintln!("Failed to create cache client: {}", e);
        e
    })?;

    if config.cache.enabled {
        tracing::info!("Cache enabled and connected");
    } else {
        tracing::info!("Cache disabled - using mock cache (no-op)");
    }

    // Create auth service
    let auth_service = AuthService::new(config.clone()).map_err(|e| {
        eprintln!("Failed to create auth service: {}", e);
        e
    })?;

    // Create broadcast service for WebSocket
    let broadcast = BroadcastService::new();
    tracing::info!("Broadcast service initialized");

    // Create user connection registry for personalized WebSocket messages
    let user_connections = vauban_web::services::connections::UserConnectionRegistry::new();
    tracing::info!("User connection registry initialized");

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        db_pool: db_pool.clone(),
        cache,
        auth_service,
        broadcast: broadcast.clone(),
        user_connections,
    };

    // Start background tasks for WebSocket updates
    start_dashboard_tasks(broadcast, db_pool.clone()).await;

    // Start cleanup tasks for expired sessions and API keys
    start_cleanup_tasks(db_pool).await;

    // Build application
    let app = create_app(app_state).await?;

    // Load TLS configuration (HTTPS only, TLS 1.3)
    let tls_config = load_tls_config(&config).await.map_err(|e| {
        eprintln!("Failed to load TLS configuration: {}", e);
        e
    })?;

    // Start HTTPS server (HTTP is not supported)
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid address: {}", e))?;

    tracing::info!(
        address = %addr,
        cert = %config.server.tls.cert_path,
        "HTTPS server listening (TLS 1.3 only)"
    );

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Load TLS configuration from certificate files.
/// Configures rustls for TLS 1.3 only (no TLS 1.2 or lower).
async fn load_tls_config(config: &Config) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    use rustls::ServerConfig;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs::File;
    use std::io::BufReader;

    let cert_path = &config.server.tls.cert_path;
    let key_path = &config.server.tls.key_path;

    // Validate that certificate files exist
    if !std::path::Path::new(cert_path).exists() {
        return Err(format!(
            "TLS certificate not found: {}. Run scripts/generate-dev-certs.sh for development.",
            cert_path
        )
        .into());
    }
    if !std::path::Path::new(key_path).exists() {
        return Err(format!("TLS private key not found: {}", key_path).into());
    }

    // Load certificate chain
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut cert_reader)
        .filter_map(|cert| cert.ok())
        .collect();

    if cert_chain.is_empty() {
        return Err("No valid certificates found in certificate file".into());
    }

    // Load CA chain if provided (for intermediate certificates)
    let mut full_chain = cert_chain;
    if let Some(ca_path) = &config.server.tls.ca_chain_path
        && std::path::Path::new(ca_path).exists()
    {
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_reader_iter(&mut ca_reader)
                .filter_map(|cert| cert.ok())
                .collect();
        full_chain.extend(ca_certs);
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .map_err(|e| format!("No valid private key found in key file: {}", e))?;

    // Build rustls config with TLS 1.3 ONLY
    // Explicitly restrict to TLS 1.3 protocol version (no TLS 1.2 or lower)
    let server_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(full_chain, private_key)?;

    tracing::debug!(
        "TLS configured: TLS 1.3 only, {} cipher suites available",
        server_config.crypto_provider().cipher_suites.len()
    );

    Ok(RustlsConfig::from_config(std::sync::Arc::new(
        server_config,
    )))
}

/// Create Axum application.
///
/// Routes are organized into:
/// - Web routes: Always active, serve HTML pages for human users
/// - API routes: Conditionally active based on config.api.enabled, serve JSON for M2M
async fn create_app(state: AppState) -> Result<Router, AppError> {
    use secrecy::ExposeSecret;
    
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, request_parts| {
            let host = request_parts
                .headers
                .get(axum::http::header::HOST)
                .and_then(|value| value.to_str().ok());
            let origin = origin.to_str().ok();

            match (origin, host) {
                (Some(origin), Some(host)) => is_same_origin(origin, host),
                _ => false,
            }
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    // Get flash secret key from config
    let flash_secret = state.config.secret_key.expose_secret().as_bytes().to_vec();

    // ==========================================================================
    // WEB ROUTES - Always active (HTML pages for human users)
    // ==========================================================================
    let web_routes = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Static files (served from static/ directory)
        .route("/static/{*path}", get(serve_static))
        // WebSocket routes (real-time updates)
        .route("/ws/dashboard", get(handlers::websocket::dashboard_ws))
        .route("/ws/session/{id}", get(handlers::websocket::session_ws))
        .route(
            "/ws/notifications",
            get(handlers::websocket::notifications_ws),
        )
        // Authentication pages and form handlers
        .route("/login", get(handlers::web::login_page))
        .route("/auth/login", post(handlers::auth::login_web))
        .route("/auth/logout", post(handlers::auth::logout_web))
        // Dashboard pages
        .route("/", get(handlers::web::dashboard_home))
        .route("/dashboard", get(handlers::web::dashboard_home))
        .route("/dashboard/", get(handlers::web::dashboard_home))
        .route("/admin", get(handlers::web::dashboard_admin))
        // Accounts pages
        // User management routes - literal paths MUST come before parameterized paths
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
        .route("/accounts/profile", get(handlers::web::profile))
        .route("/accounts/mfa", get(handlers::web::mfa_setup))
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
        .route("/accounts/groups", get(handlers::web::group_list))
        .route("/accounts/groups/{uuid}", get(handlers::web::group_detail))
        // Assets pages - GET for viewing, POST for form submission (PRG pattern)
        .route("/assets", get(handlers::web::asset_list))
        .route("/assets/groups", get(handlers::web::asset_group_list))
        .route(
            "/assets/groups/{uuid}",
            get(handlers::web::asset_group_detail),
        )
        .route(
            "/assets/groups/{uuid}/edit",
            get(handlers::web::asset_group_edit).post(handlers::web::update_asset_group),
        )
        .route("/assets/access", get(handlers::web::access_rules_list))
        .route("/assets/search", get(handlers::web::asset_search))
        .route(
            "/assets/{uuid}/edit",
            get(handlers::web::asset_edit).post(handlers::web::update_asset_web),
        )
        .route(
            "/assets/{uuid}/delete",
            post(handlers::web::delete_asset_web),
        )
        .route("/assets/{uuid}", get(handlers::web::asset_detail))
        // Sessions pages
        .route("/sessions", get(handlers::web::session_list))
        .route("/sessions/{id}/terminate", post(handlers::web::terminate_session_web))
        .route("/sessions/recordings", get(handlers::web::recording_list))
        .route(
            "/sessions/recordings/{id}/play",
            get(handlers::web::recording_play),
        )
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route("/sessions/approvals", get(handlers::web::approval_list))
        .route(
            "/sessions/approvals/{uuid}",
            get(handlers::web::approval_detail),
        )
        .route("/sessions/active", get(handlers::web::active_sessions));

    // ==========================================================================
    // API ROUTES - Conditionally active based on config.api.enabled
    // These are M2M (Machine-to-Machine) endpoints returning JSON only
    // ==========================================================================
    let api_enabled = state.config.api.enabled;

    let api_routes = if api_enabled {
        tracing::info!("API routes enabled at {}", state.config.api.prefix);
        Router::new()
            // Authentication API
            .route("/api/v1/auth/login", post(handlers::auth::login))
            .route("/api/v1/auth/logout", post(handlers::auth::logout))
            .route("/api/v1/auth/mfa/setup", post(handlers::auth::setup_mfa))
            // Accounts API
            .route("/api/v1/accounts", get(handlers::api::list_users))
            .route("/api/v1/accounts", post(handlers::api::create_user))
            .route("/api/v1/accounts/{uuid}", get(handlers::api::get_user))
            .route("/api/v1/accounts/{uuid}", put(handlers::api::update_user))
            .route(
                "/api/v1/accounts/{uuid}",
                axum::routing::delete(|| async { "Not implemented" }),
            )
            // Assets API
            .route("/api/v1/assets", get(handlers::api::list_assets))
            .route("/api/v1/assets", post(handlers::api::create_asset))
            .route("/api/v1/assets/{uuid}", get(handlers::api::get_asset))
            .route("/api/v1/assets/{uuid}", put(handlers::api::update_asset))
            .route(
                "/api/v1/assets/{uuid}",
                axum::routing::delete(|| async { "Not implemented" }),
            )
            // Sessions API
            .route("/api/v1/sessions", get(handlers::api::list_sessions))
            .route("/api/v1/sessions", post(handlers::api::create_session))
            .route("/api/v1/sessions/{uuid}", get(handlers::api::get_session))
            .route(
                "/api/v1/sessions/{uuid}",
                axum::routing::delete(|| async { "Not implemented" }),
            )
            .route(
                "/api/v1/sessions/{id}/terminate",
                post(handlers::api::terminate_session),
            )
    } else {
        tracing::info!("API routes disabled by configuration");
        Router::new()
            // Return 404 for all API routes when disabled
            .route("/api/v1/{*path}", get(api_disabled_handler).post(api_disabled_handler).put(api_disabled_handler).delete(api_disabled_handler))
    };

    // Merge web and API routes
    let flash_key = middleware::flash::FlashSecretKey(flash_secret);
    let app = web_routes
        .merge(api_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    std::time::Duration::from_secs(30),
                ))
                .layer(cors)
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    middleware::csrf::csrf_cookie_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    flash_key,
                    middleware::flash::flash_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    middleware::auth::auth_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    middleware::audit::audit_middleware,
                )),
        )
        .with_state(state);

    Ok(app)
}

/// Determine if the Origin header matches the request host.
fn is_same_origin(origin: &str, host: &str) -> bool {
    let origin = origin.trim_end_matches('/');
    let expected = format!("https://{}", host);
    origin == expected
}

/// Handler for disabled API routes.
async fn api_disabled_handler() -> (axum::http::StatusCode, &'static str) {
    (axum::http::StatusCode::NOT_FOUND, "API is disabled")
}

/// Health check endpoint.
async fn health_check() -> &'static str {
    "OK"
}

/// Serve static files (placeholder - implement proper static file serving).
async fn serve_static(
    axum::extract::Path(_path): axum::extract::Path<String>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    // TODO: Implement proper static file serving
    Err(axum::http::StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== health_check Tests ====================

    #[tokio::test]
    async fn test_health_check_returns_ok() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }

    // ==================== serve_static Tests ====================

    #[tokio::test]
    async fn test_serve_static_returns_not_found() {
        let path = axum::extract::Path("test.css".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_serve_static_any_path_returns_not_found() {
        let path = axum::extract::Path("js/app.js".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
    }

    // ==================== Configuration Tests ====================

    #[test]
    fn test_socket_addr_parsing() {
        let addr: Result<SocketAddr, _> = "127.0.0.1:8080".parse();
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().port(), 8080);
    }

    #[test]
    fn test_socket_addr_parsing_invalid() {
        let addr: Result<SocketAddr, _> = "invalid:address".parse();
        assert!(addr.is_err());
    }

    #[test]
    fn test_socket_addr_ipv6() {
        let addr: Result<SocketAddr, _> = "[::1]:8443".parse();
        assert!(addr.is_ok());
    }

    // ==================== Additional health_check Tests ====================

    #[tokio::test]
    async fn test_health_check_is_static_str() {
        let response = health_check().await;
        assert!(response.len() == 2);
    }

    // ==================== serve_static Tests ====================

    #[tokio::test]
    async fn test_serve_static_nested_path() {
        let path = axum::extract::Path("images/logo.png".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_serve_static_empty_path() {
        let path = axum::extract::Path("".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_serve_static_with_dots() {
        let path = axum::extract::Path("../../../etc/passwd".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
    }

    // ==================== SocketAddr Tests ====================

    #[test]
    fn test_socket_addr_format_string() {
        let host = "127.0.0.1";
        let port = 8443u16;
        let addr_str = format!("{}:{}", host, port);
        let addr: SocketAddr = addr_str.parse().unwrap();
        assert_eq!(addr.port(), 8443);
    }

    #[test]
    fn test_socket_addr_ipv6_full() {
        let addr: Result<SocketAddr, _> = "[2001:db8:85a3::8a2e:370:7334]:443".parse();
        assert!(addr.is_ok());
    }

    #[test]
    fn test_socket_addr_any_interface() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    fn test_socket_addr_localhost_variations() {
        let localhost: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(localhost.ip().is_loopback());

        let ipv6_localhost: SocketAddr = "[::1]:80".parse().unwrap();
        assert!(ipv6_localhost.ip().is_loopback());
    }

    // ==================== Port Tests ====================

    #[test]
    fn test_common_https_port() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_development_port() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_high_port() {
        let addr: SocketAddr = "127.0.0.1:65535".parse().unwrap();
        assert_eq!(addr.port(), 65535);
    }

    // ==================== CORS Methods Test ====================

    #[test]
    fn test_http_methods_available() {
        // Verify all HTTP methods used in CORS are valid
        assert_eq!(Method::GET.as_str(), "GET");
        assert_eq!(Method::POST.as_str(), "POST");
        assert_eq!(Method::PUT.as_str(), "PUT");
        assert_eq!(Method::DELETE.as_str(), "DELETE");
        assert_eq!(Method::PATCH.as_str(), "PATCH");
        assert_eq!(Method::OPTIONS.as_str(), "OPTIONS");
    }

    // ==================== CORS Origin Tests ====================

    #[test]
    fn test_is_same_origin_https_match() {
        let origin = "https://example.com:8443";
        let host = "example.com:8443";
        assert!(is_same_origin(origin, host));
    }

    #[test]
    fn test_is_same_origin_trailing_slash() {
        let origin = "https://example.com";
        let host = "example.com";
        assert!(is_same_origin(origin, host));
        assert!(is_same_origin("https://example.com/", host));
    }

    #[test]
    fn test_is_same_origin_scheme_mismatch() {
        let origin = "http://example.com";
        let host = "example.com";
        assert!(!is_same_origin(origin, host));
    }

    #[test]
    fn test_is_same_origin_host_mismatch() {
        let origin = "https://other.example.com";
        let host = "example.com";
        assert!(!is_same_origin(origin, host));
    }
}
