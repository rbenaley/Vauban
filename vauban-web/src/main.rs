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
    cors::{Any, CorsLayer},
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
    tasks::start_dashboard_tasks,
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

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        db_pool: db_pool.clone(),
        cache,
        auth_service,
        broadcast: broadcast.clone(),
    };

    // Start background tasks for WebSocket updates
    start_dashboard_tasks(broadcast, db_pool).await;

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
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Load TLS configuration from certificate files.
/// Configures rustls for TLS 1.3 only (no TLS 1.2 or lower).
async fn load_tls_config(config: &Config) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let cert_path = &config.server.tls.cert_path;
    let key_path = &config.server.tls.key_path;

    // Validate that certificate files exist
    if !std::path::Path::new(cert_path).exists() {
        return Err(format!(
            "TLS certificate not found: {}. Run scripts/generate-dev-certs.sh for development.",
            cert_path
        ).into());
    }
    if !std::path::Path::new(key_path).exists() {
        return Err(format!("TLS private key not found: {}", key_path).into());
    }

    // Load certificate chain
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<_> = certs(&mut cert_reader)
        .filter_map(|cert| cert.ok())
        .collect();

    if cert_chain.is_empty() {
        return Err("No valid certificates found in certificate file".into());
    }

    // Load CA chain if provided (for intermediate certificates)
    let mut full_chain = cert_chain;
    if let Some(ca_path) = &config.server.tls.ca_chain_path {
        if std::path::Path::new(ca_path).exists() {
            let ca_file = File::open(ca_path)?;
            let mut ca_reader = BufReader::new(ca_file);
            let ca_certs: Vec<_> = certs(&mut ca_reader)
                .filter_map(|cert| cert.ok())
                .collect();
            full_chain.extend(ca_certs);
        }
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = private_key(&mut key_reader)?
        .ok_or("No valid private key found in key file")?;

    // Build rustls config with TLS 1.3 ONLY
    // Explicitly restrict to TLS 1.3 protocol version (no TLS 1.2 or lower)
    let server_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(full_chain, private_key)?;

    tracing::debug!(
        "TLS configured: TLS 1.3 only, {} cipher suites available",
        server_config.crypto_provider().cipher_suites.len()
    );

    Ok(RustlsConfig::from_config(std::sync::Arc::new(server_config)))
}

/// Create Axum application.
async fn create_app(state: AppState) -> Result<Router, AppError> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
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

    let app = Router::new()
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
        // Web pages (HTML)
        .route("/login", get(handlers::web::login_page))
        .route("/", get(handlers::web::dashboard_home))
        .route("/dashboard", get(handlers::web::dashboard_home))
        .route("/dashboard/", get(handlers::web::dashboard_home))
        .route("/admin", get(handlers::web::dashboard_admin))
        // Accounts pages
        .route("/accounts/users", get(handlers::web::user_list))
        .route("/accounts/users/{uuid}", get(handlers::web::user_detail))
        .route("/accounts/profile", get(handlers::web::profile))
        .route("/accounts/mfa", get(handlers::web::mfa_setup))
        // Assets pages (specific routes before generic {id} route)
        .route("/assets", get(handlers::web::asset_list))
        .route("/assets/groups", get(handlers::web::asset_group_list))
        .route(
            "/assets/groups/{uuid}",
            get(handlers::web::asset_group_detail),
        )
        .route(
            "/assets/groups/{uuid}/edit",
            get(handlers::web::asset_group_edit),
        )
        .route("/assets/access", get(handlers::web::access_rules_list))
        .route("/assets/{id}", get(handlers::web::asset_detail))
        // Sessions pages
        .route("/sessions", get(handlers::web::session_list))
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
        .route("/sessions/active", get(handlers::web::active_sessions))
        // Groups pages (user groups)
        .route("/accounts/groups", get(handlers::web::group_list))
        .route("/accounts/groups/{uuid}", get(handlers::web::group_detail))
        // Authentication routes
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/logout", post(handlers::auth::logout))
        .route("/api/auth/mfa/setup", post(handlers::auth::setup_mfa))
        // API v1 routes
        .route("/api/v1/accounts", get(handlers::accounts::list_users))
        .route("/api/v1/accounts", post(handlers::accounts::create_user))
        .route("/api/v1/accounts/{uuid}", get(handlers::accounts::get_user))
        .route(
            "/api/v1/accounts/{uuid}",
            put(handlers::accounts::update_user),
        )
        .route(
            "/api/v1/accounts/{uuid}",
            axum::routing::delete(|| async { "Not implemented" }),
        )
        .route("/api/v1/assets", get(handlers::assets::list_assets))
        .route("/api/v1/assets", post(handlers::assets::create_asset))
        .route("/api/v1/assets/{uuid}", get(handlers::assets::get_asset))
        .route("/api/v1/assets/{uuid}", put(handlers::assets::update_asset))
        .route(
            "/api/v1/assets/{uuid}",
            axum::routing::delete(|| async { "Not implemented" }),
        )
        // Asset groups API
        .route(
            "/api/v1/assets/groups/{uuid}",
            post(handlers::web::update_asset_group),
        )
        .route("/api/v1/sessions", get(handlers::sessions::list_sessions))
        .route("/api/v1/sessions", post(handlers::sessions::create_session))
        .route(
            "/api/v1/sessions/{uuid}",
            get(handlers::sessions::get_session),
        )
        .route(
            "/api/v1/sessions/{uuid}",
            axum::routing::delete(|| async { "Not implemented" }),
        )
        .route(
            "/api/v1/sessions/{id}/terminate",
            post(handlers::sessions::terminate_session),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(
                    axum::http::StatusCode::REQUEST_TIMEOUT,
                    std::time::Duration::from_secs(30),
                ))
                .layer(cors)
                .layer(axum::middleware::from_fn_with_state(
                    state.auth_service.clone(),
                    middleware::auth::auth_middleware,
                ))
                .layer(axum::middleware::from_fn(
                    middleware::audit::audit_middleware,
                )),
        )
        .with_state(state);

    Ok(app)
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
