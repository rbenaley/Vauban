/// VAUBAN Web - Main application entry point.
///
/// Rust web application using Axum, Diesel, and Askama.

use axum::{
    http::Method,
    routing::{get, post, put},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vauban_web::{
    config::{Config, LogFormat},
    db::create_pool,
    cache::create_cache_client,
    error::AppError,
    services::auth::AuthService,
    handlers,
    middleware,
    AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration first (needed for logging setup)
    let config = Config::from_env()
        .map_err(|e| {
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
    let db_pool = create_pool(&config)
        .map_err(|e| {
            eprintln!("Failed to create database pool: {}", e);
            e
        })?;

    // Create cache client (will use mock if disabled or unavailable)
    let cache = create_cache_client(&config).await
        .map_err(|e| {
            eprintln!("Failed to create cache client: {}", e);
            e
        })?;
    
    if config.cache.enabled {
        tracing::info!("Cache enabled and connected");
    } else {
        tracing::info!("Cache disabled - using mock cache (no-op)");
    }

    // Create auth service
    let auth_service = AuthService::new(config.clone())
        .map_err(|e| {
            eprintln!("Failed to create auth service: {}", e);
            e
        })?;

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        db_pool,
        cache,
        auth_service,
    };

    // Build application
    let app = create_app(app_state).await?;

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!(address = %addr, "Server listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create Axum application.
async fn create_app(state: AppState) -> Result<Router, AppError> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::OPTIONS])
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
        
        // Web pages (HTML)
        .route("/login", get(handlers::web::login_page))
        .route("/", get(handlers::web::dashboard_home))
        .route("/dashboard", get(handlers::web::dashboard_home))
        .route("/dashboard/", get(handlers::web::dashboard_home))
        .route("/dashboard/widgets/stats", get(handlers::web::dashboard_widget_stats))
        .route("/dashboard/widgets/active-sessions", get(handlers::web::dashboard_widget_active_sessions))
        .route("/dashboard/widgets/recent-activity", get(handlers::web::dashboard_widget_recent_activity))
        .route("/admin", get(handlers::web::dashboard_admin))
        
        // Accounts pages
        .route("/accounts/users", get(handlers::web::user_list))
        .route("/accounts/users/{uuid}", get(handlers::web::user_detail))
        .route("/accounts/profile", get(handlers::web::profile))
        .route("/accounts/mfa", get(handlers::web::mfa_setup))
        
        // Assets pages (specific routes before generic {id} route)
        .route("/assets", get(handlers::web::asset_list))
        .route("/assets/groups", get(handlers::web::asset_group_list))
        .route("/assets/groups/{uuid}", get(handlers::web::asset_group_detail))
        .route("/assets/groups/{uuid}/edit", get(handlers::web::asset_group_edit))
        .route("/assets/access", get(handlers::web::access_rules_list))
        .route("/assets/{id}", get(handlers::web::asset_detail))
        
        // Sessions pages
        .route("/sessions", get(handlers::web::session_list))
        .route("/sessions/recordings", get(handlers::web::recording_list))
        .route("/sessions/recordings/{id}/play", get(handlers::web::recording_play))
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route("/sessions/approvals", get(handlers::web::approval_list))
        .route("/sessions/approvals/{uuid}", get(handlers::web::approval_detail))
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
        .route("/api/v1/accounts/{uuid}", put(handlers::accounts::update_user))
        .route("/api/v1/accounts/{uuid}", axum::routing::delete(|| async { "Not implemented" }))
        
        .route("/api/v1/assets", get(handlers::assets::list_assets))
        .route("/api/v1/assets", post(handlers::assets::create_asset))
        .route("/api/v1/assets/{uuid}", get(handlers::assets::get_asset))
        .route("/api/v1/assets/{uuid}", put(handlers::assets::update_asset))
        .route("/api/v1/assets/{uuid}", axum::routing::delete(|| async { "Not implemented" }))
        // Asset groups API
        .route("/api/v1/assets/groups/{uuid}", post(handlers::web::update_asset_group))
        
        .route("/api/v1/sessions", get(handlers::sessions::list_sessions))
        .route("/api/v1/sessions", post(handlers::sessions::create_session))
        .route("/api/v1/sessions/{uuid}", get(handlers::sessions::get_session))
        .route("/api/v1/sessions/{uuid}", axum::routing::delete(|| async { "Not implemented" }))
        
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, std::time::Duration::from_secs(30)))
                .layer(cors)
                .layer(axum::middleware::from_fn_with_state(state.auth_service.clone(), middleware::auth::auth_middleware))
                .layer(axum::middleware::from_fn(middleware::audit::audit_middleware))
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
