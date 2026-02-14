// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
#![cfg_attr(test, allow(
    clippy::unwrap_used, clippy::expect_used, clippy::panic,
    clippy::print_stdout, clippy::print_stderr
))]

/// VAUBAN Web - Main application entry point.
///
/// Rust web application using Axum, Diesel, and Askama.
/// Runs exclusively over HTTPS with TLS 1.3.
use axum::{
    Router,
    http::Method,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use secrecy::ExposeSecret;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import for supervisor and vault IPC clients
use vauban_web::ipc::{SupervisorClient, VaultCryptoClient};

/// Initialize the supervisor client if running under supervisor.
///
/// Returns the supervisor client if IPC is available, None otherwise.
/// The client spawns a dedicated thread for IPC communication (heartbeat, TCP brokering).
/// The `server_handle` is used for M-8/M-10 graceful shutdown.
fn init_supervisor_client(server_handle: axum_server::Handle<std::net::SocketAddr>) -> Option<Arc<SupervisorClient>> {
    use std::os::unix::io::RawFd;

    // Check if we're running under supervisor (IPC environment variables set)
    let ipc_read_fd: RawFd = match std::env::var("VAUBAN_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let ipc_write_fd: RawFd = match std::env::var("VAUBAN_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // Clear environment variables immediately for security
    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
    }

    let client = SupervisorClient::new(ipc_read_fd, ipc_write_fd, Some(server_handle));
    tracing::info!("Supervisor client initialized (running under supervisor)");
    Some(Arc::new(client))
}

use vauban_web::{
    AppState,
    cache::create_cache_client,
    config::{Config, LogFormat},
    db::create_pool_sandboxed,
    error::AppError,
    handlers, middleware,
    ipc::ProxySshClient,
    services::auth::AuthService,
    services::broadcast::BroadcastService,
    services::rate_limit::RateLimiter,
    tasks::{start_cleanup_tasks, start_dashboard_tasks},
};

/// Initialize SSH proxy client if IPC environment variables are set.
///
/// Returns Some(Arc<ProxySshClient>) if VAUBAN_PROXY_SSH_IPC_READ and VAUBAN_PROXY_SSH_IPC_WRITE
/// environment variables are set (running under supervisor), None otherwise.
fn init_ssh_proxy_client() -> Option<Arc<ProxySshClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_PROXY_SSH_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_PROXY_SSH_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // Clear environment variables immediately for security
    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_SSH_IPC_WRITE");
    }

    match ProxySshClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("SSH proxy client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize SSH proxy client: {}", e);
            None
        }
    }
}

/// Initialize the vault crypto client if running under supervisor (M-1, C-2).
///
/// Returns Some(Arc<VaultCryptoClient>) if VAUBAN_VAULT_IPC_READ and VAUBAN_VAULT_IPC_WRITE
/// environment variables are set (running under supervisor), None otherwise.
fn init_vault_client() -> Option<Arc<VaultCryptoClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_VAULT_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_VAULT_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // Clear environment variables immediately for security
    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_VAULT_IPC_READ");
        std::env::remove_var("VAUBAN_VAULT_IPC_WRITE");
    }

    match VaultCryptoClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("Vault crypto client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize vault crypto client: {}", e);
            None
        }
    }
}

// Early startup uses eprintln! because tracing may not be initialized yet.
// These are critical error paths that must be visible even without structured logging.
#[allow(clippy::print_stderr)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // M-8/M-10: Create server handle early for graceful shutdown.
    // The handle is shared with the supervisor IPC thread so it can trigger
    // graceful HTTP server shutdown instead of calling process::exit(0).
    let server_handle = axum_server::Handle::new();

    // Initialize supervisor client if running under supervisor
    // This must be done early, before any async runtime setup
    let supervisor_client = init_supervisor_client(server_handle.clone());

    // Install the default crypto provider for rustls (aws-lc-rs)
    // This must be done before any TLS operations
    // SAFETY: This is a startup invariant - the app cannot run without TLS
    #[allow(clippy::expect_used)]
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

    // ========================================================================
    // PHASE 1: Open all resources BEFORE entering Capsicum sandbox
    // After cap_enter(), no new file descriptors can be opened.
    // ========================================================================

    // 1. Parse address and bind socket BEFORE sandbox
    // This must be done before cap_enter() as bind() requires access to network namespace
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid address: {}", e))?;

    let tokio_listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        e
    })?;

    // Convert to std listener BEFORE entering sandbox
    // This must be done before cap_enter() as the conversion may require syscalls
    let std_listener = tokio_listener.into_std().map_err(|e| {
        eprintln!("Failed to convert listener: {}", e);
        e
    })?;
    tracing::info!(address = %addr, "Socket bound for HTTPS");

    // 2. Load TLS configuration (opens certificate files)
    let tls_config = load_tls_config(&config).await.map_err(|e| {
        eprintln!("Failed to load TLS configuration: {}", e);
        e
    })?;
    tracing::debug!("TLS configuration loaded");

    // 3. Create database pool with all connections pre-established (sandbox mode)
    // Uses fixed-size pool where all connections are validated at startup
    let db_pool = create_pool_sandboxed(&config).await.map_err(|e| {
        eprintln!("Failed to create database pool: {}", e);
        e
    })?;

    // 4. Create cache client and validate connection
    let cache = create_cache_client(&config).await.map_err(|e| {
        eprintln!("Failed to create cache client: {}", e);
        e
    })?;

    // Validate cache connection before entering sandbox
    cache.validate_connection().await.map_err(|e| {
        eprintln!("Failed to validate cache connection: {}", e);
        e
    })?;

    if cache.is_redis() {
        tracing::info!("Cache enabled and validated (Redis/Valkey)");
    } else {
        tracing::info!("Cache disabled - using mock cache (no-op)");
    }

    // 5. Create auth service (may open files for key material)
    let auth_service = AuthService::new(config.clone()).map_err(|e| {
        eprintln!("Failed to create auth service: {}", e);
        e
    })?;

    // 6. Create other services (no file access needed)
    let broadcast = BroadcastService::new();
    tracing::debug!("Broadcast service initialized");

    let user_connections = vauban_web::services::connections::UserConnectionRegistry::new();
    tracing::debug!("User connection registry initialized");

    // 7. Create rate limiter (may open Redis connection)
    let rate_limiter = RateLimiter::new(
        config.cache.enabled,
        Some(config.cache.url.expose_secret()),
        config.security.rate_limit_per_minute,
    )?;
    tracing::info!(
        "Rate limiter initialized (backend: {}, limit: {}/min)",
        if config.cache.enabled {
            "Redis"
        } else {
            "in-memory"
        },
        config.security.rate_limit_per_minute
    );

    // 8. Static files are embedded in the binary (see static_assets module).
    //    No filesystem access needed - files are compiled in via include_bytes!().
    tracing::info!(
        files = vauban_web::static_assets::STATIC_FILES.len(),
        "Static assets compiled into binary"
    );

    // ========================================================================
    // PHASE 2: Enter Capsicum sandbox (point of no return)
    // After this, no new file descriptors can be opened.
    // ========================================================================

    enter_sandbox(&std_listener)?;

    // ========================================================================
    // PHASE 3: Build application and serve requests
    // All resources are now pre-opened, running in sandbox mode.
    // ========================================================================

    // Create SSH proxy client if running under supervisor
    let ssh_proxy = init_ssh_proxy_client();

    // Spawn SSH proxy IPC processing task if client is available
    if let Some(ref client) = ssh_proxy {
        let client_clone = Arc::clone(client);
        tokio::spawn(async move {
            if let Err(e) = client_clone.process_incoming().await {
                tracing::error!(error = %e, "SSH proxy IPC processing task failed");
            }
        });
        tracing::info!("SSH proxy IPC processing task started");
    }

    // Create vault crypto client if running under supervisor (M-1, C-2)
    let vault_client = init_vault_client();

    // Spawn vault IPC processing task if client is available
    if let Some(ref client) = vault_client {
        let client_clone = Arc::clone(client);
        tokio::spawn(async move {
            if let Err(e) = client_clone.process_incoming().await {
                tracing::error!(error = %e, "Vault IPC processing task failed");
            }
        });
        tracing::info!("Vault IPC processing task started");
    }

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        db_pool: db_pool.clone(),
        cache,
        auth_service,
        broadcast: broadcast.clone(),
        user_connections,
        rate_limiter,
        ssh_proxy,
        supervisor: supervisor_client,
        vault_client,
    };

    // Start background tasks for WebSocket updates
    start_dashboard_tasks(broadcast, db_pool.clone()).await;

    // Start cleanup tasks for expired sessions and API keys
    start_cleanup_tasks(db_pool).await;

    // Build application router
    let app = create_app(app_state).await?;

    tracing::info!(
        address = %addr,
        cert = %config.server.tls.cert_path,
        sandbox = %cfg!(target_os = "freebsd"),
        "HTTPS server listening (TLS 1.3 only)"
    );

    // M-8/M-10: Pass server_handle so graceful_shutdown() from supervisor IPC
    // thread will cause this .serve() to return, letting main() exit normally
    // and all Drop/Zeroize destructors run.
    axum_server::from_tcp_rustls(std_listener, tls_config)?
        .handle(server_handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Enter Capsicum capability mode (FreeBSD sandbox).
///
/// After calling this function:
/// - No new file descriptors can be opened from the global namespace
/// - The process can only access pre-opened file descriptors
/// - If any connection is lost, the process must exit for respawn
///
/// On non-FreeBSD platforms, this is a no-op with a warning.
#[cfg(target_os = "freebsd")]
fn enter_sandbox(_listener: &std::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    use shared::capsicum;

    // Enter capability mode - point of no return
    // After this, no new file descriptors can be opened from global namespace.
    //
    // Note: We do NOT limit rights on the listening socket because tokio/axum
    // require capabilities that are difficult to enumerate precisely (accept,
    // fcntl, ioctl, poll events, etc.). The primary security comes from
    // cap_enter() itself which prevents opening new files/sockets.
    capsicum::enter_capability_mode()
        .map_err(|e| format!("Failed to enter capability mode: {}", e))?;

    tracing::info!("Entered Capsicum capability mode - sandbox active");
    Ok(())
}

#[cfg(not(target_os = "freebsd"))]
fn enter_sandbox(_listener: &std::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
    tracing::warn!("Capsicum not available on this platform - running without sandbox");
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
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_reader)
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
    // WEBSOCKET ROUTES - No timeout (long-lived connections)
    // ==========================================================================

    // Session ownership middleware: verifies the authenticated user owns the
    // session (or is staff/superuser) before allowing WebSocket upgrade.
    let session_guard = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_session_guard,
    );

    let ws_routes = Router::new()
        .route("/ws/dashboard", get(handlers::websocket::dashboard_ws))
        // Session-specific routes get the ownership guard middleware
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
        .route(
            "/ws/terminal/{session_id}",
            get(handlers::websocket::terminal_ws).layer(session_guard),
        );

    // ==========================================================================
    // WEB ROUTES - Always active (HTML pages for human users)
    // ==========================================================================
    let web_routes = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Static files (served from static/ directory)
        .route("/static/{*path}", get(serve_static))
        // HTMX utility routes
        .route("/htmx/empty", get(handlers::web::htmx_empty))
        // Authentication pages and form handlers
        .route("/login", get(handlers::web::login_page))
        .route("/auth/login", post(handlers::auth::login_web))
        .route("/auth/logout", post(handlers::auth::logout_web))
        // MFA setup and verification (after login, before dashboard access)
        .route(
            "/mfa/setup",
            get(handlers::auth::mfa_setup_page).post(handlers::auth::mfa_setup_submit),
        )
        .route(
            "/mfa/verify",
            get(handlers::auth::mfa_verify_page).post(handlers::auth::mfa_verify_submit),
        )
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
        // Assets pages - GET for viewing, POST for form submission (PRG pattern)
        // Literal routes MUST come before parameterized routes
        .route("/assets/new", get(handlers::web::asset_create_form))
        .route(
            "/assets",
            get(handlers::web::asset_list).post(handlers::web::create_asset_web),
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
        .route(
            "/sessions/{id}/terminate",
            post(handlers::web::terminate_session_web),
        )
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
            "/sessions/terminal/{session_id}",
            get(handlers::web::terminal_page),
        );

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
            // Note: MFA setup is only available via web interface (/mfa/setup), not API
            // Accounts API
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
            // Assets API
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
            // SSH host key API (H-9)
            .route(
                "/api/v1/assets/{uuid}/ssh-host-key",
                get(handlers::api::get_ssh_host_key_status)
                    .post(handlers::api::fetch_ssh_host_key_api),
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
            // Sessions API
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
            .route(
                "/api/v1/sessions/{id}/terminate",
                post(handlers::api::terminate_session),
            )
            // Groups API (read-only)
            .route(
                "/api/v1/groups/{uuid}/members",
                get(handlers::api::list_group_members),
            )
    } else {
        tracing::info!("API routes disabled by configuration");
        Router::new()
            // Return 404 for all API routes when disabled
            .route(
                "/api/v1/{*path}",
                get(api_disabled_handler)
                    .post(api_disabled_handler)
                    .put(api_disabled_handler)
                    .delete(api_disabled_handler),
            )
    };

    // Common middleware layers (applied to all routes)
    let flash_key = middleware::flash::FlashSecretKey(flash_secret);
    let common_layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        // Security headers (XSS, clickjacking, MIME sniffing protection)
        .layer(axum::middleware::from_fn(
            middleware::security::security_headers_middleware,
        ))
        .layer(cors.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf::csrf_cookie_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            flash_key.clone(),
            middleware::flash::flash_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::audit::audit_middleware,
        ));

    // WebSocket routes - NO timeout (long-lived connections)
    let ws_app = ws_routes.layer(common_layers.clone());

    // Web and API routes - WITH 30s timeout for regular HTTP requests
    let http_app = web_routes
        .merge(api_routes)
        .layer(
            common_layers.layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                std::time::Duration::from_secs(30),
            )),
        );

    // Merge all routes
    let app = ws_app
        .merge(http_app)
        .fallback(handlers::web::fallback_handler)
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
/// Health check endpoint that verifies database and cache connectivity.
///
/// Returns:
/// - 200 OK with "OK" if all services are healthy
/// - 503 Service Unavailable if database or cache is unreachable
///
/// In sandbox mode, a failing health check may indicate the service
/// needs to be respawned.
async fn health_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;

    // Check database connectivity
    if let Err(e) = state.db_pool.get().await {
        tracing::warn!("Health check failed: database unavailable: {}", e);
        return (StatusCode::SERVICE_UNAVAILABLE, "DB unavailable");
    }

    // Check cache connectivity (if Redis is enabled)
    if state.cache.is_redis()
        && let Err(e) = state.cache.validate_connection().await
    {
        tracing::warn!("Health check failed: cache unavailable: {}", e);
        return (StatusCode::SERVICE_UNAVAILABLE, "Cache unavailable");
    }

    (StatusCode::OK, "OK")
}

/// Serve static files from the compiled-in asset registry.
///
/// All static files are embedded in the binary via `include_bytes!()` (see
/// the [`vauban_web::static_assets`] module).  This handler performs a simple
/// lookup in the compile-time registry -- no filesystem access at all.
///
/// Security:
/// - Only files explicitly listed in `static_assets::STATIC_FILES` can be served.
/// - An attacker who compromises the filesystem cannot inject new assets.
/// - Rejects paths containing `..` or null bytes as an extra precaution.
async fn serve_static(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    use axum::body::Body;
    use axum::http::{Response, header};

    // Extra defence-in-depth: reject traversal even though the lookup is a
    // simple string match against the compiled registry.
    if path.contains("..") || path.contains('\0') {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    let asset = vauban_web::static_assets::lookup(&path)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        // Cache static assets for 1 hour (browser), allow CDN caching
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(asset.content))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vauban_web::unwrap_ok;

    // ==================== health_check Tests ====================
    // Note: Full health_check tests require a database connection.
    // These are covered by integration tests. Here we test related functionality.

    #[test]
    fn test_health_check_status_codes_exist() {
        // Verify the status codes we use are valid
        assert_eq!(axum::http::StatusCode::OK.as_u16(), 200);
        assert_eq!(axum::http::StatusCode::SERVICE_UNAVAILABLE.as_u16(), 503);
    }

    // ==================== serve_static Tests ====================

    #[test]
    fn test_static_assets_registry_not_empty() {
        assert!(
            !vauban_web::static_assets::STATIC_FILES.is_empty(),
            "Static assets registry must contain at least one file"
        );
    }

    #[test]
    fn test_static_assets_lookup_known_files() {
        assert!(
            vauban_web::static_assets::lookup("js/tailwind-config.js").is_some(),
            "tailwind-config.js must be in the compiled registry"
        );
        assert!(
            vauban_web::static_assets::lookup("css/vauban.css").is_some(),
            "vauban.css must be in the compiled registry"
        );
    }

    #[test]
    fn test_static_assets_lookup_rejects_unknown() {
        assert!(vauban_web::static_assets::lookup("malicious.php").is_none());
        assert!(vauban_web::static_assets::lookup("../../../etc/passwd").is_none());
    }

    // ==================== Configuration Tests ====================

    #[test]
    fn test_socket_addr_parsing() {
        let addr: Result<SocketAddr, _> = "127.0.0.1:8080".parse();
        assert!(addr.is_ok());
        assert_eq!(unwrap_ok!(addr).port(), 8080);
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

    // ==================== serve_static Security Tests ====================

    #[tokio::test]
    async fn test_serve_static_rejects_traversal() {
        let path = axum::extract::Path("../../../etc/passwd".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_static_rejects_null_byte() {
        let path = axum::extract::Path("js/app\0.js".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_static_returns_not_found_for_unknown() {
        let path = axum::extract::Path("nonexistent.js".to_string());
        let result = serve_static(path).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_serve_static_serves_compiled_js() {
        let path = axum::extract::Path("js/tailwind-config.js".to_string());
        let result = serve_static(path).await;
        assert!(result.is_ok(), "Must serve compiled-in JS file");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/javascript; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_serve_static_serves_compiled_css() {
        let path = axum::extract::Path("css/vauban.css".to_string());
        let result = serve_static(path).await;
        assert!(result.is_ok(), "Must serve compiled-in CSS file");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
    }

    // ==================== SocketAddr Tests ====================

    #[test]
    fn test_socket_addr_format_string() {
        let host = "127.0.0.1";
        let port = 8443u16;
        let addr_str = format!("{}:{}", host, port);
        let addr: SocketAddr = unwrap_ok!(addr_str.parse());
        assert_eq!(addr.port(), 8443);
    }

    #[test]
    fn test_socket_addr_ipv6_full() {
        let addr: Result<SocketAddr, _> = "[2001:db8:85a3::8a2e:370:7334]:443".parse();
        assert!(addr.is_ok());
    }

    #[test]
    fn test_socket_addr_any_interface() {
        let addr: SocketAddr = unwrap_ok!("0.0.0.0:8080".parse());
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    fn test_socket_addr_localhost_variations() {
        let localhost: SocketAddr = unwrap_ok!("127.0.0.1:80".parse());
        assert!(localhost.ip().is_loopback());

        let ipv6_localhost: SocketAddr = unwrap_ok!("[::1]:80".parse());
        assert!(ipv6_localhost.ip().is_loopback());
    }

    // ==================== Port Tests ====================

    #[test]
    fn test_common_https_port() {
        let addr: SocketAddr = unwrap_ok!("0.0.0.0:443".parse());
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_development_port() {
        let addr: SocketAddr = unwrap_ok!("127.0.0.1:3000".parse());
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_high_port() {
        let addr: SocketAddr = unwrap_ok!("127.0.0.1:65535".parse());
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

    // ==================== HeartbeatState Tests ====================

    #[test]
    fn test_init_supervisor_client_without_env_vars() {
        // Without IPC environment variables, should return None
        // (service not running under supervisor)
        let handle = axum_server::Handle::new();
        let result = init_supervisor_client(handle);
        assert!(result.is_none());
    }

    /// Test IPC message handling for Drain/DrainComplete cycle.
    /// This tests the IPC protocol without needing the SupervisorClient.
    #[test]
    fn test_ipc_drain_message_cycle() {
        use shared::ipc::IpcChannel;
        use shared::messages::{ControlMessage, Message};

        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();

        // Send Drain message
        let drain = Message::Control(ControlMessage::Drain);
        supervisor_channel.send(&drain).unwrap();

        // Handle on service side
        let msg = service_channel.recv().unwrap();
        if let Message::Control(ControlMessage::Drain) = msg {
            let response = Message::Control(ControlMessage::DrainComplete {
                pending_requests: 0,
            });
            service_channel.send(&response).unwrap();
        }

        // Verify DrainComplete on supervisor side
        let response = supervisor_channel.recv().unwrap();
        if let Message::Control(ControlMessage::DrainComplete { pending_requests }) = response {
            assert_eq!(pending_requests, 0, "No pending requests during drain");
        } else {
            panic!("Expected DrainComplete message");
        }
    }

    /// Test IPC message handling for Ping/Pong cycle.
    #[test]
    fn test_ipc_ping_pong_cycle() {
        use shared::ipc::IpcChannel;
        use shared::messages::{ControlMessage, Message, ServiceStats};

        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();

        // Send Ping from "supervisor"
        let ping = Message::Control(ControlMessage::Ping { seq: 42 });
        supervisor_channel.send(&ping).unwrap();

        // Handle on service side
        let msg = service_channel.recv().unwrap();
        if let Message::Control(ControlMessage::Ping { seq }) = msg {
            let stats = ServiceStats {
                uptime_secs: 123,
                requests_processed: 100,
                requests_failed: 5,
                active_connections: 0,
                pending_requests: 0,
            };
            let pong = Message::Control(ControlMessage::Pong { seq, stats });
            service_channel.send(&pong).unwrap();
        }

        // Verify response on supervisor side
        let response = supervisor_channel.recv().unwrap();
        if let Message::Control(ControlMessage::Pong { seq, stats }) = response {
            assert_eq!(seq, 42, "Pong seq should match Ping seq");
            assert_eq!(stats.requests_processed, 100);
            assert_eq!(stats.requests_failed, 5);
        } else {
            panic!("Expected Pong message");
        }
    }
}
