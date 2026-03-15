// L-1: Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic
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
use rustls::server::ResolvesServerCert;
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

// Import for supervisor, vault, and Access IPC clients
use vauban_web::ipc::{AccessIpcClient, AuthIpcClient, SupervisorClient, VaultCryptoClient};

/// Initialize the supervisor client if running under supervisor.
///
/// Returns the supervisor client and a TLS cert receiver if IPC is available, None otherwise.
/// The client spawns a dedicated thread for IPC communication (heartbeat, TCP brokering).
/// The `server_handle` is used for M-8/M-10 graceful shutdown.
fn init_supervisor_client(
    server_handle: axum_server::Handle<std::net::SocketAddr>,
) -> (
    Option<Arc<SupervisorClient>>,
    Option<std::sync::mpsc::Receiver<vauban_web::ipc::TlsCertData>>,
) {
    use std::os::unix::io::RawFd;

    let ipc_read_fd: RawFd = match std::env::var("VAUBAN_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return (None, None),
        },
        Err(_) => return (None, None),
    };

    let ipc_write_fd: RawFd = match std::env::var("VAUBAN_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return (None, None),
        },
        Err(_) => return (None, None),
    };

    let fd_passing_socket: Option<RawFd> = std::env::var("VAUBAN_FD_PASSING_SOCKET")
        .ok()
        .and_then(|val| val.parse().ok());

    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_IPC_READ");
        std::env::remove_var("VAUBAN_IPC_WRITE");
        std::env::remove_var("VAUBAN_FD_PASSING_SOCKET");
    }

    let (client, tls_cert_rx) = SupervisorClient::new(
        ipc_read_fd,
        ipc_write_fd,
        fd_passing_socket,
        Some(server_handle),
    );
    tracing::info!(
        fd_passing = fd_passing_socket.is_some(),
        "Supervisor client initialized (running under supervisor)"
    );
    (Some(Arc::new(client)), Some(tls_cert_rx))
}

use vauban_web::{
    AppState,
    cache::create_cache_client,
    config::{Config, LogFormat},
    db::create_pool_sandboxed,
    error::AppError,
    handlers,
    ipc::{ProxyRdpClient, ProxySshClient},
    middleware,
    services::auth::AuthService,
    services::broadcast::BroadcastService,
    services::rate_limit::RateLimiter,
    tasks::{self, start_cleanup_tasks, start_dashboard_tasks},
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

/// Initialize RDP proxy client if IPC environment variables are set.
///
/// Returns Some(Arc<ProxyRdpClient>) if VAUBAN_PROXY_RDP_IPC_READ and VAUBAN_PROXY_RDP_IPC_WRITE
/// environment variables are set (running under supervisor), None otherwise.
fn init_rdp_proxy_client() -> Option<Arc<ProxyRdpClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_PROXY_RDP_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_PROXY_RDP_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_RDP_IPC_WRITE");
    }

    match ProxyRdpClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("RDP proxy client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize RDP proxy client: {}", e);
            None
        }
    }
}

/// Initialize the Access IPC client if running under supervisor.
///
/// Returns Some(Arc<AccessIpcClient>) if VAUBAN_ACCESS_IPC_READ and VAUBAN_ACCESS_IPC_WRITE
/// environment variables are set (running under supervisor), None otherwise.
fn init_access_client() -> Option<Arc<AccessIpcClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_ACCESS_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_ACCESS_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
        std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
    }

    match AccessIpcClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("Access IPC client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize Access IPC client: {}", e);
            None
        }
    }
}

/// Initialize the auth IPC client if running under supervisor.
///
/// Returns Some(Arc<AuthIpcClient>) if VAUBAN_AUTH_IPC_READ and VAUBAN_AUTH_IPC_WRITE
/// environment variables are set (running under supervisor), None otherwise.
fn init_auth_client() -> Option<Arc<AuthIpcClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_AUTH_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_AUTH_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_AUTH_IPC_READ");
        std::env::remove_var("VAUBAN_AUTH_IPC_WRITE");
    }

    match AuthIpcClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("Auth IPC client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize Auth IPC client: {}", e);
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
    let (supervisor_client, tls_cert_rx) = init_supervisor_client(server_handle.clone());

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

    // 1. Obtain listening socket: either from supervisor (SCM_RIGHTS) or bind directly
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| format!("Invalid address: {}", e))?;

    let std_listener = if let Some(ref sup) = supervisor_client {
        if let Some(fd_socket) = sup.fd_passing_socket() {
            use shared::ipc::recv_fd;
            let owned_fd = recv_fd(fd_socket).map_err(|e| {
                format!("Failed to receive listening socket from supervisor: {}", e)
            })?;
            let listener = unsafe {
                use std::os::unix::io::FromRawFd;
                std::net::TcpListener::from_raw_fd(std::os::unix::io::IntoRawFd::into_raw_fd(
                    owned_fd,
                ))
            };
            tracing::info!(address = %addr, "Received pre-bound listening socket from supervisor");
            listener
        } else {
            tracing::warn!("Running under supervisor but no FD passing socket, binding directly");
            let tokio_listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
                eprintln!("Failed to bind to {}: {}", addr, e);
                e
            })?;
            tokio_listener.into_std().map_err(|e| {
                eprintln!("Failed to convert listener: {}", e);
                e
            })?
        }
    } else {
        let tokio_listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            eprintln!("Failed to bind to {}: {}", addr, e);
            e
        })?;
        let listener = tokio_listener.into_std().map_err(|e| {
            eprintln!("Failed to convert listener: {}", e);
            e
        })?;
        tracing::info!(address = %addr, "Socket bound for HTTPS");
        listener
    };

    // 2. Load TLS configuration
    //    Under supervisor: wait for TlsCertProvision from IPC (cert data in memory).
    //    In dev mode: read certificate files from disk.
    //    When ACME is enabled, returns a dynamic resolver for zero-downtime
    //    certificate rotation and TLS-ALPN-01 challenge support.
    let tls_cert_data = if let Some(rx) = tls_cert_rx {
        use std::time::Duration;
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(data) => {
                tracing::info!("Received TLS certificate data from supervisor via IPC");
                Some(data)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to receive TLS certificate from supervisor: {e}, falling back to files"
                );
                None
            }
        }
    } else {
        None
    };

    // Keep a copy of the cert PEM for extract_cert_info (needed for ACME scheduling)
    let supervisor_cert_pem = tls_cert_data.as_ref().map(|d| d.cert_pem.clone());

    let (tls_config, acme_resolver) =
        load_tls_config(&config, tls_cert_data).await.map_err(|e| {
            eprintln!("Failed to load TLS configuration: {}", e);
            e
        })?;
    tracing::debug!(
        acme_resolver = acme_resolver.is_some(),
        "TLS configuration loaded"
    );

    // Register ACME resolver with supervisor IPC handler (if both are available).
    // This allows the supervisor to send ACME challenge/cert messages to the resolver.
    if let Some(ref resolver) = acme_resolver
        && let Some(ref sup) = supervisor_client
    {
        sup.set_acme_resolver(Arc::clone(resolver));
    }

    // Extract certificate metadata BEFORE cap_enter() (file I/O forbidden after).
    // Under supervisor: use PEM data received via IPC. Otherwise: read from file.
    let cert_expiry = if config.server.tls.acme.as_ref().is_some_and(|a| a.enabled) {
        let cert_info_result = if let Some(ref pem) = supervisor_cert_pem {
            tasks::extract_cert_info_from_pem(pem)
        } else {
            tasks::extract_cert_info(&config.server.tls.cert_path)
        };
        match cert_info_result {
            Ok(info) => {
                let self_signed = info.self_signed;
                let expiry = Arc::new(tasks::CertExpiry::new(info));
                tracing::info!(
                    days_remaining = expiry.days_remaining(),
                    self_signed = self_signed,
                    cert_path = %config.server.tls.cert_path,
                    "Certificate metadata extracted before sandbox"
                );
                Some(expiry)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to extract certificate metadata, renewal will be requested immediately"
                );
                let info = tasks::CertInfo {
                    not_after_epoch: 0,
                    self_signed: true,
                };
                Some(Arc::new(tasks::CertExpiry::new(info)))
            }
        }
    } else {
        None
    };

    // Register cert expiry tracker with supervisor so AcmeCertActivate updates it.
    if let Some(ref expiry) = cert_expiry
        && let Some(ref sup) = supervisor_client
    {
        sup.set_cert_expiry(Arc::clone(expiry));
    }

    // 3. Create database pool with all connections pre-established (sandbox mode)
    // Uses fixed-size pool where all connections are validated at startup
    let db_pool = create_pool_sandboxed(&config).await.map_err(|e| {
        eprintln!("Failed to create database pool: {}", e);
        e
    })?;

    // Register DB pool and Tokio handle with supervisor for admin command processing.
    // The supervisor IPC thread (sync) uses block_on(handle) to run async DB ops.
    if let Some(ref sup) = supervisor_client {
        sup.set_admin_pool(db_pool.clone());
        sup.set_tokio_handle(tokio::runtime::Handle::current());
    }

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
    let ws_counter = vauban_web::services::connections::WsConnectionCounter::new(
        config.websocket.max_connections_per_user,
    );
    tracing::info!(
        max_per_user = config.websocket.max_connections_per_user,
        "WebSocket connection counter initialized"
    );

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

    // Create RDP proxy client if running under supervisor
    let rdp_proxy = init_rdp_proxy_client();

    // Spawn RDP proxy IPC processing task if client is available
    if let Some(ref client) = rdp_proxy {
        let client_clone = Arc::clone(client);
        tokio::spawn(async move {
            if let Err(e) = client_clone.process_incoming().await {
                tracing::error!(error = %e, "RDP proxy IPC processing task failed");
            }
        });
        tracing::info!("RDP proxy IPC processing task started");
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

    // Create Access IPC client if running under supervisor
    let access_client = init_access_client();

    // Spawn Access IPC processing task if client is available
    if let Some(ref client) = access_client {
        let client_clone = Arc::clone(client);
        tokio::spawn(async move {
            if let Err(e) = client_clone.process_incoming().await {
                tracing::error!(error = %e, "Access IPC processing task failed");
            }
        });
        tracing::info!("Access IPC processing task started");
    }

    // Create Auth IPC client if running under supervisor
    let auth_ipc_client = init_auth_client();

    if let Some(ref client) = auth_ipc_client {
        let client_clone = Arc::clone(client);
        tokio::spawn(async move {
            if let Err(e) = client_clone.process_incoming().await {
                tracing::error!(error = %e, "Auth IPC processing task failed");
            }
        });
        tracing::info!("Auth IPC processing task started");
    }

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        db_pool: db_pool.clone(),
        cache,
        auth_service,
        broadcast: broadcast.clone(),
        user_connections,
        ws_counter,
        rate_limiter,
        ssh_proxy,
        rdp_proxy,
        supervisor: supervisor_client.clone(),
        vault_client,
        access_client,
        auth_ipc_client,
    };

    // Start background tasks for WebSocket updates
    start_dashboard_tasks(broadcast, db_pool.clone()).await;

    // Start cleanup tasks for expired sessions and API keys
    start_cleanup_tasks(db_pool).await;

    // Start ACME certificate monitoring task (if enabled)
    if let Some(ref acme_config) = config.server.tls.acme
        && acme_config.enabled
        && let (Some(resolver), Some(expiry)) = (&acme_resolver, &cert_expiry)
    {
        tasks::start_acme_monitoring(
            acme_config.clone(),
            config.server.tls.cert_path.clone(),
            config.server.tls.key_path.clone(),
            supervisor_client.clone(),
            Arc::clone(resolver),
            Arc::clone(expiry),
        )
        .await;
    }

    // Build application router
    let app = create_app(app_state).await?;

    tracing::info!(
        address = %addr,
        cert = %config.server.tls.cert_path,
        sandbox = %cfg!(target_os = "freebsd"),
        "HTTPS server listening (TLS 1.3 only)"
    );

    // Ensure non-blocking mode: tokio's into_std() may reset to blocking,
    // and SCM_RIGHTS sockets are blocking by default. axum-server panics
    // if the socket is blocking when registering with the tokio reactor.
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set listener to non-blocking: {}", e))?;

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
///
/// When ACME is enabled, returns an `AcmeResolver` that supports dynamic
/// certificate rotation and TLS-ALPN-01 challenges. The resolver is wrapped
/// in an `Arc` so it can be shared with the IPC handler for certificate updates.
///
/// When ACME is disabled, uses a static certificate configuration.
/// When `tls_cert_data` is provided (from supervisor IPC), uses the PEM data directly
/// without any filesystem access to certificate files.
async fn load_tls_config(
    config: &Config,
    tls_cert_data: Option<vauban_web::ipc::TlsCertData>,
) -> Result<
    (
        RustlsConfig,
        Option<Arc<vauban_web::acme::resolver::AcmeResolver>>,
    ),
    Box<dyn std::error::Error>,
> {
    use rustls::ServerConfig;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use vauban_web::acme::resolver::AcmeResolver;

    let acme_enabled = config.server.tls.acme.as_ref().is_some_and(|a| a.enabled);

    // Resolve PEM data: either from supervisor IPC or from files.
    // The private key stays inside SensitiveString (zeroized on drop) and is
    // only briefly exposed via as_str() for parsing into PrivateKeyDer.
    let (cert_pem_data, key_pem_sensitive) = if let Some(cert_data) = tls_cert_data {
        (cert_data.cert_pem, cert_data.key_pem)
    } else {
        // Dev mode: read from files
        let cert_path = &config.server.tls.cert_path;
        let key_path = &config.server.tls.key_path;

        let cert_exists = std::path::Path::new(cert_path).exists();
        let key_exists = std::path::Path::new(key_path).exists();

        if !cert_exists || !key_exists {
            if let Some(acme_config) = config.server.tls.acme.as_ref()
                && acme_config.enabled
            {
                tracing::warn!(
                    cert_path = %cert_path,
                    key_path = %key_path,
                    "Certificate files not found, generating self-signed bootstrap certificate for ACME"
                );
                let resolver = Arc::new(AcmeResolver::new(Arc::new(
                    vauban_web::acme::resolver::generate_self_signed_cert(
                        &acme_config.domains,
                        cert_path,
                        key_path,
                    )?,
                )));

                let mut server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);

                server_config.alpn_protocols =
                    vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];

                tracing::info!(
                    "TLS configured with self-signed bootstrap certificate (ACME will replace it)"
                );

                return Ok((
                    RustlsConfig::from_config(Arc::new(server_config)),
                    Some(resolver),
                ));
            }

            if !cert_exists {
                return Err(format!(
                    "TLS certificate not found: {}. Run scripts/generate-dev-certs.sh for development.",
                    cert_path
                )
                .into());
            }
            return Err(format!("TLS private key not found: {}", key_path).into());
        }

        use shared::messages::SensitiveString;
        use zeroize::Zeroize;

        let cert_pem = std::fs::read_to_string(cert_path)?;
        let mut key_pem = std::fs::read_to_string(key_path)?;
        let key_sensitive = SensitiveString::new(key_pem.clone());
        key_pem.zeroize();
        (cert_pem, key_sensitive)
    };

    // Parse PEM data into cert chain and private key
    let cert_pem_bytes = cert_pem_data.as_bytes();
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem_bytes)
        .filter_map(|cert| cert.ok())
        .collect();

    if cert_chain.is_empty() {
        return Err("No valid certificates found in certificate data".into());
    }

    // Load CA chain if provided (for intermediate certificates, file-based only)
    let mut full_chain = cert_chain;
    if let Some(ca_path) = &config.server.tls.ca_chain_path
        && std::path::Path::new(ca_path).exists()
    {
        use std::fs::File;
        use std::io::BufReader;
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_reader_iter(&mut ca_reader)
                .filter_map(|cert| cert.ok())
                .collect();
        full_chain.extend(ca_certs);
    }

    // Parse private key from PEM data -- brief exposure via as_str(),
    // key_pem_sensitive is zeroized when it goes out of scope.
    let key_pem_bytes = key_pem_sensitive.as_str().as_bytes();
    let private_key = PrivateKeyDer::from_pem_slice(key_pem_bytes)
        .map_err(|e| format!("No valid private key found in key data: {}", e))?;
    drop(key_pem_sensitive);

    if acme_enabled {
        // ACME mode: use dynamic resolver for zero-downtime cert rotation
        // and TLS-ALPN-01 challenge support.
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
            .map_err(|e| format!("Unsupported key type: {}", e))?;
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(full_chain, signing_key));

        let resolver = Arc::new(AcmeResolver::new(certified_key));

        let mut server_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);

        // Advertise both h2 and acme-tls/1 ALPN protocols
        server_config.alpn_protocols =
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];

        tracing::info!(
            "TLS configured with ACME dynamic resolver (TLS 1.3 only, TLS-ALPN-01 enabled)"
        );

        Ok((
            RustlsConfig::from_config(Arc::new(server_config)),
            Some(resolver),
        ))
    } else {
        // Static mode: standard certificate, no ACME support.
        let server_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(full_chain, private_key)?;

        tracing::debug!(
            "TLS configured: TLS 1.3 only, {} cipher suites available",
            server_config.crypto_provider().cipher_suites.len()
        );

        Ok((RustlsConfig::from_config(Arc::new(server_config)), None))
    }
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
    let session_guard =
        axum::middleware::from_fn_with_state(state.clone(), handlers::websocket::ws_session_guard);

    // L-8: ws_connection_limit middleware enforces per-user WebSocket connection limit
    // on ALL WS routes. Every current and future handler added to ws_routes is
    // automatically protected.
    let ws_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_connection_limit,
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
            get(handlers::websocket::terminal_ws).layer(session_guard.clone()),
        )
        .route(
            "/ws/rdp/{session_id}",
            get(handlers::websocket::rdp_ws).layer(session_guard),
        )
        // L-8: Apply per-user connection limit to ALL WebSocket routes
        .layer(ws_limit_layer);

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
        .route(
            "/recordings/{session_uuid}",
            get(handlers::web::serve_recording),
        )
        .route(
            "/recordings/{session_uuid}/manifest.mpd",
            get(handlers::web::serve_manifest),
        )
        .route(
            "/recordings/{session_uuid}/{segment}",
            get(handlers::web::serve_segment),
        )
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route("/sessions/approvals", get(handlers::web::approval_list))
        .route(
            "/sessions/approvals/{uuid}",
            get(handlers::web::approval_detail),
        )
        .route("/sessions/active", get(handlers::web::active_sessions))
        // SSH connection endpoints
        .route("/assets/{uuid}/connect", post(handlers::web::connect_ssh))
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
        )
        // RDP connection endpoints
        .route(
            "/assets/{uuid}/connect-rdp",
            post(handlers::web::connect_rdp),
        )
        .route("/sessions/rdp/{session_id}", get(handlers::web::rdp_page));

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
                get(handlers::api::get_session).delete(|| async {
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
            // Access rules API
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
    let http_app =
        web_routes
            .merge(api_routes)
            .layer(common_layers.layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                std::time::Duration::from_secs(30),
            )));

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
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    use axum::body::Body;
    use axum::http::{Response, header};

    if path.contains("..") || path.contains('\0') {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    let asset =
        vauban_web::static_assets::lookup(&path).ok_or(axum::http::StatusCode::NOT_FOUND)?;

    let etag = asset.etag();

    if let Some(inm) = headers.get(header::IF_NONE_MATCH)
        && inm.as_bytes() == etag.as_bytes()
    {
        return Response::builder()
            .status(axum::http::StatusCode::NOT_MODIFIED)
            .header(header::ETAG, &etag)
            .body(Body::empty())
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        .header(
            header::CACHE_CONTROL,
            "public, max-age=300, must-revalidate",
        )
        .header(header::ETAG, &etag)
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
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_static_rejects_null_byte() {
        let path = axum::extract::Path("js/app\0.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_serve_static_returns_not_found_for_unknown() {
        let path = axum::extract::Path("nonexistent.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_serve_static_serves_compiled_js() {
        let path = axum::extract::Path("js/tailwind-config.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_ok(), "Must serve compiled-in JS file");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/javascript; charset=utf-8"
        );
        assert!(
            response.headers().get("etag").is_some(),
            "Must include ETag"
        );
    }

    #[tokio::test]
    async fn test_serve_static_serves_compiled_css() {
        let path = axum::extract::Path("css/vauban.css".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_ok(), "Must serve compiled-in CSS file");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
        assert!(
            response.headers().get("etag").is_some(),
            "Must include ETag"
        );
    }

    #[tokio::test]
    async fn test_serve_static_304_with_matching_etag() {
        use axum::http::header;

        let path = axum::extract::Path("js/tailwind-config.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let first = serve_static(path, headers).await.unwrap();
        let etag = first.headers().get("etag").unwrap().clone();

        let path2 = axum::extract::Path("js/tailwind-config.js".to_string());
        let mut headers2 = axum::http::HeaderMap::new();
        headers2.insert(header::IF_NONE_MATCH, etag);
        let second = serve_static(path2, headers2).await.unwrap();
        assert_eq!(second.status(), axum::http::StatusCode::NOT_MODIFIED);
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
        // Without IPC environment variables, should return (None, None)
        // (service not running under supervisor)
        let handle = axum_server::Handle::new();
        let (client, cert_rx) = init_supervisor_client(handle);
        assert!(client.is_none());
        assert!(cert_rx.is_none());
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

    // ==================== TLS Certificate Provisioning Tests ====================

    #[test]
    fn test_load_tls_config_accepts_tls_cert_data_parameter() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("tls_cert_data: Option<vauban_web::ipc::TlsCertData>"),
            "load_tls_config must accept optional TlsCertData"
        );
    }

    #[test]
    fn test_supervisor_mode_receives_tls_cert_via_ipc() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("recv_timeout"),
            "main must wait for TlsCertProvision with a timeout"
        );
        assert!(
            source.contains("supervisor_cert_pem"),
            "main must store cert PEM for extract_cert_info_from_pem"
        );
    }

    #[test]
    fn test_extract_cert_info_uses_pem_from_supervisor() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("extract_cert_info_from_pem"),
            "main must use extract_cert_info_from_pem when running under supervisor"
        );
    }
}
