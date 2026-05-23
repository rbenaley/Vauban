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

/// VAUBAN Web - Main application entry point.
///
/// Rust web application using Axum, Diesel, and Askama.
/// Runs exclusively over HTTPS with TLS 1.3.
use axum::{
    Router,
    extract::Path,
    http::Method,
    response::Redirect,
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
/// The `server_handle` is used for graceful shutdown.
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
    ipc::{ProxyIacsClient, ProxyRdpClient, ProxySshClient},
    middleware, services,
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

/// Initialize IACS proxy client if IPC environment variables are set.
///
/// Returns `Some(Arc<ProxyIacsClient>)` when both
/// `VAUBAN_PROXY_IACS_IPC_READ` and `VAUBAN_PROXY_IACS_IPC_WRITE` are
/// set by the supervisor, `None` otherwise (dev / test mode where the
/// legacy in-process iacs sshd is used as a fallback).
fn init_iacs_proxy_client() -> Option<Arc<ProxyIacsClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = match std::env::var("VAUBAN_PROXY_IACS_IPC_READ") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    let write_fd: RawFd = match std::env::var("VAUBAN_PROXY_IACS_IPC_WRITE") {
        Ok(val) => match val.parse() {
            Ok(fd) => fd,
            Err(_) => return None,
        },
        Err(_) => return None,
    };

    // SAFETY: We are early in startup, before spawning async tasks.
    unsafe {
        std::env::remove_var("VAUBAN_PROXY_IACS_IPC_READ");
        std::env::remove_var("VAUBAN_PROXY_IACS_IPC_WRITE");
    }

    match ProxyIacsClient::new(read_fd, write_fd) {
        Ok(client) => {
            tracing::info!("IACS proxy client initialized (running under supervisor)");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize IACS proxy client: {}", e);
            None
        }
    }
}

/// Initialize the Access IPC client if running under supervisor.
///
/// Returns `Ok(Arc<AccessIpcClient>)` when both `VAUBAN_ACCESS_IPC_READ` and
/// `VAUBAN_ACCESS_IPC_WRITE` are set by the supervisor. Vauban-web cannot run
/// in a standalone mode: Casbin is the single source of truth for
/// authorization, so if the IPC channel to vauban-access is not available the
/// binary refuses to start.
fn init_access_client() -> anyhow::Result<Arc<AccessIpcClient>> {
    use std::os::unix::io::RawFd;

    let read_fd: RawFd = std::env::var("VAUBAN_ACCESS_IPC_READ")
        .map_err(|_| anyhow::anyhow!(
            "VAUBAN_ACCESS_IPC_READ is not set. vauban-web must be launched under vauban-supervisor \
             with vauban-access wired up; standalone execution is not supported."
        ))?
        .parse()
        .map_err(|e| anyhow::anyhow!("VAUBAN_ACCESS_IPC_READ must be a valid file descriptor: {}", e))?;

    let write_fd: RawFd = std::env::var("VAUBAN_ACCESS_IPC_WRITE")
        .map_err(|_| anyhow::anyhow!(
            "VAUBAN_ACCESS_IPC_WRITE is not set. vauban-web must be launched under vauban-supervisor \
             with vauban-access wired up; standalone execution is not supported."
        ))?
        .parse()
        .map_err(|e| anyhow::anyhow!("VAUBAN_ACCESS_IPC_WRITE must be a valid file descriptor: {}", e))?;

    // SAFETY: We are early in startup, before spawning async tasks
    unsafe {
        std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
        std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
    }

    let client = AccessIpcClient::new(read_fd, write_fd)
        .map_err(|e| anyhow::anyhow!("Failed to initialize Access IPC client: {}", e))?;
    tracing::info!("Access IPC client initialized (running under supervisor)");
    Ok(client)
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

/// Initialize the vault crypto client if running under supervisor.
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
    // Create server handle early for graceful shutdown.
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

    // Install the configured brand name (`[product.brand].name`) into
    // the process-wide template cell so every Askama page picks up
    // the white-label wordmark in the sidebar's top-left corner. The
    // call is idempotent: only the first value wins, matching the
    // boot-config-only contract documented on `set_brand_name`.
    vauban_web::templates::base::set_brand_name(config.product.brand.name.clone());
    tracing::info!(brand = %config.product.brand.name, "Brand name installed");

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

    vauban_web::services::asset_membership::warn_if_single_group_mode_inconsistent_with_data(
        &db_pool,
        config.assets.allow_multiple_groups_per_asset,
    )
    .await;

    // SECURITY (boot invariant): the singleton "All assets" virtual group
    // MUST exist before we serve traffic. Without it, list_accessible_asset_ids
    // and can_access_asset would silently degrade (every virtual rule would
    // have no effect), making policy evaluation diverge from vauban-access's
    // own view -- the proxy-side AccessGuard would then disagree with the
    // UI-side decision, which is a hard "fail loud" condition.
    {
        let mut conn = db_pool.get().await.map_err(|e| {
            eprintln!(
                "Failed to acquire DB connection for virtual-group boot check: {}",
                e
            );
            e
        })?;
        vauban_web::services::virtual_group::init_or_die(&mut conn)
            .await
            .map_err(|e| {
                eprintln!(
                    "Boot-time virtual 'All assets' group invariant check failed: {}. \
                     Re-run migration 20260424000000_virtual_asset_group_all to recover.",
                    e
                );
                e
            })?;
    }

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

    // ========================================================================
    // IACS tunnel orphan reconciliation (boot)
    // ========================================================================
    // proxy-iacs / in-process sshd state is in-memory only. A supervisor
    // restart leaves `tunnel_active` rows in proxy_sessions until we
    // explicitly flip them (SSH/RDP get the same treatment via cleanup).
    if config.industrial.enabled {
        match vauban_web::services::iacs_tunnel::reconcile_orphaned_iacs_tunnels_on_boot(&db_pool)
            .await
        {
            Ok(n) if n > 0 => tracing::info!(
                reconciled = n,
                "iacs_tunnel: boot reconciliation cleared stale active rows"
            ),
            Ok(_) => tracing::debug!("iacs_tunnel: boot reconciliation found no stale rows"),
            Err(e) => tracing::warn!(
                error = %e,
                "iacs_tunnel: boot reconciliation failed (stale rows may linger)"
            ),
        }
    }

    // Create IACS proxy client if running under supervisor (Lot 3:
    // per-asset target resolution).
    let proxy_iacs = init_iacs_proxy_client();

    if let Some(ref client) = proxy_iacs {
        let client_clone = Arc::clone(client);
        let broadcast_for_iacs = broadcast.clone();
        let pool_for_iacs = db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = client_clone
                .process_incoming_with_state(broadcast_for_iacs, pool_for_iacs)
                .await
            {
                tracing::error!(error = %e, "IACS proxy IPC processing task failed");
            }
        });
        tracing::info!("IACS proxy IPC processing task started");
    }

    // Create vault crypto client if running under supervisor
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

    // Create Access IPC client (mandatory - hard fail if not running under
    // supervisor). Casbin is essential; there is no standalone fallback.
    let access_client = init_access_client()?;

    // Spawn Access IPC processing task (always present in production).
    {
        let client_clone = Arc::clone(&access_client);
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

    // Build mailer (Issue #10). The dispatcher task owns the same
    // Notify; HTTP handlers fire `notify_one()` after a successful
    // `Mailer::queue` to wake the task. When `[mailer]` is disabled,
    // the Mailer turns into a no-op (queue() returns Ok without
    // touching the DB) so handlers do not need to special-case it.
    let mailer = vauban_web::services::mailer::Mailer::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        config.mailer.enabled,
        config.mailer.max_attempts,
    );

    // Bastion Watch dashboard plumbing. Both trackers are cheap to
    // create (a few atomics) and shared across the SYSTEM HEALTH
    // tile, the HTTP middleware, and the dashboard pusher.
    let http_rate =
        std::sync::Arc::new(vauban_web::services::system_health::HttpRateTracker::new());
    let live_session_history =
        std::sync::Arc::new(vauban_web::services::system_health::LiveSessionHistory::default());
    let broker_latency_tracker = supervisor_client
        .as_ref()
        .map(|c| std::sync::Arc::clone(c.broker_latency()))
        .unwrap_or_else(|| {
            // Dev mode without supervisor: stand-alone tracker that
            // never receives samples (snapshot stays empty / "n/a").
            std::sync::Arc::new(
                vauban_web::services::broker_latency::BrokerLatencyTracker::default(),
            )
        });
    let system_health_cache =
        std::sync::Arc::new(vauban_web::services::system_health::SystemHealthCache::new(
            db_pool.clone(),
            broker_latency_tracker,
            http_rate.clone(),
        ));

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
        proxy_iacs,
        supervisor: supervisor_client.clone(),
        vault_client,
        access_client,
        auth_ipc_client,
        mailer,
        http_rate,
        live_session_history,
        system_health_cache,
        iacs_tunnel_registry: vauban_web::services::iacs_tunnel::TunnelRegistry::new(),
    };

    // === Lot 5: legacy in-process IACS sshd is deprecated in favour
    // of the privileged-separated `vauban-proxy-iacs` service.
    //
    // When `app_state.proxy_iacs.is_some()` (production / supervised
    // mode), the in-process sshd MUST NOT be spawned -- the listener
    // bind would race with the supervisor's pre-bind on the same
    // port, and the in-process path is incompatible with Capsicum on
    // FreeBSD anyway. The watchdog still runs (it is DB-backed and
    // protocol-agnostic; it terminates revoked tunnels via the new
    // IPC instead of the in-process registry).
    //
    // The legacy in-process sshd is only spawned when no proxy-iacs
    // IPC channel exists (dev / test mode without supervisor). This
    // branch survives until the legacy module is fully retired in a
    // follow-up cleanup; deletion would cascade through dozens of
    // unit tests and is out of scope for this lot.
    let proxy_iacs_present = app_state.proxy_iacs.is_some();
    if config.industrial.enabled && !proxy_iacs_present {
        let registry = app_state.iacs_tunnel_registry.clone();
        let pool = app_state.db_pool.clone();
        let tunnel_cfg = config.industrial.iacs_tunnel.clone();
        let server_registry = registry.clone();
        let server_pool = pool.clone();
        let server_cfg = tunnel_cfg.clone();
        let server_broadcast = app_state.broadcast.clone();
        tokio::spawn(async move {
            match vauban_web::services::iacs_tunnel::spawn_iacs_tunnel_server_with_broadcast(
                server_registry,
                server_pool,
                server_cfg,
                Some(server_broadcast),
            )
            .await
            {
                Ok((addr, join)) => {
                    tracing::info!(bind_addr = %addr, "iacs_tunnel: sshd boot OK");
                    if let Err(e) = join.await {
                        tracing::error!(error = ?e, "iacs_tunnel: sshd task ended unexpectedly");
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "iacs_tunnel: sshd boot FAILED -- IACS tunnels disabled \
                         until restart, web UI and other features keep running"
                    );
                }
            }
        });
        // L4: revocation + TTL watchdog. Runs forever; intentionally
        // de-coupled from the sshd task so a sshd panic does not
        // also stop revocation.
        let _watchdog =
            vauban_web::services::iacs_tunnel::spawn_watchdog(registry, pool, tunnel_cfg);
        tracing::info!("iacs_tunnel: revocation watchdog spawned");
    } else if config.industrial.enabled {
        // proxy_iacs_present == true: spawn the revocation watchdog
        // anyway. The watchdog is DB-backed and protocol-agnostic;
        // it runs in vauban-web (which holds the DB pool) rather
        // than vauban-proxy-iacs (which is DB-less). Revoked tunnels
        // are terminated via the new `IacsTunnelTerminate` IPC sent
        // to proxy-iacs.
        let pool = app_state.db_pool.clone();
        let tunnel_cfg = config.industrial.iacs_tunnel.clone();
        let registry = app_state.iacs_tunnel_registry.clone();
        let proxy_iacs_for_wd = app_state.proxy_iacs.clone();
        let _watchdog = vauban_web::services::iacs_tunnel::spawn_watchdog_with_proxy_iacs(
            registry,
            pool,
            tunnel_cfg,
            proxy_iacs_for_wd,
        );
        tracing::info!("iacs_tunnel: revocation watchdog spawned (proxy-iacs IPC mode)");
    } else {
        tracing::info!(
            industrial_enabled = config.industrial.enabled,
            "iacs_tunnel: sshd not started (industrial.enabled = false)"
        );
    }

    // Start background tasks for WebSocket updates
    start_dashboard_tasks(broadcast, db_pool.clone()).await;

    // Start cleanup tasks for expired/idle sessions and API keys
    // (Issue #8: idle_timeout drives the auth_sessions purge predicate).
    // Issue #29 v1.4: cleanup also enqueues recording hydration for
    // every session it transitions to terminated/disconnected, hence
    // the `app_state.clone()` instead of just `db_pool`.
    start_cleanup_tasks(app_state.clone(), config.security.session_idle_timeout_secs).await;

    // Email dispatcher (Issue #10). Drains email_outbox via the
    // supervisor-brokered SMTP socket. No-op when the [mailer] block
    // is disabled.
    vauban_web::tasks::mailer::start_mailer_dispatcher(app_state.clone());

    // Bastion Watch dashboard pusher: a single Tokio task that
    // recomputes the dashboard snapshot every second and broadcasts
    // per-tile HTML fragments via `WsChannel::DashboardStats`. It
    // self-throttles when no subscriber is connected, so the cost is
    // zero on an idle bastion.
    vauban_web::tasks::dashboard_pusher::start_dashboard_pusher(app_state.clone());

    // Recording integrity hydrator (issue #29 / UX-28 v1.4):
    // event-driven. PRIMARY path = per-call-site `enqueue_hydration`
    // after every UPDATE disconnected_at (~5s latency). At boot we
    // run a one-shot bootstrap to rattrape the backlog (legacy
    // recordings + sessions in-flight during a downtime), then
    // schedule a daily reconciliation cron in the configured IANA timezone
    // as SAFETY NET. Requires the supervisor (FD passing for `meta.json`);
    // silently skipped without one (development mode).
    if config.recording.hydration_enabled
        && let Some(ref sup) = supervisor_client
        && let Ok(cron_tz) = config.recording.daily_cron_timezone()
    {
        let handle = tokio::runtime::Handle::current();
        let missing_meta_grace =
            std::time::Duration::from_secs(config.recording.hydration_missing_meta_grace_secs);
        // Boot bootstrap: detached, one-shot, exits when backlog empty.
        // Pass the live broadcast handle so any hydration the bootstrap
        // performs at boot also fires `recording_hydrated` WS events
        // (Recording Details / List pages auto-refresh without polling).
        std::mem::drop(vauban_web::tasks::run_bootstrap_hydration(
            &handle,
            db_pool.clone(),
            Arc::clone(sup),
            config.recording.hydration_batch_size,
            config.recording.storage_path.clone(),
            missing_meta_grace,
            app_state.broadcast.clone(),
        ));
        // Daily reconciliation: SAFETY NET, runs once a day.
        vauban_web::tasks::start_daily_reconciliation(
            handle,
            db_pool.clone(),
            Arc::clone(sup),
            config.recording.hydration_batch_size,
            config.recording.storage_path.clone(),
            missing_meta_grace,
            cron_tz,
            config.recording.hydration_daily_cron_hour,
            app_state.broadcast.clone(),
        );
    } else if config.recording.hydration_enabled {
        tracing::info!(
            "recording hydrator disabled: no supervisor (development mode without SCM_RIGHTS)"
        );
    } else {
        tracing::info!("recording hydrator disabled by config");
    }

    // Recording retention reaper: purge aged / quota-exceeded recordings
    // (TOML-only config). At boot we run a one-shot bootstrap (mirrors
    // the hydrator), then schedule a daily cron as SAFETY NET.
    // Requires supervisor for disk delete.
    if config.recording.retention_enabled
        && let Some(ref sup) = supervisor_client
        && let Ok(cron_tz) = config.recording.daily_cron_timezone()
    {
        let handle = tokio::runtime::Handle::current();
        let retention_config = vauban_web::tasks::RecordingRetentionTaskConfig {
            retention_days: config.recording.retention_days,
            max_size_gib: config.recording.retention_max_size_gib,
            batch_size: config.recording.retention_batch_size,
            storage_base: config.recording.storage_path.clone(),
            cron_tz,
            cron_hour: config.recording.retention_daily_cron_hour,
        };
        std::mem::drop(vauban_web::tasks::run_bootstrap_retention(
            &handle,
            db_pool.clone(),
            Arc::clone(sup),
            retention_config.clone(),
        ));
        vauban_web::tasks::start_recording_retention(
            handle,
            db_pool.clone(),
            Arc::clone(sup),
            retention_config,
        );
    } else if config.recording.retention_enabled {
        tracing::info!(
            "recording retention disabled: no supervisor (development mode without SCM_RIGHTS)"
        );
    } else {
        tracing::info!("recording retention disabled by config");
    }

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

    // ws_connection_limit middleware enforces per-user WebSocket connection limit
    // on ALL WS routes. Every current and future handler added to ws_routes is
    // automatically protected.
    let ws_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        handlers::websocket::ws_connection_limit,
    );

    // SECURITY: gate the admin-only WS broadcasts (`/ws/sessions/list`
    // and `/ws/sessions/active`) on the `admin:view` Casbin
    // permission BEFORE the `WebSocketUpgrade` extractor runs.
    // Otherwise unauthorised users get a 400 (extractor rejection on
    // missing upgrade headers) instead of the canonical 403 and the
    // endpoint leaks to unauthenticated network probes.
    let ws_admin_view_layer = axum::middleware::from_fn(handlers::websocket::ws_admin_view_guard);

    let ws_routes = Router::new()
        .route("/ws/dashboard", get(handlers::websocket::dashboard_ws))
        // SECURITY (Bastion Watch isolation): the per-user dashboard
        // endpoint subscribes to `dashboard:user:<uuid>` -- a
        // parametric, high-cardinality channel -- and is the
        // fan-out for the L2 SQL-filtered snapshot computed by the
        // pusher under `DashboardScope::User(self.id)`. Non-
        // supervisor users land here; supervisors land on
        // `/ws/dashboard` (singleton `DashboardStats`).
        .route(
            "/ws/dashboard/personal",
            get(handlers::websocket::dashboard_personal_ws),
        )
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
            get(handlers::websocket::active_sessions_ws).layer(ws_admin_view_layer.clone()),
        )
        .route(
            "/ws/sessions/list",
            get(handlers::websocket::session_list_ws).layer(ws_admin_view_layer),
        )
        .route(
            "/ws/terminal/{session_id}",
            get(handlers::websocket::terminal_ws).layer(session_guard.clone()),
        )
        .route(
            "/ws/rdp/{session_id}",
            get(handlers::websocket::rdp_ws).layer(session_guard),
        )
        // Apply per-user connection limit to ALL WebSocket routes
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
        // Self-service password rotation, opened from a modal on the profile
        // page. Step-up TOTP enforced inside the handler (single-use within
        // its 30-second window, RFC 6238 §5.2). No GET counterpart on
        // purpose: the form is rendered inline by the profile template, so a
        // direct GET would only encourage stray bookmarks to a non-existent
        // page.
        .route(
            "/accounts/profile/password",
            post(handlers::web::change_own_password_web),
        )
        .route("/accounts/mfa", get(handlers::web::mfa_setup))
        // Issue #8: renamed from /accounts/sessions to disambiguate web
        // login sessions from bastion proxy sessions in the UI.
        .route(
            "/accounts/login-sessions",
            get(handlers::web::user_sessions),
        )
        .route(
            "/accounts/login-sessions/{uuid}/revoke",
            post(handlers::web::revoke_session),
        )
        // Admin: all users' web login sessions (renamed from /admin/sessions
        // for the same reason).
        .route(
            "/accounts/all-login-sessions",
            get(handlers::web::admin_user_sessions),
        )
        .route(
            "/accounts/all-login-sessions/{uuid}/revoke",
            post(handlers::web::admin_revoke_session),
        )
        // 301 redirects for backward compatibility (bookmarks, external
        // links). Safe to drop after one release cycle.
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
        // Assets pages - GET for viewing only (issue #27: user zone is
        // session-only, no CRUD). All asset CRUD lives under
        // `/assets/manage/*`, gated by `require_assets_manage`. The
        // user zone exposes a single GET on `/assets` (list filtered
        // by access rules) and a single GET on `/assets/{uuid}`
        // (connect / request-access page); every other verb is in the
        // admin nest below. There is intentionally NO legacy-URL
        // redirect because v1.0 has not shipped, so we do not have any
        // bookmarks or external clients to preserve compatibility for.
        .route("/assets", get(handlers::web::asset_list))
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
        // Issue #34: the user-zone `/assets/{uuid}` detail page has
        // been REMOVED. It used to load `description`, dates,
        // ssh-host-key fingerprint and the full UUID for any caller
        // with `assets:read` (ie. every user) -- including users who
        // were about to OPEN the "Request Access" modal, which only
        // needs `uuid`, `asset_type` and `require_mfa`. Those three
        // fields now travel inside `AssetListItem` so the modaux
        // (Request Access + Justification) are inlined on the
        // `/assets` list and never require a detail page.  The
        // legacy URL is parked on a constant 410 Gone (anti-enum,
        // audit-friendly) -- see `gone_asset_user_view`.
        .route("/assets/{uuid}", get(handlers::web::gone_asset_user_view))
        // Sessions pages
        .route("/sessions", get(handlers::web::session_list))
        .route(
            "/sessions/{uuid}/terminate",
            post(handlers::web::terminate_session_web),
        )
        .route("/sessions/recordings", get(handlers::web::recording_list))
        // Recording-centric detail page (issue #29 / UX-28). UUID-keyed
        // to avoid sequential ID enumeration.
        .route(
            "/sessions/recordings/{uuid}",
            get(handlers::web::recording_detail),
        )
        .route(
            "/sessions/recordings/{uuid}/download",
            get(handlers::web::download_recording),
        )
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
            "/recordings/{session_uuid}/session.cast",
            get(handlers::web::serve_ssh_recording),
        )
        .route(
            "/recordings/{session_uuid}/{segment}",
            get(handlers::web::serve_segment),
        )
        .route("/sessions/{id}", get(handlers::web::session_detail))
        .route("/audit/approvals", get(handlers::web::approval_audit_list))
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
        .route(
            "/sessions/request",
            post(handlers::web::submit_access_request),
        )
        .route("/sessions/my-requests", get(handlers::web::my_requests))
        .route(
            "/sessions/my-requests/{uuid}/cancel",
            post(handlers::web::cancel_access_request),
        )
        // IACS / EWS user-zone routes (palier 6).
        //
        // The kill-switch is enforced via `perms.iacs_request`
        // (collapsed to `false` by `permission_context_middleware`
        // when `[industrial].enabled = false`); each handler
        // re-asserts the flag and returns 404 on a deny path so the
        // module's existence is not leaked via 403s. Admin-zone
        // routes (gated by `iacs:manage`) land in palier 7.
        .route(
            "/iacs/onboard",
            get(handlers::web::iacs::iacs_onboard_form)
                .post(handlers::web::iacs::iacs_submit_onboarding),
        )
        .route(
            "/iacs/onboard/{uuid}/edit-form",
            get(handlers::web::iacs::iacs_edit_form),
        )
        .route(
            "/iacs/onboard/{uuid}/edit",
            post(handlers::web::iacs::iacs_edit_request),
        )
        .route(
            "/iacs/onboard/{uuid}/cancel",
            post(handlers::web::iacs::iacs_cancel_request),
        )
        .route(
            "/iacs/{uuid}/offboard-self",
            post(handlers::web::iacs::iacs_offboard_self),
        )
        .route("/sessions/active", get(handlers::web::active_sessions))
        // IACS tunnel session endpoints (user zone). Both gates are
        // re-checked inside the handlers; the route layer just makes
        // them addressable. The status page is intentionally NOT
        // gated by `assets:read` -- once a session is created, the
        // owner must always be able to see the connection details
        // even if their `assets:read` was revoked between sessions.
        .route(
            "/assets/{uuid}/connect-iacs",
            post(handlers::web::connect_iacs),
        )
        .route(
            "/sessions/{uuid}/iacs/status",
            get(handlers::web::iacs_tunnel_status_page),
        )
        // SSH connection endpoints (user zone: opening sessions)
        .route("/assets/{uuid}/connect", post(handlers::web::connect_ssh))
        // SSH host key verification stays in the user zone because it
        // is part of the connect flow (refuses to open a session when
        // the stored fingerprint does not match). The administrative
        // counterpart (`fetch-host-key`, which writes the trusted key
        // into the asset record) lives under `/assets/manage/*`.
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

    // --------------------------------------------------------------------
    // Issue #27 -- ADMIN ASSET MANAGEMENT (`/assets/manage/*`)
    // --------------------------------------------------------------------
    //
    // Defence-in-depth: a `Router::nest` carrying the
    // `require_assets_manage` middleware makes every route under
    // `/assets/manage/*` return 403 BEFORE the handler is called when
    // the caller lacks the `assets:manage` Casbin permission. Each
    // handler in `crate::handlers::web::manage_assets` (and
    // `fetch_ssh_host_key` in `crate::handlers::web::ssh`) ALSO
    // re-asserts the same flag inside its body. The two checks are
    // intentional: one would catch a routing misconfiguration that
    // bypassed the other, and the test suite asserts that both layers
    // exist (`tests::manage_assets_gate_in_signature_test` and
    // `tests::require_assets_manage_failclosed_test`).
    //
    // The literal `/deleted`, `/new`, `/search` paths are declared
    // BEFORE the parameterized `{uuid}` paths so the axum router does
    // not attempt to parse them as a UUID.
    let manage_assets_routes = Router::new()
        .route("/", get(handlers::web::manage_asset_list))
        .route(
            "/new",
            get(handlers::web::asset_create_form).post(handlers::web::create_asset_web),
        )
        .route("/deleted", get(handlers::web::asset_deleted_list))
        .route("/search", get(handlers::web::asset_search))
        .route("/{uuid}", get(handlers::web::asset_detail))
        .route(
            "/{uuid}/edit",
            get(handlers::web::asset_edit).post(handlers::web::update_asset_web),
        )
        .route("/{uuid}/delete", post(handlers::web::delete_asset_web))
        .route(
            "/{uuid}/fetch-host-key",
            post(handlers::web::fetch_ssh_host_key),
        )
        .route_layer(axum::middleware::from_fn(
            middleware::require_assets_manage::require_assets_manage,
        ));

    let web_routes = web_routes.nest("/assets/manage", manage_assets_routes);

    // --------------------------------------------------------------------
    // Palier 7 -- IACS ADMIN MANAGEMENT (`/iacs/admin/*`)
    // --------------------------------------------------------------------
    //
    // Mirrors the `/assets/manage` defence-in-depth pattern: the
    // entire sub-tree is fenced by `route_layer(require_iacs_manage)`
    // so a non-admin gets 403 BEFORE the handler runs (anti-
    // enumeration: `/iacs/admin/{random-uuid}` cannot be used as an
    // oracle for EWS / request existence). Each handler ALSO
    // re-asserts `perms.iacs_manage` at the top of its body so a
    // routing misconfiguration that hoists a handler outside of the
    // nest still fails closed.
    //
    // Kill-switch interaction: when `[industrial].enabled = false`
    // the `permission_context_middleware` collapses `iacs_manage` to
    // `false`; the route_layer then refuses every admin-zone request
    // exactly as if the caller lacked the Casbin permission.
    let iacs_admin_routes = Router::new()
        .route("/", get(handlers::web::iacs::iacs_admin_list))
        .route(
            "/request/{uuid}",
            get(handlers::web::iacs::iacs_admin_request_detail),
        )
        .route(
            "/request/{uuid}/approve",
            post(handlers::web::iacs::iacs_admin_approve),
        )
        .route(
            "/request/{uuid}/reject",
            post(handlers::web::iacs::iacs_admin_reject),
        )
        .route(
            "/ews/{uuid}",
            get(handlers::web::iacs::iacs_admin_ews_detail),
        )
        .route(
            "/ews/{uuid}/disable",
            post(handlers::web::iacs::iacs_admin_disable),
        )
        .route(
            "/ews/{uuid}/enable",
            post(handlers::web::iacs::iacs_admin_enable),
        )
        .route(
            "/ews/{uuid}/offboard",
            post(handlers::web::iacs::iacs_admin_offboard),
        )
        .route_layer(axum::middleware::from_fn(
            middleware::require_iacs_manage::require_iacs_manage,
        ));

    let web_routes = web_routes.nest("/iacs/admin", iacs_admin_routes);

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
            // DELETE stub returns 501 Not Implemented (not 200 OK)
            .route(
                "/api/v1/accounts/{uuid}",
                get(handlers::api::get_user)
                    .put(handlers::api::update_user)
                    .delete(|| async {
                        (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                    }),
            )
            // Assets API -- USER ZONE (read-only listing).
            // Issue #27: every write operation lives under
            // `/api/v1/assets/manage/*` (admin nest below). v1.0 has
            // not shipped, so there are no legacy `/api/v1/assets/*`
            // verbs to preserve compatibility for; M2M clients (CLI,
            // IaC, orchestrators) target the canonical admin URLs
            // directly. The DELETE stub stays at the legacy path so
            // unsupported verbs get a canonical "not implemented"
            // answer instead of falling through to the global 404.
            .route("/api/v1/assets", get(handlers::api::list_assets))
            .route(
                "/api/v1/assets/{uuid}",
                axum::routing::delete(|| async {
                    (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                }),
            )
            // Sessions API
            .route("/api/v1/sessions", get(handlers::api::list_sessions))
            .route("/api/v1/sessions", post(handlers::api::create_session))
            // DELETE stub returns 501 Not Implemented (not 200 OK)
            .route(
                "/api/v1/sessions/{uuid}",
                get(handlers::api::get_session).delete(|| async {
                    (axum::http::StatusCode::NOT_IMPLEMENTED, "Not implemented")
                }),
            )
            .route(
                "/api/v1/sessions/{uuid}/terminate",
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
            // Issue #27 -- ADMIN ASSET MANAGEMENT API
            // (`/api/v1/assets/manage/*`)
            //
            // Same defence-in-depth as the web nest above: the
            // `require_assets_manage` middleware fences the entire
            // sub-tree at the routing layer and every handler in
            // `crate::handlers::api::manage_assets` re-asserts the
            // flag inside its body. The literal `groups` segment is
            // declared BEFORE the parameterized `{uuid}` so axum does
            // not attempt to parse it as a UUID.
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
                        get(handlers::api::get_asset).put(handlers::api::update_asset),
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
        // Bastion Watch HTTP rate accounting. Counts every request
        // into a 60-bucket sliding window so the System Health
        // tile's `req/s (60s avg)` reflects real traffic. The
        // tracker is process-wide and shared with the dashboard
        // pusher via `AppState.http_rate`. Mounted on the global
        // common_layers so it covers EVERY route -- web, api, and
        // ws -- and bench traffic (`wrk`, `oha`, ...) is counted.
        .layer(axum::middleware::from_fn_with_state(
            state.http_rate.clone(),
            services::system_health::record_http_request,
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
        // Pre-compute Casbin-backed PermissionContext once per authenticated
        // request, after the auth middleware has populated AuthUser. Templates
        // and handlers consume the result via the FromRequestParts extractor.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::permissions::permission_context_middleware,
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

    // ==================== SSH Recording Route & Static Assets Tests ====================

    #[test]
    fn test_ssh_recording_route_exists() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("/recordings/{session_uuid}/session.cast"),
            "SSH recording route must exist"
        );
        assert!(
            source.contains("serve_ssh_recording"),
            "route must point to serve_ssh_recording handler"
        );
    }

    #[test]
    fn test_asciinema_static_assets_registered() {
        assert!(
            vauban_web::static_assets::lookup("js/asciinema-player.min.js").is_some(),
            "asciinema-player.min.js must be in the static assets registry"
        );
        assert!(
            vauban_web::static_assets::lookup("js/asciinema-init.js").is_some(),
            "asciinema-init.js must be in the static assets registry"
        );
        assert!(
            vauban_web::static_assets::lookup("css/asciinema-player.css").is_some(),
            "asciinema-player.css must be in the static assets registry"
        );
    }

    #[tokio::test]
    async fn test_serve_static_serves_asciinema_js() {
        let path = axum::extract::Path("js/asciinema-player.min.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_ok(), "Must serve asciinema player JS");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/javascript; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_serve_static_serves_asciinema_css() {
        let path = axum::extract::Path("css/asciinema-player.css".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_ok(), "Must serve asciinema player CSS");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn test_serve_static_serves_asciinema_init() {
        let path = axum::extract::Path("js/asciinema-init.js".to_string());
        let headers = axum::http::HeaderMap::new();
        let result = serve_static(path, headers).await;
        assert!(result.is_ok(), "Must serve asciinema init JS");
        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
