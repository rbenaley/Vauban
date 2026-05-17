//! Configuration module for vauban-supervisor.
//!
//! Uses the centralized configuration from the workspace root `config/` directory.
//! Configuration is shared with vauban-web and other components.
//!
//! Supports two modes:
//! - Development: All services run as current user
//! - Production: Each service runs with dedicated UID/GID
//!
//! Configuration directory lookup order:
//! 1. VAUBAN_CONFIG_DIR environment variable (if set)
//! 2. Workspace root config/ directory (based on CARGO_MANIFEST_DIR)
//! 3. /usr/local/etc/vauban/ (production on FreeBSD)

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Main configuration structure.
#[derive(Debug, Deserialize)]
pub struct SupervisorConfig {
    /// Environment: "development" or "production" (defaults to production)
    #[serde(default)]
    pub environment: Environment,
    /// Path to service binaries
    pub bin_path: String,
    pub supervisor: SupervisorSettings,
    #[allow(dead_code)]
    pub logging: LoggingConfig,
    /// Server bind address (used by supervisor to bind the listening socket).
    #[serde(default)]
    pub server: ServerBindConfig,
    pub services: HashMap<String, ServiceConfig>,
    /// RBAC configuration (Casbin model and policy paths).
    #[serde(default)]
    pub access: AccessConfig,
    /// Auth service configuration (Argon2id parameters).
    #[serde(default)]
    pub auth: AuthConfig,
    /// RDP proxy configuration (injected as env vars at spawn).
    #[serde(default)]
    pub rdp: RdpProxyConfig,
    /// Session recording configuration.
    #[serde(default)]
    pub recording: RecordingConfig,
    /// Database configuration (shared URL for services that need DB access).
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Email notification configuration (Issue #10).
    ///
    /// The supervisor reads this block to enforce a strict (host, port)
    /// whitelist on `TcpConnectRequest { target_service: Web }` messages.
    /// Even though the mailer code lives in vauban-web, the SUPERVISOR
    /// is the authoritative gatekeeper for outbound TCP and refuses to
    /// connect anywhere else when the requester is the Web service.
    #[serde(default)]
    pub mailer: MailerConfig,
    /// Industrial / IACS tunnel configuration.
    ///
    /// Two responsibilities for the supervisor:
    ///   1. Pre-bind the russh sshd listener (privileged port allowed,
    ///      socket FD passed to vauban-proxy-iacs via `VAUBAN_IACS_LISTENER_FD`),
    ///      so proxy-iacs only needs `accept()` after `cap_enter()`.
    ///   2. Apply the same SSRF defence-in-depth as for the mailer: a
    ///      `TcpConnectRequest { target_service: ProxyIacs }` whose
    ///      destination resolves to a loopback IP is rejected unless
    ///      `industrial.iacs_tunnel.allow_loopback_targets = true`
    ///      (test/dev only).
    #[serde(default)]
    pub industrial: IndustrialConfig,
}

/// Database configuration for services that require direct DB access.
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_url")]
    pub url: String,
}

fn default_database_url() -> String {
    "postgresql://vauban:vauban@localhost/vauban".to_string()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
        }
    }
}

/// RBAC (Casbin) configuration.
///
/// These paths are injected as environment variables into `vauban-access`
/// at spawn time. The access service loads the model and policies before
/// entering the Capsicum sandbox.
#[derive(Debug, Deserialize)]
pub struct AccessConfig {
    #[serde(default = "default_rbac_model_path")]
    pub model_path: String,
    #[serde(default = "default_rbac_policy_path")]
    pub policy_path: String,
}

fn default_rbac_model_path() -> String {
    "config/access/model.conf".to_string()
}

fn default_rbac_policy_path() -> String {
    "config/access/default_policy.csv".to_string()
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            model_path: default_rbac_model_path(),
            policy_path: default_rbac_policy_path(),
        }
    }
}

/// Auth service configuration (Argon2id parameters).
///
/// Injected as environment variables into `vauban-auth` at spawn time.
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_argon2_memory_kb")]
    pub argon2_memory_kb: u32,
    #[serde(default = "default_argon2_iterations")]
    pub argon2_iterations: u32,
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
}

fn default_argon2_memory_kb() -> u32 {
    19456
}
fn default_argon2_iterations() -> u32 {
    2
}
fn default_argon2_parallelism() -> u32 {
    1
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kb: default_argon2_memory_kb(),
            argon2_iterations: default_argon2_iterations(),
            argon2_parallelism: default_argon2_parallelism(),
        }
    }
}

/// RDP proxy configuration.
///
/// These values are injected as environment variables into `vauban-proxy-rdp`
/// at spawn time, so the proxy never needs to read the TOML file itself.
#[derive(Debug, Deserialize)]
pub struct RdpProxyConfig {
    /// H.264 encoder bitrate in bits per second (default: 5 Mbps).
    #[serde(default = "default_video_bitrate_bps")]
    pub video_bitrate_bps: u32,
}

fn default_video_bitrate_bps() -> u32 {
    5_000_000
}

impl Default for RdpProxyConfig {
    fn default() -> Self {
        Self {
            video_bitrate_bps: default_video_bitrate_bps(),
        }
    }
}

/// Session recording configuration.
#[derive(Debug, Deserialize)]
pub struct RecordingConfig {
    #[serde(default = "default_recording_enabled")]
    pub enabled: bool,
    #[serde(default = "default_recording_storage_path")]
    pub storage_path: String,
    /// Enable recording of RDP sessions.
    #[serde(default = "default_recording_enabled")]
    pub rdp: bool,
    /// Enable recording of SSH sessions.
    #[serde(default = "default_recording_enabled")]
    pub ssh: bool,
}

fn default_recording_enabled() -> bool {
    true
}

fn default_recording_storage_path() -> String {
    "recordings".to_string()
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: default_recording_enabled(),
            storage_path: default_recording_storage_path(),
            rdp: default_recording_enabled(),
            ssh: default_recording_enabled(),
        }
    }
}

/// Email notification configuration (Issue #10), supervisor view.
///
/// The supervisor only needs to know:
///   1. Whether the mailer is enabled. When `enabled = false`, every
///      `TcpConnectRequest { target_service: Web }` is fail-closed.
///   2. The exact `(smtp_host, smtp_port)` couple that vauban-web is
///      allowed to brokered-connect to. Anything else is fail-closed.
///
/// All other knobs (credentials, retry policy, ...) live in vauban-web.
//
// `dead_code` is allowed temporarily on the fields and `allows()` because
// the supervisor hookup that consumes them lives in
// `handle_tcp_connect_request` and is wired in the next commit. Removing
// the allows once the wiring is in place is enforced by a regression test
// (`mailer_loaded_from_default_toml_is_disabled` already touches the
// fields and would break if they are ever removed).
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Deserialize)]
pub struct MailerConfig {
    /// Master switch. When false, the supervisor refuses to broker any
    /// TCP connection on behalf of vauban-web.
    #[serde(default)]
    pub enabled: bool,
    /// Allowed SMTP host (DNS name, exact match required).
    #[serde(default)]
    pub smtp_host: String,
    /// Allowed SMTP port (exact match required).
    #[serde(default)]
    pub smtp_port: u16,
}

impl MailerConfig {
    /// Returns `true` iff the mailer is enabled and `(host, port)`
    /// matches the configured whitelist (case-insensitive on host as
    /// per RFC 1035 §2.3.3).
    ///
    /// This is the SSRF guard: vauban-web cannot trick the supervisor
    /// into opening a socket to anywhere else just by forging a
    /// `TcpConnectRequest`.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        self.enabled
            && port == self.smtp_port
            && !self.smtp_host.is_empty()
            && host.eq_ignore_ascii_case(&self.smtp_host)
    }
}

/// Industrial control systems configuration (supervisor view).
///
/// The single source of truth for the master industrial-surface
/// switch is `industrial.enabled`. When `false`, the supervisor:
///
///   * does NOT spawn `vauban-proxy-iacs` (skipped in the startup
///     loop and the watchdog respawn paths),
///   * does NOT pre-bind the IACS sshd listener,
///   * does NOT pre-load the host key.
///
/// The previous per-feature switch `industrial.iacs_tunnel.enabled`
/// has been retired (May 2026): if industrial mode is on, the IACS
/// tunnel is on; the supervisor warns at boot if the deprecated key
/// is still present in the deployed TOML and ignores it.
#[derive(Debug, Clone, Deserialize)]
pub struct IndustrialConfig {
    /// Master switch. Default `true` (the industrial surface ships
    /// turned on; an operator opts out explicitly with
    /// `enabled = false`). Read by every Vauban service that runs
    /// industrial-only logic.
    #[serde(default = "default_industrial_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub iacs_tunnel: IacsTunnelSupervisorConfig,
}

fn default_industrial_enabled() -> bool {
    true
}

impl Default for IndustrialConfig {
    fn default() -> Self {
        Self {
            enabled: default_industrial_enabled(),
            iacs_tunnel: IacsTunnelSupervisorConfig::default(),
        }
    }
}

/// Supervisor's view of `[industrial.iacs_tunnel]`. Only the fields
/// the supervisor needs are deserialised here; vauban-web and
/// vauban-proxy-iacs each parse the broader block separately.
///
/// There is NO active `enabled` switch here: the IACS surface is
/// gated exclusively by `industrial.enabled`. The
/// `_deprecated_enabled` field below exists only so the supervisor
/// can emit a one-shot deprecation warning at boot when the legacy
/// key is still present in a deployed TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct IacsTunnelSupervisorConfig {
    /// DEPRECATED (May 2026). Captured here only to allow the
    /// supervisor to log a deprecation warning at boot. Always
    /// ignored at runtime. Use `industrial.enabled` instead.
    #[serde(default, rename = "enabled")]
    pub _deprecated_enabled: Option<bool>,
    /// Listener bind address ("host:port") for the sshd that EWS
    /// hosts connect to with `ssh -L`. Defaults to `127.0.0.1:4321`
    /// for backwards compatibility with development setups; production
    /// deployments should pin a routable address.
    ///
    /// SECURITY / privileged-port: the supervisor binds this socket
    /// BEFORE dropping privileges (same pattern as the HTTPS listener),
    /// so port < 1024 is safe. The raw FD is then inherited by
    /// `vauban-proxy-iacs` across `fork+execv` (env
    /// `VAUBAN_IACS_LISTENER_FD`), and the proxy only needs `accept()`
    /// after `cap_enter`.
    #[serde(default = "default_iacs_tunnel_bind_addr")]
    pub bind_addr: String,
    /// Allow brokered TCP connect to a loopback address. False in
    /// production (anti-SSRF defence-in-depth: the asset.hostname
    /// MUST resolve to a non-loopback IP), true only for E2E tests
    /// where the fake industrial server runs on `127.0.0.1`.
    #[serde(default)]
    pub allow_loopback_targets: bool,
    /// Persistent path for the russh sshd ed25519 host key consumed
    /// by `vauban-proxy-iacs`. The SUPERVISOR loads-or-generates the
    /// key BEFORE fork (`shared::iacs_host_key::prepare_host_key_fd`)
    /// and hands the file descriptor to the proxy via
    /// `VAUBAN_IACS_HOST_KEY_FD`. The proxy never opens this path
    /// itself: under FreeBSD Capsicum, post-`cap_enter` `open()` on
    /// an absolute path returns `errno 94` ("Not permitted in
    /// capability mode"). Defaults to the production path under
    /// `/var/lib/vauban/`; dev / CI override to a repo-local path
    /// that the unprivileged dev user can write.
    #[serde(default = "default_iacs_tunnel_host_key_path")]
    pub host_key_path: String,
    /// Maximum number of concurrent SSH `direct-tcpip` channels per
    /// authenticated EWS connection. Forwarded to `vauban-proxy-iacs`
    /// via `VAUBAN_IACS_MAX_CHANNELS_PER_SESSION`. `0` disables the
    /// cap. Default `16`. See `IacsTunnelConfig` in `vauban-web` for
    /// the full rationale (the supervisor only forwards this value;
    /// it does not consume it directly).
    #[serde(default = "default_iacs_tunnel_max_concurrent_channels_per_session")]
    pub max_concurrent_channels_per_session: u32,
}

fn default_iacs_tunnel_bind_addr() -> String {
    "127.0.0.1:4321".to_string()
}

fn default_iacs_tunnel_host_key_path() -> String {
    "/var/lib/vauban/iacs_tunnel_host_ed25519".to_string()
}

fn default_iacs_tunnel_max_concurrent_channels_per_session() -> u32 {
    16
}

impl Default for IacsTunnelSupervisorConfig {
    fn default() -> Self {
        Self {
            _deprecated_enabled: None,
            bind_addr: default_iacs_tunnel_bind_addr(),
            allow_loopback_targets: false,
            host_key_path: default_iacs_tunnel_host_key_path(),
            max_concurrent_channels_per_session:
                default_iacs_tunnel_max_concurrent_channels_per_session(),
        }
    }
}

impl IacsTunnelSupervisorConfig {
    /// Return `Some(value)` if the deployed TOML still carries the
    /// retired `industrial.iacs_tunnel.enabled` key, `None` otherwise.
    /// The supervisor calls this at boot to log a deprecation warning.
    pub fn deprecated_enabled(&self) -> Option<bool> {
        self._deprecated_enabled
    }
}

/// Logging configuration.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

/// Server bind configuration (host/port for the HTTPS listener).
/// The supervisor binds the socket as root and passes it to vauban-web via SCM_RIGHTS.
#[derive(Debug, Deserialize)]
pub struct ServerBindConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsCertPaths,
}

/// TLS certificate file paths. The supervisor reads (or generates) these
/// as root and sends the PEM data to vauban-web via IPC.
#[derive(Debug, Deserialize)]
pub struct TlsCertPaths {
    #[serde(default = "default_cert_path")]
    pub cert_path: String,
    #[serde(default = "default_key_path")]
    pub key_path: String,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8443
}

fn default_cert_path() -> String {
    "/usr/local/etc/vauban/certs/server.crt".to_string()
}

fn default_key_path() -> String {
    "/usr/local/etc/vauban/certs/server.key".to_string()
}

impl Default for ServerBindConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            tls: TlsCertPaths::default(),
        }
    }
}

impl Default for TlsCertPaths {
    fn default() -> Self {
        Self {
            cert_path: default_cert_path(),
            key_path: default_key_path(),
        }
    }
}

/// Supervisor settings (privilege separation + watchdog).
#[derive(Debug, Deserialize)]
pub struct SupervisorSettings {
    /// Enable privilege separation (default: true).
    /// When true, the supervisor setuid/setgid for each spawned child.
    /// When false (dev/testing), all processes run as the current user.
    /// The supervisor itself stays root to allow respawning children.
    #[serde(default = "default_privsep")]
    pub privsep: bool,
    pub heartbeat_interval_secs: u64,
    #[allow(dead_code)]
    pub heartbeat_timeout_secs: u64,
    pub max_missed_heartbeats: u32,
    pub max_respawns_per_hour: u32,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
}

fn default_privsep() -> bool {
    true
}

/// Environment type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    #[default]
    Production,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Development => write!(f, "development"),
            Environment::Production => write!(f, "production"),
        }
    }
}

impl Environment {
    #[allow(dead_code)]
    pub fn is_development(&self) -> bool {
        matches!(self, Environment::Development)
    }

    #[allow(dead_code)] // Will be used for production-specific logic
    pub fn is_production(&self) -> bool {
        matches!(self, Environment::Production)
    }
}

fn default_drain_timeout() -> u64 {
    30
}

/// Service configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Service display name
    pub name: String,
    /// Binary name (without path)
    pub binary: String,
    /// User ID (optional, uses default if not specified)
    pub uid: Option<u32>,
    /// Group ID (optional, uses default if not specified)
    pub gid: Option<u32>,
    /// Working directory (optional)
    #[allow(dead_code)] // Will be used when chdir is implemented
    pub workdir: Option<String>,
}

impl SupervisorConfig {
    /// Load configuration from a TOML file.
    /// Used by tests and for loading from specific paths.
    #[allow(dead_code)]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: SupervisorConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Load configuration from the centralized config directory.
    ///
    /// Uses the same directory lookup as vauban-web:
    /// 1. VAUBAN_CONFIG_DIR environment variable (if set)
    /// 2. Workspace root config/ directory (based on CARGO_MANIFEST_DIR)
    /// 3. /usr/local/etc/vauban/ (production on FreeBSD)
    ///
    /// Loads configuration:
    /// - Production (default): vauban.conf only
    /// - Development: default.toml + development.toml
    pub fn load_auto() -> Result<Self> {
        let config_dir = Self::find_config_dir()?;
        Self::load_from_dir(&config_dir)
    }

    /// Find the configuration directory.
    ///
    /// Searches in the following order:
    /// 1. VAUBAN_CONFIG_DIR environment variable (if set)
    /// 2. Workspace root config/ directory (based on CARGO_MANIFEST_DIR)
    /// 3. /usr/local/etc/vauban/ (production on FreeBSD)
    fn find_config_dir() -> Result<PathBuf> {
        // 1. Check for explicit VAUBAN_CONFIG_DIR environment variable
        if let Ok(path) = std::env::var("VAUBAN_CONFIG_DIR") {
            let config_path = PathBuf::from(&path);
            if config_path.exists() {
                return Ok(config_path);
            }
            anyhow::bail!(
                "VAUBAN_CONFIG_DIR points to non-existent directory: {}",
                path
            );
        }

        // 2. Check workspace root config/ directory (development)
        // CARGO_MANIFEST_DIR is set at compile time to the crate's directory (vauban-supervisor/)
        // We go up one level to reach the workspace root
        let workspace_config = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("config"));
        if let Some(ref config_path) = workspace_config
            && config_path.exists()
        {
            return Ok(config_path.clone());
        }

        // 3. Check system configuration directory (production on FreeBSD)
        let system_config = Path::new("/usr/local/etc/vauban");
        if system_config.exists() {
            return Ok(system_config.to_path_buf());
        }

        // No configuration directory found, fall back to embedded default
        anyhow::bail!(
            "Configuration directory not found. Searched:\n\
             - VAUBAN_CONFIG_DIR environment variable\n\
             - Workspace root config/ directory\n\
             - /usr/local/etc/vauban/"
        )
    }

    /// Load configuration from a directory containing TOML files.
    ///
    /// - Production (default): loads only `vauban.conf`
    /// - Development: loads `default.toml` + `development.toml`
    pub fn load_from_dir(config_dir: &Path) -> Result<Self> {
        let environment = std::env::var("VAUBAN_ENVIRONMENT")
            .map(|e| match e.to_lowercase().as_str() {
                "development" | "dev" => Environment::Development,
                _ => Environment::Production,
            })
            .unwrap_or(Environment::Production);

        Self::load_from_dir_with_env(config_dir, environment)
    }

    /// Load configuration from a directory with an explicit environment.
    pub fn load_from_dir_with_env(config_dir: &Path, environment: Environment) -> Result<Self> {
        let mut builder = config::Config::builder();

        if environment.is_production() {
            let conf_path = config_dir.join("vauban.conf");
            let contents = std::fs::read_to_string(&conf_path)
                .with_context(|| format!("Failed to read config file: {}", conf_path.display()))?;
            builder =
                builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
        } else {
            let default_path = config_dir.join("default.toml");
            if default_path.exists() {
                let contents = std::fs::read_to_string(&default_path).with_context(|| {
                    format!("Failed to read config file: {}", default_path.display())
                })?;
                builder =
                    builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
            }

            let env_name = match environment {
                Environment::Development => "development",
                Environment::Production => "production",
            };
            let env_path = config_dir.join(format!("{}.toml", env_name));
            if env_path.exists() {
                let contents = std::fs::read_to_string(&env_path).with_context(|| {
                    format!("Failed to read config file: {}", env_path.display())
                })?;
                builder =
                    builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
            }
        }

        let settings = builder
            .build()
            .with_context(|| "Failed to build configuration")?;

        settings
            .try_deserialize()
            .with_context(|| "Failed to deserialize supervisor configuration")
    }

    /// Get effective UID for a service.
    ///
    /// When privsep is disabled, returns None (don't change user).
    /// When privsep is enabled, returns the service's configured UID.
    pub fn effective_uid(&self, service_key: &str) -> Option<u32> {
        if !self.supervisor.privsep {
            return None;
        }
        let service = self.services.get(service_key)?;
        service.uid
    }

    /// Get effective GID for a service.
    pub fn effective_gid(&self, service_key: &str) -> Option<u32> {
        if !self.supervisor.privsep {
            return None;
        }
        let service = self.services.get(service_key)?;
        service.gid
    }

    /// Get full path to a service binary.
    ///
    /// Returns an absolute path to ensure it works after chdir.
    pub fn binary_path(&self, service_key: &str) -> Option<String> {
        let service = self.services.get(service_key)?;
        let path = format!("{}/{}", self.bin_path, service.binary);

        // Convert relative paths to absolute
        if path.starts_with("./") || !path.starts_with('/') {
            std::env::current_dir()
                .ok()
                .map(|cwd| cwd.join(&path).to_string_lossy().to_string())
        } else {
            Some(path)
        }
    }

    /// Get effective working directory for a service.
    ///
    /// In development mode, returns None (services run from workspace root).
    /// This ensures all relative paths in configuration work correctly.
    /// In production mode, uses the configured workdir if set.
    pub fn effective_workdir(&self, service_key: &str) -> Option<String> {
        let service = self.services.get(service_key)?;

        // Use explicit workdir if configured (production)
        if let Some(ref workdir) = service.workdir {
            return Some(workdir.clone());
        }

        // In development mode, don't change working directory
        // All services run from workspace root where config paths are relative to
        None
    }

    /// Build service-specific environment variables to inject at spawn time.
    ///
    /// Returns key-value pairs that `spawn_child` will set in the child process.
    /// The child is responsible for reading and immediately removing them.
    pub fn service_env_vars(&self, service_key: &str) -> Vec<(String, String)> {
        let mut vars = Vec::new();
        match service_key {
            "access" => {
                vars.push((
                    "VAUBAN_ACCESS_MODEL_PATH".to_string(),
                    self.access.model_path.clone(),
                ));
                vars.push((
                    "VAUBAN_ACCESS_POLICY_PATH".to_string(),
                    self.access.policy_path.clone(),
                ));
                vars.push((
                    "VAUBAN_DATABASE_URL".to_string(),
                    self.database.url.to_string(),
                ));
            }
            "proxy_rdp" => {
                vars.push((
                    "VAUBAN_RDP_VIDEO_BITRATE_BPS".to_string(),
                    self.rdp.video_bitrate_bps.to_string(),
                ));
                let rdp_recording = self.recording.enabled && self.recording.rdp;
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    rdp_recording.to_string(),
                ));
            }
            "proxy_ssh" => {
                let ssh_recording = self.recording.enabled && self.recording.ssh;
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    ssh_recording.to_string(),
                ));
            }
            "auth" => {
                vars.push((
                    "VAUBAN_ARGON2_MEMORY_KB".to_string(),
                    self.auth.argon2_memory_kb.to_string(),
                ));
                vars.push((
                    "VAUBAN_ARGON2_ITERATIONS".to_string(),
                    self.auth.argon2_iterations.to_string(),
                ));
                vars.push((
                    "VAUBAN_ARGON2_PARALLELISM".to_string(),
                    self.auth.argon2_parallelism.to_string(),
                ));
            }
            "audit" => {
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    self.recording.enabled.to_string(),
                ));
                vars.push((
                    "VAUBAN_RECORDING_STORAGE_PATH".to_string(),
                    self.recording.storage_path.clone(),
                ));
            }
            "proxy_iacs" => {
                // The supervisor pre-binds the IACS sshd listener and
                // hands the FD via VAUBAN_IACS_LISTENER_FD (set in
                // spawn_child via the inheritable_fds slot, NOT here
                // -- env vars set here are strings, while the FD path
                // also needs FD_CLOEXEC clearing).
                //
                // The host key is also pre-loaded by the supervisor
                // (`shared::iacs_host_key::prepare_host_key_fd` reads
                // or generates the file at `host_key_path` BEFORE the
                // fork) and the resulting OwnedFd is passed via
                // `VAUBAN_IACS_HOST_KEY_FD` -- again from the
                // inheritable_fds slot in spawn_child, NOT here. The
                // proxy NEVER opens the host key path itself: under
                // FreeBSD Capsicum, post-`cap_enter` `open()` on an
                // absolute path returns errno 94 ("Not permitted in
                // capability mode").
                //
                // Per-login channel cap. `vauban-proxy-iacs` reads
                // this value at boot and bounds the number of
                // concurrent `direct-tcpip` channels per authenticated
                // SSH login. `0` disables the cap.
                vars.push((
                    "VAUBAN_IACS_MAX_CHANNELS_PER_SESSION".to_string(),
                    self.industrial
                        .iacs_tunnel
                        .max_concurrent_channels_per_session
                        .to_string(),
                ));
            }
            _ => {}
        }
        vars
    }

    /// Get ordered list of services for startup.
    ///
    /// Returns service keys in dependency order.
    pub fn startup_order(&self) -> Vec<&str> {
        // Fixed startup order based on dependencies
        vec![
            "audit",      // No dependencies
            "vault",      // No dependencies
            "access",     // No dependencies
            "auth",       // Depends on access, vault
            "proxy_ssh",  // Depends on access, vault, audit
            "proxy_rdp",  // Depends on access, vault, audit
            "proxy_iacs", // Depends on access, audit (no vault: no target credentials)
            "web",        // Depends on auth, access, audit
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Test Helpers ====================

    /// Get the path to the workspace root config/ directory for tests.
    fn test_config_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .join("config")
    }

    /// Load development configuration from the real config files for tests.
    fn test_config() -> SupervisorConfig {
        let config_dir = test_config_dir();
        SupervisorConfig::load_from_dir_with_env(&config_dir, Environment::Development).expect(
            "Failed to load config from config/ directory. Ensure config/default.toml exists.",
        )
    }

    // ==================== Development Config Tests ====================

    #[test]
    fn test_development_config() {
        let config = test_config();

        assert!(config.environment.is_development());
        assert!(!config.supervisor.privsep);
        assert_eq!(config.services.len(), 8);
    }

    #[test]
    fn test_development_bin_path() {
        let config = test_config();
        assert_eq!(config.bin_path, "./target/debug");
    }

    #[test]
    fn test_development_log_level() {
        let config = test_config();
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_development_watchdog_config() {
        let config = test_config();
        assert_eq!(config.supervisor.heartbeat_interval_secs, 5);
        assert_eq!(config.supervisor.heartbeat_timeout_secs, 2);
        assert_eq!(config.supervisor.max_missed_heartbeats, 3);
        assert_eq!(config.supervisor.max_respawns_per_hour, 10);
        assert_eq!(config.supervisor.drain_timeout_secs, 30);
    }

    #[test]
    fn test_development_all_services_present() {
        let config = test_config();

        assert!(config.services.contains_key("audit"));
        assert!(config.services.contains_key("vault"));
        assert!(config.services.contains_key("access"));
        assert!(config.services.contains_key("auth"));
        assert!(config.services.contains_key("proxy_ssh"));
        assert!(config.services.contains_key("proxy_rdp"));
        assert!(config.services.contains_key("proxy_iacs"));
        assert!(config.services.contains_key("web"));
    }

    // ==================== Effective UID/GID Tests ====================

    #[test]
    fn test_effective_uid_development() {
        let config = test_config();

        // In development, effective_uid should return None (don't change)
        assert_eq!(config.effective_uid("audit"), None);
        assert_eq!(config.effective_uid("web"), None);
    }

    #[test]
    fn test_effective_gid_development() {
        let config = test_config();

        // In development, effective_gid should return None (don't change)
        assert_eq!(config.effective_gid("audit"), None);
        assert_eq!(config.effective_gid("web"), None);
    }

    #[test]
    fn test_effective_uid_unknown_service() {
        let config = test_config();

        // Unknown service should return None
        assert_eq!(config.effective_uid("unknown"), None);
    }

    #[test]
    fn test_effective_gid_unknown_service() {
        let config = test_config();

        // Unknown service should return None
        assert_eq!(config.effective_gid("unknown"), None);
    }

    // ==================== Binary Path Tests ====================

    #[test]
    fn test_binary_path() {
        let config = test_config();

        // binary_path returns an absolute path
        let path = config.binary_path("audit");
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(
            path.ends_with("target/debug/vauban-audit"),
            "path was: {}",
            path
        );
    }

    #[test]
    fn test_binary_path_all_services() {
        let config = test_config();

        let services = [
            "audit",
            "vault",
            "access",
            "auth",
            "proxy_ssh",
            "proxy_rdp",
            "proxy_iacs",
            "web",
        ];
        for service in services {
            let path = config.binary_path(service);
            assert!(path.is_some(), "binary_path for {} should be Some", service);
            let path = path.unwrap();
            assert!(
                path.contains("target/debug/vauban-"),
                "path {} should contain 'target/debug/vauban-'",
                path
            );
        }
    }

    #[test]
    fn test_binary_path_unknown_service() {
        let config = test_config();

        let path = config.binary_path("nonexistent");
        assert!(path.is_none());
    }

    // ==================== Effective Workdir Tests ====================

    #[test]
    fn test_effective_workdir_development() {
        let config = test_config();

        // In development, workdir should be None (run from workspace root)
        // This ensures all relative paths in configuration work correctly
        let workdir = config.effective_workdir("audit");
        assert!(workdir.is_none(), "Development workdir should be None");
    }

    #[test]
    fn test_effective_workdir_all_services_development() {
        let config = test_config();

        let services = [
            "audit",
            "vault",
            "access",
            "auth",
            "proxy_ssh",
            "proxy_rdp",
            "proxy_iacs",
            "web",
        ];

        for key in services {
            let workdir = config.effective_workdir(key);
            assert!(
                workdir.is_none(),
                "Development workdir for {} should be None to run from workspace root",
                key
            );
        }
    }

    #[test]
    fn test_effective_workdir_unknown_service() {
        let config = test_config();

        let workdir = config.effective_workdir("nonexistent");
        assert!(workdir.is_none());
    }

    /// Regression test: ensure development workdir is None so relative paths work.
    ///
    /// When services run from workspace root, relative paths like "vauban-web/certs/..."
    /// resolve correctly. If workdir were set to "vauban-web", the path would become
    /// "vauban-web/vauban-web/certs/..." which is incorrect.
    #[test]
    fn test_development_workdir_none_prevents_path_doubling() {
        let config = test_config();

        // Critical: web service must NOT have a workdir in development
        // Otherwise paths like "vauban-web/certs/..." would fail
        let web_workdir = config.effective_workdir("web");
        assert!(
            web_workdir.is_none(),
            "Web service workdir must be None in development to prevent path doubling. \
             If workdir is 'vauban-web', then paths like 'vauban-web/certs/...' in config \
             would resolve to 'vauban-web/vauban-web/certs/...' which doesn't exist."
        );
    }

    // ==================== Startup Order Tests ====================

    #[test]
    fn test_startup_order() {
        let config = test_config();
        let order = config.startup_order();

        assert_eq!(order.len(), 8);
        assert_eq!(order[0], "audit");
        assert_eq!(order[7], "web");
    }

    #[test]
    fn test_startup_order_dependencies() {
        let config = test_config();
        let order = config.startup_order();

        // Verify dependency order
        let audit_pos = order.iter().position(|&s| s == "audit").unwrap();
        let vault_pos = order.iter().position(|&s| s == "vault").unwrap();
        let access_pos = order.iter().position(|&s| s == "access").unwrap();
        let auth_pos = order.iter().position(|&s| s == "auth").unwrap();
        let web_pos = order.iter().position(|&s| s == "web").unwrap();

        // Auth depends on access and vault, so should start after them
        assert!(auth_pos > access_pos);
        assert!(auth_pos > vault_pos);

        // Web depends on auth, access, audit
        assert!(web_pos > auth_pos);
        assert!(web_pos > access_pos);
        assert!(web_pos > audit_pos);
    }

    // ==================== Environment Tests ====================

    #[test]
    fn test_environment_is_development() {
        assert!(Environment::Development.is_development());
        assert!(!Environment::Development.is_production());
    }

    #[test]
    fn test_environment_is_production() {
        assert!(Environment::Production.is_production());
        assert!(!Environment::Production.is_development());
    }

    // ==================== ServiceConfig Tests ====================

    #[test]
    fn test_service_config_name() {
        let config = test_config();

        let audit = config.services.get("audit").unwrap();
        assert_eq!(audit.name, "vauban-audit");
        assert_eq!(audit.binary, "vauban-audit");
    }

    #[test]
    fn test_service_config_no_uid_gid_in_development() {
        let config = test_config();

        for service in config.services.values() {
            assert!(service.uid.is_none());
            assert!(service.gid.is_none());
        }
    }

    // ==================== Load Config Tests ====================

    #[test]
    fn test_load_from_config_dir() {
        let config_dir = test_config_dir();
        let config =
            SupervisorConfig::load_from_dir_with_env(&config_dir, Environment::Development);
        assert!(config.is_ok(), "Failed to load config: {:?}", config.err());
        let config = config.unwrap();
        assert!(config.environment.is_development());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = SupervisorConfig::load("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    // ==================== RDP Config Tests ====================

    #[test]
    fn test_access_config_default() {
        let access = AccessConfig::default();
        assert_eq!(access.model_path, "config/access/model.conf");
        assert_eq!(access.policy_path, "config/access/default_policy.csv");
    }

    #[test]
    fn test_access_config_loaded_from_toml() {
        let config = test_config();
        assert_eq!(config.access.model_path, "config/access/model.conf");
        assert_eq!(
            config.access.policy_path,
            "config/access/default_policy.csv"
        );
    }

    #[test]
    fn test_rdp_config_default() {
        let rdp = RdpProxyConfig::default();
        assert_eq!(rdp.video_bitrate_bps, 5_000_000);
    }

    #[test]
    fn test_rdp_config_loaded_from_toml() {
        let config = test_config();
        assert_eq!(config.rdp.video_bitrate_bps, 5_000_000);
    }

    // ==================== Service Env Vars Tests ====================

    #[test]
    fn test_service_env_vars_proxy_rdp() {
        let config = test_config();
        let vars = config.service_env_vars("proxy_rdp");
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "VAUBAN_RDP_VIDEO_BITRATE_BPS");
        assert_eq!(vars[0].1, "5000000");
        assert_eq!(vars[1].0, "VAUBAN_RECORDING_ENABLED");
        assert_eq!(vars[1].1, "true");
    }

    #[test]
    fn test_service_env_vars_audit() {
        let config = test_config();
        let vars = config.service_env_vars("audit");
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "VAUBAN_RECORDING_ENABLED");
        assert_eq!(vars[0].1, "true");
        assert_eq!(vars[1].0, "VAUBAN_RECORDING_STORAGE_PATH");
        assert_eq!(vars[1].1, "recordings");
    }

    #[test]
    fn test_service_env_vars_other_services_empty() {
        let config = test_config();
        for key in ["vault", "web"] {
            let vars = config.service_env_vars(key);
            assert!(
                vars.is_empty(),
                "service_env_vars for {} should be empty, got {:?}",
                key,
                vars
            );
        }
    }

    #[test]
    fn test_service_env_vars_proxy_ssh() {
        let config = test_config();
        let vars = config.service_env_vars("proxy_ssh");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "VAUBAN_RECORDING_ENABLED");
        assert_eq!(vars[0].1, "true");
    }

    #[test]
    fn test_service_env_vars_auth() {
        let config = test_config();
        let vars = config.service_env_vars("auth");
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, "VAUBAN_ARGON2_MEMORY_KB");
        assert_eq!(vars[1].0, "VAUBAN_ARGON2_ITERATIONS");
        assert_eq!(vars[2].0, "VAUBAN_ARGON2_PARALLELISM");
    }

    #[test]
    fn test_service_env_vars_access() {
        let config = test_config();
        let vars = config.service_env_vars("access");
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, "VAUBAN_ACCESS_MODEL_PATH");
        assert_eq!(vars[0].1, "config/access/model.conf");
        assert_eq!(vars[1].0, "VAUBAN_ACCESS_POLICY_PATH");
        assert_eq!(vars[1].1, "config/access/default_policy.csv");
        assert_eq!(vars[2].0, "VAUBAN_DATABASE_URL");
    }

    #[test]
    fn test_recording_config_defaults() {
        let config = test_config();
        assert!(config.recording.enabled);
        assert!(config.recording.rdp);
        assert!(config.recording.ssh);
        assert_eq!(config.recording.storage_path, "recordings");
    }

    // ==================== Server Bind Config Tests ====================

    #[test]
    fn test_server_bind_config_default() {
        let sbc = ServerBindConfig::default();
        assert_eq!(sbc.host, "0.0.0.0");
        assert_eq!(sbc.port, 8443);
    }

    #[test]
    fn test_server_bind_config_loaded_from_toml() {
        let config = test_config();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8443);
    }

    #[test]
    fn test_server_bind_config_production() {
        let config_dir = test_config_dir();
        let config = SupervisorConfig::load_from_dir_with_env(&config_dir, Environment::Production)
            .expect("Failed to load production config");
        assert_eq!(config.server.host, "0.0.0.0");
        assert!(config.server.port > 0, "port should be set");
    }

    // ==================== Mailer SSRF whitelist (Issue #10) ====================

    fn mailer(enabled: bool, host: &str, port: u16) -> MailerConfig {
        MailerConfig {
            enabled,
            smtp_host: host.to_string(),
            smtp_port: port,
        }
    }

    #[test]
    fn mailer_allows_exact_host_port_when_enabled() {
        let m = mailer(true, "smtp.example.com", 587);
        assert!(m.allows("smtp.example.com", 587));
    }

    #[test]
    fn mailer_denies_when_disabled_even_if_match() {
        let m = mailer(false, "smtp.example.com", 587);
        assert!(!m.allows("smtp.example.com", 587));
    }

    #[test]
    fn mailer_denies_wrong_host() {
        let m = mailer(true, "smtp.example.com", 587);
        assert!(!m.allows("evil.example.com", 587));
    }

    #[test]
    fn mailer_denies_wrong_port() {
        let m = mailer(true, "smtp.example.com", 587);
        assert!(!m.allows("smtp.example.com", 25));
    }

    #[test]
    fn mailer_denies_empty_host() {
        let m = mailer(true, "", 587);
        // even when "match" formally holds (host.eq_ignore_ascii_case(""))
        // we MUST fail-closed because an empty whitelist must not
        // implicitly allow an empty target.
        assert!(!m.allows("", 587));
    }

    #[test]
    fn mailer_host_match_is_case_insensitive() {
        let m = mailer(true, "smtp.example.com", 587);
        assert!(m.allows("SMTP.Example.Com", 587));
    }

    #[test]
    fn mailer_default_is_disabled_and_denies_everything() {
        let m = MailerConfig::default();
        assert!(!m.enabled);
        assert!(!m.allows("any", 1));
        assert!(!m.allows("", 0));
    }

    #[test]
    fn mailer_loaded_from_default_toml_is_disabled() {
        let config = test_config();
        assert!(
            !config.mailer.enabled,
            "default.toml ships with mailer disabled (operator must opt-in)"
        );
    }
}
