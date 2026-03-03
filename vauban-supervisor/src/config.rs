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
    pub services: HashMap<String, ServiceConfig>,
    /// RDP proxy configuration (injected as env vars at spawn).
    #[serde(default)]
    pub rdp: RdpProxyConfig,
    /// Session recording configuration.
    #[serde(default)]
    pub recording: RecordingConfig,
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
    #[allow(dead_code)]
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

/// Logging configuration.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

/// Supervisor privilege separation and watchdog settings.
#[derive(Debug, Deserialize)]
pub struct SupervisorSettings {
    /// Enable privilege separation (default: true).
    /// When true, the supervisor setuid/setgid for each child and drops
    /// its own privileges to uid/gid after spawning all services.
    /// When false (dev/testing), all processes run as the current user.
    #[serde(default = "default_privsep")]
    pub privsep: bool,
    /// UID the supervisor drops to after spawning children (production).
    #[serde(default)]
    pub uid: Option<u32>,
    /// GID the supervisor drops to after spawning children (production).
    #[serde(default)]
    pub gid: Option<u32>,
    /// Watchdog configuration
    pub watchdog: WatchdogConfig,
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

/// Watchdog configuration.
#[derive(Debug, Deserialize)]
pub struct WatchdogConfig {
    pub heartbeat_interval_secs: u64,
    #[allow(dead_code)] // Will be used when heartbeat timeout is implemented
    pub heartbeat_timeout_secs: u64,
    pub max_missed_heartbeats: u32,
    pub max_respawns_per_hour: u32,
    /// Maximum time to wait for drain completion (default: 30s per Section 9.2)
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
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
            anyhow::bail!("VAUBAN_CONFIG_DIR points to non-existent directory: {}", path);
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
            builder = builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
        } else {
            let default_path = config_dir.join("default.toml");
            if default_path.exists() {
                let contents = std::fs::read_to_string(&default_path)
                    .with_context(|| format!("Failed to read config file: {}", default_path.display()))?;
                builder = builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
            }

            let env_name = match environment {
                Environment::Development => "development",
                Environment::Production => "production",
            };
            let env_path = config_dir.join(format!("{}.toml", env_name));
            if env_path.exists() {
                let contents = std::fs::read_to_string(&env_path)
                    .with_context(|| format!("Failed to read config file: {}", env_path.display()))?;
                builder = builder.add_source(config::File::from_str(&contents, config::FileFormat::Toml));
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

    /// Get the UID the supervisor should drop to after spawning children.
    pub fn supervisor_uid(&self) -> Option<u32> {
        if !self.supervisor.privsep {
            return None;
        }
        self.supervisor.uid
    }

    /// Get the GID the supervisor should drop to after spawning children.
    pub fn supervisor_gid(&self) -> Option<u32> {
        if !self.supervisor.privsep {
            return None;
        }
        self.supervisor.gid
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
            "audit",     // No dependencies
            "vault",     // No dependencies
            "rbac",      // No dependencies
            "auth",      // Depends on rbac, vault
            "proxy_ssh", // Depends on rbac, vault, audit
            "proxy_rdp", // Depends on rbac, vault, audit
            "web",       // Depends on auth, rbac, audit
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
        SupervisorConfig::load_from_dir_with_env(&config_dir, Environment::Development)
            .expect("Failed to load config from config/ directory. Ensure config/default.toml exists.")
    }

    // ==================== Development Config Tests ====================

    #[test]
    fn test_development_config() {
        let config = test_config();
        
        assert!(config.environment.is_development());
        assert!(!config.supervisor.privsep);
        assert_eq!(config.services.len(), 7);
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
        assert_eq!(config.supervisor.watchdog.heartbeat_interval_secs, 5);
        assert_eq!(config.supervisor.watchdog.heartbeat_timeout_secs, 2);
        assert_eq!(config.supervisor.watchdog.max_missed_heartbeats, 3);
        assert_eq!(config.supervisor.watchdog.max_respawns_per_hour, 10);
        assert_eq!(config.supervisor.watchdog.drain_timeout_secs, 30);
    }

    #[test]
    fn test_development_all_services_present() {
        let config = test_config();
        
        assert!(config.services.contains_key("audit"));
        assert!(config.services.contains_key("vault"));
        assert!(config.services.contains_key("rbac"));
        assert!(config.services.contains_key("auth"));
        assert!(config.services.contains_key("proxy_ssh"));
        assert!(config.services.contains_key("proxy_rdp"));
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
        assert!(path.ends_with("target/debug/vauban-audit"), "path was: {}", path);
    }

    #[test]
    fn test_binary_path_all_services() {
        let config = test_config();
        
        let services = ["audit", "vault", "rbac", "auth", "proxy_ssh", "proxy_rdp", "web"];
        for service in services {
            let path = config.binary_path(service);
            assert!(path.is_some(), "binary_path for {} should be Some", service);
            let path = path.unwrap();
            assert!(path.contains("target/debug/vauban-"), "path {} should contain 'target/debug/vauban-'", path);
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
        
        let services = ["audit", "vault", "rbac", "auth", "proxy_ssh", "proxy_rdp", "web"];
        
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
        
        assert_eq!(order.len(), 7);
        assert_eq!(order[0], "audit");
        assert_eq!(order[6], "web");
    }

    #[test]
    fn test_startup_order_dependencies() {
        let config = test_config();
        let order = config.startup_order();
        
        // Verify dependency order
        let audit_pos = order.iter().position(|&s| s == "audit").unwrap();
        let vault_pos = order.iter().position(|&s| s == "vault").unwrap();
        let rbac_pos = order.iter().position(|&s| s == "rbac").unwrap();
        let auth_pos = order.iter().position(|&s| s == "auth").unwrap();
        let web_pos = order.iter().position(|&s| s == "web").unwrap();
        
        // Auth depends on rbac and vault, so should start after them
        assert!(auth_pos > rbac_pos);
        assert!(auth_pos > vault_pos);
        
        // Web depends on auth, rbac, audit
        assert!(web_pos > auth_pos);
        assert!(web_pos > rbac_pos);
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
        
        for (_, service) in &config.services {
            assert!(service.uid.is_none());
            assert!(service.gid.is_none());
        }
    }

    // ==================== Load Config Tests ====================

    #[test]
    fn test_load_from_config_dir() {
        let config_dir = test_config_dir();
        let config = SupervisorConfig::load_from_dir_with_env(&config_dir, Environment::Development);
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
        for key in ["vault", "rbac", "auth", "proxy_ssh", "web"] {
            let vars = config.service_env_vars(key);
            assert!(
                vars.is_empty(),
                "service_env_vars for {} should be empty, got {:?}", key, vars
            );
        }
    }

    #[test]
    fn test_recording_config_defaults() {
        let config = test_config();
        assert!(config.recording.enabled);
        assert!(config.recording.rdp);
        assert!(config.recording.ssh);
        assert_eq!(config.recording.storage_path, "recordings");
    }
}
