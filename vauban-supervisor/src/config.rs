//! Configuration module for vauban-supervisor.
//!
//! Supports two modes:
//! - Development: All services run as current user
//! - Production: Each service runs with dedicated UID/GID

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Main configuration structure.
#[derive(Debug, Deserialize)]
pub struct SupervisorConfig {
    pub supervisor: SupervisorSettings,
    pub defaults: DefaultCredentials,
    pub services: HashMap<String, ServiceConfig>,
}

/// Supervisor settings.
#[derive(Debug, Deserialize)]
pub struct SupervisorSettings {
    /// Environment: "development" or "production"
    pub environment: Environment,
    /// Path to service binaries
    pub bin_path: String,
    /// Log level
    #[allow(dead_code)] // Will be used for dynamic log configuration
    pub log_level: String,
    /// Watchdog configuration
    pub watchdog: WatchdogConfig,
}

/// Environment type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
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
}

/// Default credentials for development mode.
#[derive(Debug, Deserialize)]
pub struct DefaultCredentials {
    /// Default UID (0 = don't change, use current user)
    pub uid: u32,
    /// Default GID (0 = don't change, use current user)
    pub gid: u32,
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
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let config: SupervisorConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        
        Ok(config)
    }

    /// Load configuration based on environment.
    ///
    /// Looks for config files in this order:
    /// 1. Path specified in VAUBAN_CONFIG environment variable
    /// 2. ./config/{environment}.toml
    /// 3. /usr/local/etc/vauban/supervisor.toml (production)
    /// 4. Default embedded configuration
    pub fn load_auto() -> Result<Self> {
        // Check environment variable first
        if let Ok(config_path) = std::env::var("VAUBAN_CONFIG") {
            return Self::load(&config_path);
        }

        // Check for development config
        let dev_config = Path::new("config/development.toml");
        if dev_config.exists() {
            return Self::load(dev_config);
        }

        // Check for production config
        let prod_config = Path::new("/usr/local/etc/vauban/supervisor.toml");
        if prod_config.exists() {
            return Self::load(prod_config);
        }

        // Fall back to embedded default (development)
        Self::default_development()
    }

    /// Get effective UID for a service.
    ///
    /// In development mode (uid=0), returns None (don't change user).
    /// In production mode, returns the configured UID.
    pub fn effective_uid(&self, service_key: &str) -> Option<u32> {
        let service = self.services.get(service_key)?;
        
        // Service-specific UID takes precedence
        let uid = service.uid.unwrap_or(self.defaults.uid);
        
        // 0 means "don't change" (development mode)
        if uid == 0 {
            None
        } else {
            Some(uid)
        }
    }

    /// Get effective GID for a service.
    pub fn effective_gid(&self, service_key: &str) -> Option<u32> {
        let service = self.services.get(service_key)?;
        
        let gid = service.gid.unwrap_or(self.defaults.gid);
        
        if gid == 0 {
            None
        } else {
            Some(gid)
        }
    }

    /// Get full path to a service binary.
    ///
    /// Returns an absolute path to ensure it works after chdir.
    pub fn binary_path(&self, service_key: &str) -> Option<String> {
        let service = self.services.get(service_key)?;
        let path = format!("{}/{}", self.supervisor.bin_path, service.binary);
        
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
    /// In development mode, uses the service's source directory (e.g., "vauban-web").
    /// In production mode, uses the configured workdir if set.
    pub fn effective_workdir(&self, service_key: &str) -> Option<String> {
        let service = self.services.get(service_key)?;
        
        // Use explicit workdir if configured
        if let Some(ref workdir) = service.workdir {
            return Some(workdir.clone());
        }
        
        // In development mode, use the service's source directory
        if self.supervisor.environment.is_development() {
            // Convert service name to directory (e.g., "vauban-web" -> "vauban-web")
            Some(service.name.clone())
        } else {
            None
        }
    }

    /// Create default development configuration.
    pub fn default_development() -> Result<Self> {
        let toml_str = r#"
[supervisor]
environment = "development"
bin_path = "./target/debug"
log_level = "debug"

[supervisor.watchdog]
heartbeat_interval_secs = 5
heartbeat_timeout_secs = 2
max_missed_heartbeats = 3
max_respawns_per_hour = 10

[defaults]
uid = 0
gid = 0

[services.audit]
name = "vauban-audit"
binary = "vauban-audit"

[services.vault]
name = "vauban-vault"
binary = "vauban-vault"

[services.rbac]
name = "vauban-rbac"
binary = "vauban-rbac"

[services.auth]
name = "vauban-auth"
binary = "vauban-auth"

[services.proxy_ssh]
name = "vauban-proxy-ssh"
binary = "vauban-proxy-ssh"

[services.proxy_rdp]
name = "vauban-proxy-rdp"
binary = "vauban-proxy-rdp"

[services.web]
name = "vauban-web"
binary = "vauban-web"
"#;
        toml::from_str(toml_str).context("Failed to parse default configuration")
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

    // ==================== Default Development Config Tests ====================

    #[test]
    fn test_default_development_config() {
        let config = SupervisorConfig::default_development().unwrap();
        
        assert!(config.supervisor.environment.is_development());
        assert_eq!(config.defaults.uid, 0);
        assert_eq!(config.defaults.gid, 0);
        assert_eq!(config.services.len(), 7);
    }

    #[test]
    fn test_default_development_bin_path() {
        let config = SupervisorConfig::default_development().unwrap();
        assert_eq!(config.supervisor.bin_path, "./target/debug");
    }

    #[test]
    fn test_default_development_log_level() {
        let config = SupervisorConfig::default_development().unwrap();
        assert_eq!(config.supervisor.log_level, "debug");
    }

    #[test]
    fn test_default_development_watchdog_config() {
        let config = SupervisorConfig::default_development().unwrap();
        assert_eq!(config.supervisor.watchdog.heartbeat_interval_secs, 5);
        assert_eq!(config.supervisor.watchdog.heartbeat_timeout_secs, 2);
        assert_eq!(config.supervisor.watchdog.max_missed_heartbeats, 3);
        assert_eq!(config.supervisor.watchdog.max_respawns_per_hour, 10);
    }

    #[test]
    fn test_default_development_all_services_present() {
        let config = SupervisorConfig::default_development().unwrap();
        
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
        let config = SupervisorConfig::default_development().unwrap();
        
        // In development, effective_uid should return None (don't change)
        assert_eq!(config.effective_uid("audit"), None);
        assert_eq!(config.effective_uid("web"), None);
    }

    #[test]
    fn test_effective_gid_development() {
        let config = SupervisorConfig::default_development().unwrap();
        
        // In development, effective_gid should return None (don't change)
        assert_eq!(config.effective_gid("audit"), None);
        assert_eq!(config.effective_gid("web"), None);
    }

    #[test]
    fn test_effective_uid_unknown_service() {
        let config = SupervisorConfig::default_development().unwrap();
        
        // Unknown service should return None
        assert_eq!(config.effective_uid("unknown"), None);
    }

    #[test]
    fn test_effective_gid_unknown_service() {
        let config = SupervisorConfig::default_development().unwrap();
        
        // Unknown service should return None
        assert_eq!(config.effective_gid("unknown"), None);
    }

    // ==================== Binary Path Tests ====================

    #[test]
    fn test_binary_path() {
        let config = SupervisorConfig::default_development().unwrap();
        
        // binary_path returns an absolute path
        let path = config.binary_path("audit");
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.ends_with("target/debug/vauban-audit"), "path was: {}", path);
    }

    #[test]
    fn test_binary_path_all_services() {
        let config = SupervisorConfig::default_development().unwrap();
        
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
        let config = SupervisorConfig::default_development().unwrap();
        
        let path = config.binary_path("nonexistent");
        assert!(path.is_none());
    }

    // ==================== Effective Workdir Tests ====================

    #[test]
    fn test_effective_workdir_development() {
        let config = SupervisorConfig::default_development().unwrap();
        
        // In development, workdir should be the service directory name
        let workdir = config.effective_workdir("audit");
        assert!(workdir.is_some());
        assert_eq!(workdir.unwrap(), "vauban-audit");
    }

    #[test]
    fn test_effective_workdir_all_services() {
        let config = SupervisorConfig::default_development().unwrap();
        
        let expected = [
            ("audit", "vauban-audit"),
            ("vault", "vauban-vault"),
            ("rbac", "vauban-rbac"),
            ("auth", "vauban-auth"),
            ("proxy_ssh", "vauban-proxy-ssh"),
            ("proxy_rdp", "vauban-proxy-rdp"),
            ("web", "vauban-web"),
        ];
        
        for (key, expected_workdir) in expected {
            let workdir = config.effective_workdir(key);
            assert!(workdir.is_some(), "workdir for {} should be Some", key);
            assert_eq!(workdir.unwrap(), expected_workdir, "workdir mismatch for {}", key);
        }
    }

    #[test]
    fn test_effective_workdir_unknown_service() {
        let config = SupervisorConfig::default_development().unwrap();
        
        let workdir = config.effective_workdir("nonexistent");
        assert!(workdir.is_none());
    }

    // ==================== Startup Order Tests ====================

    #[test]
    fn test_startup_order() {
        let config = SupervisorConfig::default_development().unwrap();
        let order = config.startup_order();
        
        assert_eq!(order.len(), 7);
        assert_eq!(order[0], "audit");
        assert_eq!(order[6], "web");
    }

    #[test]
    fn test_startup_order_dependencies() {
        let config = SupervisorConfig::default_development().unwrap();
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
        let config = SupervisorConfig::default_development().unwrap();
        
        let audit = config.services.get("audit").unwrap();
        assert_eq!(audit.name, "vauban-audit");
        assert_eq!(audit.binary, "vauban-audit");
    }

    #[test]
    fn test_service_config_no_uid_gid_in_development() {
        let config = SupervisorConfig::default_development().unwrap();
        
        for (_, service) in &config.services {
            assert!(service.uid.is_none());
            assert!(service.gid.is_none());
        }
    }

    // ==================== Load Config Tests ====================

    #[test]
    fn test_load_from_development_toml() {
        // Load from actual config file if it exists
        let path = "config/development.toml";
        if std::path::Path::new(path).exists() {
            let config = SupervisorConfig::load(path);
            assert!(config.is_ok());
            let config = config.unwrap();
            assert!(config.supervisor.environment.is_development());
        }
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = SupervisorConfig::load("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }
}
