//! Configuration module for vauban-supervisor.
//!
//! Uses the centralized configuration from the workspace root `config/` directory.
//! Configuration is shared with vauban-web and other components.
//!
//! Supports two modes:
//! - Development: All services run as current user
//! - Production: Each service runs with dedicated UID/GID
//!
//! Configuration directory lookup order (via [`shared::config_dir`]):
//! 1. `VAUBAN_CONFIG_DIR` environment variable (if set; must exist)
//! 2. `/usr/local/etc/vauban/` (FreeBSD package path) when present
//! 3. Workspace root `config/` -- **debug builds only**
//!
//! Release / packaged binaries never fall back to a compile-time workspace
//! path (issue #38).

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
    /// Tamper-evident audit log (WORM) configuration.
    ///
    /// Deliberately a SEPARATE tree from `[recording]`: the WORM log is an
    /// append-only, never-deleted security artefact, whereas session recordings
    /// are large media subject to a retention reaper. Keeping them apart lets
    /// operators apply distinct ownership, backup, and immutability policies
    /// (e.g. mount `log_path` on an append-only / WORM filesystem).
    #[serde(default)]
    pub audit: AuditConfig,
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
    /// Security configuration shared with vauban-web ([security] block).
    ///
    /// The supervisor only consumes `allowed_client_networks`: it validates
    /// the CIDR list fail-closed at boot and transports it to the sandboxed
    /// IACS proxy via `VAUBAN_CLIENT_ACL_NETWORKS` so the sshd accept loop
    /// can gate peers before any SSH byte is exchanged.
    #[serde(default)]
    pub security: SecurityConfig,
}

/// `[security]` block (subset relevant to the supervisor).
///
/// The full block is owned by vauban-web; unknown keys are ignored here.
#[derive(Debug, Default, Deserialize)]
pub struct SecurityConfig {
    /// Global client IP allowlist (CIDR list). Empty = disabled.
    /// Loopback is always permitted by the matcher (anti-lockout).
    #[serde(default)]
    pub allowed_client_networks: Vec<String>,
}

impl SecurityConfig {
    /// Fail-closed CIDR validation (same matcher as vauban-web and
    /// proxy-iacs, so the accepted grammar can never drift).
    pub fn validate(&self) -> Result<()> {
        shared::client_acl::ClientAcl::parse(&self.allowed_client_networks)
            .map_err(|e| anyhow::anyhow!("[security] {e}"))?;
        Ok(())
    }

    /// Canonical comma-separated env-var form for `VAUBAN_CLIENT_ACL_NETWORKS`.
    pub fn client_acl_env_value(&self) -> String {
        self.allowed_client_networks
            .iter()
            .map(|s| s.trim())
            .collect::<Vec<_>>()
            .join(",")
    }
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
    /// LDAPS/AD directory authentication. When enabled, the
    /// supervisor brokers a TCP socket to the directory on behalf of the
    /// sandboxed `vauban-auth` (which terminates TLS + binds). Disabled by
    /// default (`[auth.ldaps].enabled = false`).
    #[serde(default)]
    pub ldaps: LdapConfig,
    /// Kerberos KDC brokering for RDP assets in `kerberos_restricted_admin`
    /// auth mode. When enabled, the supervisor relays the sandboxed RDP
    /// proxy's KDC exchanges (AS-REQ / TGS-REQ) to the configured KDC over
    /// TCP 88 (the proxy cannot `connect()` itself). Disabled by default
    /// (`[auth.kerberos].enabled = false`).
    #[serde(default)]
    pub kerberos: KerberosConfig,
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
            ldaps: LdapConfig::default(),
            kerberos: KerberosConfig::default(),
        }
    }
}

/// LDAPS/AD directory authentication configuration (supervisor view).
///
/// The supervisor needs the directory endpoint (to enforce the `(host, port)`
/// broker whitelist, exactly like [`MailerConfig::allows`] for the mailer) and
/// the trust material (`ca_cert_file`, read as root and shipped pre-seal to
/// `vauban-auth` via [`shared::messages::Message::AuthLdapProvision`]). The
/// plaintext password never transits the supervisor: the bind happens inside
/// the sandboxed auth service.
///
/// SECURITY: only `ldaps://` is accepted; a `url` starting with `ldap://`
/// (plaintext) is rejected at config load (see [`LdapConfig::validate`]).
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// Master switch. When false, the supervisor refuses to broker any TCP
    /// connection on behalf of `vauban-auth` and ships no provisioning.
    #[serde(default)]
    pub enabled: bool,
    /// `ldaps://host[:port]` of the directory (default LDAPS port is 636).
    #[serde(default)]
    pub url: String,
    /// DN/UPN template; `{username}` is substituted by auth at bind time
    /// (e.g. `{username}@example.com` or `uid={username},ou=users,dc=ex,dc=com`).
    #[serde(default)]
    pub dn_template: String,
    /// Path to the PEM CA bundle validating the directory's TLS certificate.
    /// Read by the supervisor (root) and forwarded pre-seal to auth.
    #[serde(default = "default_ldap_ca_cert_file")]
    pub ca_cert_file: String,
    /// Per-attempt timeout budget in seconds (broker + TLS + bind).
    #[serde(default = "default_ldap_timeout_secs")]
    pub timeout_secs: u64,
    /// Authentication source order for unknown usernames, e.g.
    /// `["ldap", "local"]`. Consumed by vauban-web (the supervisor does not
    /// route logins); accepted here so the `[auth.ldaps]` block has a single
    /// schema across services.
    #[allow(dead_code)]
    #[serde(default = "default_ldap_order")]
    pub order: Vec<String>,
    /// Minimum username character count accepted on the login form before an
    /// LDAPS bind is attempted. Consumed by vauban-web; accepted here for a
    /// single `[auth.ldaps]` schema. Absolute floor is
    /// [`shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR`] (boot fails if lower).
    #[allow(dead_code)]
    #[serde(default = "default_ldap_login_username_min_length")]
    pub login_username_min_length: usize,
    /// Minimum password character count accepted on the login form before an
    /// LDAPS bind is attempted. Consumed by vauban-web; accepted here for a
    /// single `[auth.ldaps]` schema. Absolute floor is
    /// [`shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR`] (boot fails if lower).
    #[allow(dead_code)]
    #[serde(default = "default_ldap_login_password_min_length")]
    pub login_password_min_length: usize,
}

fn default_ldap_ca_cert_file() -> String {
    "/usr/local/etc/vauban/certs/ldap_ca.pem".to_string()
}

fn default_ldap_timeout_secs() -> u64 {
    5
}

fn default_ldap_order() -> Vec<String> {
    vec!["ldap".to_string(), "local".to_string()]
}

fn default_ldap_login_username_min_length() -> usize {
    shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR
}

fn default_ldap_login_password_min_length() -> usize {
    shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            dn_template: String::new(),
            ca_cert_file: default_ldap_ca_cert_file(),
            timeout_secs: default_ldap_timeout_secs(),
            order: default_ldap_order(),
            login_username_min_length: default_ldap_login_username_min_length(),
            login_password_min_length: default_ldap_login_password_min_length(),
        }
    }
}

impl LdapConfig {
    /// Parse the configured `ldaps://host[:port]` URL into a `(host, port)`
    /// couple. Returns `None` if the scheme is not `ldaps://` or the host is
    /// empty (fail-closed). The default LDAPS port is 636.
    ///
    /// Bracketed IPv6 literals (`ldaps://[::1]:636`) are supported; the rare
    /// bracketed form without an explicit port is treated as default-port.
    pub fn endpoint(&self) -> Option<(String, u16)> {
        let rest = self.url.strip_prefix("ldaps://")?;
        // Drop any path/query component after the authority.
        let authority = rest.split(['/', '?']).next().unwrap_or(rest);
        if authority.is_empty() {
            return None;
        }
        // Bracketed IPv6 literal: [host] or [host]:port.
        if let Some(after) = authority.strip_prefix('[') {
            let (host, tail) = after.split_once(']')?;
            if host.is_empty() {
                return None;
            }
            return match tail.strip_prefix(':') {
                Some(p) => Some((host.to_string(), p.parse().ok()?)),
                None if tail.is_empty() => Some((host.to_string(), 636)),
                None => None,
            };
        }
        match authority.rsplit_once(':') {
            Some((h, p)) => {
                if h.is_empty() {
                    return None;
                }
                Some((h.to_string(), p.parse().ok()?))
            }
            None => Some((authority.to_string(), 636)),
        }
    }

    /// SSRF guard for the LDAPS broker: returns `true` iff LDAP is enabled and
    /// `(host, port)` exactly matches the configured directory endpoint
    /// (case-insensitive host, per RFC 1035 §2.3.3). This is the supervisor's
    // allow-untested-claim: whitelist unit tests live in this module (allows()).
    /// authoritative gate: `vauban-auth` cannot forge a `TcpConnectRequest` to
    /// any other destination.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        match self.endpoint() {
            Some((h, p)) => port == p && !h.is_empty() && host.eq_ignore_ascii_case(&h),
            None => false,
        }
    }

    /// Reject transport-downgrading or malformed configurations at load time.
    ///
    /// Login length floors are validated even when LDAP is disabled (so flipping
    /// `enabled` later cannot start with an illegal config). When enabled, the
    /// `url` MUST use the `ldaps://` scheme (plaintext `ldap://` is forbidden),
    /// resolve to a valid `(host, port)`, and a non-empty `dn_template` MUST be
    /// set.
    pub fn validate(&self) -> Result<()> {
        shared::validation::validate_ldap_login_length_config(
            self.login_username_min_length,
            self.login_password_min_length,
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        if !self.enabled {
            return Ok(());
        }
        if self.url.starts_with("ldap://") {
            anyhow::bail!(
                "[auth.ldaps] url must use ldaps:// (plaintext ldap:// is forbidden): {}",
                self.url
            );
        }
        if self.endpoint().is_none() {
            anyhow::bail!(
                "[auth.ldaps] url must be a valid ldaps://host[:port] URL when enabled: {:?}",
                self.url
            );
        }
        if self.dn_template.is_empty() {
            anyhow::bail!("[auth.ldaps] dn_template must be set when ldaps is enabled");
        }
        Ok(())
    }
}

/// Kerberos KDC brokering configuration (supervisor view).
///
/// The sandboxed RDP proxy cannot open a socket to the KDC (TCP 88); during
/// the CredSSP Kerberos leg it relays each sspi `NetworkRequest` to the
/// supervisor via [`shared::messages::Message::KerberosKdcRequest`]. The
/// supervisor owns the authoritative `(host, port)` endpoint here and connects
/// ONLY to it, ignoring any host embedded in the relayed request (mirrors the
/// LDAPS `allows` SSRF gate). No secret transits this struct: the AS-REQ /
/// TGS-REQ bytes are produced in-memory by sspi inside the proxy.
#[derive(Debug, Clone, Deserialize)]
pub struct KerberosConfig {
    /// Master switch. When false, the supervisor refuses to broker any KDC
    /// exchange (fail-closed).
    #[serde(default)]
    pub enabled: bool,
    /// Kerberos realm (uppercase), e.g. `EXAMPLE.COM`. Consumed by the RDP
    /// proxy for SPN construction; accepted here so the `[auth.kerberos]`
    /// block has a single schema.
    #[serde(default)]
    pub realm: String,
    /// KDC hostname or IP address (the domain controller).
    #[serde(default)]
    pub kdc_host: String,
    /// KDC TCP port (Kerberos default 88).
    #[serde(default = "default_kdc_port")]
    pub kdc_port: u16,
    /// Per-exchange timeout budget in seconds (broker TCP connect + I/O).
    #[serde(default = "default_kerberos_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_kdc_port() -> u16 {
    88
}

fn default_kerberos_timeout_secs() -> u64 {
    5
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            realm: String::new(),
            kdc_host: String::new(),
            kdc_port: default_kdc_port(),
            timeout_secs: default_kerberos_timeout_secs(),
        }
    }
}

impl KerberosConfig {
    /// Configured KDC endpoint as a `(host, port)` couple. Returns `None`
    /// (fail-closed) when the host is empty.
    pub fn endpoint(&self) -> Option<(String, u16)> {
        if self.kdc_host.is_empty() {
            return None;
        }
        Some((self.kdc_host.clone(), self.kdc_port))
    }

    /// SSRF guard for the KDC broker: returns `true` iff Kerberos is enabled
    /// and a KDC endpoint is configured. Unlike the LDAPS broker, the relayed
    /// Kerberos request carries no caller-chosen destination (the supervisor
    /// always connects to its own configured KDC), so this is a pure
    /// enabled + configured check rather than a per-request host match.
    pub fn allows(&self) -> bool {
        self.enabled && self.endpoint().is_some()
    }

    /// Reject malformed configurations at load time. A disabled block is
    /// always valid. When enabled, `realm` and `kdc_host` MUST be set.
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.realm.is_empty() {
            anyhow::bail!("[auth.kerberos] realm must be set when kerberos is enabled");
        }
        if self.kdc_host.is_empty() {
            anyhow::bail!("[auth.kerberos] kdc_host must be set when kerberos is enabled");
        }
        if self.kdc_port == 0 {
            anyhow::bail!("[auth.kerberos] kdc_port must be non-zero when kerberos is enabled");
        }
        Ok(())
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
    /// Master switch for session recording (all protocols).
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
    /// Enable recording of IACS tunnel sessions (PCAP bundle).
    #[serde(default = "default_recording_enabled")]
    pub iacs: bool,
    /// Interval (ms) between periodic `fdatasync` sweeps of the active SSH/RDP
    /// recordings in vauban-audit. 0 disables the sweep (legacy behaviour /
    /// instant rollback knob). Default 1000 ms => RPO ~1 s of media on crash.
    #[serde(default = "default_recording_fsync_interval_ms")]
    pub fsync_interval_ms: u64,
}

fn default_recording_enabled() -> bool {
    true
}

fn default_recording_storage_path() -> String {
    "recordings".to_string()
}

fn default_recording_fsync_interval_ms() -> u64 {
    1000
}

impl RecordingConfig {
    pub fn rdp_recording_enabled(&self) -> bool {
        self.enabled && self.rdp
    }

    pub fn ssh_recording_enabled(&self) -> bool {
        self.enabled && self.ssh
    }

    pub fn iacs_recording_enabled(&self) -> bool {
        self.enabled && self.iacs
    }

    /// True when vauban-audit should accept recording IPC.
    pub fn audit_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: default_recording_enabled(),
            storage_path: default_recording_storage_path(),
            rdp: default_recording_enabled(),
            ssh: default_recording_enabled(),
            iacs: default_recording_enabled(),
            fsync_interval_ms: default_recording_fsync_interval_ms(),
        }
    }
}

/// Tamper-evident audit log (WORM) configuration.
///
/// Kept separate from `[recording]` on purpose -- see the field doc on
/// [`SupervisorConfig::audit`].
#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    /// Root directory of the append-only WORM segments
    /// (`<log_path>/YYYY/MM/audit-<n>.jsonl`). Defaults to the workspace-local
    /// `audit` in dev; set to an absolute path such as `/var/vauban/audit` in
    /// production. The supervisor is the only writer (FD broker, append-only).
    #[serde(default = "default_audit_log_path")]
    pub log_path: String,
    /// Optional explicit path to the sealed audit WORM signing key. When unset,
    /// the supervisor derives `<log_path>/signing_key.sealed`. Set it to store
    /// the sealed key in a dedicated secrets directory.
    #[serde(default)]
    pub signing_key_path: Option<String>,
}

fn default_audit_log_path() -> String {
    "audit".to_string()
}

impl AuditConfig {
    /// Filesystem root of the WORM segments. The supervisor joins the
    /// audit-child-supplied `YYYY/MM/audit-<n>.jsonl` segment name under this
    /// directory (after structural validation -- VAU-006 confinement).
    pub fn log_path(&self) -> &str {
        &self.log_path
    }

    /// Filesystem path of the sealed audit WORM signing key.
    ///
    /// Honours the optional `signing_key_path` override, otherwise derives
    /// `<log_path>/signing_key.sealed`. This is the exact path the supervisor
    /// reads to forward the sealed ciphertext to the audit child, and the same
    /// location the vault `seal-audit-key` provisioning command targets by
    /// default (via `VAUBAN_AUDIT_SIGNING_KEY_PATH` / `VAUBAN_AUDIT_LOG_PATH`).
    pub fn signing_key_path(&self) -> std::path::PathBuf {
        match &self.signing_key_path {
            Some(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
            _ => std::path::Path::new(&self.log_path).join("signing_key.sealed"),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: default_audit_log_path(),
            signing_key_path: None,
        }
    }
}

/// Email notification configuration (Issue #10), supervisor view.
///
/// The supervisor uses `[mailer]` for:
///   1. SSRF whitelist gate on `TcpConnectRequest { target_service: Mailer }`.
///   2. Pre-seal `MailerSmtpProvision` IPC to the sealed vauban-mailer leaf.
#[derive(Debug, Clone, Deserialize)]
pub struct MailerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub from_address: String,
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub reply_to: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default = "default_smtp_encryption")]
    pub smtp_encryption: shared::messages::SmtpEncryption,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default = "default_sensitive_string")]
    pub smtp_password: shared::messages::SensitiveString,
    #[serde(default)]
    pub helo_name: String,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: i64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: i32,
    #[serde(default = "default_smtp_timeout_secs")]
    pub smtp_timeout_secs: u64,
    #[serde(default = "default_broker_timeout_secs")]
    pub broker_timeout_secs: u64,
    /// When true, SMTP STARTTLS accepts self-signed / private-CA certs.
    /// Allowed in every environment (including production). Default false.
    #[serde(default)]
    pub smtp_accept_invalid_certs: bool,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_smtp_encryption() -> shared::messages::SmtpEncryption {
    shared::messages::SmtpEncryption::Starttls
}

fn default_sensitive_string() -> shared::messages::SensitiveString {
    shared::messages::SensitiveString::new(String::new())
}

fn default_poll_interval_secs() -> u64 {
    10
}

fn default_batch_size() -> i64 {
    16
}

fn default_max_attempts() -> i32 {
    5
}

fn default_smtp_timeout_secs() -> u64 {
    30
}

fn default_broker_timeout_secs() -> u64 {
    30
}

impl Default for MailerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            from_address: String::new(),
            from_name: String::new(),
            reply_to: String::new(),
            smtp_host: String::new(),
            smtp_port: default_smtp_port(),
            smtp_encryption: default_smtp_encryption(),
            smtp_username: String::new(),
            smtp_password: default_sensitive_string(),
            helo_name: String::new(),
            poll_interval_secs: default_poll_interval_secs(),
            batch_size: default_batch_size(),
            max_attempts: default_max_attempts(),
            smtp_timeout_secs: default_smtp_timeout_secs(),
            broker_timeout_secs: default_broker_timeout_secs(),
            smtp_accept_invalid_certs: false,
        }
    }
}

impl MailerConfig {
    /// Returns `true` iff the mailer is enabled and `(host, port)`
    /// matches the configured whitelist (case-insensitive on host).
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
    /// Master switch. Default `false` -- IACS is opt-in; set
    /// `enabled = true` in TOML to expose the industrial surface.
    /// Read by every Vauban service that runs industrial-only logic.
    #[serde(default = "default_industrial_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub iacs_tunnel: IacsTunnelSupervisorConfig,
}

fn default_industrial_enabled() -> bool {
    false
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

        config.auth.ldaps.validate()?;
        config.auth.kerberos.validate()?;
        config.security.validate()?;

        Ok(config)
    }

    /// Load configuration from the centralized config directory.
    ///
    /// Uses [`shared::config_dir`] (same resolution as vauban-web).
    ///
    /// Loads configuration:
    /// - Production (default): vauban.conf only
    /// - Development: default.toml + development.toml
    pub fn load_auto() -> Result<Self> {
        let config_dir = Self::find_config_dir()?;
        Self::load_from_dir(&config_dir)
    }

    /// Find the configuration directory via [`shared::config_dir::find_config_dir`].
    fn find_config_dir() -> Result<PathBuf> {
        // Compile-time workspace `config/` is only consulted under
        // `ConfigDirProfile::Debug` (release packages never use it).
        let workspace_config = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("config"));
        shared::config_dir::find_config_dir(workspace_config)
            .with_context(|| "Failed to resolve VAUBAN configuration directory")
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

        let config: SupervisorConfig = settings
            .try_deserialize()
            .with_context(|| "Failed to deserialize supervisor configuration")?;

        config.auth.ldaps.validate()?;
        config.auth.kerberos.validate()?;
        config.security.validate()?;

        Ok(config)
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
                let rdp_recording = self.recording.rdp_recording_enabled();
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    rdp_recording.to_string(),
                ));
            }
            "proxy_ssh" => {
                let ssh_recording = self.recording.ssh_recording_enabled();
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
                // Tells vauban-auth whether to wait for an AuthLdapProvision
                // message (and trust anchor) before sealing its sandbox. When
                // false, auth skips the pre-seal wait entirely (no startup
                // delay). The actual url/CA/dn_template are delivered via IPC,
                // never as env vars (the CA could be large; the password is
                // never shipped).
                vars.push((
                    "VAUBAN_LDAP_ENABLED".to_string(),
                    self.auth.ldaps.enabled.to_string(),
                ));
            }
            "audit" => {
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    self.recording.audit_enabled().to_string(),
                ));
                vars.push((
                    "VAUBAN_RECORDING_STORAGE_PATH".to_string(),
                    self.recording.storage_path.clone(),
                ));
                vars.push((
                    "VAUBAN_RECORDING_FSYNC_INTERVAL_MS".to_string(),
                    self.recording.fsync_interval_ms.to_string(),
                ));
                // WORM signing: if the operator has provisioned a sealed audit
                // signing key (`vauban-vault seal-audit-key`), hand its
                // ciphertext to audit so it can unseal via VaultDecrypt{audit}
                // and Ed25519-seal the WORM log. Absent ciphertext means
                // audit will refuse to start (fail-closed PAM posture).
                // The path honours the optional `[audit] signing_key_path`
                // override and otherwise derives from `[audit] log_path` --
                // never a hard-coded absolute.
                let sealed_path = self.audit.signing_key_path();
                if let Ok(ciphertext) = std::fs::read_to_string(&sealed_path) {
                    let ciphertext = ciphertext.trim().to_string();
                    if !ciphertext.is_empty() {
                        vars.push(("VAUBAN_AUDIT_SIGNING_KEY_SEALED".to_string(), ciphertext));
                    }
                }
            }
            "proxy_iacs" => {
                let iacs_recording = self.recording.iacs_recording_enabled();
                vars.push((
                    "VAUBAN_RECORDING_ENABLED".to_string(),
                    iacs_recording.to_string(),
                ));
                vars.push((
                    "VAUBAN_IACS_MAX_CHANNELS_PER_SESSION".to_string(),
                    self.industrial
                        .iacs_tunnel
                        .max_concurrent_channels_per_session
                        .to_string(),
                ));
                // Global client IP ACL: the IACS sshd accept loop gates
                // peers with the same shared matcher as vauban-web. The
                // ranges were validated fail-closed at supervisor boot.
                vars.push((
                    "VAUBAN_CLIENT_ACL_NETWORKS".to_string(),
                    self.security.client_acl_env_value(),
                ));
            }
            "mailer" => {
                vars.push((
                    "VAUBAN_DATABASE_URL".to_string(),
                    self.database.url.to_string(),
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
            "mailer",     // Sealed leaf: outbox drain + SMTP (no TOPOLOGY peers)
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

    /// `default.toml` only -- no `development.toml` overlay.
    fn load_default_toml_only() -> SupervisorConfig {
        let path = test_config_dir().join("default.toml");
        let contents = std::fs::read_to_string(&path).expect("config/default.toml must exist");
        config::Config::builder()
            .add_source(config::File::from_str(&contents, config::FileFormat::Toml))
            .build()
            .expect("build default.toml")
            .try_deserialize()
            .expect("deserialize default.toml")
    }

    // ==================== Development Config Tests ====================

    #[test]
    fn test_development_config() {
        let config = test_config();

        assert!(config.environment.is_development());
        assert!(!config.supervisor.privsep);
        assert_eq!(config.services.len(), 9);
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
        assert!(config.services.contains_key("mailer"));
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

        assert_eq!(order.len(), 9);
        assert_eq!(order[0], "audit");
        assert_eq!(order[7], "web");
        assert_eq!(order[8], "mailer");
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

        // Mailer is a sealed leaf: start after web (outbox writers ready)
        let mailer_pos = order.iter().position(|&s| s == "mailer").unwrap();
        assert!(mailer_pos > web_pos);
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
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, "VAUBAN_RECORDING_ENABLED");
        assert_eq!(vars[0].1, "true");
        assert_eq!(vars[1].0, "VAUBAN_RECORDING_STORAGE_PATH");
        assert_eq!(vars[1].1, "recordings");
        assert_eq!(vars[2].0, "VAUBAN_RECORDING_FSYNC_INTERVAL_MS");
        assert_eq!(vars[2].1, "1000");
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
        assert_eq!(vars.len(), 4);
        assert_eq!(vars[0].0, "VAUBAN_ARGON2_MEMORY_KB");
        assert_eq!(vars[1].0, "VAUBAN_ARGON2_ITERATIONS");
        assert_eq!(vars[2].0, "VAUBAN_ARGON2_PARALLELISM");
        assert_eq!(vars[3].0, "VAUBAN_LDAP_ENABLED");
        // Disabled by default in dev config.
        assert_eq!(vars[3].1, "false");
    }

    #[test]
    fn test_service_env_vars_proxy_iacs_carries_client_acl() {
        let mut config = test_config();
        config.security.allowed_client_networks =
            vec!["10.0.0.0/8".to_string(), "104.28.30.3/32".to_string()];
        let vars = config.service_env_vars("proxy_iacs");
        let acl = vars
            .iter()
            .find(|(k, _)| k == "VAUBAN_CLIENT_ACL_NETWORKS")
            .expect("proxy_iacs env vars must carry VAUBAN_CLIENT_ACL_NETWORKS");
        assert_eq!(acl.1, "10.0.0.0/8,104.28.30.3/32");
    }

    #[test]
    fn test_service_env_vars_proxy_iacs_client_acl_empty_when_disabled() {
        let config = test_config();
        let vars = config.service_env_vars("proxy_iacs");
        let acl = vars
            .iter()
            .find(|(k, _)| k == "VAUBAN_CLIENT_ACL_NETWORKS")
            .expect("the env var must be present even when the ACL is disabled");
        assert_eq!(acl.1, "", "empty ACL must serialise to an empty string");
    }

    #[test]
    fn test_security_config_validate_accepts_valid_cidrs() {
        let sec = SecurityConfig {
            allowed_client_networks: vec![
                "10.0.0.0/8".to_string(),
                "10.20.0.0/28".to_string(),
                "104.28.30.3/32".to_string(),
                "2001:db8::/32".to_string(),
            ],
        };
        assert!(sec.validate().is_ok());
    }

    #[test]
    fn test_security_config_validate_rejects_invalid_cidr_fail_closed() {
        let sec = SecurityConfig {
            allowed_client_networks: vec!["10.0.0.0/8".to_string(), "garbage".to_string()],
        };
        let err = sec.validate().expect_err("invalid CIDR must fail the boot");
        assert!(
            err.to_string().contains("garbage"),
            "error must name the offending entry: {err}"
        );
    }

    #[test]
    fn test_security_config_default_is_disabled() {
        let sec = SecurityConfig::default();
        assert!(sec.allowed_client_networks.is_empty());
        assert!(sec.validate().is_ok());
        assert_eq!(sec.client_acl_env_value(), "");
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
        assert!(config.recording.iacs);
        assert_eq!(config.recording.storage_path, "recordings");
    }

    #[test]
    fn test_audit_config_defaults_are_separate_from_recordings() {
        let audit = AuditConfig::default();
        // The WORM log lives in its OWN tree, never under recordings.
        assert_eq!(audit.log_path(), "audit");
        assert!(audit.signing_key_path.is_none());
        assert_eq!(
            audit.signing_key_path(),
            std::path::PathBuf::from("audit/signing_key.sealed")
        );
    }

    #[test]
    fn test_audit_signing_key_path_derives_from_log_path() {
        let audit = AuditConfig {
            log_path: "/var/vauban/audit".to_string(),
            ..Default::default()
        };
        assert_eq!(
            audit.signing_key_path(),
            std::path::PathBuf::from("/var/vauban/audit/signing_key.sealed")
        );
    }

    #[test]
    fn test_audit_signing_key_path_explicit_override_wins() {
        let audit = AuditConfig {
            log_path: "/var/vauban/audit".to_string(),
            signing_key_path: Some("/secrets/audit.sealed".to_string()),
        };
        assert_eq!(
            audit.signing_key_path(),
            std::path::PathBuf::from("/secrets/audit.sealed")
        );

        // A blank override falls back to the log-path derivation.
        let audit = AuditConfig {
            log_path: "/var/vauban/audit".to_string(),
            signing_key_path: Some("   ".to_string()),
        };
        assert_eq!(
            audit.signing_key_path(),
            std::path::PathBuf::from("/var/vauban/audit/signing_key.sealed")
        );
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
            ..MailerConfig::default()
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
        let config = load_default_toml_only();
        assert!(
            !config.mailer.enabled,
            "default.toml ships with mailer disabled (operator must opt-in)"
        );
    }

    #[test]
    fn mailer_development_toml_opts_in() {
        let config = test_config();
        assert!(
            config.mailer.enabled,
            "development.toml enables the sealed mailer for the local SMTP sink"
        );
    }

    // ==================== LDAPS config tests ====================

    fn ldap(enabled: bool, url: &str) -> LdapConfig {
        LdapConfig {
            enabled,
            url: url.to_string(),
            dn_template: "{username}@example.com".to_string(),
            ..LdapConfig::default()
        }
    }

    #[test]
    fn ldap_default_is_disabled_and_denies_everything() {
        let l = LdapConfig::default();
        assert!(!l.enabled);
        assert!(!l.allows("dc1.example.com", 636));
        assert!(!l.allows("", 0));
        // Disabled is always a valid config.
        assert!(l.validate().is_ok());
    }

    #[test]
    fn ldap_loaded_from_default_toml_is_disabled() {
        let config = test_config();
        assert!(
            !config.auth.ldaps.enabled,
            "default.toml ships with ldaps disabled (operator must opt-in)"
        );
    }

    #[test]
    fn ldap_endpoint_parses_host_and_explicit_port() {
        let l = ldap(true, "ldaps://dc1.example.com:3269");
        assert_eq!(l.endpoint(), Some(("dc1.example.com".to_string(), 3269)));
    }

    #[test]
    fn ldap_endpoint_defaults_port_636() {
        let l = ldap(true, "ldaps://dc1.example.com");
        assert_eq!(l.endpoint(), Some(("dc1.example.com".to_string(), 636)));
    }

    #[test]
    fn ldap_endpoint_supports_bracketed_ipv6() {
        let l = ldap(true, "ldaps://[2001:db8::1]:636");
        assert_eq!(l.endpoint(), Some(("2001:db8::1".to_string(), 636)));
        let l2 = ldap(true, "ldaps://[2001:db8::1]");
        assert_eq!(l2.endpoint(), Some(("2001:db8::1".to_string(), 636)));
    }

    #[test]
    fn ldap_endpoint_rejects_plaintext_scheme() {
        let l = ldap(true, "ldap://dc1.example.com:389");
        assert_eq!(l.endpoint(), None);
    }

    #[test]
    fn ldap_allows_exact_host_port_when_enabled() {
        let l = ldap(true, "ldaps://dc1.example.com:636");
        assert!(l.allows("dc1.example.com", 636));
        assert!(l.allows("DC1.Example.COM", 636)); // case-insensitive
    }

    #[test]
    fn ldap_denies_when_disabled_even_if_match() {
        let l = ldap(false, "ldaps://dc1.example.com:636");
        assert!(!l.allows("dc1.example.com", 636));
    }

    #[test]
    fn ldap_denies_wrong_host_or_port() {
        let l = ldap(true, "ldaps://dc1.example.com:636");
        assert!(!l.allows("evil.example.com", 636));
        assert!(!l.allows("dc1.example.com", 389));
    }

    #[test]
    fn ldap_validate_rejects_plaintext_url_when_enabled() {
        let l = ldap(true, "ldap://dc1.example.com");
        let err = l.validate().unwrap_err().to_string();
        assert!(
            err.contains("ldaps://"),
            "expected scheme-downgrade rejection, got: {err}"
        );
    }

    #[test]
    fn ldap_validate_rejects_empty_url_when_enabled() {
        let l = ldap(true, "");
        assert!(l.validate().is_err());
    }

    #[test]
    fn ldap_validate_rejects_empty_dn_template_when_enabled() {
        let l = LdapConfig {
            enabled: true,
            url: "ldaps://dc1.example.com:636".to_string(),
            dn_template: String::new(),
            ..LdapConfig::default()
        };
        let err = l.validate().unwrap_err().to_string();
        assert!(err.contains("dn_template"), "got: {err}");
    }

    #[test]
    fn ldap_validate_accepts_valid_enabled_config() {
        let l = ldap(true, "ldaps://dc1.example.com:636");
        assert!(l.validate().is_ok());
    }

    #[test]
    fn ldap_default_login_mins_match_shared_floors() {
        let l = LdapConfig::default();
        assert_eq!(
            l.login_username_min_length,
            shared::validation::LDAP_LOGIN_USERNAME_MIN_FLOOR
        );
        assert_eq!(
            l.login_password_min_length,
            shared::validation::LDAP_LOGIN_PASSWORD_MIN_FLOOR
        );
        assert!(l.validate().is_ok());
    }

    #[test]
    fn ldap_validate_rejects_login_mins_below_floors_even_when_disabled() {
        let short_user = LdapConfig {
            enabled: false,
            login_username_min_length: 2,
            ..LdapConfig::default()
        };
        let err = short_user.validate().unwrap_err().to_string();
        assert!(err.contains("login_username_min_length"), "got: {err}");

        let short_pass = LdapConfig {
            enabled: false,
            login_password_min_length: 11,
            ..LdapConfig::default()
        };
        let err = short_pass.validate().unwrap_err().to_string();
        assert!(err.contains("login_password_min_length"), "got: {err}");
    }

    #[test]
    fn ldap_validate_accepts_raised_login_mins() {
        let l = LdapConfig {
            enabled: true,
            url: "ldaps://dc1.example.com:636".to_string(),
            dn_template: "{username}@example.com".to_string(),
            login_username_min_length: 8,
            login_password_min_length: 20,
            ..LdapConfig::default()
        };
        assert!(l.validate().is_ok());
    }

    #[test]
    fn config_load_rejects_plaintext_ldap_url() {
        let toml = r#"
bin_path = "./target/debug"

[supervisor]
privsep = false
heartbeat_interval_secs = 5
heartbeat_timeout_secs = 2
max_missed_heartbeats = 3
max_respawns_per_hour = 10

[logging]
level = "debug"

[auth.ldaps]
enabled = true
url = "ldap://dc1.example.com:389"
dn_template = "{username}@example.com"

[services]
"#;
        let dir = std::env::temp_dir().join(format!("vauban-ldap-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, toml).unwrap();
        let result = SupervisorConfig::load(&path);
        std::fs::remove_file(&path).ok();
        assert!(
            result.is_err(),
            "loading a config with a plaintext ldap:// url must fail"
        );
        assert!(
            result.unwrap_err().to_string().contains("ldaps://"),
            "error should explain the ldaps:// requirement"
        );
    }

    // ===================== [auth.kerberos] tests =====================

    fn krb(enabled: bool, realm: &str, kdc_host: &str) -> KerberosConfig {
        KerberosConfig {
            enabled,
            realm: realm.to_string(),
            kdc_host: kdc_host.to_string(),
            ..KerberosConfig::default()
        }
    }

    #[test]
    fn kerberos_default_is_disabled_and_port_88() {
        let k = KerberosConfig::default();
        assert!(!k.enabled);
        assert_eq!(k.kdc_port, 88);
        assert!(!k.allows());
        assert!(k.endpoint().is_none());
    }

    #[test]
    fn kerberos_allows_only_when_enabled_and_configured() {
        assert!(!krb(false, "EXAMPLE.COM", "dc1.example.com").allows());
        assert!(!krb(true, "EXAMPLE.COM", "").allows());
        assert!(krb(true, "EXAMPLE.COM", "dc1.example.com").allows());
    }

    #[test]
    fn kerberos_endpoint_uses_configured_host_and_port() {
        let mut k = krb(true, "EXAMPLE.COM", "dc1.example.com");
        k.kdc_port = 8888;
        assert_eq!(k.endpoint(), Some(("dc1.example.com".to_string(), 8888)));
    }

    #[test]
    fn kerberos_validate_disabled_is_always_ok() {
        assert!(KerberosConfig::default().validate().is_ok());
    }

    #[test]
    fn kerberos_validate_rejects_missing_realm() {
        let k = krb(true, "", "dc1.example.com");
        let err = k.validate().unwrap_err().to_string();
        assert!(err.contains("realm"), "got: {err}");
    }

    #[test]
    fn kerberos_validate_rejects_missing_kdc_host() {
        let k = krb(true, "EXAMPLE.COM", "");
        let err = k.validate().unwrap_err().to_string();
        assert!(err.contains("kdc_host"), "got: {err}");
    }

    #[test]
    fn kerberos_validate_rejects_zero_port() {
        let mut k = krb(true, "EXAMPLE.COM", "dc1.example.com");
        k.kdc_port = 0;
        let err = k.validate().unwrap_err().to_string();
        assert!(err.contains("kdc_port"), "got: {err}");
    }

    #[test]
    fn kerberos_validate_accepts_valid_enabled_config() {
        assert!(
            krb(true, "EXAMPLE.COM", "dc1.example.com")
                .validate()
                .is_ok()
        );
    }
}
