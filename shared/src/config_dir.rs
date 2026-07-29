//! Configuration directory resolution (packaged FreeBSD vs development).
//!
//! Lookup order:
//! 1. `VAUBAN_CONFIG_DIR` when set (must exist; fail-closed otherwise)
//! 2. [`SYSTEM_CONFIG_DIR`] (`/usr/local/etc/vauban`) when present
//! 3. Workspace `config/` via a caller-supplied path -- **debug builds only**
//!
//! Release / packaged binaries never consult a compile-time workspace path, so
//! a FreeBSD package cannot silently load `config/vauban.conf` from a leftover
//! source tree (issue #38).

use std::fmt;
use std::path::{Path, PathBuf};

/// FreeBSD system configuration directory (package install path).
pub const SYSTEM_CONFIG_DIR: &str = "/usr/local/etc/vauban";

/// Environment variable that overrides the config directory.
pub const ENV_CONFIG_DIR: &str = "VAUBAN_CONFIG_DIR";

/// Whether workspace-path fallback is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDirProfile {
    /// Packaged / `--release` binaries: env, then system path only.
    Release,
    /// Debug builds: may fall back to a workspace `config/` after the system path.
    Debug,
}

/// Errors from [`resolve_config_dir`] / [`find_config_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDirError {
    /// `VAUBAN_CONFIG_DIR` was set but does not exist on disk.
    EnvPointsMissing { path: String },
    /// No usable config directory for the active profile.
    NotFound { profile: ConfigDirProfile },
}

impl fmt::Display for ConfigDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvPointsMissing { path } => {
                write!(
                    f,
                    "{ENV_CONFIG_DIR} points to non-existent directory: {path}"
                )
            }
            Self::NotFound { profile } => match profile {
                ConfigDirProfile::Release => write!(
                    f,
                    "Configuration directory not found. Searched:\n\
                     - {ENV_CONFIG_DIR} environment variable\n\
                     - {SYSTEM_CONFIG_DIR}/"
                ),
                ConfigDirProfile::Debug => write!(
                    f,
                    "Configuration directory not found. Searched:\n\
                     - {ENV_CONFIG_DIR} environment variable\n\
                     - {SYSTEM_CONFIG_DIR}/\n\
                     - Workspace root config/ directory"
                ),
            },
        }
    }
}

impl std::error::Error for ConfigDirError {}

/// Pure config-directory resolution (filesystem existence pre-checked).
///
/// * `env_dir` -- value of `VAUBAN_CONFIG_DIR` when the variable is set, with
///   whether that path exists.
/// * `system_dir` -- system install path and whether it exists.
/// * `workspace_dir` -- optional workspace `config/` path (ignored in
///   [`ConfigDirProfile::Release`] even when it exists).
pub fn resolve_config_dir(
    env_dir: Option<(&Path, bool)>,
    system_dir: (&Path, bool),
    workspace_dir: Option<(&Path, bool)>,
    profile: ConfigDirProfile,
) -> Result<PathBuf, ConfigDirError> {
    if let Some((path, exists)) = env_dir {
        if exists {
            return Ok(path.to_path_buf());
        }
        return Err(ConfigDirError::EnvPointsMissing {
            path: path.display().to_string(),
        });
    }

    let (system_path, system_exists) = system_dir;
    if system_exists {
        return Ok(system_path.to_path_buf());
    }

    if profile == ConfigDirProfile::Debug
        && let Some((ws_path, ws_exists)) = workspace_dir
        && ws_exists
    {
        return Ok(ws_path.to_path_buf());
    }

    Err(ConfigDirError::NotFound { profile })
}

/// Profile selected for the current compilation unit.
#[must_use]
pub fn compile_time_profile() -> ConfigDirProfile {
    if cfg!(debug_assertions) {
        ConfigDirProfile::Debug
    } else {
        ConfigDirProfile::Release
    }
}

/// Resolve the config directory using the process environment and filesystem.
///
/// `workspace_config` is only consulted under [`ConfigDirProfile::Debug`].
/// Pass `None` from release-minded call sites if desired; release profile
/// ignores it regardless.
pub fn find_config_dir(workspace_config: Option<PathBuf>) -> Result<PathBuf, ConfigDirError> {
    let profile = compile_time_profile();
    let env_dir = std::env::var_os(ENV_CONFIG_DIR).map(PathBuf::from);
    let env = env_dir.as_ref().map(|p| (p.as_path(), p.exists()));
    let system = Path::new(SYSTEM_CONFIG_DIR);
    let workspace = workspace_config.as_ref().map(|p| (p.as_path(), p.exists()));
    resolve_config_dir(env, (system, system.exists()), workspace, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_wins_over_system_and_workspace() {
        let env = Path::new("/tmp/vauban-env-config");
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/tmp/workspace/config");
        let got = resolve_config_dir(
            Some((env, true)),
            (system, true),
            Some((workspace, true)),
            ConfigDirProfile::Release,
        )
        .expect("env exists");
        assert_eq!(got, env);
    }

    #[test]
    fn missing_env_is_fail_closed() {
        let env = Path::new("/no/such/vauban-config-dir");
        let err = resolve_config_dir(
            Some((env, false)),
            (Path::new(SYSTEM_CONFIG_DIR), true),
            None,
            ConfigDirProfile::Release,
        )
        .expect_err("missing env must fail");
        assert!(matches!(err, ConfigDirError::EnvPointsMissing { .. }));
    }

    #[test]
    fn release_uses_system_when_env_unset() {
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/home/builder/Vauban/config");
        let got = resolve_config_dir(
            None,
            (system, true),
            Some((workspace, true)),
            ConfigDirProfile::Release,
        )
        .expect("system");
        assert_eq!(got, system);
    }

    #[test]
    fn release_never_falls_back_to_workspace() {
        let workspace = Path::new("/home/builder/Vauban/config");
        let err = resolve_config_dir(
            None,
            (Path::new(SYSTEM_CONFIG_DIR), false),
            Some((workspace, true)),
            ConfigDirProfile::Release,
        )
        .expect_err("release must not use workspace");
        assert_eq!(
            err,
            ConfigDirError::NotFound {
                profile: ConfigDirProfile::Release
            }
        );
    }

    #[test]
    fn debug_falls_back_to_workspace_after_system() {
        let workspace = Path::new("/home/dev/Vauban/config");
        let got = resolve_config_dir(
            None,
            (Path::new(SYSTEM_CONFIG_DIR), false),
            Some((workspace, true)),
            ConfigDirProfile::Debug,
        )
        .expect("debug workspace");
        assert_eq!(got, workspace);
    }

    #[test]
    fn debug_prefers_system_over_workspace() {
        let system = Path::new(SYSTEM_CONFIG_DIR);
        let workspace = Path::new("/home/dev/Vauban/config");
        let got = resolve_config_dir(
            None,
            (system, true),
            Some((workspace, true)),
            ConfigDirProfile::Debug,
        )
        .expect("system");
        assert_eq!(got, system);
    }
}
