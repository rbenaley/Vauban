//! Fail-closed singleton via a PID file.
//!
//! Production default: `/var/run/vcp/vcp.pid` (same runtime dir as the
//! storage helper socket). Development: `/tmp/vcp.pid`.
//!
//! A listen-port conflict is not enough: another app may own the port.
//! The PID file records **our** instance; when the file exists we require
//! a live process whose exact name is `vcp` before refusing to start.
//! Stale files (dead PID or PID reused by a non-`vcp` process) are removed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exact process name required for a held PID file to block startup.
pub const VCP_PROCESS_NAME: &str = "vcp";

/// Owns the PID file for the lifetime of the portal process.
#[derive(Debug)]
pub struct PidFileGuard {
    path: PathBuf,
    pid: u32,
}

impl PidFileGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if let Ok(contents) = fs::read_to_string(&self.path)
            && contents.trim() == self.pid.to_string()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Parse a PID file body (`"12345\n"`).
pub fn parse_pid_file_contents(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u32>().ok().filter(|&pid| pid > 0)
}

/// Basename of a `ps` `comm` value (`/path/vcp` → `vcp`).
pub fn process_name_basename(comm: &str) -> &str {
    Path::new(comm.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(comm.trim())
}

/// Whether `comm` is the portal binary name `vcp` (not helpers).
pub fn comm_is_vcp(comm: &str) -> bool {
    process_name_basename(comm) == VCP_PROCESS_NAME
}

/// Classify a PID found in an existing PID file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidFileStatus {
    /// Live process named `vcp` — fail closed.
    HeldByVcp { pid: u32 },
    /// Missing / dead / non-`vcp` — safe to replace.
    Stale,
}

/// Decide from aliveness + process name whether the file blocks startup.
///
/// If the process is alive but its name cannot be read, treat as held
/// (fail closed).
pub fn classify_pid_holder(pid: u32, alive: bool, comm: Option<&str>) -> PidFileStatus {
    if pid == 0 || !alive {
        return PidFileStatus::Stale;
    }
    match comm {
        Some(name) if comm_is_vcp(name) => PidFileStatus::HeldByVcp { pid },
        Some(_) => PidFileStatus::Stale,
        None => PidFileStatus::HeldByVcp { pid },
    }
}

fn process_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn process_comm(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn status_of_recorded_pid(pid: u32) -> PidFileStatus {
    let alive = process_is_alive(pid);
    let comm = process_comm(pid);
    classify_pid_holder(pid, alive, comm.as_deref())
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create PID file directory {}: {e}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn write_pid_exclusive(path: &Path, pid: u32) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    writeln!(file, "{pid}")?;
    file.sync_all()?;
    Ok(())
}

/// Acquire exclusive ownership of `pid_file` for this process.
///
/// Fail closed when another live `vcp` holds the file. Replace stale files.
pub fn acquire(pid_file: impl AsRef<Path>) -> anyhow::Result<PidFileGuard> {
    let path = pid_file.as_ref().to_path_buf();
    if path.as_os_str().is_empty() {
        anyhow::bail!("server.pid_file must not be empty");
    }

    let self_pid = std::process::id();
    ensure_parent_dir(&path)?;

    for _ in 0..8 {
        match write_pid_exclusive(&path, self_pid) {
            Ok(()) => {
                return Ok(PidFileGuard {
                    path,
                    pid: self_pid,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let raw = fs::read_to_string(&path).unwrap_or_default();
                match parse_pid_file_contents(&raw) {
                    Some(existing) if existing == self_pid => {
                        // Same process already owns the file (re-entrant).
                        return Ok(PidFileGuard {
                            path,
                            pid: self_pid,
                        });
                    }
                    Some(existing) => match status_of_recorded_pid(existing) {
                        PidFileStatus::HeldByVcp { pid } => {
                            anyhow::bail!(
                                "another {VCP_PROCESS_NAME} process is already running \
                                 (pid {pid}, pid_file {}); stop it before starting a new instance",
                                path.display()
                            );
                        }
                        PidFileStatus::Stale => {
                            // Remove only if contents unchanged (avoid racing a fresh writer).
                            if fs::read_to_string(&path)
                                .ok()
                                .and_then(|s| parse_pid_file_contents(&s))
                                == Some(existing)
                            {
                                let _ = fs::remove_file(&path);
                            }
                        }
                    },
                    None => {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
            Err(e) => {
                anyhow::bail!("failed to create PID file {}: {e}", path.display());
            }
        }
    }

    anyhow::bail!(
        "failed to acquire PID file {} after contention; retry",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn parse_pid_file_contents_accepts_digits() {
        assert_eq!(parse_pid_file_contents("12345\n"), Some(12345));
        assert_eq!(parse_pid_file_contents("  7  "), Some(7));
        assert_eq!(parse_pid_file_contents(""), None);
        assert_eq!(parse_pid_file_contents("0"), None);
        assert_eq!(parse_pid_file_contents("nope"), None);
    }

    #[test]
    fn comm_is_vcp_exact_basename() {
        assert!(comm_is_vcp("vcp"));
        assert!(comm_is_vcp("/usr/local/bin/vcp"));
        assert!(!comm_is_vcp("vcp-cli"));
        assert!(!comm_is_vcp("vcp-store"));
        assert!(!comm_is_vcp("nginx"));
    }

    #[test]
    fn classify_held_vs_stale() {
        assert_eq!(
            classify_pid_holder(10, true, Some("vcp")),
            PidFileStatus::HeldByVcp { pid: 10 }
        );
        assert_eq!(
            classify_pid_holder(10, true, Some("nginx")),
            PidFileStatus::Stale
        );
        assert_eq!(
            classify_pid_holder(10, false, Some("vcp")),
            PidFileStatus::Stale
        );
        assert_eq!(
            classify_pid_holder(10, true, None),
            PidFileStatus::HeldByVcp { pid: 10 }
        );
    }

    #[test]
    fn acquire_then_second_fails_while_held_if_comm_is_vcp() {
        // This test process is not named `vcp`, so a second acquire after a
        // live non-vcp PID is treated as stale. Cover the HeldByVcp path via
        // classify + a real exclusive acquire/drop cycle instead.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vcp.pid");
        let first = acquire(&path).unwrap();
        assert_eq!(first.pid(), std::process::id());
        assert_eq!(
            parse_pid_file_contents(&fs::read_to_string(&path).unwrap()),
            Some(first.pid())
        );
        drop(first);
        assert!(!path.exists());
        let second = acquire(&path).unwrap();
        drop(second);
    }

    #[test]
    fn acquire_replaces_stale_dead_pid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vcp.pid");
        fs::write(&path, "999999\n").unwrap();
        let guard = acquire(&path).unwrap();
        assert_eq!(
            parse_pid_file_contents(&fs::read_to_string(&path).unwrap()),
            Some(guard.pid())
        );
        drop(guard);
    }

    #[test]
    fn acquire_replaces_pid_reused_by_non_vcp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vcp.pid");
        // Current test binary is alive but not named `vcp` → stale.
        fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let guard = acquire(&path).unwrap();
        assert_eq!(guard.pid(), std::process::id());
        drop(guard);
    }

    #[test]
    fn run_server_acquires_pid_file_before_db_connect() {
        let main = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let run_server = main.find("async fn run_server").expect("run_server");
        let server = &main[run_server..];
        let acquire_at = server
            .find("process_guard::acquire")
            .expect("run_server must acquire pid file");
        let db = server
            .find("db::connect")
            .expect("run_server must call db::connect");
        let bind = server
            .find("TcpListener::bind")
            .expect("run_server must bind TcpListener");
        assert!(acquire_at < db, "pid file before db::connect");
        assert!(acquire_at < bind, "pid file before TcpListener::bind");
    }

    #[test]
    fn config_pins_runtime_pid_paths() {
        let prod = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/vcp.conf"));
        let dev = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/development.toml"
        ));
        let default = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/default.toml"));
        assert!(prod.contains("pid_file = \"/var/run/vcp/vcp.pid\""));
        assert!(dev.contains("pid_file = \"/tmp/vcp.pid\""));
        assert!(default.contains("pid_file = \"/tmp/vcp.pid\""));
    }

    #[test]
    fn justfile_run_checks_pid_file_before_cargo_run() {
        let just = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Justfile"));
        let run_idx = just
            .find("# Run the portal over HTTPS")
            .expect("run recipe docs");
        let run_body = &just[run_idx..];
        let kill_at = run_body
            .find("kill -0")
            .expect("just run must kill -0 the pid_file PID");
        assert!(
            run_body.contains("VCP_PID_FILE:-/tmp/vcp.pid") || run_body.contains("/tmp/vcp.pid"),
            "just run must default to /tmp/vcp.pid"
        );
        // Exact recipe line, not the docs mention of bare `cargo run`.
        let cargo_run_at = run_body
            .find("\n    cargo run ")
            .expect("just run must invoke cargo run");
        assert!(kill_at < cargo_run_at);
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::cases(48))]
        fn classify_never_holds_dead_or_wrong_name(
            pid in 1u32..50_000,
            alive in proptest::bool::ANY,
            name in prop::option::of(prop::sample::select(vec![
                "vcp".to_string(),
                "vcp-store".to_string(),
                "nginx".to_string(),
                "vcp-cli".to_string(),
            ])),
        ) {
            let status = classify_pid_holder(pid, alive, name.as_deref());
            match status {
                PidFileStatus::HeldByVcp { pid: held } => {
                    prop_assert_eq!(held, pid);
                    prop_assert!(alive);
                    prop_assert!(
                        name.as_deref().is_none_or(comm_is_vcp),
                        "held only for vcp or unknown comm"
                    );
                }
                PidFileStatus::Stale => {
                    prop_assert!(!alive || name.as_deref().is_some_and(|n| !comm_is_vcp(n)));
                }
            }
        }
    }

    #[test]
    fn battle_classify_under_contention() {
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..200u32 {
                    assert_eq!(
                        classify_pid_holder(i + 1, true, Some("vcp")),
                        PidFileStatus::HeldByVcp { pid: i + 1 }
                    );
                    assert_eq!(
                        classify_pid_holder(i + 1, true, Some("nginx")),
                        PidFileStatus::Stale
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("battle thread");
        }
    }
}
