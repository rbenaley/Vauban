//! Vauban Supervisor - Process manager with privilege separation.
//!
//! This is the main entry point for the Vauban bastion. It:
//! - Loads configuration from TOML file
//! - Creates all IPC pipes between services
//! - Forks and execs the 7 child services
//! - Monitors children with heartbeat watchdog
//! - Handles graceful restart on SIGHUP
//! - Respawns crashed children

mod config;

use anyhow::{Context, Result};
use config::SupervisorConfig;
use shared::ipc::IpcChannel;
use shared::messages::{ControlMessage, Message, Service};
use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Runtime state for a running child service.
struct ChildState {
    pid: libc::pid_t,
    service_key: String,
    /// IPC channel to communicate with this child.
    channel: IpcChannel,
    /// Last successful heartbeat.
    #[allow(dead_code)] // Will be used when heartbeat response is implemented
    last_pong: Instant,
    /// Number of missed heartbeats.
    missed_heartbeats: u32,
    /// Heartbeat sequence number.
    heartbeat_seq: u64,
    /// Respawn count in the last hour.
    respawn_count: u32,
    /// Last respawn timestamp.
    last_respawn: Instant,
}

/// Pipe connection topology.
struct PipeTopology {
    from: Service,
    to: Service,
}

/// All pipe connections in the mesh topology.
const TOPOLOGY: &[PipeTopology] = &[
    // Web connections
    PipeTopology { from: Service::Web, to: Service::Auth },
    PipeTopology { from: Service::Web, to: Service::Rbac },
    PipeTopology { from: Service::Web, to: Service::Audit },
    // Auth connections
    PipeTopology { from: Service::Auth, to: Service::Rbac },
    PipeTopology { from: Service::Auth, to: Service::Vault },
    // Proxy SSH connections
    PipeTopology { from: Service::ProxySsh, to: Service::Rbac },
    PipeTopology { from: Service::ProxySsh, to: Service::Vault },
    PipeTopology { from: Service::ProxySsh, to: Service::Audit },
    // Proxy RDP connections
    PipeTopology { from: Service::ProxyRdp, to: Service::Rbac },
    PipeTopology { from: Service::ProxyRdp, to: Service::Vault },
    PipeTopology { from: Service::ProxyRdp, to: Service::Audit },
];

fn main() -> ExitCode {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Vauban Supervisor starting");

    match run_supervisor() {
        Ok(()) => {
            info!("Vauban Supervisor exiting normally");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("Supervisor error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run_supervisor() -> Result<()> {
    // Load configuration
    let config = SupervisorConfig::load_auto()
        .context("Failed to load configuration")?;
    
    info!(
        "Configuration loaded: environment={:?}, bin_path={}",
        config.supervisor.environment,
        config.supervisor.bin_path
    );

    if config.supervisor.environment.is_development() {
        info!("Running in DEVELOPMENT mode - all services will use current user");
    } else {
        info!("Running in PRODUCTION mode - services will use dedicated UIDs");
    }

    // Setup signal handlers
    setup_signal_handlers()?;

    // Create all IPC pipe pairs for the mesh topology
    let pipes = create_pipe_topology()?;
    info!("Created {} pipe connections", pipes.len());

    // Spawn all child services in dependency order
    let mut children: HashMap<String, ChildState> = HashMap::new();
    
    for service_key in config.startup_order() {
        let service_config = match config.services.get(service_key) {
            Some(sc) => sc,
            None => {
                warn!("Service {} not found in configuration, skipping", service_key);
                continue;
            }
        };

        info!("Starting service: {} ({})", service_config.name, service_key);
        
        // Get effective UID/GID for this service
        let uid = config.effective_uid(service_key);
        let gid = config.effective_gid(service_key);
        
        if let (Some(u), Some(g)) = (uid, gid) {
            info!("  Will run as uid={}, gid={}", u, g);
        } else {
            info!("  Will run as current user (development mode)");
        }

        // Get binary path and working directory
        let binary_path = config.binary_path(service_key)
            .context("Failed to get binary path")?;
        let workdir = config.effective_workdir(service_key);
        
        // Create IPC channel for supervisor-to-child communication
        let (supervisor_channel, child_channel) = IpcChannel::pair()
            .context("Failed to create IPC channel")?;
        
        match spawn_child(&binary_path, uid, gid, workdir.as_deref(), child_channel) {
            Ok(pid) => {
                info!("Started {} with pid {}", service_config.name, pid);
                children.insert(service_key.to_string(), ChildState {
                    pid,
                    service_key: service_key.to_string(),
                    channel: supervisor_channel,
                    last_pong: Instant::now(),
                    missed_heartbeats: 0,
                    heartbeat_seq: 0,
                    respawn_count: 0,
                    last_respawn: Instant::now(),
                });
            }
            Err(e) => {
                error!("Failed to start {}: {}", service_config.name, e);
                // Continue starting other services
            }
        }
    }

    info!("All services started, entering watchdog loop");

    // Main watchdog loop
    let watchdog_config = &config.supervisor.watchdog;
    watchdog_loop(
        &mut children,
        &config,
        Duration::from_secs(watchdog_config.heartbeat_interval_secs),
        watchdog_config.max_missed_heartbeats,
        watchdog_config.max_respawns_per_hour,
    )?;

    Ok(())
}

fn setup_signal_handlers() -> Result<()> {
    use signal_hook::consts::{SIGCHLD, SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGCHLD])
        .context("Failed to setup signal handlers")?;

    std::thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGHUP => {
                    info!("SIGHUP received - graceful restart requested");
                    // TODO: Implement graceful restart
                }
                SIGTERM | SIGINT => {
                    info!("Shutdown signal received");
                    // TODO: Implement graceful shutdown
                    std::process::exit(0);
                }
                SIGCHLD => {
                    // Child process state changed - handled in watchdog loop
                }
                _ => {}
            }
        }
    });

    Ok(())
}

fn create_pipe_topology() -> Result<HashMap<(Service, Service), (IpcChannel, IpcChannel)>> {
    let mut pipes = HashMap::new();

    for conn in TOPOLOGY {
        let (from_channel, to_channel) = IpcChannel::pair()
            .with_context(|| format!("Failed to create pipe {:?} -> {:?}", conn.from, conn.to))?;
        pipes.insert((conn.from, conn.to), (from_channel, to_channel));
    }

    Ok(pipes)
}

fn spawn_child(
    binary_path: &str,
    uid: Option<u32>,
    gid: Option<u32>,
    workdir: Option<&str>,
    channel: IpcChannel,
) -> Result<libc::pid_t> {
    use std::ffi::CString;

    // Get raw FDs before fork (we'll pass them via env vars)
    let read_fd = channel.read_fd();
    let write_fd = channel.write_fd();

    // SAFETY: fork() is a standard POSIX call
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            Err(std::io::Error::last_os_error()).context("fork() failed")
        }
        0 => {
            // Child process
            
            // Change working directory if specified
            if let Some(dir) = workdir {
                if std::env::set_current_dir(dir).is_err() {
                    eprintln!("Failed to chdir to {}: {}", dir, std::io::Error::last_os_error());
                    std::process::exit(1);
                }
            }
            
            // Drop privileges if configured (production mode)
            if let Some(g) = gid {
                // SAFETY: setgid() is a standard POSIX call
                let ret = unsafe { libc::setgid(g) };
                if ret != 0 {
                    eprintln!("Failed to setgid({}): {}", g, std::io::Error::last_os_error());
                    std::process::exit(1);
                }
            }
            
            if let Some(u) = uid {
                // SAFETY: setuid() is a standard POSIX call
                let ret = unsafe { libc::setuid(u) };
                if ret != 0 {
                    eprintln!("Failed to setuid({}): {}", u, std::io::Error::last_os_error());
                    std::process::exit(1);
                }
            }
            
            // Set environment variables for IPC FDs
            // SAFETY: We are in a single-threaded child process right after fork(),
            // and the environment is not being accessed by other threads.
            unsafe {
                std::env::set_var("VAUBAN_IPC_READ", read_fd.to_string());
                std::env::set_var("VAUBAN_IPC_WRITE", write_fd.to_string());
            }
            
            // Exec the child binary
            let c_path = match CString::new(binary_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Invalid binary path: {}", e);
                    std::process::exit(1);
                }
            };
            
            // argv[0] = binary name
            let argv: [*const libc::c_char; 2] = [c_path.as_ptr(), std::ptr::null()];
            
            // SAFETY: execv is a standard POSIX call. If it succeeds, it doesn't return.
            // If it fails, we exit with an error.
            unsafe {
                libc::execv(c_path.as_ptr(), argv.as_ptr());
            }
            
            // If we get here, exec failed
            eprintln!("Failed to exec {}: {}", binary_path, std::io::Error::last_os_error());
            std::process::exit(1);
        }
        child_pid => {
            // Parent process - drop our copy of the channel
            // The channel FDs are now owned by the child
            drop(channel);
            Ok(child_pid)
        }
    }
}

fn watchdog_loop(
    children: &mut HashMap<String, ChildState>,
    config: &SupervisorConfig,
    heartbeat_interval: Duration,
    max_missed_heartbeats: u32,
    max_respawns_per_hour: u32,
) -> Result<()> {
    let mut last_heartbeat = Instant::now();

    loop {
        // Reap any dead children
        reap_children(children, config, max_respawns_per_hour);

        // Send heartbeats periodically
        if last_heartbeat.elapsed() >= heartbeat_interval {
            for (service_key, state) in children.iter_mut() {
                send_heartbeat(service_key, state);
            }
            last_heartbeat = Instant::now();
        }

        // Check for unresponsive children
        for (service_key, state) in children.iter_mut() {
            if state.missed_heartbeats >= max_missed_heartbeats {
                warn!("{} is unresponsive, initiating restart", service_key);
                kill_and_respawn(state, config);
            }
        }

        // Sleep briefly before next iteration
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn reap_children(
    children: &mut HashMap<String, ChildState>,
    config: &SupervisorConfig,
    max_respawns_per_hour: u32,
) {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid() is a standard POSIX call
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };

        if pid <= 0 {
            break;
        }

        // Find which service this was
        for (service_key, state) in children.iter_mut() {
            if state.pid == pid {
                if libc::WIFEXITED(status) {
                    let exit_code = libc::WEXITSTATUS(status);
                    warn!("{} exited with code {}", service_key, exit_code);
                } else if libc::WIFSIGNALED(status) {
                    let signal = libc::WTERMSIG(status);
                    warn!("{} killed by signal {}", service_key, signal);
                }

                // Respawn if not too many recent respawns
                if should_respawn(state, max_respawns_per_hour) {
                    info!("Respawning {}", service_key);
                    respawn_service(state, config);
                } else {
                    error!("{} has crashed too many times, not respawning", service_key);
                }
                break;
            }
        }
    }
}

fn send_heartbeat(service_key: &str, state: &mut ChildState) {
    use shared::ipc::poll_readable;
    
    state.heartbeat_seq += 1;
    let ping = Message::Control(ControlMessage::Ping { seq: state.heartbeat_seq });

    if let Err(e) = state.channel.send(&ping) {
        warn!("Failed to send heartbeat to {}: {}", service_key, e);
        state.missed_heartbeats += 1;
        return;
    }

    // Wait for Pong response with timeout (2 seconds)
    let timeout_ms = 2000;
    let fds = [state.channel.read_fd()];
    match poll_readable(&fds, timeout_ms) {
        Ok(ready_indices) if !ready_indices.is_empty() => {
            // Data available, try to read the response
            match state.channel.recv() {
                Ok(Message::Control(ControlMessage::Pong { seq, stats: _ })) => {
                    if seq == state.heartbeat_seq {
                        // Valid Pong received, reset missed count
                        state.missed_heartbeats = 0;
                        state.last_pong = Instant::now();
                    } else {
                        warn!("{}: Pong seq mismatch (expected {}, got {})", 
                              service_key, state.heartbeat_seq, seq);
                        state.missed_heartbeats += 1;
                    }
                }
                Ok(_) => {
                    // Received some other message, not a Pong
                    // This is fine, the service might be sending other messages
                    // Don't count as missed, but also don't reset
                }
                Err(e) => {
                    warn!("Failed to receive Pong from {}: {}", service_key, e);
                    state.missed_heartbeats += 1;
                }
            }
        }
        Ok(_) => {
            // Timeout - no response within 2 seconds (empty ready_indices)
            state.missed_heartbeats += 1;
        }
        Err(e) => {
            warn!("Poll error for {}: {}", service_key, e);
            state.missed_heartbeats += 1;
        }
    }
}

fn should_respawn(state: &mut ChildState, max_respawns_per_hour: u32) -> bool {
    // Reset counter if more than an hour since last respawn
    if state.last_respawn.elapsed() > Duration::from_secs(3600) {
        state.respawn_count = 0;
        return true;
    }

    state.respawn_count < max_respawns_per_hour
}

fn kill_and_respawn(state: &mut ChildState, config: &SupervisorConfig) {
    // Send SIGTERM
    // SAFETY: kill() is a standard POSIX call
    unsafe { libc::kill(state.pid, libc::SIGTERM) };

    // Wait up to 5 seconds
    std::thread::sleep(Duration::from_secs(5));

    // Check if still alive
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid() is a standard POSIX call
    let result = unsafe { libc::waitpid(state.pid, &mut status, libc::WNOHANG) };

    if result == 0 {
        // Still alive, send SIGKILL
        warn!("{} did not terminate, sending SIGKILL", state.service_key);
        // SAFETY: kill() is a standard POSIX call
        unsafe { libc::kill(state.pid, libc::SIGKILL) };
        // SAFETY: waitpid() is a standard POSIX call
        unsafe { libc::waitpid(state.pid, &mut status, 0) };
    }

    respawn_service(state, config);
}

fn respawn_service(state: &mut ChildState, config: &SupervisorConfig) {
    let uid = config.effective_uid(&state.service_key);
    let gid = config.effective_gid(&state.service_key);
    let workdir = config.effective_workdir(&state.service_key);
    let binary_path = match config.binary_path(&state.service_key) {
        Some(p) => p,
        None => {
            error!("Cannot respawn {}: no binary path", state.service_key);
            return;
        }
    };

    // Create new IPC channel
    let (supervisor_channel, child_channel) = match IpcChannel::pair() {
        Ok((s, c)) => (s, c),
        Err(e) => {
            error!("Failed to create IPC channel for respawn: {}", e);
            return;
        }
    };

    match spawn_child(&binary_path, uid, gid, workdir.as_deref(), child_channel) {
        Ok(pid) => {
            info!("Respawned {} with pid {}", state.service_key, pid);
            state.pid = pid;
            state.channel = supervisor_channel;
            state.missed_heartbeats = 0;
            state.respawn_count += 1;
            state.last_respawn = Instant::now();
        }
        Err(e) => {
            error!("Failed to respawn {}: {}", state.service_key, e);
        }
    }
}

fn service_key_to_enum(key: &str) -> Option<Service> {
    match key {
        "web" => Some(Service::Web),
        "auth" => Some(Service::Auth),
        "rbac" => Some(Service::Rbac),
        "vault" => Some(Service::Vault),
        "audit" => Some(Service::Audit),
        "proxy_ssh" => Some(Service::ProxySsh),
        "proxy_rdp" => Some(Service::ProxyRdp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== PipeTopology Tests ====================

    #[test]
    fn test_topology_count() {
        assert_eq!(TOPOLOGY.len(), 11);
    }

    #[test]
    fn test_topology_web_connections() {
        let web_connections: Vec<_> = TOPOLOGY
            .iter()
            .filter(|conn| conn.from == Service::Web)
            .collect();
        
        // Web connects to: Auth, Rbac, Audit
        assert_eq!(web_connections.len(), 3);
    }

    #[test]
    fn test_topology_auth_connections() {
        let auth_connections: Vec<_> = TOPOLOGY
            .iter()
            .filter(|conn| conn.from == Service::Auth)
            .collect();
        
        // Auth connects to: Rbac, Vault
        assert_eq!(auth_connections.len(), 2);
    }

    #[test]
    fn test_topology_proxy_ssh_connections() {
        let proxy_connections: Vec<_> = TOPOLOGY
            .iter()
            .filter(|conn| conn.from == Service::ProxySsh)
            .collect();
        
        // ProxySsh connects to: Rbac, Vault, Audit
        assert_eq!(proxy_connections.len(), 3);
    }

    #[test]
    fn test_topology_proxy_rdp_connections() {
        let proxy_connections: Vec<_> = TOPOLOGY
            .iter()
            .filter(|conn| conn.from == Service::ProxyRdp)
            .collect();
        
        // ProxyRdp connects to: Rbac, Vault, Audit
        assert_eq!(proxy_connections.len(), 3);
    }

    #[test]
    fn test_topology_no_self_connections() {
        for conn in TOPOLOGY {
            assert_ne!(conn.from, conn.to, "Service {:?} should not connect to itself", conn.from);
        }
    }

    // ==================== service_key_to_enum Tests ====================

    #[test]
    fn test_service_key_to_enum_all_valid() {
        assert_eq!(service_key_to_enum("web"), Some(Service::Web));
        assert_eq!(service_key_to_enum("auth"), Some(Service::Auth));
        assert_eq!(service_key_to_enum("rbac"), Some(Service::Rbac));
        assert_eq!(service_key_to_enum("vault"), Some(Service::Vault));
        assert_eq!(service_key_to_enum("audit"), Some(Service::Audit));
        assert_eq!(service_key_to_enum("proxy_ssh"), Some(Service::ProxySsh));
        assert_eq!(service_key_to_enum("proxy_rdp"), Some(Service::ProxyRdp));
    }

    #[test]
    fn test_service_key_to_enum_unknown() {
        assert_eq!(service_key_to_enum("unknown"), None);
        assert_eq!(service_key_to_enum(""), None);
        assert_eq!(service_key_to_enum("supervisor"), None);
    }

    // ==================== create_pipe_topology Tests ====================

    #[test]
    fn test_create_pipe_topology() {
        let result = create_pipe_topology();
        assert!(result.is_ok());
        
        let pipes = result.unwrap();
        assert_eq!(pipes.len(), TOPOLOGY.len());
    }

    #[test]
    fn test_create_pipe_topology_all_connections_present() {
        let pipes = create_pipe_topology().unwrap();
        
        for conn in TOPOLOGY {
            assert!(
                pipes.contains_key(&(conn.from, conn.to)),
                "Pipe {:?} -> {:?} should exist",
                conn.from,
                conn.to
            );
        }
    }

    // ==================== should_respawn Tests ====================

    #[test]
    fn test_should_respawn_first_time() {
        let mut state = ChildState {
            pid: 0,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
        };
        
        // First respawn should always be allowed
        assert!(should_respawn(&mut state, 10));
    }

    #[test]
    fn test_should_respawn_under_limit() {
        let mut state = ChildState {
            pid: 0,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 5,
            last_respawn: Instant::now(),
        };
        
        // Under limit (5 < 10), should be allowed
        assert!(should_respawn(&mut state, 10));
    }

    #[test]
    fn test_should_respawn_at_limit() {
        let mut state = ChildState {
            pid: 0,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 10,
            last_respawn: Instant::now(),
        };
        
        // At limit (10 >= 10), should NOT be allowed
        assert!(!should_respawn(&mut state, 10));
    }

    #[test]
    fn test_should_respawn_over_limit() {
        let mut state = ChildState {
            pid: 0,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 15,
            last_respawn: Instant::now(),
        };
        
        // Over limit (15 >= 10), should NOT be allowed
        assert!(!should_respawn(&mut state, 10));
    }

    // Note: Testing reset after 1 hour would require time manipulation
    // which is complex. We trust the Duration comparison works correctly.

    // ==================== ChildState Tests ====================

    #[test]
    fn test_child_state_creation() {
        let channel = IpcChannel::pair().unwrap().0;
        let state = ChildState {
            pid: 12345,
            service_key: "audit".to_string(),
            channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
        };
        
        assert_eq!(state.pid, 12345);
        assert_eq!(state.service_key, "audit");
        assert_eq!(state.missed_heartbeats, 0);
        assert_eq!(state.respawn_count, 0);
    }

    // ==================== Integration-style Tests ====================

    #[test]
    fn test_config_service_keys_match_topology() {
        let config = config::SupervisorConfig::default_development().unwrap();
        
        // All services in topology should be configurable
        let service_keys: std::collections::HashSet<_> = TOPOLOGY
            .iter()
            .flat_map(|conn| vec![conn.from, conn.to])
            .collect();
        
        for service in service_keys {
            let key = match service {
                Service::Web => "web",
                Service::Auth => "auth",
                Service::Rbac => "rbac",
                Service::Vault => "vault",
                Service::Audit => "audit",
                Service::ProxySsh => "proxy_ssh",
                Service::ProxyRdp => "proxy_rdp",
                Service::Supervisor => continue, // Supervisor not in services
            };
            
            assert!(
                config.services.contains_key(key),
                "Service {} should be in config",
                key
            );
        }
    }
}
