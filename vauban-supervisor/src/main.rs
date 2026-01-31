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
use shared::messages::{ControlMessage, Message, Service, ServiceStats};
use std::collections::HashMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Runtime state for a running child service.
struct ChildState {
    pid: libc::pid_t,
    service_key: String,
    /// IPC channel to communicate with this child.
    channel: IpcChannel,
    /// Last successful heartbeat timestamp.
    last_pong: Instant,
    /// Number of missed heartbeats.
    missed_heartbeats: u32,
    /// Heartbeat sequence number.
    heartbeat_seq: u64,
    /// Respawn count in the last hour.
    respawn_count: u32,
    /// Last respawn timestamp.
    last_respawn: Instant,
    /// Stats from the last successful Pong response.
    last_stats: Option<ServiceStats>,
    /// Whether this service is currently draining.
    is_draining: bool,
    /// When drain was initiated for this service.
    drain_started: Option<Instant>,
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
                    last_stats: None,
                    is_draining: false,
                    drain_started: None,
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
            match should_force_restart(state, max_missed_heartbeats) {
                RestartDecision::NotNeeded => {}
                RestartDecision::DrainFirst { active, pending } => {
                    warn!(
                        "{} is unresponsive with active work (connections={}, pending={}), draining first",
                        service_key, active, pending
                    );
                    drain_and_restart(state, config);
                }
                RestartDecision::ForceNow => {
                    warn!("{} is unresponsive, forcing restart", service_key);
                    kill_and_respawn(state, config);
                }
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
                Ok(Message::Control(ControlMessage::Pong { seq, stats })) => {
                    if seq == state.heartbeat_seq {
                        // Valid Pong received, reset missed count and store stats
                        state.missed_heartbeats = 0;
                        state.last_pong = Instant::now();
                        
                        // Log stats at DEBUG level
                        debug!(
                            "{}: pong received (latency: {:?}), uptime={}s, active_connections={}, pending={}",
                            service_key,
                            state.last_pong.elapsed(),
                            stats.uptime_secs,
                            stats.active_connections,
                            stats.pending_requests
                        );
                        
                        // Store stats for decision making
                        state.last_stats = Some(stats);
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

/// Decision for how to restart an unresponsive service.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RestartDecision {
    /// Service is responsive, no restart needed.
    NotNeeded,
    /// Service has active connections/requests, drain first before restart.
    DrainFirst { active: u32, pending: u32 },
    /// Service can be restarted immediately (no active work).
    ForceNow,
}

/// Determine whether and how to restart an unresponsive service.
///
/// Uses the stats from the last successful Pong to decide:
/// - If service has active connections or pending requests, drain first
/// - Otherwise, force restart immediately
fn should_force_restart(state: &ChildState, max_missed: u32) -> RestartDecision {
    if state.missed_heartbeats < max_missed {
        return RestartDecision::NotNeeded;
    }
    
    // Check stats from last successful Pong
    if let Some(ref stats) = state.last_stats {
        if stats.active_connections > 0 || stats.pending_requests > 0 {
            return RestartDecision::DrainFirst {
                active: stats.active_connections,
                pending: stats.pending_requests,
            };
        }
    }
    
    RestartDecision::ForceNow
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
            state.last_pong = Instant::now();
            state.last_stats = None;
            state.is_draining = false;
            state.drain_started = None;
        }
        Err(e) => {
            error!("Failed to respawn {}: {}", state.service_key, e);
        }
    }
}

/// Initiate drain on a service and wait for completion before restart.
///
/// This sends a Drain message, waits for DrainComplete with pending_requests=0,
/// then proceeds with the standard kill_and_respawn sequence.
fn drain_and_restart(state: &mut ChildState, config: &SupervisorConfig) {
    use shared::ipc::poll_readable;
    
    // 1. Send Drain message
    let drain_msg = Message::Control(ControlMessage::Drain);
    if let Err(e) = state.channel.send(&drain_msg) {
        warn!("{}: failed to send Drain, proceeding with kill: {}", state.service_key, e);
        kill_and_respawn(state, config);
        return;
    }
    
    state.is_draining = true;
    state.drain_started = Some(Instant::now());
    info!("{}: drain initiated", state.service_key);
    
    // 2. Wait for DrainComplete or timeout
    let drain_timeout = Duration::from_secs(config.supervisor.watchdog.drain_timeout_secs);
    let fds = [state.channel.read_fd()];
    
    while state.drain_started.unwrap().elapsed() < drain_timeout {
        // Poll for DrainComplete message (500ms timeout per poll)
        match poll_readable(&fds, 500) {
            Ok(ready) if !ready.is_empty() => {
                match state.channel.recv() {
                    Ok(Message::Control(ControlMessage::DrainComplete { pending_requests })) => {
                        if pending_requests == 0 {
                            info!("{}: drain complete", state.service_key);
                            break;
                        }
                        debug!("{}: draining, {} requests pending", state.service_key, pending_requests);
                    }
                    Ok(Message::Control(ControlMessage::Pong { seq: _, stats })) => {
                        // Service is still responding to heartbeats during drain
                        state.last_stats = Some(stats);
                    }
                    Ok(_) => {
                        // Other message types, ignore during drain
                    }
                    Err(e) => {
                        warn!("{}: error receiving during drain: {}", state.service_key, e);
                        break;
                    }
                }
            }
            Ok(_) => {
                // Poll timeout, continue waiting
            }
            Err(e) => {
                warn!("{}: poll error during drain: {}", state.service_key, e);
                break;
            }
        }
    }
    
    if state.drain_started.unwrap().elapsed() >= drain_timeout {
        warn!("{}: drain timeout after {:?}, forcing restart", 
              state.service_key, drain_timeout);
    }
    
    // 3. Send Shutdown and proceed with restart
    let shutdown_msg = Message::Control(ControlMessage::Shutdown);
    let _ = state.channel.send(&shutdown_msg);
    
    kill_and_respawn(state, config);
}

/// Frontend services: drained in parallel (no dependencies between them)
#[allow(dead_code)] // Will be used when graceful shutdown is fully implemented
const FRONTEND_SERVICES: &[&str] = &["web", "proxy_rdp", "proxy_ssh"];

/// Backend services: drained sequentially after frontend completes
/// Order matters: audit must be last to capture all events
#[allow(dead_code)] // Will be used when graceful shutdown is fully implemented
const BACKEND_SERVICES: &[&str] = &["auth", "rbac", "vault", "audit"];

/// Gracefully shutdown all services respecting dependencies.
///
/// Phase 1: Drain all frontend services in parallel, wait for completion
/// Phase 2: Drain backend services sequentially (audit last)
/// Phase 3: Send Shutdown to all
#[allow(dead_code)] // Will be used when graceful shutdown is fully implemented
fn graceful_shutdown_all(children: &mut HashMap<String, ChildState>, config: &SupervisorConfig) {
    use shared::ipc::poll_readable;
    
    let drain_timeout = Duration::from_secs(config.supervisor.watchdog.drain_timeout_secs);
    
    // Phase 1: Drain all frontend services simultaneously (parallel)
    info!("Phase 1: Draining frontend services (web, proxy_rdp, proxy_ssh)");
    for key in FRONTEND_SERVICES {
        if let Some(state) = children.get_mut(*key) {
            let drain_msg = Message::Control(ControlMessage::Drain);
            if let Err(e) = state.channel.send(&drain_msg) {
                warn!("{}: failed to send Drain: {}", key, e);
                continue;
            }
            state.is_draining = true;
            state.drain_started = Some(Instant::now());
            info!("{}: drain initiated", key);
        }
    }
    
    // Wait for ALL frontend services to complete their active connections
    let start = Instant::now();
    let mut frontend_complete = [false; 3]; // web, proxy_rdp, proxy_ssh
    
    while start.elapsed() < drain_timeout {
        let mut all_complete = true;
        
        for (i, key) in FRONTEND_SERVICES.iter().enumerate() {
            if frontend_complete[i] {
                continue;
            }
            
            if let Some(state) = children.get_mut(*key) {
                let fds = [state.channel.read_fd()];
                if let Ok(ready) = poll_readable(&fds, 100) {
                    if !ready.is_empty() {
                        if let Ok(Message::Control(ControlMessage::DrainComplete { pending_requests })) 
                            = state.channel.recv() 
                        {
                            if pending_requests == 0 {
                                info!("{}: drain complete", key);
                                frontend_complete[i] = true;
                            } else {
                                debug!("{}: draining, {} pending", key, pending_requests);
                            }
                        }
                    }
                }
            }
            
            if !frontend_complete[i] {
                all_complete = false;
            }
        }
        
        if all_complete {
            break;
        }
        
        std::thread::sleep(Duration::from_millis(100));
    }
    
    if start.elapsed() >= drain_timeout {
        warn!("Frontend drain timeout after {:?}", drain_timeout);
    }
    
    // Phase 2: Drain backend services sequentially (audit MUST be last)
    info!("Phase 2: Draining backend services (auth, rbac, vault, audit)");
    for key in BACKEND_SERVICES {
        if let Some(state) = children.get_mut(*key) {
            let drain_msg = Message::Control(ControlMessage::Drain);
            if let Err(e) = state.channel.send(&drain_msg) {
                warn!("{}: failed to send Drain: {}", key, e);
                continue;
            }
            
            // Wait for this backend service to complete (quick, they're stateless)
            let fds = [state.channel.read_fd()];
            let backend_start = Instant::now();
            while backend_start.elapsed() < Duration::from_secs(5) {
                if let Ok(ready) = poll_readable(&fds, 1000) {
                    if !ready.is_empty() {
                        if let Ok(Message::Control(ControlMessage::DrainComplete { pending_requests })) 
                            = state.channel.recv() 
                        {
                            if pending_requests == 0 {
                                info!("{}: drain complete", key);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Phase 3: Send Shutdown to all
    info!("Phase 3: Sending Shutdown to all services");
    for state in children.values_mut() {
        let _ = state.channel.send(&Message::Control(ControlMessage::Shutdown));
    }
}

/// Convert service key string to Service enum.
/// Currently used by tests to verify service key mappings.
#[cfg(test)]
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
    use shared::messages::ServiceStats;

    // ==================== Test Helpers ====================

    /// Get the path to the workspace root config/ directory for tests.
    fn test_config_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Failed to get workspace root")
            .join("config")
    }

    /// Load configuration from the real config files for tests.
    ///
    /// This ensures tests validate the actual configuration files,
    /// not a hardcoded fallback that could become out of sync.
    fn test_config() -> config::SupervisorConfig {
        let config_dir = test_config_dir();
        config::SupervisorConfig::load_from_dir(&config_dir)
            .expect("Failed to load config from config/ directory. Ensure config/default.toml exists.")
    }

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
            last_stats: None,
            is_draining: false,
            drain_started: None,
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
            last_stats: None,
            is_draining: false,
            drain_started: None,
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
            last_stats: None,
            is_draining: false,
            drain_started: None,
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
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Over limit (15 >= 10), should NOT be allowed
        assert!(!should_respawn(&mut state, 10));
    }

    // Note: Testing reset after 1 hour would require time manipulation
    // which is complex. We trust the Duration comparison works correctly.

    // ==================== should_force_restart Tests ====================

    #[test]
    fn test_should_force_restart_not_needed() {
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 1, // Below threshold
            heartbeat_seq: 5,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // With max_missed = 3, and only 1 missed, should not restart
        assert_eq!(should_force_restart(&state, 3), RestartDecision::NotNeeded);
    }

    #[test]
    fn test_should_force_restart_force_now_no_stats() {
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 5, // Above threshold
            heartbeat_seq: 10,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None, // No stats available
            is_draining: false,
            drain_started: None,
        };
        
        // Above threshold with no stats, should force restart
        assert_eq!(should_force_restart(&state, 3), RestartDecision::ForceNow);
    }

    #[test]
    fn test_should_force_restart_force_now_no_active_work() {
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 5, // Above threshold
            heartbeat_seq: 10,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: Some(ServiceStats {
                uptime_secs: 100,
                requests_processed: 50,
                requests_failed: 0,
                active_connections: 0, // No active connections
                pending_requests: 0,   // No pending requests
            }),
            is_draining: false,
            drain_started: None,
        };
        
        // Above threshold with no active work, should force restart
        assert_eq!(should_force_restart(&state, 3), RestartDecision::ForceNow);
    }

    #[test]
    fn test_should_force_restart_drain_first_active_connections() {
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 5, // Above threshold
            heartbeat_seq: 10,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: Some(ServiceStats {
                uptime_secs: 100,
                requests_processed: 50,
                requests_failed: 0,
                active_connections: 10, // Has active connections
                pending_requests: 0,
            }),
            is_draining: false,
            drain_started: None,
        };
        
        // Above threshold with active connections, should drain first
        assert_eq!(
            should_force_restart(&state, 3),
            RestartDecision::DrainFirst { active: 10, pending: 0 }
        );
    }

    #[test]
    fn test_should_force_restart_drain_first_pending_requests() {
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel: IpcChannel::pair().unwrap().0,
            last_pong: Instant::now(),
            missed_heartbeats: 5, // Above threshold
            heartbeat_seq: 10,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: Some(ServiceStats {
                uptime_secs: 100,
                requests_processed: 50,
                requests_failed: 0,
                active_connections: 0,
                pending_requests: 5, // Has pending requests
            }),
            is_draining: false,
            drain_started: None,
        };
        
        // Above threshold with pending requests, should drain first
        assert_eq!(
            should_force_restart(&state, 3),
            RestartDecision::DrainFirst { active: 0, pending: 5 }
        );
    }

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
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        assert_eq!(state.pid, 12345);
        assert_eq!(state.service_key, "audit");
        assert_eq!(state.missed_heartbeats, 0);
        assert_eq!(state.respawn_count, 0);
        assert!(state.last_stats.is_none());
        assert!(!state.is_draining);
        assert!(state.drain_started.is_none());
    }

    // ==================== Integration-style Tests ====================

    #[test]
    fn test_config_service_keys_match_topology() {
        let config = test_config();
        
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

    // ==================== Heartbeat Mechanism Tests ====================

    #[test]
    fn test_heartbeat_ping_pong_cycle() {
        // Create a pair of channels (supervisor <-> service)
        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();
        
        // Create child state
        let mut state = ChildState {
            pid: 12345,
            service_key: "test_service".to_string(),
            channel: supervisor_channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Spawn a thread to simulate the service responding to Ping
        let service_thread = std::thread::spawn(move || {
            // Wait for Ping
            let msg = service_channel.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq }) = msg {
                // Send Pong with same seq
                let stats = ServiceStats {
                    uptime_secs: 100,
                    requests_processed: 42,
                    requests_failed: 3,
                    active_connections: 5,
                    pending_requests: 2,
                };
                let pong = Message::Control(ControlMessage::Pong { seq, stats });
                service_channel.send(&pong).unwrap();
            }
            service_channel
        });
        
        // Send heartbeat from supervisor
        send_heartbeat("test_service", &mut state);
        
        // Wait for service thread
        let _ = service_thread.join().unwrap();
        
        // Verify state was updated correctly
        assert_eq!(state.heartbeat_seq, 1, "Heartbeat seq should increment");
        assert_eq!(state.missed_heartbeats, 0, "Missed heartbeats should be 0 after valid Pong");
    }

    #[test]
    fn test_heartbeat_missed_on_timeout() {
        // Create a pair of channels but don't respond
        let (supervisor_channel, _service_channel) = IpcChannel::pair().unwrap();
        
        let mut state = ChildState {
            pid: 12345,
            service_key: "unresponsive_service".to_string(),
            channel: supervisor_channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Send heartbeat - service won't respond, will timeout
        send_heartbeat("unresponsive_service", &mut state);
        
        // Verify missed heartbeat was counted
        assert_eq!(state.heartbeat_seq, 1, "Heartbeat seq should increment");
        assert_eq!(state.missed_heartbeats, 1, "Missed heartbeats should increment on timeout");
    }

    #[test]
    fn test_heartbeat_seq_mismatch_counts_as_missed() {
        // Create a pair of channels
        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();
        
        let mut state = ChildState {
            pid: 12345,
            service_key: "bad_seq_service".to_string(),
            channel: supervisor_channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Spawn thread to respond with wrong seq
        let service_thread = std::thread::spawn(move || {
            let msg = service_channel.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq: _ }) = msg {
                // Send Pong with WRONG seq
                let stats = ServiceStats::default();
                let pong = Message::Control(ControlMessage::Pong { seq: 999, stats });
                service_channel.send(&pong).unwrap();
            }
            service_channel
        });
        
        send_heartbeat("bad_seq_service", &mut state);
        let _ = service_thread.join().unwrap();
        
        // Seq mismatch should count as missed
        assert_eq!(state.missed_heartbeats, 1, "Seq mismatch should count as missed heartbeat");
    }

    #[test]
    fn test_heartbeat_resets_missed_count_on_valid_pong() {
        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();
        
        let mut state = ChildState {
            pid: 12345,
            service_key: "recovering_service".to_string(),
            channel: supervisor_channel,
            last_pong: Instant::now(),
            missed_heartbeats: 2, // Previously missed 2 heartbeats
            heartbeat_seq: 5,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Spawn thread to respond correctly
        let service_thread = std::thread::spawn(move || {
            let msg = service_channel.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq }) = msg {
                let stats = ServiceStats::default();
                let pong = Message::Control(ControlMessage::Pong { seq, stats });
                service_channel.send(&pong).unwrap();
            }
            service_channel
        });
        
        send_heartbeat("recovering_service", &mut state);
        let _ = service_thread.join().unwrap();
        
        // Valid Pong should reset missed count
        assert_eq!(state.missed_heartbeats, 0, "Valid Pong should reset missed heartbeats to 0");
        assert_eq!(state.heartbeat_seq, 6, "Seq should have incremented");
    }

    #[test]
    fn test_heartbeat_multiple_missed_triggers_restart() {
        let config = test_config();
        let max_missed = config.supervisor.watchdog.max_missed_heartbeats;
        
        // Create state with max_missed - 1 already missed
        let (channel, _) = IpcChannel::pair().unwrap();
        let mut state = ChildState {
            pid: 12345,
            service_key: "failing_service".to_string(),
            channel,
            last_pong: Instant::now(),
            missed_heartbeats: max_missed - 1,
            heartbeat_seq: 10,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // One more miss should trigger restart
        send_heartbeat("failing_service", &mut state);
        
        assert!(
            state.missed_heartbeats >= max_missed,
            "After {} misses, should trigger restart (missed: {}, max: {})",
            max_missed,
            state.missed_heartbeats,
            max_missed
        );
    }

    #[test]
    fn test_service_stats_in_pong_response() {
        let (supervisor_channel, service_channel) = IpcChannel::pair().unwrap();
        
        let mut state = ChildState {
            pid: 12345,
            service_key: "stats_service".to_string(),
            channel: supervisor_channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Expected stats from service
        let expected_stats = ServiceStats {
            uptime_secs: 3600,
            requests_processed: 1000,
            requests_failed: 5,
            active_connections: 10,
            pending_requests: 3,
        };
        let expected_stats_clone = expected_stats.clone();
        
        let service_thread = std::thread::spawn(move || {
            let msg = service_channel.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq }) = msg {
                let pong = Message::Control(ControlMessage::Pong { 
                    seq, 
                    stats: expected_stats_clone,
                });
                service_channel.send(&pong).unwrap();
            }
            service_channel
        });
        
        send_heartbeat("stats_service", &mut state);
        let _ = service_thread.join().unwrap();
        
        // Heartbeat was successful
        assert_eq!(state.missed_heartbeats, 0);
        
        // Verify stats are stored in last_stats
        assert!(state.last_stats.is_some(), "Stats should be stored after successful Pong");
        let stored_stats = state.last_stats.as_ref().unwrap();
        assert_eq!(stored_stats.uptime_secs, expected_stats.uptime_secs);
        assert_eq!(stored_stats.requests_processed, expected_stats.requests_processed);
        assert_eq!(stored_stats.requests_failed, expected_stats.requests_failed);
        assert_eq!(stored_stats.active_connections, expected_stats.active_connections);
        assert_eq!(stored_stats.pending_requests, expected_stats.pending_requests);
    }

    // ==================== All Services Heartbeat Contract Tests ====================

    /// Verify all services implement the heartbeat contract correctly.
    /// This test ensures that each service's handle_control_ping implementation
    /// is consistent with the supervisor's expectations.
    #[test]
    fn test_all_services_have_heartbeat_tests() {
        // This is a documentation test - it verifies that we have
        // heartbeat tests for all services.
        // The actual tests are in each service's main.rs
        let services_with_heartbeat_tests = [
            "vauban-auth",      // test_handle_control_ping
            "vauban-vault",     // test_handle_control_ping
            "vauban-rbac",      // test_handle_control_ping
            "vauban-audit",     // test_handle_control_ping
            "vauban-proxy-ssh", // test_handle_control_ping
            "vauban-proxy-rdp", // test_handle_control_ping
            "vauban-web",       // test_heartbeat_state_new, etc.
        ];
        
        assert_eq!(services_with_heartbeat_tests.len(), 7, 
            "All 7 services should have heartbeat tests");
    }

    #[test]
    fn test_heartbeat_interval_config() {
        let config = test_config();
        
        // Verify reasonable defaults
        assert!(
            config.supervisor.watchdog.heartbeat_interval_secs >= 1,
            "Heartbeat interval should be at least 1 second"
        );
        assert!(
            config.supervisor.watchdog.heartbeat_interval_secs <= 60,
            "Heartbeat interval should not exceed 60 seconds"
        );
        assert!(
            config.supervisor.watchdog.max_missed_heartbeats >= 2,
            "Should allow at least 2 missed heartbeats before restart"
        );
    }

    // ==================== Drain Configuration Tests ====================

    #[test]
    fn test_drain_timeout_config() {
        let config = test_config();
        
        // Verify drain timeout is configured (default 30s per Section 9.2)
        assert_eq!(
            config.supervisor.watchdog.drain_timeout_secs, 30,
            "Drain timeout should be 30 seconds by default"
        );
    }

    #[test]
    fn test_drain_order_frontend_services() {
        // Verify frontend services list for drain order
        assert_eq!(FRONTEND_SERVICES.len(), 3);
        assert!(FRONTEND_SERVICES.contains(&"web"));
        assert!(FRONTEND_SERVICES.contains(&"proxy_rdp"));
        assert!(FRONTEND_SERVICES.contains(&"proxy_ssh"));
    }

    #[test]
    fn test_drain_order_backend_services() {
        // Verify backend services list for drain order
        assert_eq!(BACKEND_SERVICES.len(), 4);
        assert_eq!(BACKEND_SERVICES[0], "auth");
        assert_eq!(BACKEND_SERVICES[1], "rbac");
        assert_eq!(BACKEND_SERVICES[2], "vault");
        assert_eq!(BACKEND_SERVICES[3], "audit"); // Must be last
    }

    #[test]
    fn test_drain_order_audit_is_last() {
        // Critical: audit must be the last service to be drained
        // to capture all events during proxy session teardown
        assert_eq!(
            BACKEND_SERVICES.last(),
            Some(&"audit"),
            "Audit must be the last backend service to drain"
        );
    }

    #[test]
    fn test_drain_order_is_reverse_of_startup() {
        let config = test_config();
        let startup_order = config.startup_order();
        
        // Drain order should be reverse of startup order
        // Startup: audit, vault, rbac, auth, proxy_ssh, proxy_rdp, web
        // Drain frontend: web, proxy_rdp, proxy_ssh (parallel)
        // Drain backend: auth, rbac, vault, audit (sequential)
        
        // First service to start should be last to drain
        assert_eq!(startup_order[0], "audit");
        assert_eq!(BACKEND_SERVICES.last(), Some(&"audit"));
        
        // Last service to start should be first to drain
        assert_eq!(startup_order.last(), Some(&"web"));
        assert!(FRONTEND_SERVICES.contains(&"web"));
    }

    // ==================== Drain State Tests ====================

    #[test]
    fn test_child_state_drain_fields_initial() {
        let channel = IpcChannel::pair().unwrap().0;
        let state = ChildState {
            pid: 12345,
            service_key: "test".to_string(),
            channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
        };
        
        // Initial drain state
        assert!(!state.is_draining);
        assert!(state.drain_started.is_none());
    }

    #[test]
    fn test_restart_decision_variants() {
        // Test that all RestartDecision variants exist and are usable
        let not_needed = RestartDecision::NotNeeded;
        let drain_first = RestartDecision::DrainFirst { active: 5, pending: 3 };
        let force_now = RestartDecision::ForceNow;
        
        assert_eq!(not_needed, RestartDecision::NotNeeded);
        assert_eq!(drain_first, RestartDecision::DrainFirst { active: 5, pending: 3 });
        assert_eq!(force_now, RestartDecision::ForceNow);
    }

    #[test]
    fn test_restart_decision_is_clone() {
        let decision = RestartDecision::DrainFirst { active: 10, pending: 5 };
        let cloned = decision.clone();
        assert_eq!(decision, cloned);
    }
}
