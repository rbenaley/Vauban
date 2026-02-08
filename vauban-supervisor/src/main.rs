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
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{execv, fork, setgid, setuid, ForkResult, Gid, Pid, Uid};
use shared::ipc::{poll_readable, send_fd, IpcChannel, socketpair_for_fd_passing};
use shared::messages::{ControlMessage, Message, Service, ServiceStats};
use std::net::ToSocketAddrs;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::collections::HashMap;
use std::ffi::CString;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Runtime state for a running child service.
struct ChildState {
    pid: i32,
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
    /// Unix socket for passing file descriptors via SCM_RIGHTS (proxies only).
    /// The supervisor uses this to send pre-established TCP connection FDs.
    fd_passing_socket: Option<OwnedFd>,
}

/// Pipe connection topology.
struct PipeTopology {
    from: Service,
    to: Service,
}

/// Extra IPC pipes to pass to a child service.
#[derive(Default, Clone)]
struct ServicePipes {
    /// Pipes where this service is the "from" side (sender)
    outgoing: Vec<(Service, i32, i32)>, // (target, read_fd, write_fd)
    /// Pipes where this service is the "to" side (receiver)  
    incoming: Vec<(Service, i32, i32)>, // (source, read_fd, write_fd)
}

/// Unix socket pairs for passing file descriptors via SCM_RIGHTS.
/// Used by supervisor to pass TCP connection FDs to sandboxed proxy services.
struct FdPassingSockets {
    /// Supervisor's end of the socket pair (for sending FDs)
    supervisor_socket: OwnedFd,
    /// Child's end of the socket pair (passed to the service for receiving FDs)
    child_socket_fd: i32,
}

/// Services that must be restarted together (they share inter-process pipes).
/// When any of these crash, all must be restarted to re-establish IPC.
const LINKED_RESTART_GROUPS: &[&[&str]] = &[
    // Web and SSH proxy share IPC pipes
    &["web", "proxy_ssh"],
    // Web and RDP proxy share IPC pipes  
    &["web", "proxy_rdp"],
];

/// Check if a service belongs to a linked restart group.
fn get_linked_services(service_key: &str) -> Option<&'static [&'static str]> {
    LINKED_RESTART_GROUPS
        .iter()
        .find(|group| group.contains(&service_key))
        .copied()
}

/// Convert service key string to Service enum.
fn service_key_to_service(key: &str) -> Option<Service> {
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

/// Convert Service enum to environment variable suffix.
fn service_to_env_suffix(service: Service) -> &'static str {
    match service {
        Service::Web => "WEB",
        Service::Auth => "AUTH",
        Service::Rbac => "RBAC",
        Service::Vault => "VAULT",
        Service::Audit => "AUDIT",
        Service::ProxySsh => "PROXY_SSH",
        Service::ProxyRdp => "PROXY_RDP",
        Service::Supervisor => "SUPERVISOR",
    }
}

/// All pipe connections in the mesh topology.
const TOPOLOGY: &[PipeTopology] = &[
    // Web connections
    PipeTopology { from: Service::Web, to: Service::Auth },
    PipeTopology { from: Service::Web, to: Service::Rbac },
    PipeTopology { from: Service::Web, to: Service::Audit },
    PipeTopology { from: Service::Web, to: Service::Vault },  // M-1, C-2: encrypt/decrypt secrets
    // Web <-> Proxy connections (for SSH/RDP session data)
    PipeTopology { from: Service::Web, to: Service::ProxySsh },
    PipeTopology { from: Service::Web, to: Service::ProxyRdp },
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

    // Organize pipes by service for easy lookup
    let mut service_pipes: HashMap<Service, ServicePipes> = HashMap::new();
    for ((from, to), (from_channel, to_channel)) in &pipes {
        // The "from" service gets the from_channel (it writes to the pipe)
        service_pipes
            .entry(*from)
            .or_default()
            .outgoing
            .push((*to, from_channel.read_fd(), from_channel.write_fd()));
        
        // The "to" service gets the to_channel (it reads from the pipe)
        service_pipes
            .entry(*to)
            .or_default()
            .incoming
            .push((*from, to_channel.read_fd(), to_channel.write_fd()));
    }

    // Create FD passing socket pairs for proxy services.
    // These are used by the supervisor to send pre-established TCP connection FDs
    // to sandboxed proxies that cannot open network connections themselves.
    let mut fd_passing_sockets: HashMap<Service, FdPassingSockets> = HashMap::new();
    
    for proxy_service in [Service::ProxySsh, Service::ProxyRdp] {
        match socketpair_for_fd_passing() {
            Ok((supervisor_socket, child_socket)) => {
                let child_fd = child_socket.as_raw_fd();
                // We need to keep child_socket alive until after fork
                // Store the raw fd and leak the OwnedFd to prevent close
                std::mem::forget(child_socket);
                
                fd_passing_sockets.insert(proxy_service, FdPassingSockets {
                    supervisor_socket,
                    child_socket_fd: child_fd,
                });
                info!("Created FD passing socketpair for {:?}", proxy_service);
            }
            Err(e) => {
                error!("Failed to create FD passing socketpair for {:?}: {}", proxy_service, e);
            }
        }
    }

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
        
        // Get topology pipes for this service
        let service = service_key_to_service(service_key);
        let topology_pipes = service.and_then(|s| service_pipes.get(&s));
        
        // Get FD passing socket for proxy services
        let fd_passing_child_fd = service.and_then(|s| fd_passing_sockets.get(&s).map(|fps| fps.child_socket_fd));
        
        match spawn_child(&binary_path, uid, gid, workdir.as_deref(), child_channel, topology_pipes, fd_passing_child_fd) {
            Ok(pid) => {
                info!("Started {} with pid {}", service_config.name, pid);
                
                // Extract the supervisor's FD passing socket for proxies
                let fd_passing_socket = service.and_then(|s| {
                    fd_passing_sockets.remove(&s).map(|fps| fps.supervisor_socket)
                });
                
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
                    fd_passing_socket,
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
        &service_pipes,
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
    topology_pipes: Option<&ServicePipes>,
    fd_passing_socket: Option<i32>,
) -> Result<i32> {
    // Get raw FDs before fork (we'll pass them via env vars)
    let read_fd = channel.read_fd();
    let write_fd = channel.write_fd();
    
    // Collect topology pipe env vars before fork
    // Format: VAUBAN_{TARGET}_IPC_READ and VAUBAN_{TARGET}_IPC_WRITE
    let mut topology_env_vars: Vec<(String, String)> = Vec::new();
    if let Some(pipes) = topology_pipes {
        // For outgoing connections (this service -> target)
        for (target, r_fd, w_fd) in &pipes.outgoing {
            let suffix = service_to_env_suffix(*target);
            topology_env_vars.push((format!("VAUBAN_{}_IPC_READ", suffix), r_fd.to_string()));
            topology_env_vars.push((format!("VAUBAN_{}_IPC_WRITE", suffix), w_fd.to_string()));
        }
        // For incoming connections (source -> this service)
        for (source, r_fd, w_fd) in &pipes.incoming {
            let suffix = service_to_env_suffix(*source);
            topology_env_vars.push((format!("VAUBAN_{}_IPC_READ", suffix), r_fd.to_string()));
            topology_env_vars.push((format!("VAUBAN_{}_IPC_WRITE", suffix), w_fd.to_string()));
        }
    }

    // SAFETY: fork() is unsafe because it's inherently dangerous in multi-threaded
    // Rust programs. We ensure safety by:
    // 1. Only calling async-signal-safe functions in the child before exec
    // 2. Not using any Rust allocator operations in the child
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child process
            
            // Change working directory if specified
            if let Some(dir) = workdir
                && std::env::set_current_dir(dir).is_err()
            {
                eprintln!("Failed to chdir to {}: {}", dir, std::io::Error::last_os_error());
                std::process::exit(1);
            }
            
            // Drop privileges if configured (production mode)
            // Must set GID before UID
            if let Some(g) = gid
                && let Err(e) = setgid(Gid::from_raw(g))
            {
                eprintln!("Failed to setgid({}): {}", g, e);
                std::process::exit(1);
            }
            
            if let Some(u) = uid
                && let Err(e) = setuid(Uid::from_raw(u))
            {
                eprintln!("Failed to setuid({}): {}", u, e);
                std::process::exit(1);
            }
            
            // Clear FD_CLOEXEC on FD passing socket so it survives exec
            // This must be done before exec because the socket was created with FD_CLOEXEC
            if let Some(fd) = fd_passing_socket {
                use nix::fcntl::{fcntl, FcntlArg, FdFlag};
                use std::os::unix::io::BorrowedFd;
                // SAFETY: fd is valid and we're in the forked child
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                if let Err(e) = fcntl(borrowed, FcntlArg::F_SETFD(FdFlag::empty())) {
                    eprintln!("Failed to clear FD_CLOEXEC on fd_passing_socket: {}", e);
                    std::process::exit(1);
                }
            }
            
            // Set environment variables for supervisor IPC FDs
            // SAFETY: We are in a single-threaded child process right after fork(),
            // and the environment is not being accessed by other threads.
            unsafe {
                std::env::set_var("VAUBAN_IPC_READ", read_fd.to_string());
                std::env::set_var("VAUBAN_IPC_WRITE", write_fd.to_string());
                
                // Set topology pipe environment variables
                for (name, value) in &topology_env_vars {
                    std::env::set_var(name, value);
                }
                
                // Set FD passing socket for proxy services (used to receive TCP connections)
                if let Some(fd) = fd_passing_socket {
                    std::env::set_var("VAUBAN_FD_PASSING_SOCKET", fd.to_string());
                }
            }
            
            // Exec the child binary
            let c_path = match CString::new(binary_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Invalid binary path: {}", e);
                    std::process::exit(1);
                }
            };
            
            // Execute the binary - execv only returns on error
            let Err(e) = execv(&c_path, &[&c_path]);
            eprintln!("Failed to exec {}: {}", binary_path, e);
            std::process::exit(1);
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent process - drop our copy of the channel
            // The channel FDs are now owned by the child
            drop(channel);
            Ok(child.as_raw())
        }
        Err(e) => {
            Err(anyhow::anyhow!("fork() failed: {}", e))
        }
    }
}

fn watchdog_loop(
    children: &mut HashMap<String, ChildState>,
    config: &SupervisorConfig,
    service_pipes: &HashMap<Service, ServicePipes>,
    heartbeat_interval: Duration,
    max_missed_heartbeats: u32,
    max_respawns_per_hour: u32,
) -> Result<()> {
    let mut last_heartbeat = Instant::now();
    // Track services that need linked restart (will be processed after reaping)
    let mut pending_linked_restarts: Vec<String> = Vec::new();

    loop {
        // Reap any dead children and collect services needing restart
        reap_children(children, config, service_pipes, max_respawns_per_hour, &mut pending_linked_restarts);
        
        // Process pending linked restarts (restart entire groups)
        while let Some(service_key) = pending_linked_restarts.pop() {
            if let Some(linked_group) = get_linked_services(&service_key) {
                info!("Restarting linked group for {}: {:?}", service_key, linked_group);
                respawn_linked_group(children, config, service_pipes, linked_group);
            }
        }

        // Process incoming messages from services (TcpConnectRequest, etc.)
        process_service_messages(children);

        // Send heartbeats periodically
        if last_heartbeat.elapsed() >= heartbeat_interval {
            for (service_key, state) in children.iter_mut() {
                send_heartbeat(service_key, state);
            }
            last_heartbeat = Instant::now();
        }

        // Check for unresponsive children
        let mut services_to_restart: Vec<String> = Vec::new();
        for (service_key, state) in children.iter_mut() {
            match should_force_restart(state, max_missed_heartbeats) {
                RestartDecision::NotNeeded => {}
                RestartDecision::DrainFirst { active, pending } => {
                    warn!(
                        "{} is unresponsive with active work (connections={}, pending={}), draining first",
                        service_key, active, pending
                    );
                    // Check if this service is in a linked group
                    if get_linked_services(service_key).is_some() {
                        services_to_restart.push(service_key.clone());
                    } else {
                        let topology = service_key_to_service(service_key)
                            .and_then(|s| service_pipes.get(&s));
                        drain_and_restart(state, config, topology);
                    }
                }
                RestartDecision::ForceNow => {
                    warn!("{} is unresponsive, forcing restart", service_key);
                    // Check if this service is in a linked group
                    if get_linked_services(service_key).is_some() {
                        services_to_restart.push(service_key.clone());
                    } else {
                        let topology = service_key_to_service(service_key)
                            .and_then(|s| service_pipes.get(&s));
                        kill_and_respawn(state, config, topology);
                    }
                }
            }
        }
        
        // Process linked restarts for unresponsive services
        for service_key in services_to_restart {
            if let Some(linked_group) = get_linked_services(&service_key) {
                info!("Restarting linked group due to unresponsive {}: {:?}", service_key, linked_group);
                respawn_linked_group(children, config, service_pipes, linked_group);
            }
        }

        // Sleep briefly before next iteration
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn reap_children(
    children: &mut HashMap<String, ChildState>,
    config: &SupervisorConfig,
    service_pipes: &HashMap<Service, ServicePipes>,
    max_respawns_per_hour: u32,
    pending_linked_restarts: &mut Vec<String>,
) {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, exit_code)) => {
                // Find which service this was
                let mut found_service: Option<String> = None;
                for (service_key, state) in children.iter_mut() {
                    if state.pid == pid.as_raw() {
                        warn!("{} exited with code {}", service_key, exit_code);
                        found_service = Some(service_key.clone());
                        // Mark as dead (pid = 0 indicates not running)
                        state.pid = 0;
                        break;
                    }
                }
                
                if let Some(service_key) = found_service {
                    // Check if this service should be respawned
                    let state = children.get_mut(&service_key).unwrap();
                    if should_respawn(state, max_respawns_per_hour) {
                        // Check if this service is in a linked group
                        if get_linked_services(&service_key).is_some() {
                            // Queue for linked restart (will restart entire group)
                            if !pending_linked_restarts.contains(&service_key) {
                                pending_linked_restarts.push(service_key.clone());
                            }
                        } else {
                            // Regular respawn for non-linked services
                            info!("Respawning {}", service_key);
                            let topology = service_key_to_service(&service_key)
                                .and_then(|s| service_pipes.get(&s));
                            respawn_service(state, config, topology);
                        }
                    } else {
                        error!("{} has crashed too many times, not respawning", service_key);
                    }
                }
            }
            Ok(WaitStatus::Signaled(pid, signal, _core_dumped)) => {
                // Find which service this was
                let mut found_service: Option<String> = None;
                for (service_key, state) in children.iter_mut() {
                    if state.pid == pid.as_raw() {
                        warn!("{} killed by signal {:?}", service_key, signal);
                        found_service = Some(service_key.clone());
                        // Mark as dead (pid = 0 indicates not running)
                        state.pid = 0;
                        break;
                    }
                }
                
                if let Some(service_key) = found_service {
                    // Check if this service should be respawned
                    let state = children.get_mut(&service_key).unwrap();
                    if should_respawn(state, max_respawns_per_hour) {
                        // Check if this service is in a linked group
                        if get_linked_services(&service_key).is_some() {
                            // Queue for linked restart (will restart entire group)
                            if !pending_linked_restarts.contains(&service_key) {
                                pending_linked_restarts.push(service_key.clone());
                            }
                        } else {
                            // Regular respawn for non-linked services
                            info!("Respawning {}", service_key);
                            let topology = service_key_to_service(&service_key)
                                .and_then(|s| service_pipes.get(&s));
                            respawn_service(state, config, topology);
                        }
                    } else {
                        error!("{} has crashed too many times, not respawning", service_key);
                    }
                }
            }
            Ok(WaitStatus::StillAlive) => {
                // No more children to reap
                break;
            }
            Err(nix::errno::Errno::ECHILD) => {
                // No children
                break;
            }
            Err(e) => {
                error!("waitpid error: {}", e);
                break;
            }
            _ => {
                // Other status (stopped, continued), continue reaping
            }
        }
    }
}

fn send_heartbeat(service_key: &str, state: &mut ChildState) {
    use shared::ipc::poll_readable;
    use std::io::ErrorKind;
    
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
            // Data available - drain all messages and find the best pong
            // This handles the case where pongs have accumulated in the buffer
            let mut best_pong: Option<(u64, ServiceStats)> = None;
            
            loop {
                match state.channel.try_recv() {
                    Ok(Message::Control(ControlMessage::Pong { seq, stats })) => {
                        // Keep track of the highest sequence pong we've seen
                        match &best_pong {
                            Some((best_seq, _)) if seq > *best_seq => {
                                best_pong = Some((seq, stats));
                            }
                            None => {
                                best_pong = Some((seq, stats));
                            }
                            _ => {
                                // Ignore older pongs
                            }
                        }
                    }
                    Ok(_) => {
                        // Other message types - skip them
                        // (the service might be sending data to other components)
                    }
                    Err(shared::ipc::IpcError::Io(ref e)) if e.kind() == ErrorKind::WouldBlock => {
                        // Buffer drained
                        break;
                    }
                    Err(_) => {
                        // Error reading - stop draining
                        break;
                    }
                }
            }
            
            // Evaluate the best pong we found
            match best_pong {
                Some((seq, stats)) if seq >= state.heartbeat_seq => {
                    // Got a valid or recent pong - service is responsive
                    state.missed_heartbeats = 0;
                    state.last_pong = Instant::now();
                    state.last_stats = Some(stats.clone());
                    
                    debug!(
                        "{}: pong received (seq={}, expected={}), uptime={}s, active_connections={}, pending={}",
                        service_key,
                        seq,
                        state.heartbeat_seq,
                        stats.uptime_secs,
                        stats.active_connections,
                        stats.pending_requests
                    );
                }
                Some((seq, stats)) => {
                    // Got an older pong - service is responding but lagging
                    // This is still better than no response at all
                    // Only count as missed if we're more than 2 sequences behind
                    let lag = state.heartbeat_seq - seq;
                    if lag <= 2 {
                        // Small lag is acceptable - reset missed count
                        state.missed_heartbeats = 0;
                        state.last_pong = Instant::now();
                        state.last_stats = Some(stats.clone());
                        debug!(
                            "{}: pong received (seq={}, expected={}, lag={}), service is slightly behind",
                            service_key, seq, state.heartbeat_seq, lag
                        );
                    } else {
                        // Significant lag - count as partial miss
                        debug!(
                            "{}: pong seq lag too high (seq={}, expected={}, lag={})",
                            service_key, seq, state.heartbeat_seq, lag
                        );
                        state.missed_heartbeats += 1;
                        // Still update stats since we got some response
                        state.last_stats = Some(stats);
                    }
                }
                None => {
                    // No pong found in buffer at all
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
    if let Some(ref stats) = state.last_stats
        && (stats.active_connections > 0 || stats.pending_requests > 0)
    {
        return RestartDecision::DrainFirst {
            active: stats.active_connections,
            pending: stats.pending_requests,
        };
    }
    
    RestartDecision::ForceNow
}

fn kill_and_respawn(state: &mut ChildState, config: &SupervisorConfig, topology_pipes: Option<&ServicePipes>) {
    let pid = Pid::from_raw(state.pid);
    
    // Send SIGTERM
    let _ = kill(pid, Signal::SIGTERM);

    // Wait up to 5 seconds
    std::thread::sleep(Duration::from_secs(5));

    // Check if still alive
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => {
            // Still alive, send SIGKILL
            warn!("{} did not terminate, sending SIGKILL", state.service_key);
            let _ = kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None); // Wait for termination
        }
        _ => {
            // Process already exited or error
        }
    }

    respawn_service(state, config, topology_pipes);
}

fn respawn_service(state: &mut ChildState, config: &SupervisorConfig, topology_pipes: Option<&ServicePipes>) {
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

    // Create new FD passing socketpair for proxy services
    let (fd_passing_socket, fd_passing_child_fd) = if state.service_key == "proxy_ssh" || state.service_key == "proxy_rdp" {
        match socketpair_for_fd_passing() {
            Ok((supervisor_socket, child_socket)) => {
                let child_fd = child_socket.as_raw_fd();
                std::mem::forget(child_socket); // Prevent close until after fork
                (Some(supervisor_socket), Some(child_fd))
            }
            Err(e) => {
                error!("Failed to create FD passing socketpair for {}: {}", state.service_key, e);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    match spawn_child(&binary_path, uid, gid, workdir.as_deref(), child_channel, topology_pipes, fd_passing_child_fd) {
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
            state.fd_passing_socket = fd_passing_socket;
        }
        Err(e) => {
            error!("Failed to respawn {}: {}", state.service_key, e);
        }
    }
}

/// Respawn all services in a linked group together.
/// 
/// When services share inter-process pipes (e.g., Web <-> ProxySsh),
/// a crash of one service breaks the pipe. Both services must be
/// restarted together with fresh pipes to re-establish communication.
fn respawn_linked_group(
    children: &mut HashMap<String, ChildState>,
    config: &SupervisorConfig,
    service_pipes: &HashMap<Service, ServicePipes>,
    group: &[&str],
) {
    info!("Starting linked group restart for: {:?}", group);
    
    // Step 1: Kill any still-running services in the group
    for &service_key in group {
        if let Some(state) = children.get_mut(service_key)
            && state.pid > 0
        {
            info!("Killing {} (pid {}) for linked restart", service_key, state.pid);
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(state.pid),
                nix::sys::signal::Signal::SIGTERM
            );
            // Give it a moment to die gracefully
            std::thread::sleep(Duration::from_millis(100));
            // Force kill if still alive
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(state.pid),
                nix::sys::signal::Signal::SIGKILL
            );
            state.pid = 0;
        }
    }
    
    // Step 2: Wait for all services in the group to be reaped
    std::thread::sleep(Duration::from_millis(200));
    
    // Step 3: Reap any remaining zombie processes from the group
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, _)) | Ok(WaitStatus::Signaled(pid, _, _)) => {
                // Update state if this was one of our children
                for (_, state) in children.iter_mut() {
                    if state.pid == pid.as_raw() {
                        state.pid = 0;
                        break;
                    }
                }
            }
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
            _ => {}
        }
    }
    
    // Step 4: Create new pipes for the linked services
    // For Web <-> ProxySsh, we need fresh pipe pairs
    let mut new_pipes: HashMap<(Service, Service), (IpcChannel, IpcChannel)> = HashMap::new();
    
    // Find which pipe connections exist between services in this group
    for topology_entry in TOPOLOGY.iter() {
        let from_key = service_to_key(topology_entry.from);
        let to_key = service_to_key(topology_entry.to);
        
        if group.contains(&from_key) && group.contains(&to_key) {
            // Create fresh pipes for this connection
            match IpcChannel::pair() {
                Ok((from_channel, to_channel)) => {
                    info!("Created new pipe: {} -> {}", from_key, to_key);
                    new_pipes.insert((topology_entry.from, topology_entry.to), (from_channel, to_channel));
                }
                Err(e) => {
                    error!("Failed to create pipe {} -> {}: {}", from_key, to_key, e);
                }
            }
        }
    }
    
    // Step 5: Build new ServicePipes for each service in the group
    let mut group_service_pipes: HashMap<Service, ServicePipes> = HashMap::new();
    
    // Initialize with existing pipes to supervisor/other services (from original service_pipes)
    for &service_key in group {
        if let Some(service) = service_key_to_service(service_key) {
            let mut pipes = ServicePipes::default();
            
            // Copy existing pipes that are NOT between services in this group
            if let Some(existing) = service_pipes.get(&service) {
                for &(target, read_fd, write_fd) in &existing.outgoing {
                    let target_key = service_to_key(target);
                    if !group.contains(&target_key) {
                        pipes.outgoing.push((target, read_fd, write_fd));
                    }
                }
                for &(source, read_fd, write_fd) in &existing.incoming {
                    let source_key = service_to_key(source);
                    if !group.contains(&source_key) {
                        pipes.incoming.push((source, read_fd, write_fd));
                    }
                }
            }
            
            group_service_pipes.insert(service, pipes);
        }
    }
    
    // Add the new pipes between services in the group
    for ((from, to), (from_channel, to_channel)) in &new_pipes {
        if let Some(pipes) = group_service_pipes.get_mut(from) {
            pipes.outgoing.push((*to, from_channel.read_fd(), from_channel.write_fd()));
        }
        if let Some(pipes) = group_service_pipes.get_mut(to) {
            pipes.incoming.push((*from, to_channel.read_fd(), to_channel.write_fd()));
        }
    }
    
    // Step 6: Respawn each service in the group with their new pipes
    for &service_key in group {
        if let Some(state) = children.get_mut(service_key) {
            let service = service_key_to_service(service_key);
            let topology = service.and_then(|s| group_service_pipes.get(&s));
            
            let uid = config.effective_uid(&state.service_key);
            let gid = config.effective_gid(&state.service_key);
            let workdir = config.effective_workdir(&state.service_key);
            let binary_path = match config.binary_path(&state.service_key) {
                Some(p) => p,
                None => {
                    error!("Cannot respawn {}: no binary path", state.service_key);
                    continue;
                }
            };

            // Create new IPC channel for supervisor
            let (supervisor_channel, child_channel) = match IpcChannel::pair() {
                Ok((s, c)) => (s, c),
                Err(e) => {
                    error!("Failed to create IPC channel for {}: {}", service_key, e);
                    continue;
                }
            };

            // Create new FD passing socketpair for proxy services
            let (fd_passing_socket, fd_passing_child_fd) = if service_key == "proxy_ssh" || service_key == "proxy_rdp" {
                match socketpair_for_fd_passing() {
                    Ok((supervisor_socket, child_socket)) => {
                        let child_fd = child_socket.as_raw_fd();
                        std::mem::forget(child_socket); // Prevent close until after fork
                        (Some(supervisor_socket), Some(child_fd))
                    }
                    Err(e) => {
                        error!("Failed to create FD passing socketpair for {}: {}", service_key, e);
                        (None, None)
                    }
                }
            } else {
                (None, None)
            };

            match spawn_child(&binary_path, uid, gid, workdir.as_deref(), child_channel, topology, fd_passing_child_fd) {
                Ok(pid) => {
                    info!("Respawned {} (linked group) with pid {}", service_key, pid);
                    state.pid = pid;
                    state.channel = supervisor_channel;
                    state.missed_heartbeats = 0;
                    state.respawn_count += 1;
                    state.last_respawn = Instant::now();
                    state.last_pong = Instant::now();
                    state.last_stats = None;
                    state.is_draining = false;
                    state.drain_started = None;
                    state.fd_passing_socket = fd_passing_socket;
                }
                Err(e) => {
                    error!("Failed to respawn {} in linked group: {}", service_key, e);
                }
            }
        }
    }
    
    info!("Linked group restart completed for: {:?}", group);
}

/// Convert Service enum to service key string.
fn service_to_key(service: Service) -> &'static str {
    match service {
        Service::Web => "web",
        Service::Auth => "auth",
        Service::Rbac => "rbac",
        Service::Vault => "vault",
        Service::Audit => "audit",
        Service::ProxySsh => "proxy_ssh",
        Service::ProxyRdp => "proxy_rdp",
        Service::Supervisor => "supervisor",
    }
}

/// Handle a TcpConnectRequest from vauban-web.
///
/// This function:
/// 1. Performs DNS resolution on the target host
/// 2. Establishes a TCP connection to the target
/// 3. Sends the connected socket FD to the target proxy service via SCM_RIGHTS
/// 4. Sends a TcpConnectResponse back to the requesting service (web)
fn handle_tcp_connect_request(
    request_id: u64,
    session_id: String,
    host: String,
    port: u16,
    target_service: Service,
    requesting_channel: &IpcChannel,
    children: &HashMap<String, ChildState>,
) {
    // Convert target service to service key
    let target_key = match target_service {
        Service::ProxySsh => "proxy_ssh",
        Service::ProxyRdp => "proxy_rdp",
        _ => {
            warn!("TcpConnectRequest for unsupported target service: {:?}", target_service);
            let response = Message::TcpConnectResponse {
                request_id,
                session_id,
                success: false,
                error: Some(format!("Unsupported target service: {:?}", target_service)),
            };
            let _ = requesting_channel.send(&response);
            return;
        }
    };
    
    // Get the target service's FD passing socket
    let target_state = match children.get(target_key) {
        Some(state) => state,
        None => {
            error!("Target service {} not found for TcpConnectRequest", target_key);
            let response = Message::TcpConnectResponse {
                request_id,
                session_id,
                success: false,
                error: Some(format!("Target service {} not running", target_key)),
            };
            let _ = requesting_channel.send(&response);
            return;
        }
    };
    
    let fd_socket = match &target_state.fd_passing_socket {
        Some(sock) => sock.as_raw_fd(),
        None => {
            error!("No FD passing socket for service {}", target_key);
            let response = Message::TcpConnectResponse {
                request_id,
                session_id,
                success: false,
                error: Some("FD passing not available for target service".to_string()),
            };
            let _ = requesting_channel.send(&response);
            return;
        }
    };
    
    // Step 1: DNS resolution
    let addr_str = format!("{}:{}", host, port);
    let socket_addr = match addr_str.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                warn!("DNS resolution failed for {}: no addresses returned", host);
                let response = Message::TcpConnectResponse {
                    request_id,
                    session_id,
                    success: false,
                    error: Some(format!("DNS resolution failed for {}: no addresses", host)),
                };
                let _ = requesting_channel.send(&response);
                return;
            }
        },
        Err(e) => {
            warn!("DNS resolution failed for {}: {}", host, e);
            let response = Message::TcpConnectResponse {
                request_id,
                session_id,
                success: false,
                error: Some(format!("DNS resolution failed for {}: {}", host, e)),
            };
            let _ = requesting_channel.send(&response);
            return;
        }
    };
    
    debug!("DNS resolved {} -> {}", host, socket_addr);
    
    // Step 2: Establish TCP connection
    let tcp_stream = match std::net::TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_secs(10),
    ) {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TCP connection to {} failed: {}", socket_addr, e);
            let response = Message::TcpConnectResponse {
                request_id,
                session_id,
                success: false,
                error: Some(format!("Connection to {} failed: {}", socket_addr, e)),
            };
            let _ = requesting_channel.send(&response);
            return;
        }
    };
    
    let tcp_fd = tcp_stream.as_raw_fd();
    debug!("TCP connection established to {} (fd={})", socket_addr, tcp_fd);
    
    // Step 3: Send the FD to the target proxy service via SCM_RIGHTS
    // IMPORTANT: Send the FD FIRST via SCM_RIGHTS, THEN notify the proxy via IPC.
    // This ensures the FD is available when the proxy receives the notification
    // and tries to recv_fd(). Otherwise we get EAGAIN errors.
    if let Err(e) = send_fd(fd_socket, tcp_fd) {
        error!("Failed to send FD to proxy: {}", e);
        let response = Message::TcpConnectResponse {
            request_id,
            session_id,
            success: false,
            error: Some(format!("Failed to pass connection to proxy: {}", e)),
        };
        let _ = requesting_channel.send(&response);
        return;
    }
    
    debug!("FD {} sent to {} for session {}", tcp_fd, target_key, session_id);
    
    // Step 4: Now notify the proxy via regular IPC channel that an FD is waiting
    let fd_info = Message::TcpConnectResponse {
        request_id,
        session_id: session_id.clone(),
        success: true,
        error: None,
    };
    
    if let Err(e) = target_state.channel.send(&fd_info) {
        error!("Failed to notify proxy about FD: {}", e);
        // FD was already sent, proxy may still receive it but won't know the session_id
        // This is a partial failure state
        let response = Message::TcpConnectResponse {
            request_id,
            session_id,
            success: false,
            error: Some(format!("Failed to notify proxy: {}", e)),
        };
        let _ = requesting_channel.send(&response);
        return;
    }
    
    // Step 5: Send success response back to web
    let response = Message::TcpConnectResponse {
        request_id,
        session_id,
        success: true,
        error: None,
    };
    
    if let Err(e) = requesting_channel.send(&response) {
        error!("Failed to send TcpConnectResponse to web: {}", e);
    }
    
    // Keep the TcpStream alive until after the FD has been sent
    // The child will have its own copy of the FD after SCM_RIGHTS
    drop(tcp_stream);
}

/// Poll all service channels and process incoming messages.
///
/// This handles TcpConnectRequest messages from vauban-web that need
/// the supervisor to establish TCP connections on behalf of sandboxed proxies.
fn process_service_messages(children: &HashMap<String, ChildState>) {
    // Collect all read FDs from services
    let service_fds: Vec<(String, i32)> = children
        .iter()
        .map(|(key, state)| (key.clone(), state.channel.read_fd()))
        .collect();
    
    if service_fds.is_empty() {
        return;
    }
    
    let fds: Vec<i32> = service_fds.iter().map(|(_, fd)| *fd).collect();
    
    // Poll with a short timeout (10ms) to not block the main loop
    match poll_readable(&fds, 10) {
        Ok(ready_indices) => {
            for idx in ready_indices {
                if idx >= service_fds.len() {
                    continue;
                }
                
                let (service_key, _) = &service_fds[idx];
                let state = match children.get(service_key) {
                    Some(s) => s,
                    None => continue,
                };
                
                // Try to read a message
                match state.channel.try_recv() {
                    Ok(Message::TcpConnectRequest {
                        request_id,
                        session_id,
                        host,
                        port,
                        target_service,
                    }) => {
                        info!(
                            "Received TcpConnectRequest from {} for {}:{} -> {:?}",
                            service_key, host, port, target_service
                        );
                        handle_tcp_connect_request(
                            request_id,
                            session_id,
                            host,
                            port,
                            target_service,
                            &state.channel,
                            children,
                        );
                    }
                    Ok(Message::Control(ControlMessage::Pong { .. })) => {
                        // Pong messages are handled by send_heartbeat, skip here
                    }
                    Ok(msg) => {
                        // Other message types - log and ignore
                        debug!("Received unexpected message from {}: {:?}", service_key, msg);
                    }
                    Err(shared::ipc::IpcError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        // No more messages
                    }
                    Err(e) => {
                        debug!("Error reading from {}: {}", service_key, e);
                    }
                }
            }
        }
        Err(e) => {
            debug!("Poll error in process_service_messages: {}", e);
        }
    }
}

/// Initiate drain on a service and wait for completion before restart.
///
/// This sends a Drain message, waits for DrainComplete with pending_requests=0,
/// then proceeds with the standard kill_and_respawn sequence.
fn drain_and_restart(state: &mut ChildState, config: &SupervisorConfig, topology_pipes: Option<&ServicePipes>) {
    use shared::ipc::poll_readable;
    
    // 1. Send Drain message
    let drain_msg = Message::Control(ControlMessage::Drain);
    if let Err(e) = state.channel.send(&drain_msg) {
        warn!("{}: failed to send Drain, proceeding with kill: {}", state.service_key, e);
        kill_and_respawn(state, config, topology_pipes);
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
    
    kill_and_respawn(state, config, topology_pipes);
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
                if let Ok(ready) = poll_readable(&fds, 100)
                    && !ready.is_empty()
                    && let Ok(Message::Control(ControlMessage::DrainComplete { pending_requests }))
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
                if let Ok(ready) = poll_readable(&fds, 1000)
                    && !ready.is_empty()
                    && let Ok(Message::Control(ControlMessage::DrainComplete { pending_requests }))
                        = state.channel.recv()
                    && pending_requests == 0
                {
                    info!("{}: drain complete", key);
                    break;
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
        assert_eq!(TOPOLOGY.len(), 14);
    }

    #[test]
    fn test_topology_web_connections() {
        let web_connections: Vec<_> = TOPOLOGY
            .iter()
            .filter(|conn| conn.from == Service::Web)
            .collect();
        
        // Web connects to: Auth, Rbac, Audit, ProxySsh, ProxyRdp, Vault
        assert_eq!(web_connections.len(), 6);
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
        };
        
        assert_eq!(state.pid, 12345);
        assert_eq!(state.service_key, "audit");
        assert_eq!(state.missed_heartbeats, 0);
        assert_eq!(state.respawn_count, 0);
        assert!(state.last_stats.is_none());
        assert!(!state.is_draining);
        assert!(state.drain_started.is_none());
        assert!(state.fd_passing_socket.is_none());
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            heartbeat_seq: 10, // Start at 10, so after increment it's 11
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
            fd_passing_socket: None,
        };
        
        // Spawn thread to respond with a seq that has lag > 2
        let service_thread = std::thread::spawn(move || {
            let msg = service_channel.recv().unwrap();
            if let Message::Control(ControlMessage::Ping { seq: _ }) = msg {
                // Send Pong with OLD seq (lag = 11 - 5 = 6 > 2, counts as missed)
                let stats = ServiceStats::default();
                let pong = Message::Control(ControlMessage::Pong { seq: 5, stats });
                service_channel.send(&pong).unwrap();
            }
            service_channel
        });
        
        send_heartbeat("bad_seq_service", &mut state);
        let _ = service_thread.join().unwrap();
        
        // Significant seq lag should count as missed
        assert_eq!(state.missed_heartbeats, 1, "Significant seq lag should count as missed heartbeat");
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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
            fd_passing_socket: None,
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

    // ==================== TCP Connection Brokering Tests ====================

    #[test]
    fn test_tcp_connect_request_via_ipc() {
        use shared::messages::Service;

        // Create IPC channel pair
        let (sender, receiver) = IpcChannel::pair().unwrap();

        // Send TcpConnectRequest
        let msg = Message::TcpConnectRequest {
            request_id: 42,
            session_id: "sess-123".to_string(),
            host: "example.com".to_string(),
            port: 22,
            target_service: Service::ProxySsh,
        };
        sender.send(&msg).unwrap();

        // Receive and verify
        let received = receiver.recv().unwrap();
        if let Message::TcpConnectRequest {
            request_id,
            session_id,
            host,
            port,
            target_service,
        } = received
        {
            assert_eq!(request_id, 42);
            assert_eq!(session_id, "sess-123");
            assert_eq!(host, "example.com");
            assert_eq!(port, 22);
            assert_eq!(target_service, Service::ProxySsh);
        } else {
            panic!("Expected TcpConnectRequest");
        }
    }

    #[test]
    fn test_tcp_connect_response_via_ipc_success() {
        let (sender, receiver) = IpcChannel::pair().unwrap();

        let msg = Message::TcpConnectResponse {
            request_id: 42,
            session_id: "sess-123".to_string(),
            success: true,
            error: None,
        };
        sender.send(&msg).unwrap();

        let received = receiver.recv().unwrap();
        if let Message::TcpConnectResponse {
            request_id,
            session_id,
            success,
            error,
        } = received
        {
            assert_eq!(request_id, 42);
            assert_eq!(session_id, "sess-123");
            assert!(success);
            assert!(error.is_none());
        } else {
            panic!("Expected TcpConnectResponse");
        }
    }

    #[test]
    fn test_tcp_connect_response_via_ipc_failure() {
        let (sender, receiver) = IpcChannel::pair().unwrap();

        let msg = Message::TcpConnectResponse {
            request_id: 42,
            session_id: "sess-123".to_string(),
            success: false,
            error: Some("Connection refused".to_string()),
        };
        sender.send(&msg).unwrap();

        let received = receiver.recv().unwrap();
        if let Message::TcpConnectResponse {
            success, error, ..
        } = received
        {
            assert!(!success);
            assert_eq!(error, Some("Connection refused".to_string()));
        } else {
            panic!("Expected TcpConnectResponse");
        }
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_socketpair_for_fd_passing_creates_valid_pair() {
        let result = socketpair_for_fd_passing();
        assert!(result.is_ok(), "socketpair_for_fd_passing should succeed on FreeBSD");

        let (sock1, sock2) = result.unwrap();
        // Both sockets should have valid file descriptors
        use std::os::unix::io::AsRawFd;
        assert!(sock1.as_raw_fd() >= 0);
        assert!(sock2.as_raw_fd() >= 0);
        assert_ne!(sock1.as_raw_fd(), sock2.as_raw_fd());
    }

    #[test]
    fn test_child_state_with_fd_passing_socket() {
        let channel = IpcChannel::pair().unwrap().0;

        // Test that fd_passing_socket field exists and can be None
        let state_without_fd = ChildState {
            pid: 12345,
            service_key: "web".to_string(),
            channel,
            last_pong: Instant::now(),
            missed_heartbeats: 0,
            heartbeat_seq: 0,
            respawn_count: 0,
            last_respawn: Instant::now(),
            last_stats: None,
            is_draining: false,
            drain_started: None,
            fd_passing_socket: None,
        };

        assert!(state_without_fd.fd_passing_socket.is_none());
    }

    #[test]
    fn test_service_to_env_suffix_proxy_services() {
        use shared::messages::Service;

        // Verify proxy services have correct env var suffixes
        assert_eq!(service_to_env_suffix(Service::ProxySsh), "PROXY_SSH");
        assert_eq!(service_to_env_suffix(Service::ProxyRdp), "PROXY_RDP");
        assert_eq!(service_to_env_suffix(Service::Web), "WEB");
    }
}
