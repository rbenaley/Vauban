//! In-process russh `Handler` + `Server` for `vauban-proxy-iacs`.
//!
//! Same refusal matrix as the legacy in-process flavour: every
//! channel except a single `direct-tcpip` to the per-session pinned
//! `(asset_host, asset_port)` is rejected, every auth method except
//! `publickey` is rejected, and every session-scoped sub-request
//! (pty, shell, exec, subsystem, agent, tcpip-forward,
//! streamlocal-forward) returns `channel_failure` / `Ok(false)`.
//!
//! The opening of the upstream TCP connection is delegated to a
//! caller-supplied [`UpstreamOpener`]: this is the seam the main
//! binary uses to talk to `vauban-supervisor` over IPC and receive
//! the brokered FD via SCM_RIGHTS.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use russh::keys::ssh_key::Algorithm;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::auth::{AuthOutcome, PendingSessions, PendingTunnel, verify_publickey};
use crate::registry::{TunnelHandle, TunnelRegistry};
use crate::relay::{copy_with_counter, validate_target};

/// Trait abstraction over "open the upstream TCP connection to the
/// industrial asset". Production wires this to the IPC client that
/// sends `Message::TcpConnectRequest` to `vauban-supervisor` and
/// awaits the SCM_RIGHTS response. Tests can stub it with a
/// `tokio::io::duplex` or a `tokio::net::TcpStream::connect`.
#[async_trait::async_trait]
pub trait UpstreamOpener: Send + Sync + 'static {
    /// Open a connection to `(host, port)` for the pre-authorized
    /// session. Implementations MUST surface the supervisor's
    /// `TcpConnectResponse` failure as a non-`Ok` `Result`.
    async fn open(
        &self,
        pending: &PendingTunnel,
    ) -> std::io::Result<tokio::net::TcpStream>;
}

/// Server-level state shared across every accepted EWS connection.
pub struct IacsTunnelServer {
    pub registry: TunnelRegistry,
    pub pending: PendingSessions,
    pub upstream: Arc<dyn UpstreamOpener>,
}

impl IacsTunnelServer {
    pub fn new(
        registry: TunnelRegistry,
        pending: PendingSessions,
        upstream: Arc<dyn UpstreamOpener>,
    ) -> Self {
        Self {
            registry,
            pending,
            upstream,
        }
    }
}

impl Server for IacsTunnelServer {
    type Handler = IacsTunnelHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        IacsTunnelHandler {
            registry: self.registry.clone(),
            pending: self.pending.clone(),
            upstream: self.upstream.clone(),
            peer_addr,
            authorized: Mutex::new(None),
            channel_open: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn handle_session_error(
        &mut self,
        error: <Self::Handler as Handler>::Error,
    ) {
        debug!(error = ?error, "iacs_tunnel: session error");
    }
}

/// Per-connection handler. Holds the resolved tunnel triple after
/// `auth_publickey` accepted -- including the per-session
/// `(asset_host, asset_port)` used by the `validate_target` gate.
pub struct IacsTunnelHandler {
    pub registry: TunnelRegistry,
    pub pending: PendingSessions,
    pub upstream: Arc<dyn UpstreamOpener>,
    pub peer_addr: Option<std::net::SocketAddr>,
    /// `Some(pending)` once `auth_publickey` accepted.
    pub authorized: Mutex<Option<PendingTunnel>>,
    /// Lockless fast-path against a second `direct-tcpip` on the
    /// same connection.
    pub channel_open: std::sync::atomic::AtomicBool,
}

impl Handler for IacsTunnelHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'_>>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let outcome = verify_publickey(&self.pending, user, public_key, Instant::now()).await;
        match outcome {
            AuthOutcome::Accept(pending) => {
                info!(
                    peer = ?self.peer_addr,
                    session_uuid = %pending.session_uuid,
                    user_uuid = %pending.user_uuid,
                    asset_uuid = %pending.asset_uuid,
                    ews_uuid = %pending.ews_uuid,
                    asset_target = format!("{}:{}", pending.asset_host, pending.asset_port),
                    "iacs_tunnel: auth accepted"
                );
                let mut slot = self.authorized.lock().await;
                *slot = Some(pending);
                Ok(Auth::Accept)
            }
            AuthOutcome::Reject(reason) => {
                debug!(
                    peer = ?self.peer_addr,
                    session_uuid = %user,
                    ?reason,
                    "iacs_tunnel: auth rejected"
                );
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused channel_open_session");
        Ok(false)
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused channel_open_x11");
        Ok(false)
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused channel_open_forwarded_tcpip");
        Ok(false)
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            peer = ?self.peer_addr,
            "iacs_tunnel: refused channel_open_direct_streamlocal"
        );
        Ok(false)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // At-most-one direct-tcpip per accepted SSH login: prevents
        // multi-channel exfil over a single auth.
        if self
            .channel_open
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            warn!(
                peer = ?self.peer_addr,
                "iacs_tunnel: refused second direct-tcpip on same session"
            );
            return Ok(false);
        }
        let pending = match self.authorized.lock().await.clone() {
            Some(p) => p,
            None => {
                error!(
                    peer = ?self.peer_addr,
                    "iacs_tunnel: direct-tcpip without auth state"
                );
                return Ok(false);
            }
        };
        // Per-session target validation: the EWS MUST request a
        // `direct-tcpip` to exactly the `(asset_host, asset_port)`
        // pinned in `IacsTunnelOpen`. Anything else is rejected.
        if !validate_target(
            host_to_connect,
            port_to_connect,
            &pending.asset_host,
            pending.asset_port,
        ) {
            warn!(
                peer = ?self.peer_addr,
                requested = format!("{}:{}", host_to_connect, port_to_connect),
                expected = format!("{}:{}", pending.asset_host, pending.asset_port),
                "iacs_tunnel: refused direct-tcpip to wrong target"
            );
            return Ok(false);
        }
        // Open the upstream connection through the supervisor
        // broker. On failure we close the channel so the EWS sees
        // a clean error.
        let upstream_stream = match self.upstream.open(&pending).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    peer = ?self.peer_addr,
                    target = format!("{}:{}", pending.asset_host, pending.asset_port),
                    error = %e,
                    "iacs_tunnel: upstream connect failed"
                );
                return Ok(false);
            }
        };
        info!(
            peer = ?self.peer_addr,
            session_uuid = %pending.session_uuid,
            target = format!("{}:{}", pending.asset_host, pending.asset_port),
            "iacs_tunnel: tunnel_active"
        );
        let handle = TunnelHandle::new(
            pending.session_uuid,
            pending.user_uuid,
            pending.asset_uuid,
            pending.ews_uuid,
            self.peer_addr,
        );
        self.registry.insert(handle.clone());
        spawn_relay(channel, upstream_stream, handle);
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused tcpip_forward (-R)");
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused streamlocal_forward");
        Ok(false)
    }
}

impl Drop for IacsTunnelHandler {
    fn drop(&mut self) {
        if let Ok(slot) = self.authorized.try_lock()
            && let Some(p) = slot.as_ref()
        {
            self.registry.close_and_remove(&p.session_uuid);
            debug!(session_uuid = %p.session_uuid, "iacs_tunnel: drop cleanup");
        }
    }
}

fn spawn_relay(
    channel: Channel<Msg>,
    upstream: tokio::net::TcpStream,
    handle: TunnelHandle,
) {
    let stream = channel.into_stream();
    let (reader_ssh, writer_ssh) = tokio::io::split(stream);
    let (reader_tcp, writer_tcp) = upstream.into_split();
    let h_out = handle.clone();
    let h_in = handle.clone();
    let bytes_out = handle.bytes_out.clone();
    let bytes_in = handle.bytes_in.clone();
    let h_close = handle.clone();
    let outbound = tokio::spawn(async move {
        let _ = copy_with_counter(reader_ssh, writer_tcp, bytes_out, h_out).await;
    });
    let inbound = tokio::spawn(async move {
        let _ = copy_with_counter(reader_tcp, writer_ssh, bytes_in, h_in).await;
    });
    tokio::spawn(async move {
        let _ = tokio::join!(outbound, inbound);
        h_close.close();
        let (bin, bout) = h_close.counters();
        info!(
            session_uuid = %h_close.session_uuid,
            bytes_in = bin,
            bytes_out = bout,
            "iacs_tunnel: tunnel_closed"
        );
    });
}

/// Build the russh server config (host key, methods, timeouts).
pub fn build_server_config(host_key: PrivateKey) -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: std::time::Duration::from_secs(1),
        keys: vec![host_key],
        inactivity_timeout: Some(std::time::Duration::from_secs(600)),
        keepalive_interval: Some(std::time::Duration::from_secs(60)),
        keepalive_max: 3,
        ..Default::default()
    })
}

/// Load (or generate-and-persist) the ed25519 host key.
pub fn load_or_generate_host_key(path: &PathBuf) -> std::io::Result<PrivateKey> {
    if path.exists() {
        let data = std::fs::read_to_string(path)?;
        return PrivateKey::from_openssh(&data)
            .map_err(|e| std::io::Error::other(format!("invalid host key: {e}")));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::OsRng,
        Algorithm::Ed25519,
    )
    .map_err(|e| std::io::Error::other(format!("ed25519 keygen: {e}")))?;
    let openssh = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| std::io::Error::other(format!("encode host key: {e}")))?;
    std::fs::write(path, openssh.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)?.permissions();
        perm.set_mode(0o600);
        std::fs::set_permissions(path, perm)?;
    }
    Ok(key)
}
