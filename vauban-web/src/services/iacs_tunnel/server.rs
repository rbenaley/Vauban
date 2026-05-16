//! In-process russh `Handler` + `Server` implementation for the
//! IACS tunnel sshd. Rejects every channel type except a single
//! `direct-tcpip` to the configured `target_addr`.
//!
//! Refusal matrix (pinned by the adversarial test suite):
//!
//! | client request                      | response                |
//! |-------------------------------------|-------------------------|
//! | `password` auth                     | `Auth::reject()`        |
//! | `keyboard-interactive` auth         | `Auth::reject()`        |
//! | `pty-req`                           | `channel_failure`       |
//! | `shell`                             | `channel_failure`       |
//! | `exec`                              | `channel_failure`       |
//! | `subsystem`                         | `channel_failure`       |
//! | `auth-agent-req@openssh.com`        | `channel_failure`       |
//! | `tcpip-forward` (-R)                | `Ok(false)`             |
//! | `streamlocal-forward@openssh.com`   | `Ok(false)`             |
//! | `direct-streamlocal@openssh.com`    | `Ok(false)`             |
//! | `direct-tcpip` to wrong host:port   | `Ok(false)`             |
//! | `direct-tcpip` past per-login cap   | `Ok(false)`             |
//! | `channel_open_session`              | `Ok(false)`             |
//! | `channel_open_x11`                  | `Ok(false)`             |
//! | `direct-tcpip` to target_addr       | accepted, relay starts  |
//!
//! Multiple concurrent `direct-tcpip` channels per authenticated
//! login are accepted by design (each TCP `accept()` on the EWS-side
//! `ssh -L` listener spawns a new channel; a single SSH login MUST
//! be able to serve more than one client at a time). The per-login
//! cap (`IacsTunnelConfig::max_concurrent_channels_per_session`,
//! default 16, `0` disables) bounds in-flight channels and is the
//! sole defence against fan-out exfil. Closed channels return their
//! slot to the pool.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh::keys::ssh_key::Algorithm;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::IacsTunnelConfig;
use crate::db::DbPool;
use crate::services::broadcast::{BroadcastService, WsChannel};

use super::auth::{AuthOutcome, verify_pubkey};
use super::registry::{TunnelHandle, TunnelRegistry};
use super::relay::{connect_target, copy_with_counter, validate_target};

/// Top-level server. Built once at boot, lives for the duration of
/// the `vauban-web` process.
pub struct IacsTunnelServer {
    pub registry: TunnelRegistry,
    pub db_pool: DbPool,
    pub target_addr: Arc<String>,
    pub config: Arc<IacsTunnelConfig>,
    /// Optional broadcast service. When wired (production main),
    /// the server pushes lifecycle + stats events on
    /// `WsChannel::SessionLive(uuid)` so the status page updates
    /// without polling. When `None` (the L3 adversarial test
    /// suite, which builds a sshd-only fixture), broadcasts are
    /// silently skipped.
    pub broadcast: Option<BroadcastService>,
}

impl IacsTunnelServer {
    pub fn new(
        registry: TunnelRegistry,
        db_pool: DbPool,
        config: IacsTunnelConfig,
    ) -> Self {
        let target_addr = Arc::new(config.target_addr.clone());
        Self {
            registry,
            db_pool,
            target_addr,
            config: Arc::new(config),
            broadcast: None,
        }
    }

    pub fn with_broadcast(mut self, b: BroadcastService) -> Self {
        self.broadcast = Some(b);
        self
    }
}

impl Server for IacsTunnelServer {
    type Handler = IacsTunnelHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        IacsTunnelHandler {
            registry: self.registry.clone(),
            db_pool: self.db_pool.clone(),
            target_addr: self.target_addr.clone(),
            peer_addr,
            session_uuid_str: Mutex::new(None),
            handle: Mutex::new(None),
            live_channels: Arc::new(AtomicUsize::new(0)),
            max_channels_per_session: self.config.max_concurrent_channels_per_session as usize,
            broadcast: self.broadcast.clone(),
        }
    }

    fn handle_session_error(
        &mut self,
        error: <Self::Handler as Handler>::Error,
    ) {
        // Connection-level errors (KEX abort, malformed packet) are
        // non-fatal: the per-connection task already exited cleanly,
        // we just log so operators can correlate with peer logs.
        debug!(error = ?error, "iacs_tunnel: session error");
    }
}

/// Per-connection handler. Carries the resolved session/EWS/user
/// triple once auth succeeds; before that it is empty so a deny
/// path cannot leak previous-session state.
pub struct IacsTunnelHandler {
    pub registry: TunnelRegistry,
    pub db_pool: DbPool,
    pub target_addr: Arc<String>,
    pub peer_addr: Option<std::net::SocketAddr>,
    /// `Some(uuid_str)` once `auth_publickey` accepted. Lock held
    /// only briefly across non-await sections so we never collide
    /// with the russh polling loop.
    pub session_uuid_str: Mutex<Option<String>>,
    /// `Some(handle)` once a tunnel has been accepted on this
    /// connection. Shared across every concurrent `direct-tcpip`
    /// channel of the same login (the `(session_uuid, ews_uuid,
    /// user_uuid)` triple is per-login, not per-channel).
    pub handle: Mutex<Option<TunnelHandle>>,
    /// Live `direct-tcpip` channel counter on this connection. Each
    /// successful channel open increments the counter; the relay
    /// task decrements it when the channel closes. Bounded by
    /// `max_channels_per_session`. The pre-fix single-shot
    /// `AtomicBool::swap(true)` is replaced by this bounded counter
    /// so `ssh -L` can serve more than one local TCP `accept()` per
    /// SSH login (the normal OpenSSH behaviour).
    pub live_channels: Arc<AtomicUsize>,
    /// Snapshot of `IacsTunnelConfig::max_concurrent_channels_per_session`
    /// at handler-creation time. `0` disables the cap.
    pub max_channels_per_session: usize,
    /// Optional broadcast service for L5 lifecycle / stats events.
    pub broadcast: Option<BroadcastService>,
}

/// Broadcast helper. Pushes a JSON payload on the
/// `WsChannel::SessionLive(uuid)` channel iff broadcast is wired.
/// All errors are swallowed -- a status push failure must never
/// bring down the tunnel itself.
async fn push_event(
    broadcast: &Option<BroadcastService>,
    session_uuid: &Uuid,
    payload: serde_json::Value,
) {
    if let Some(b) = broadcast {
        let channel = WsChannel::SessionLive(session_uuid.to_string());
        let channel_name = channel.as_str();
        let _ = b.send_raw(&channel_name, payload.to_string()).await;
    }
}

impl Handler for IacsTunnelHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<Auth, Self::Error> {
        // Defence in depth: the Config below already restricts
        // methods to publickey, but if a future refactor widens
        // it we still refuse.
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
        // Accept the offer so russh continues the signature
        // exchange. The real DB-backed verification happens in
        // `auth_publickey`.
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let mut conn = match self.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, peer = ?self.peer_addr, "iacs_tunnel: DB pool failure on auth");
                return Ok(Auth::reject());
            }
        };
        let outcome = verify_pubkey(&mut conn, user, public_key).await;
        match outcome {
            AuthOutcome::Accept { ews_uuid, user_uuid } => {
                info!(
                    peer = ?self.peer_addr,
                    session_uuid = %user,
                    %ews_uuid,
                    %user_uuid,
                    "iacs_tunnel: auth accepted"
                );
                let session_uuid = match uuid::Uuid::parse_str(user) {
                    Ok(u) => u,
                    Err(_) => {
                        // Should never happen: verify_pubkey already
                        // parses the user as a UUID before accepting.
                        // We log loudly and reject defensively rather
                        // than panic in a long-running server task.
                        warn!(
                            user = %user,
                            "iacs_tunnel: auth accepted but session UUID failed to re-parse \
                             (defensive reject)"
                        );
                        return Ok(Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        });
                    }
                };
                let handle = TunnelHandle::new(session_uuid, ews_uuid, user_uuid);
                if let Ok(mut peer_slot) = handle.peer_addr.lock() {
                    *peer_slot = self.peer_addr;
                }
                {
                    let mut slot = self.session_uuid_str.lock().await;
                    *slot = Some(user.to_string());
                }
                {
                    let mut slot = self.handle.lock().await;
                    *slot = Some(handle.clone());
                }
                self.registry.insert(handle);
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

    // -- channel openings: refuse everything except direct-tcpip
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
        warn!(peer = ?self.peer_addr, "iacs_tunnel: refused channel_open_direct_streamlocal");
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
        // Acquire a slot from the per-login channel pool. Multiple
        // concurrent `direct-tcpip` channels are accepted by design;
        // the cap protects against fan-out exfil. The slot is
        // released by `spawn_relay` when the relay task completes,
        // so a closed channel returns its slot to the pool.
        if self.max_channels_per_session > 0 {
            let prev = self.live_channels.fetch_add(1, Ordering::SeqCst);
            if prev >= self.max_channels_per_session {
                self.live_channels.fetch_sub(1, Ordering::SeqCst);
                warn!(
                    peer = ?self.peer_addr,
                    cap = self.max_channels_per_session,
                    in_flight = prev,
                    "iacs_tunnel: refused direct-tcpip (per-login channel cap reached)"
                );
                return Ok(false);
            }
        } else {
            self.live_channels.fetch_add(1, Ordering::SeqCst);
        }
        // From here on, every early-return MUST decrement the slot.
        if !validate_target(host_to_connect, port_to_connect, &self.target_addr) {
            self.live_channels.fetch_sub(1, Ordering::SeqCst);
            warn!(
                peer = ?self.peer_addr,
                requested = format!("{}:{}", host_to_connect, port_to_connect),
                expected = %self.target_addr,
                "iacs_tunnel: refused direct-tcpip to wrong target"
            );
            return Ok(false);
        }
        let handle = match self.handle.lock().await.clone() {
            Some(h) => h,
            None => {
                self.live_channels.fetch_sub(1, Ordering::SeqCst);
                error!(peer = ?self.peer_addr, "iacs_tunnel: direct-tcpip without auth state");
                return Ok(false);
            }
        };
        // Open the upstream TCP connection. If it fails, we
        // refuse the channel so the EWS sees a clean error.
        let target = self.target_addr.to_string();
        let upstream = match connect_target(&target).await {
            Ok(s) => s,
            Err(e) => {
                self.live_channels.fetch_sub(1, Ordering::SeqCst);
                error!(
                    peer = ?self.peer_addr,
                    target = %target,
                    error = %e,
                    "iacs_tunnel: connect to target failed"
                );
                handle.close();
                self.registry.remove(&handle.session_uuid);
                return Ok(false);
            }
        };
        info!(
            peer = ?self.peer_addr,
            session_uuid = %handle.session_uuid,
            target = %target,
            "iacs_tunnel: tunnel_active"
        );
        // L5: flip `proxy_sessions.status` to `tunnel_active` and
        // push the WS lifecycle event so the status page
        // transitions from "waiting" to "active" without polling.
        let pool = self.db_pool.clone();
        let sess = handle.session_uuid;
        tokio::spawn(async move {
            if let Ok(mut c) = pool.get().await {
                use crate::schema::proxy_sessions as ps;
                use diesel::prelude::*;
                use diesel_async::RunQueryDsl;
                let _ = diesel::update(ps::table.filter(ps::uuid.eq(sess)))
                    .set((
                        ps::status.eq("tunnel_active"),
                        ps::connected_at.eq(chrono::Utc::now()),
                    ))
                    .execute(&mut c)
                    .await;
            }
        });
        push_event(
            &self.broadcast,
            &handle.session_uuid,
            serde_json::json!({
                "type": "tunnel_active",
                "peer_ip": self.peer_addr.map(|a| a.ip().to_string()),
                "ews_uuid": handle.ews_uuid.to_string(),
            }),
        )
        .await;
        spawn_relay(
            channel,
            upstream,
            handle.clone(),
            self.broadcast.clone(),
            Arc::clone(&self.live_channels),
        );
        Ok(true)
    }

    // -- session-channel commands: refuse them all (defence in
    // depth: these can only fire after channel_open_session,
    // which we already refused)
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
        // Best-effort cleanup if the connection died before the
        // relay tasks observed the close. Reading the handle slot
        // from inside Drop is safe (no await).
        if let Ok(slot) = self.handle.try_lock()
            && let Some(h) = slot.as_ref()
        {
            self.registry.close_and_remove(&h.session_uuid);
            debug!(session_uuid = %h.session_uuid, "iacs_tunnel: drop cleanup");
        }
    }
}

/// Spawn the bidirectional relay between a russh channel (the EWS)
/// and the upstream TCP socket (the IACS asset). Each direction
/// runs in its own task so a stuck reader on one side cannot
/// block the other; both tasks exit when either side EOFs or
/// when the `TunnelHandle` is closed.
fn spawn_relay(
    channel: Channel<Msg>,
    upstream: tokio::net::TcpStream,
    handle: TunnelHandle,
    broadcast: Option<BroadcastService>,
    live_channels: Arc<AtomicUsize>,
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

    // L5: periodic stats pusher. Samples bytes_in/out every 5 s
    // and pushes a `tunnel_stats` payload on
    // `WsChannel::SessionLive(uuid)`. Exits when the handle
    // closes (the relay tasks signal via `wait_close`).
    let stats_handle = handle.clone();
    let stats_broadcast = broadcast.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.tick().await;
        loop {
            tokio::select! {
                _ = stats_handle.wait_close() => break,
                _ = tick.tick() => {
                    let (bytes_in, bytes_out) = stats_handle.counters();
                    push_event(
                        &stats_broadcast,
                        &stats_handle.session_uuid,
                        serde_json::json!({
                            "type": "tunnel_stats",
                            "bytes_in": bytes_in,
                            "bytes_out": bytes_out,
                        }),
                    )
                    .await;
                }
            }
        }
    });

    tokio::spawn(async move {
        // Tear-down sentinel: when EITHER direction exits, the
        // tunnel CHANNEL is over. We release the per-login channel
        // slot so a new local TCP `accept()` on the EWS can open
        // another `direct-tcpip` (the bug-fix that turned the
        // pre-fix `AtomicBool::swap(true)` into a bounded counter).
        //
        // We also call `h_close.close()` and emit `tunnel_closed`
        // for backward compat with the v0.7.x status-page WS
        // contract: the in-process flavour is single-channel-shaped
        // by design and is being deprecated in favour of
        // `vauban-proxy-iacs` (which has a cleaner per-channel
        // handle model). For multi-channel scenarios on this
        // legacy flavour the close is idempotent; subsequent
        // channels still relay correctly because `validate_target`
        // and the handle slot are independent of the registry.
        let _ = tokio::join!(outbound, inbound);
        live_channels
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .ok();
        h_close.close();
        let (bin, bout) = h_close.counters();
        info!(
            session_uuid = %h_close.session_uuid,
            bytes_in = bin,
            bytes_out = bout,
            channel_count_after = live_channels.load(Ordering::SeqCst),
            "iacs_tunnel: tunnel_closed"
        );
        push_event(
            &broadcast,
            &h_close.session_uuid,
            serde_json::json!({
                "type": "tunnel_closed",
                "bytes_in": bin,
                "bytes_out": bout,
                "reason": "ews_disconnect",
            }),
        )
        .await;
    });
}

// ===================================================================
// Boot
// ===================================================================

/// Build the russh `Config` (host key, methods, timeouts) for the
/// IACS sshd. Public so the adversarial tests can rebuild the same
/// config and run an isolated server on `127.0.0.1:0`.
pub fn build_server_config(host_key: PrivateKey) -> Arc<ServerConfig> {
    Arc::new(ServerConfig {
        // Publickey only -- no password fallback, no
        // keyboard-interactive. The handler also refuses both
        // explicitly as belt-and-braces.
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        // 1 s constant-time rejection (russh default), good
        // enough to defeat naive timing oracles. The L6 lot
        // tightens this further with a stddev pin.
        auth_rejection_time: std::time::Duration::from_secs(1),
        keys: vec![host_key],
        // 10 min idle timeout: enough for an industrial poll
        // cycle to span without re-handshake; short enough to
        // cap leaked sessions.
        inactivity_timeout: Some(std::time::Duration::from_secs(600)),
        keepalive_interval: Some(std::time::Duration::from_secs(60)),
        keepalive_max: 3,
        ..Default::default()
    })
}

/// Load (or generate-and-persist) the ed25519 host key for the
/// IACS sshd. The file is written with `0o600` permissions and
/// only ever generated when missing -- callers that pass a path
/// inside a writable directory.
pub fn load_or_generate_host_key(path: &PathBuf) -> std::io::Result<PrivateKey> {
    if path.exists() {
        let data = std::fs::read_to_string(path)?;
        // OpenSSH-format private key.
        return PrivateKey::from_openssh(&data)
            .map_err(|e| std::io::Error::other(format!("invalid host key: {}", e)));
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
    .map_err(|e| std::io::Error::other(format!("ed25519 keygen: {}", e)))?;
    let openssh = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| std::io::Error::other(format!("encode host key: {}", e)))?;
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

/// Spawn the IACS sshd as a `tokio::spawn`ed task. Returns a
/// `JoinHandle` so the caller can await it (the test suite
/// does), and the bound `SocketAddr` so the test can connect
/// without racing the bind.
///
/// Production callers ignore the join handle (the task lives for
/// the duration of the process); a panic inside the russh task
/// is caught at the per-session boundary inside russh, so a
/// malformed packet from one client cannot tear down the whole
/// listener.
pub async fn spawn_iacs_tunnel_server(
    registry: TunnelRegistry,
    db_pool: DbPool,
    config: IacsTunnelConfig,
) -> std::io::Result<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    spawn_iacs_tunnel_server_with_broadcast(registry, db_pool, config, None).await
}

/// Variant of [`spawn_iacs_tunnel_server`] that wires a
/// [`BroadcastService`] so the server can push WS events on
/// `WsChannel::SessionLive(uuid)`. Production main calls this;
/// the L3 adversarial test suite calls the broadcastless
/// variant above.
pub async fn spawn_iacs_tunnel_server_with_broadcast(
    registry: TunnelRegistry,
    db_pool: DbPool,
    config: IacsTunnelConfig,
    broadcast: Option<BroadcastService>,
) -> std::io::Result<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    if !config.enabled {
        return Err(std::io::Error::other(
            "iacs_tunnel: server is disabled in config",
        ));
    }
    if config.bind_addr == config.target_addr {
        return Err(std::io::Error::other(format!(
            "iacs_tunnel: bind_addr ({}) must not equal target_addr ({})",
            config.bind_addr, config.target_addr
        )));
    }
    let host_key = load_or_generate_host_key(&PathBuf::from(&config.host_key_path))?;
    let server_config = build_server_config(host_key);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    let local = listener.local_addr()?;
    info!(bind_addr = %local, target = %config.target_addr, "iacs_tunnel: sshd listening");
    let mut srv = IacsTunnelServer::new(registry, db_pool, config);
    if let Some(b) = broadcast {
        srv = srv.with_broadcast(b);
    }
    let join = tokio::spawn(async move {
        let mut running = srv.run_on_socket(server_config, &listener);
        (&mut running).await
    });
    Ok((local, join))
}
