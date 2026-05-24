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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Config as ServerConfig, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use shared::messages::Message;
use tokio::sync::{Mutex, mpsc::UnboundedSender};
use tracing::{debug, error, info, warn};

use crate::auth::{AuthOutcome, PendingSessions, PendingTunnel, verify_publickey};
use crate::iacs_recording::{ChannelRecorder, IacsRecordingHub};
use crate::registry::{SessionHandles, TunnelHandle, TunnelRegistry};
use crate::relay::{copy_with_counter_and_record, validate_target};
use shared::messages::IacsRecordingDirection;
use shared::iacs_protocol::ExpectedProfile;

/// Channel used by the russh handler / relay tasks to push
/// `IacsTunnelStatusUpdate` and `IacsTunnelClosed` IPC messages
/// back to vauban-web. Wrapped in an `mpsc` so a single writer
/// task drains the queue and serialises the writes onto the web
/// IPC fd: multiple russh tasks may emit concurrently without
/// racing on the underlying pipe.
///
/// In tests `None` disables the reporting (the test harness drives
/// the russh handler directly without an IPC peer); production
/// always wires this up in `main.rs` BEFORE the accept loop spawns.
pub type WebReporter = Option<UnboundedSender<Message>>;

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
    async fn open(&self, pending: &PendingTunnel) -> std::io::Result<tokio::net::TcpStream>;
}

/// Server-level state shared across every accepted EWS connection.
pub struct IacsTunnelServer {
    pub registry: TunnelRegistry,
    pub pending: PendingSessions,
    /// Map of `russh::server::Handle` per authenticated SSH session,
    /// populated in `Handler::auth_succeeded` and consulted by the
    /// `Message::IacsTunnelTerminate` IPC handler to dispatch a
    /// `Disconnect::ByApplication` and force-tear-down the EWS link
    /// even when no `direct-tcpip` channel is currently open.
    pub session_handles: SessionHandles,
    pub upstream: Arc<dyn UpstreamOpener>,
    /// Cap on the number of concurrent `direct-tcpip` channels
    /// accepted per authenticated EWS connection. `0` disables the
    /// cap (unlimited concurrent channels per login -- still gated by
    /// the per-session target-address pin and the supervisor broker).
    /// See `IacsTunnelConfig::max_concurrent_channels_per_session` in
    /// `vauban-web` for the rationale.
    pub max_channels_per_session: usize,
    /// Outbound IPC channel to vauban-web. See [`WebReporter`].
    pub web_reporter: WebReporter,
    /// PCAP recording hub (ProxyIacs → Audit). `None` when recording disabled.
    pub recording: Option<IacsRecordingHub>,
}

impl IacsTunnelServer {
    pub fn new(
        registry: TunnelRegistry,
        pending: PendingSessions,
        session_handles: SessionHandles,
        upstream: Arc<dyn UpstreamOpener>,
        max_channels_per_session: usize,
        web_reporter: WebReporter,
        recording: Option<IacsRecordingHub>,
    ) -> Self {
        Self {
            registry,
            pending,
            session_handles,
            upstream,
            max_channels_per_session,
            web_reporter,
            recording,
        }
    }
}

impl Server for IacsTunnelServer {
    type Handler = IacsTunnelHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        IacsTunnelHandler {
            registry: self.registry.clone(),
            pending: self.pending.clone(),
            session_handles: self.session_handles.clone(),
            upstream: self.upstream.clone(),
            peer_addr,
            authorized: Mutex::new(None),
            live_channels: Arc::new(AtomicUsize::new(0)),
            max_channels_per_session: self.max_channels_per_session,
            web_reporter: self.web_reporter.clone(),
            recording: self.recording.clone(),
            channel_counter: Arc::new(AtomicUsize::new(0)),
            tunnel_active_emitted: Arc::new(AtomicBool::new(false)),
            session_total_bytes_in: Arc::new(AtomicUsize::new(0)),
            session_total_bytes_out: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        debug!(error = ?error, "iacs_tunnel: session error");
    }
}

/// Per-connection handler. Holds the resolved tunnel triple after
/// `auth_publickey` accepted -- including the per-session
/// `(asset_host, asset_port)` used by the `validate_target` gate.
pub struct IacsTunnelHandler {
    pub registry: TunnelRegistry,
    pub pending: PendingSessions,
    /// Per-session russh handle map -- see
    /// [`SessionHandles`](crate::registry::SessionHandles). Cloned
    /// from the parent `IacsTunnelServer` so every handler shares
    /// the same underlying `DashMap`.
    pub session_handles: SessionHandles,
    pub upstream: Arc<dyn UpstreamOpener>,
    pub peer_addr: Option<std::net::SocketAddr>,
    /// `Some(pending)` once `auth_publickey` accepted.
    pub authorized: Mutex<Option<PendingTunnel>>,
    /// Live `direct-tcpip` channel counter on this connection. Each
    /// successful channel open increments the counter; the relay task
    /// decrements it when the channel closes (so a closed channel
    /// returns its slot to the pool, allowing the EWS to open new
    /// `direct-tcpip` channels for new local TCP `accept()`s -- the
    /// normal `ssh -L` workflow).
    pub live_channels: Arc<AtomicUsize>,
    /// Snapshot of the server-level cap at handler-creation time.
    /// `0` means unlimited. Per-handler so a future config-reload
    /// path stays trivial.
    pub max_channels_per_session: usize,
    /// Outbound IPC channel to vauban-web -- see [`WebReporter`].
    pub web_reporter: WebReporter,
    /// PCAP recording hub when enabled.
    pub recording: Option<IacsRecordingHub>,
    /// Monotonic `channel_id` counter for this EWS SSH login.
    pub channel_counter: Arc<AtomicUsize>,
    /// `true` once the per-EWS-login `IacsTunnelStatusUpdate { status =
    /// "tunnel_active" }` has been emitted on the web IPC. The first
    /// successful `direct-tcpip` flips it; subsequent channels do not
    /// re-emit (the DB transition `waiting_client -> tunnel_active`
    /// is idempotent in vauban-web but we still avoid the log noise).
    pub tunnel_active_emitted: Arc<AtomicBool>,
    /// Cumulative byte counters across every channel of this EWS
    /// login. Used to populate the `IacsTunnelClosed { bytes_in,
    /// bytes_out }` payload at handler-drop time.
    pub session_total_bytes_in: Arc<AtomicUsize>,
    pub session_total_bytes_out: Arc<AtomicUsize>,
}

impl Handler for IacsTunnelHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
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

    /// Capture the per-session `russh::server::Handle` so the
    /// `Message::IacsTunnelTerminate` IPC can force-disconnect the
    /// SSH session from outside the Handler call-stack. This is the
    /// EARLIEST point in the russh lifecycle where both the resolved
    /// `PendingTunnel.session_uuid` (stored in `self.authorized` by
    /// `auth_publickey`) and the live `Session` ref are
    /// simultaneously available; capturing here covers the full
    /// `waiting_client` window (auth done, no `direct-tcpip` yet)
    /// AND every subsequent `tunnel_active` / multi-channel state.
    ///
    /// The handle is stored in the shared
    /// [`SessionHandles`](crate::registry::SessionHandles) registry
    /// and removed in this handler's `Drop` impl. Idempotent: a
    /// second auth on the same `session_uuid` (not expected in
    /// practice but possible after a reconnect refactor) replaces
    /// the previous handle.
    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if let Some(p) = self.authorized.lock().await.as_ref() {
            self.session_handles
                .insert(p.session_uuid, session.handle());
            debug!(
                session_uuid = %p.session_uuid,
                "iacs_tunnel: russh handle registered for forced disconnect"
            );
        }
        Ok(())
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
        // Acquire a slot from the per-login channel pool. Multiple
        // concurrent `direct-tcpip` channels per authenticated SSH
        // login are accepted by design: every TCP `accept()` on the
        // EWS-side `ssh -L` listener spawns a new SSH channel over
        // the existing tunnel, and that's how a single SSH login
        // serves more than one client. The cap protects against
        // fan-out exfil while preserving legitimate multi-client
        // industrial traffic; every channel still validates the
        // pinned `(asset_host, asset_port)` and flows through the
        // supervisor's SCM_RIGHTS broker, so multi-channel does NOT
        // widen the reachable target set.
        //
        // `max_channels_per_session = 0` disables the cap (unlimited
        // concurrent channels per login). The slot is RELEASED in
        // `spawn_relay` when the channel closes, so a closed channel
        // returns its slot to the pool -- the bug fix that turned
        // a single-shot `AtomicBool::swap(true)` into a bounded
        // counter.
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
        // From here on, EVERY early-return path MUST decrement
        // `live_channels` so a rejected channel does not eat a slot
        // forever. The successful path hands ownership of the slot
        // to the relay task, which decrements when the relay ends.
        let pending = match self.authorized.lock().await.clone() {
            Some(p) => p,
            None => {
                self.live_channels.fetch_sub(1, Ordering::SeqCst);
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
            self.live_channels.fetch_sub(1, Ordering::SeqCst);
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
                self.live_channels.fetch_sub(1, Ordering::SeqCst);
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
            channel_count = self.live_channels.load(Ordering::SeqCst),
            "iacs_tunnel: tunnel_active"
        );
        // Emit the per-session `tunnel_active` IPC ONCE per EWS
        // login (idempotent on the vauban-web side, but we keep
        // the log noise down). This is the seam that flips
        // `proxy_sessions.status` from `waiting_client` to
        // `tunnel_active` in the database, populates `connected_at`
        // and the `client_ip` (via `peer_ip`), and triggers the
        // `WsChannel::ActiveSessionsList` broadcast that surfaces
        // the row on `/sessions/active` and the Bastion Watch
        // dashboard. Without this IPC the row stays in
        // `waiting_client` forever and never appears on the active
        // sessions surfaces (issue: 0.7.11 active-list integration
        // landed without the producer side, so the IPC hooks were
        // dormant).
        if !self.tunnel_active_emitted.swap(true, Ordering::SeqCst)
            && let Some(tx) = self.web_reporter.as_ref()
        {
            let peer_ip = self.peer_addr.map(|sa| sa.ip().to_string());
            let msg = Message::IacsTunnelStatusUpdate {
                session_id: pending.session_uuid.to_string(),
                status: "tunnel_active".to_string(),
                bytes_in: 0,
                bytes_out: 0,
                peer_ip,
            };
            if let Err(e) = tx.send(msg) {
                warn!(
                    session_uuid = %pending.session_uuid,
                    error = %e,
                    "iacs_tunnel: failed to enqueue IacsTunnelStatusUpdate (web channel closed?)"
                );
            }
        }
        let handle = TunnelHandle::new(
            pending.session_uuid,
            pending.user_uuid,
            pending.asset_uuid,
            pending.ews_uuid,
            self.peer_addr,
        );
        self.registry.insert(handle.clone());
        let channel_id = self.channel_counter.fetch_add(1, Ordering::SeqCst) as u32 + 1;
        let recorder = self.recording.as_ref().map(|hub| {
            hub.send_channel_start(
                &pending.session_uuid.to_string(),
                channel_id,
                &pending.asset_host,
                pending.asset_port,
            );
            hub.channel_recorder(pending.session_uuid.to_string(), channel_id)
        });
        spawn_relay(RelayJob {
            channel,
            upstream: upstream_stream,
            handle,
            live_channels: Arc::clone(&self.live_channels),
            session_total_bytes_in: Arc::clone(&self.session_total_bytes_in),
            session_total_bytes_out: Arc::clone(&self.session_total_bytes_out),
            expected_profile: ExpectedProfile::from_industrial_label(&pending.industrial_protocol),
            recorder,
            recording_hub: self.recording.clone(),
            channel_id,
        });
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
            // Drop the russh handle slot so a subsequent terminate
            // IPC for the same `session_uuid` becomes a no-op
            // instead of trying to disconnect a dead session.
            self.session_handles.remove(&p.session_uuid);
            debug!(session_uuid = %p.session_uuid, "iacs_tunnel: drop cleanup");
            // Notify vauban-web so the `proxy_sessions.status` row
            // flips to `terminated`, `disconnected_at` is anchored,
            // and the row leaves `/sessions/active`. Only fires if a
            // `tunnel_active` was previously emitted -- a connection
            // that never reached `direct-tcpip` (failed auth, no
            // channel) was never persisted as `tunnel_active`, so
            // there is nothing to close in vauban-web's view.
            if self.tunnel_active_emitted.load(Ordering::SeqCst)
                && let Some(tx) = self.web_reporter.as_ref()
            {
                let peer_ip = self.peer_addr.map(|sa| sa.ip().to_string());
                let bytes_in = self.session_total_bytes_in.load(Ordering::SeqCst) as u64;
                let bytes_out = self.session_total_bytes_out.load(Ordering::SeqCst) as u64;
                let msg = Message::IacsTunnelClosed {
                    request_id: 0,
                    session_id: p.session_uuid.to_string(),
                    reason: "ews_disconnect".to_string(),
                    bytes_in,
                    bytes_out,
                    peer_ip,
                };
                if let Err(e) = tx.send(msg) {
                    debug!(
                        session_uuid = %p.session_uuid,
                        error = %e,
                        "iacs_tunnel: drop could not enqueue IacsTunnelClosed"
                    );
                }
            }
            if self.tunnel_active_emitted.load(Ordering::SeqCst)
                && let Some(ref hub) = self.recording
            {
                hub.send_session_end(&p.session_uuid.to_string());
            }
        }
    }
}

struct RelayJob {
    channel: Channel<Msg>,
    upstream: tokio::net::TcpStream,
    handle: TunnelHandle,
    live_channels: Arc<AtomicUsize>,
    session_total_bytes_in: Arc<AtomicUsize>,
    session_total_bytes_out: Arc<AtomicUsize>,
    expected_profile: ExpectedProfile,
    recorder: Option<ChannelRecorder>,
    recording_hub: Option<IacsRecordingHub>,
    channel_id: u32,
}

fn spawn_relay(job: RelayJob) {
    let RelayJob {
        channel,
        upstream,
        handle,
        live_channels,
        session_total_bytes_in,
        session_total_bytes_out,
        expected_profile,
        recorder,
        recording_hub,
        channel_id,
    } = job;
    let stream = channel.into_stream();
    let (reader_ssh, writer_ssh) = tokio::io::split(stream);
    let (reader_tcp, writer_tcp) = upstream.into_split();
    let h_out = handle.clone();
    let h_in = handle.clone();
    let bytes_out = handle.bytes_out.clone();
    let bytes_in = handle.bytes_in.clone();
    let h_close = handle.clone();
    let session_uuid = handle.session_uuid;
    let session_id_str = session_uuid.to_string();
    let recorder_out = recorder.clone();
    let outbound = tokio::spawn(async move {
        let outcome = crate::protocol_gate::filtered_copy_with_counter(
            reader_ssh,
            writer_tcp,
            bytes_out,
            h_out.clone(),
            expected_profile,
            session_uuid,
            recorder_out,
        )
        .await;
        if matches!(
            outcome,
            crate::protocol_gate::ProtocolGateOutcome::ForeignProtocol { .. }
                | crate::protocol_gate::ProtocolGateOutcome::Unconfirmed
        ) {
            h_out.close();
        }
    });
    let inbound = tokio::spawn(async move {
        let _ = copy_with_counter_and_record(
            reader_tcp,
            writer_ssh,
            bytes_in,
            h_in,
            IacsRecordingDirection::AssetToEws,
            recorder,
        )
        .await;
    });
    tokio::spawn(async move {
        let _ = tokio::join!(outbound, inbound);
        if let Some(ref hub) = recording_hub {
            hub.send_channel_end(&session_id_str, channel_id);
        }
        let (bin, bout) = h_close.counters();
        // Accumulate this channel's traffic into the per-EWS-login
        // totals so the `IacsTunnelClosed` IPC emitted at handler
        // drop carries the cumulative byte counts (sum across every
        // `direct-tcpip` channel of the same session).
        session_total_bytes_in.fetch_add(bin as usize, Ordering::SeqCst);
        session_total_bytes_out.fetch_add(bout as usize, Ordering::SeqCst);
        h_close.close();
        // Release the per-login channel slot so the EWS can open a
        // new `direct-tcpip` for the next local TCP `accept()`.
        // Saturating sub: a panic in the relay task that ran before
        // the increment would otherwise underflow.
        live_channels
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .ok();
        info!(
            session_uuid = %h_close.session_uuid,
            bytes_in = bin,
            bytes_out = bout,
            channel_count_after = live_channels.load(Ordering::SeqCst),
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

// `load_or_generate_host_key` has moved to
// `shared::iacs_host_key::load_or_generate_host_key`. The proxy NEVER
// opens the host key path itself any more: the supervisor pre-loads
// it BEFORE fork (`prepare_host_key_fd`) and the proxy parses the
// inherited FD BEFORE Capsicum (`read_host_key_from_fd`). See the
// `host_key_loaded_before_capsicum_test` pin tests for the invariant.
