//! Hop-2 bytes on the dedicated web data pipe.
//!
//! The leaf has no TCP listener. `vauban-web` sends one
//! [`Message::McpRelayRequest`] plus ordered [`Message::McpRelayBody`]
//! chunks; this module reassembles them and feeds the existing `/mcp`
//! router. Responses go back as chunks on the same pipe.

use crate::tunnel::TunnelTimeouts;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use shared::ipc::{IpcChannel, IpcError};
use shared::messages::{MCP_PIPE_CHUNK_BYTES, Message};
use shared::pipe_store::EXIT_CODE_RESPAWN;
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc};
use tower::ServiceExt;
use tracing::{debug, info, warn};

pub const RELAY_MAX_INFLIGHT: usize = 64;

/// Who delivered this hop-2 request. Missing on the router is fail-closed.
#[derive(Clone, Debug)]
pub enum McpIngress {
    Direct {
        #[allow(dead_code)]
        client_ip: String,
    },
    Tunnel {
        #[allow(dead_code)]
        tunnel_id: u64,
        #[allow(dead_code)]
        client_ip: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    Header,
    Oversize,
    UnknownRelay,
    Protocol,
}

#[derive(Debug)]
struct Inflight {
    client_ip: String,
    authorization: String,
    content_type: String,
    accept: String,
    mcp_session_id: Option<String>,
    mcp_protocol_version: Option<String>,
    body_len: u32,
    chunks: BTreeMap<u32, Vec<u8>>,
    saw_last: bool,
    last_seq: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRelay {
    pub relay_id: u64,
    pub client_ip: String,
    pub authorization: String,
    pub content_type: String,
    pub accept: String,
    pub mcp_session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub body: Vec<u8>,
}

/// Reassembles concurrent relays. Chunks may arrive out of order.
#[derive(Default)]
pub struct RelayAssembler {
    inflight: BTreeMap<u64, Inflight>,
}

impl RelayAssembler {
    pub fn push(&mut self, msg: &Message) -> Result<Option<AssembledRelay>, (u64, AssembleError)> {
        match msg {
            Message::McpRelayRequest {
                relay_id,
                client_ip,
                authorization,
                content_type,
                accept,
                mcp_session_id,
                mcp_protocol_version,
                body_len,
            } => {
                if !header_ok(authorization.as_str())
                    || !header_safe(content_type)
                    || !header_safe(accept)
                    || mcp_session_id.as_deref().is_some_and(|s| !header_safe(s))
                    || mcp_protocol_version
                        .as_deref()
                        .is_some_and(|s| !header_safe(s))
                {
                    return Err((*relay_id, AssembleError::Header));
                }
                if *body_len as usize > crate::upstream_http::MAX_UPSTREAM_BODY_BYTES {
                    return Err((*relay_id, AssembleError::Oversize));
                }
                self.inflight.insert(
                    *relay_id,
                    Inflight {
                        client_ip: client_ip.clone(),
                        authorization: authorization.as_str().to_string(),
                        content_type: content_type.clone(),
                        accept: accept.clone(),
                        mcp_session_id: mcp_session_id.clone(),
                        mcp_protocol_version: mcp_protocol_version.clone(),
                        body_len: *body_len,
                        chunks: BTreeMap::new(),
                        saw_last: false,
                        last_seq: None,
                    },
                );
                if *body_len == 0 {
                    return Ok(self.take_if_complete(*relay_id));
                }
                Ok(None)
            }
            Message::McpRelayBody {
                relay_id,
                seq,
                last,
                data,
            } => {
                let Some(slot) = self.inflight.get_mut(relay_id) else {
                    return Err((*relay_id, AssembleError::UnknownRelay));
                };
                if slot.chunks.contains_key(seq) {
                    return Err((*relay_id, AssembleError::Protocol));
                }
                if let Some(last_seq) = slot.last_seq
                    && *seq > last_seq
                {
                    return Err((*relay_id, AssembleError::Protocol));
                }
                if *last {
                    if slot.saw_last {
                        return Err((*relay_id, AssembleError::Protocol));
                    }
                    slot.saw_last = true;
                    slot.last_seq = Some(*seq);
                }
                slot.chunks.insert(*seq, data.clone());
                let total: usize = slot.chunks.values().map(Vec::len).sum();
                if total > slot.body_len as usize {
                    return Err((*relay_id, AssembleError::Oversize));
                }
                Ok(self.take_if_complete(*relay_id))
            }
            _ => Ok(None),
        }
    }

    fn take_if_complete(&mut self, relay_id: u64) -> Option<AssembledRelay> {
        let ready = self.inflight.get(&relay_id).is_some_and(|slot| {
            let total: usize = slot.chunks.values().map(Vec::len).sum();
            let contiguous = slot.chunks.keys().copied().eq(0..slot.chunks.len() as u32);
            (slot.body_len == 0 || slot.saw_last) && contiguous && total == slot.body_len as usize
        });
        if !ready {
            return None;
        }
        let slot = self.inflight.remove(&relay_id)?;
        let mut body = Vec::with_capacity(slot.body_len as usize);
        for chunk in slot.chunks.into_values() {
            body.extend(chunk);
        }
        Some(AssembledRelay {
            relay_id,
            client_ip: slot.client_ip,
            authorization: slot.authorization,
            content_type: slot.content_type,
            accept: slot.accept,
            mcp_session_id: slot.mcp_session_id,
            mcp_protocol_version: slot.mcp_protocol_version,
            body,
        })
    }
}

/// Visible-ASCII header value. Empty is allowed for optional headers.
pub fn header_safe(value: &str) -> bool {
    value
        .chars()
        .all(|c| c == '\t' || (c >= ' ' && c != '\u{7f}'))
}

/// Non-empty [`header_safe`] value (Authorization).
pub fn header_ok(value: &str) -> bool {
    !value.is_empty() && header_safe(value)
}

pub fn build_relay_request(relay: &AssembledRelay) -> Result<Request<Body>, ()> {
    if !header_ok(&relay.authorization) {
        return Err(());
    }
    let mut builder = Request::builder().method("POST").uri("/mcp").header(
        "authorization",
        HeaderValue::from_str(&relay.authorization).map_err(|_| ())?,
    );
    if !relay.content_type.is_empty() && header_safe(&relay.content_type) {
        builder = builder.header(
            "content-type",
            HeaderValue::from_str(&relay.content_type).map_err(|_| ())?,
        );
    }
    if !relay.accept.is_empty() && header_safe(&relay.accept) {
        builder = builder.header(
            "accept",
            HeaderValue::from_str(&relay.accept).map_err(|_| ())?,
        );
    }
    if let Some(sid) = relay
        .mcp_session_id
        .as_deref()
        .filter(|s| !s.is_empty() && header_safe(s))
    {
        builder = builder.header(
            "mcp-session-id",
            HeaderValue::from_str(sid).map_err(|_| ())?,
        );
    }
    if let Some(ver) = relay
        .mcp_protocol_version
        .as_deref()
        .filter(|s| !s.is_empty() && header_safe(s))
    {
        builder = builder.header(
            "mcp-protocol-version",
            HeaderValue::from_str(ver).map_err(|_| ())?,
        );
    }
    let mut req = builder
        .body(Body::from(relay.body.clone()))
        .map_err(|_| ())?;
    req.extensions_mut().insert(McpIngress::Direct {
        client_ip: relay.client_ip.clone(),
    });
    Ok(req)
}

pub fn chunk_bytes(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }
    data.chunks(MCP_PIPE_CHUNK_BYTES)
        .map(|c| c.to_vec())
        .collect()
}

fn would_block(err: &IpcError) -> bool {
    matches!(err, IpcError::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

/// What one poll of the data pipe should do.
///
/// Supervisor shutdown wins over a dead peer: exiting 0 keeps the
/// supervisor from treating a graceful stop as [`EXIT_CODE_RESPAWN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataLoopPoll {
    Continue,
    Shutdown,
    Respawn,
}

fn classify_data_poll(shutdown_ready: bool, recv_is_terminal: bool) -> DataLoopPoll {
    if shutdown_ready {
        DataLoopPoll::Shutdown
    } else if recv_is_terminal {
        DataLoopPoll::Respawn
    } else {
        DataLoopPoll::Continue
    }
}

fn shutdown_is_ready(rx: &mut tokio::sync::broadcast::Receiver<()>) -> bool {
    match rx.try_recv() {
        Ok(())
        | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_))
        | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => true,
        Err(tokio::sync::broadcast::error::TryRecvError::Empty) => false,
    }
}

/// Limits for one data loop. Values come from the supervisor env.
#[derive(Debug, Clone, Copy)]
pub struct DataLoopConfig {
    pub max_inflight: usize,
    pub max_tunnels: usize,
    pub max_tunnels_per_ip: usize,
    pub relay_timeout: Duration,
    pub tunnel: TunnelTimeouts,
}

impl Default for DataLoopConfig {
    fn default() -> Self {
        Self {
            max_inflight: RELAY_MAX_INFLIGHT,
            max_tunnels: 256,
            max_tunnels_per_ip: 16,
            relay_timeout: Duration::from_secs(90),
            tunnel: TunnelTimeouts::default(),
        }
    }
}

impl DataLoopConfig {
    /// Read the limits the supervisor emits for `proxy_mcp`. A missing
    /// or unparsable value keeps the default.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let num = |name: &str| get(name).and_then(|v| v.trim().parse::<u64>().ok());
        let base = Self::default();
        let secs = |name: &str, fallback: Duration| {
            num(name)
                .filter(|v| *v > 0)
                .map_or(fallback, Duration::from_secs)
        };
        let count = |name: &str, fallback: usize| {
            num(name)
                .filter(|v| *v > 0)
                .map_or(fallback, |v| v as usize)
        };
        Self {
            max_inflight: count("VAUBAN_MCP_RELAY_MAX_INFLIGHT", base.max_inflight),
            max_tunnels: count("VAUBAN_MCP_MAX_TUNNELS", base.max_tunnels),
            max_tunnels_per_ip: count("VAUBAN_MCP_MAX_TUNNELS_PER_IP", base.max_tunnels_per_ip),
            relay_timeout: secs("VAUBAN_MCP_RELAY_TIMEOUT_SECS", base.relay_timeout),
            tunnel: TunnelTimeouts {
                handshake: base.tunnel.handshake,
                idle: secs("VAUBAN_MCP_TUNNEL_IDLE_SECS", base.tunnel.idle),
            },
        }
    }
}

struct LeafSlot {
    inbound: mpsc::Sender<Vec<u8>>,
    client_ip: String,
}

/// Live tunnels on the leaf. Every removal is reported to web once.
pub struct TunnelTable {
    slots: HashMap<u64, LeafSlot>,
    /// Live tunnels per client IP. Only `insert` and `remove` write it;
    /// an IP with no tunnel has no entry.
    per_ip: HashMap<String, usize>,
    max_total: usize,
    max_per_ip: usize,
}

impl TunnelTable {
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            slots: HashMap::new(),
            per_ip: HashMap::new(),
            max_total: max_total.max(1),
            max_per_ip: max_per_ip.max(1),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn per_ip(&self, client_ip: &str) -> usize {
        self.per_ip.get(client_ip).copied().unwrap_or(0)
    }

    /// `Err(reason)` when another tunnel would exceed a cap.
    pub fn admit(&self, client_ip: &str) -> Result<(), &'static str> {
        if self.slots.len() >= self.max_total {
            return Err("max_tunnels");
        }
        if self.per_ip(client_ip) >= self.max_per_ip {
            return Err("max_tunnels_per_ip");
        }
        Ok(())
    }

    pub fn insert(&mut self, tunnel_id: u64, inbound: mpsc::Sender<Vec<u8>>, client_ip: String) {
        self.remove(tunnel_id);
        *self.per_ip.entry(client_ip.clone()).or_insert(0) += 1;
        self.slots
            .insert(tunnel_id, LeafSlot { inbound, client_ip });
    }

    pub fn remove(&mut self, tunnel_id: u64) -> bool {
        let Some(slot) = self.slots.remove(&tunnel_id) else {
            return false;
        };
        if let Some(count) = self.per_ip.get_mut(&slot.client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_ip.remove(&slot.client_ip);
            }
        }
        true
    }

    /// `per_ip` equals a recount of `slots` and holds no zero entry.
    #[cfg(test)]
    fn consistent(&self) -> bool {
        let mut recount: HashMap<&str, usize> = HashMap::new();
        for slot in self.slots.values() {
            *recount.entry(slot.client_ip.as_str()).or_insert(0) += 1;
        }
        recount.len() == self.per_ip.len()
            && recount
                .iter()
                .all(|(ip, n)| self.per_ip.get(*ip) == Some(n))
    }

    /// Queue client bytes. `Some(reason)` means the tunnel was removed
    /// and web must be told; bytes are never silently dropped.
    pub fn deliver(&mut self, tunnel_id: u64, data: Vec<u8>) -> Option<&'static str> {
        let slot = self.slots.get(&tunnel_id)?;
        let reason = match slot.inbound.try_send(data) {
            Ok(()) => return None,
            Err(TrySendError::Full(_)) => "backpressure",
            Err(TrySendError::Closed(_)) => "closed",
        };
        self.remove(tunnel_id);
        Some(reason)
    }
}

/// Send `msg`. A message over `MAX_MESSAGE_SIZE` is dropped and
/// reported; any other error means the pipe is gone.
fn write_or_drop(
    channel: &IpcChannel,
    msg: &Message,
    closed_tx: &mpsc::UnboundedSender<(u64, &'static str)>,
) -> Result<(), IpcError> {
    match channel.send(msg) {
        Ok(()) => Ok(()),
        Err(IpcError::MessageTooLarge { size }) => {
            warn!(size, "MCP data message too large; dropped");
            match msg {
                Message::McpRelayResponse { relay_id, .. }
                | Message::McpRelayBody { relay_id, .. } => {
                    channel.send(&Message::McpRelayAbort {
                        relay_id: *relay_id,
                        reason: "oversize".into(),
                    })?;
                }
                Message::McpTunnelData { tunnel_id, .. } => {
                    let _ = closed_tx.send((*tunnel_id, "oversize"));
                }
                _ => {}
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Read the data pipe until supervisor shutdown or the peer closes.
///
/// Shutdown returns success. An unexpected close returns
/// [`EXIT_CODE_RESPAWN`] so the supervisor replaces the pipe.
pub async fn data_ipc_loop(
    channel: IpcChannel,
    router: axum::Router,
    config: DataLoopConfig,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> ExitCode {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<(u64, &'static str)>();
    let writer = Arc::new(channel);
    let reader = Arc::clone(&writer);
    let writer_closed = closed_tx.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_or_drop(&writer, &msg, &writer_closed) {
                warn!(error = %e, "MCP data pipe write failed; writer stopped");
                return;
            }
        }
    });
    let permits = Arc::new(Semaphore::new(config.max_inflight.max(1)));
    let relay_timeout = config.relay_timeout;
    let mut assembler = RelayAssembler::default();
    let mut tunnels = TunnelTable::new(config.max_tunnels, config.max_tunnels_per_ip);
    loop {
        while let Ok((tunnel_id, reason)) = closed_rx.try_recv() {
            if tunnels.remove(tunnel_id) {
                debug!(
                    tunnel_id,
                    reason,
                    live = tunnels.len(),
                    "MCP tunnel ended on the leaf"
                );
                let _ = tx.send(Message::McpTunnelClose {
                    tunnel_id,
                    reason: reason.into(),
                });
            }
        }
        let recv = reader.try_recv();
        let terminal = match &recv {
            Err(e) if would_block(e) => false,
            Err(_) => true,
            Ok(_) => false,
        };
        match classify_data_poll(shutdown_is_ready(&mut shutdown_rx), terminal) {
            DataLoopPoll::Shutdown => {
                info!("MCP data pipe stopping for shutdown");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::SUCCESS;
            }
            DataLoopPoll::Respawn => {
                info!("MCP data pipe closed, requesting respawn");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::from(EXIT_CODE_RESPAWN as u8);
            }
            DataLoopPoll::Continue => {}
        }
        match recv {
            Ok(Message::McpTunnelOpen {
                tunnel_id,
                client_ip,
            }) => {
                if let Err(reason) = tunnels.admit(&client_ip) {
                    let _ = tx.send(Message::McpTunnelClose {
                        tunnel_id,
                        reason: reason.into(),
                    });
                    continue;
                }
                let Some(identity) = crate::tunnel::identity() else {
                    let _ = tx.send(Message::McpTunnelClose {
                        tunnel_id,
                        reason: "no_identity".into(),
                    });
                    continue;
                };
                let (stream, mut ends) = crate::tunnel::PipeStream::pair();
                tunnels.insert(tunnel_id, ends.inbound, client_ip.clone());
                let router = router.clone();
                let tx_bytes = tx.clone();
                tokio::spawn(async move {
                    while let Some(data) = ends.outbound.recv().await {
                        for piece in data.chunks(MCP_PIPE_CHUNK_BYTES) {
                            let msg = Message::McpTunnelData {
                                tunnel_id,
                                data: piece.to_vec(),
                            };
                            if tx_bytes.send(msg).is_err() {
                                return;
                            }
                        }
                    }
                });
                let closed = closed_tx.clone();
                let timeouts = config.tunnel;
                tokio::spawn(async move {
                    let ingress = McpIngress::Tunnel {
                        tunnel_id,
                        client_ip,
                    };
                    let reason =
                        crate::tunnel::serve_tunnel(identity, stream, router, ingress, timeouts)
                            .await;
                    let _ = closed.send((tunnel_id, reason));
                });
            }
            Ok(Message::McpTunnelData { tunnel_id, data }) => {
                if let Some(reason) = tunnels.deliver(tunnel_id, data) {
                    debug!(tunnel_id, reason, "MCP tunnel closed on delivery");
                    let _ = tx.send(Message::McpTunnelClose {
                        tunnel_id,
                        reason: reason.into(),
                    });
                }
            }
            Ok(Message::McpTunnelClose { tunnel_id, .. }) => {
                tunnels.remove(tunnel_id);
            }
            Ok(msg) => match assembler.push(&msg) {
                Ok(Some(relay)) => {
                    let permit = permits.clone().acquire_owned().await;
                    let Ok(permit) = permit else {
                        return ExitCode::from(EXIT_CODE_RESPAWN as u8);
                    };
                    let router = router.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        serve_one(router, relay, tx, relay_timeout).await;
                        drop(permit);
                    });
                }
                Ok(None) => {}
                Err((relay_id, reason)) => {
                    assembler.inflight.remove(&relay_id);
                    let _ = tx.send(Message::McpRelayAbort {
                        relay_id,
                        reason: format!("{reason:?}"),
                    });
                }
            },
            Err(e) if would_block(&e) => {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            Err(_) => {
                info!("MCP data pipe closed, requesting respawn");
                drop(tx);
                let _ = writer_task.await;
                return ExitCode::from(EXIT_CODE_RESPAWN as u8);
            }
        }
    }
}

async fn serve_one(
    router: axum::Router,
    relay: AssembledRelay,
    tx: mpsc::UnboundedSender<Message>,
    relay_timeout: std::time::Duration,
) {
    let relay_id = relay.relay_id;
    let req = match build_relay_request(&relay) {
        Ok(req) => req,
        Err(()) => {
            let _ = tx.send(Message::McpRelayAbort {
                relay_id,
                reason: "header".into(),
            });
            return;
        }
    };
    let response = match tokio::time::timeout(relay_timeout, router.oneshot(req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(infallible)) => match infallible {},
        Err(_) => {
            let _ = tx.send(Message::McpRelayAbort {
                relay_id,
                reason: "timeout".into(),
            });
            return;
        }
    };
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let mcp_session_id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(
        response.into_body(),
        crate::upstream_http::MAX_UPSTREAM_BODY_BYTES,
    )
    .await
    .unwrap_or_default();
    let http_status = if status == StatusCode::OK {
        200
    } else {
        status.as_u16()
    };
    let _ = tx.send(Message::McpRelayResponse {
        relay_id,
        status: http_status,
        content_type,
        mcp_session_id,
        body_len: body.len() as u32,
    });
    let chunks = chunk_bytes(&body);
    let last_index = chunks.len().saturating_sub(1);
    for (seq, data) in chunks.into_iter().enumerate() {
        let _ = tx.send(Message::McpRelayBody {
            relay_id,
            seq: seq as u32,
            last: seq == last_index,
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;

    fn small_config() -> DataLoopConfig {
        DataLoopConfig {
            max_inflight: 4,
            max_tunnels: 4,
            max_tunnels_per_ip: 4,
            relay_timeout: Duration::from_secs(1),
            tunnel: TunnelTimeouts::default(),
        }
    }

    fn install_test_identity() {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        if crate::tunnel::identity().is_some() {
            return;
        }
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["vauban-proxy-mcp.internal".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        crate::tunnel::install_identity(cert.der().to_vec(), &key.serialize_pem())
            .expect("identity");
    }

    /// Collect `McpTunnelClose` reasons until `want` arrived or `wait` passed.
    async fn closes(peer: &IpcChannel, want: usize, wait: Duration) -> Vec<(u64, String)> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut out = Vec::new();
        while out.len() < want && tokio::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(Message::McpTunnelClose { tunnel_id, reason }) => out.push((tunnel_id, reason)),
                Ok(_) => {}
                Err(e) if would_block(&e) => tokio::time::sleep(Duration::from_millis(5)).await,
                Err(_) => break,
            }
        }
        out
    }

    fn open(id: u64, ip: &str) -> Message {
        Message::McpTunnelOpen {
            tunnel_id: id,
            client_ip: ip.into(),
        }
    }

    #[test]
    fn from_env_reads_every_supervisor_key_and_keeps_defaults() {
        let env: HashMap<&str, &str> = [
            ("VAUBAN_MCP_RELAY_MAX_INFLIGHT", "7"),
            ("VAUBAN_MCP_MAX_TUNNELS", "9"),
            ("VAUBAN_MCP_MAX_TUNNELS_PER_IP", "3"),
            ("VAUBAN_MCP_RELAY_TIMEOUT_SECS", "41"),
            ("VAUBAN_MCP_TUNNEL_IDLE_SECS", "77"),
        ]
        .into_iter()
        .collect();
        let cfg = DataLoopConfig::from_env(|k| env.get(k).map(|v| v.to_string()));
        assert_eq!(cfg.max_inflight, 7);
        assert_eq!(cfg.max_tunnels, 9);
        assert_eq!(cfg.max_tunnels_per_ip, 3);
        assert_eq!(cfg.relay_timeout, Duration::from_secs(41));
        assert_eq!(cfg.tunnel.idle, Duration::from_secs(77));
        let bad = DataLoopConfig::from_env(|_| Some("zero".into()));
        let def = DataLoopConfig::default();
        assert_eq!(bad.max_inflight, def.max_inflight);
        assert_eq!(bad.relay_timeout, def.relay_timeout);
        let zero = DataLoopConfig::from_env(|_| Some("0".into()));
        assert_eq!(zero.max_tunnels, def.max_tunnels);
    }

    #[test]
    fn full_queue_closes_the_tunnel_with_backpressure() {
        let mut table = TunnelTable::new(4, 4);
        let (tx, mut rx) = mpsc::channel(1);
        table.insert(1, tx, "a".into());
        assert_eq!(table.deliver(1, b"one".to_vec()), None);
        assert_eq!(table.deliver(1, b"two".to_vec()), Some("backpressure"));
        assert!((table.len() == 0));
        assert_eq!(rx.try_recv().expect("first"), b"one");
        assert!(
            rx.try_recv().is_err(),
            "the second chunk was not half-delivered"
        );
    }

    #[test]
    fn ended_tunnel_reports_closed_on_delivery() {
        let mut table = TunnelTable::new(4, 4);
        let (tx, rx) = mpsc::channel(4);
        table.insert(1, tx, "a".into());
        drop(rx);
        assert_eq!(table.deliver(1, b"x".to_vec()), Some("closed"));
        assert_eq!(table.deliver(1, b"x".to_vec()), None);
    }

    #[test]
    fn admit_enforces_total_and_per_ip_caps() {
        let mut table = TunnelTable::new(3, 2);
        for (id, ip) in [(1, "a"), (2, "a")] {
            table.insert(id, mpsc::channel(1).0, ip.into());
        }
        assert_eq!(table.admit("a"), Err("max_tunnels_per_ip"));
        assert_eq!(table.admit("b"), Ok(()));
        table.insert(3, mpsc::channel(1).0, "b".into());
        assert_eq!(table.admit("c"), Err("max_tunnels"));
        assert!(table.remove(1));
        assert_eq!(table.admit("a"), Ok(()));
    }

    #[test]
    fn per_ip_counter_follows_insert_remove_and_backpressure() {
        let mut table = TunnelTable::new(8, 8);
        let (tx, _rx) = mpsc::channel(1);
        table.insert(1, tx, "a".into());
        table.insert(2, mpsc::channel(1).0, "a".into());
        table.insert(3, mpsc::channel(1).0, "b".into());
        assert_eq!((table.per_ip("a"), table.per_ip("b")), (2, 1));
        assert!(table.remove(2));
        assert!(!table.remove(2), "a second remove must not decrement again");
        assert_eq!(table.per_ip("a"), 1);
        assert_eq!(table.deliver(1, b"one".to_vec()), None);
        assert_eq!(table.deliver(1, b"two".to_vec()), Some("backpressure"));
        assert_eq!(table.per_ip("a"), 0);
        assert!(!table.per_ip.contains_key("a"), "zero entries are dropped");
        assert!(table.consistent());
    }

    #[test]
    fn reinserting_an_id_does_not_leak_the_old_ip() {
        let mut table = TunnelTable::new(8, 8);
        table.insert(1, mpsc::channel(1).0, "a".into());
        table.insert(1, mpsc::channel(1).0, "b".into());
        assert_eq!((table.per_ip("a"), table.per_ip("b")), (0, 1));
        assert!(table.consistent());
    }

    fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
        let start = src.find(signature).expect("signature present");
        let rest = &src[start..];
        &rest[..rest.find("\n    }\n").map_or(rest.len(), |i| i + 6)]
    }

    /// The per-IP count is a table lookup on both sides, and only the
    /// insert / remove pair writes it.
    #[test]
    fn per_ip_counters_are_lookups_written_in_one_place() {
        let leaf = include_str!("data_pipe.rs");
        let leaf_prod = leaf.split("mod tests").next().unwrap_or(leaf);
        let web = include_str!("../../vauban-web/src/ipc/proxy_mcp_data.rs");
        let web_prod = web.split("mod tests").next().unwrap_or(web);
        for (name, prod) in [("leaf", leaf_prod), ("web", web_prod)] {
            for scan in [".filter(|s| s.client_ip", ".filter(|slot| slot.client_ip"] {
                assert!(
                    !prod.contains(scan),
                    "{name}: per-IP count must not scan ({scan})"
                );
            }
            let writers = [fn_body(prod, "fn insert("), fn_body(prod, "fn remove(")];
            let mut allowed = 0;
            for body in writers {
                allowed += body.matches("self.per_ip.entry(").count()
                    + body.matches("self.per_ip.get_mut(").count()
                    + body.matches("self.per_ip.remove(").count();
            }
            let total = prod.matches("self.per_ip.entry(").count()
                + prod.matches("self.per_ip.get_mut(").count()
                + prod.matches("self.per_ip.remove(").count()
                + prod.matches("self.per_ip.insert(").count()
                + prod.matches("self.per_ip.clear(").count()
                + prod.matches("self.per_ip.retain(").count();
            assert!(allowed >= 3, "{name}: insert / remove maintain per_ip");
            assert_eq!(
                total, allowed,
                "{name}: per_ip written outside insert / remove"
            );
        }
        assert!(leaf_prod.contains("if self.per_ip(client_ip) >= self.max_per_ip"));
        assert!(web_prod.contains("map.count_for_ip(&client_ip) >= limits.max_per_ip"));
    }

    #[test]
    fn writer_loops_survive_oversize_and_handle_a_full_queue() {
        let src = include_str!("data_pipe.rs");
        let prod = src.split("mod tests").next().unwrap_or(src);
        assert!(prod.contains("write_or_drop(&writer, &msg, &writer_closed)"));
        assert!(!prod.contains("is_err() {\n                break;"));
        assert!(prod.contains("TrySendError::Full"));
        assert!(!prod.contains("let _ = inbound.try_send"));
        let web = include_str!("../../vauban-web/src/ipc/proxy_mcp_data.rs");
        assert!(web.contains("write_or_drop(&writer, &msg"));
        assert!(!web.contains("writer.send(&msg).is_err()"));
        let tunnel = include_str!("tunnel.rs");
        assert!(tunnel.contains("tokio::time::timeout(timeouts.handshake, acceptor.accept("));
        assert!(tunnel.contains("activity.idle_for(timeouts.idle)"));
    }

    #[test]
    fn oversize_relay_body_becomes_an_abort_and_the_pipe_lives() {
        let (leaf, peer) = IpcChannel::pair().expect("pair");
        let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
        let big = Message::McpRelayBody {
            relay_id: 5,
            seq: 0,
            last: true,
            data: vec![0; shared::ipc::MAX_MESSAGE_SIZE + 1],
        };
        assert!(write_or_drop(&leaf, &big, &closed_tx).is_ok());
        let tunnel = Message::McpTunnelData {
            tunnel_id: 8,
            data: vec![0; shared::ipc::MAX_MESSAGE_SIZE + 1],
        };
        assert!(write_or_drop(&leaf, &tunnel, &closed_tx).is_ok());
        assert_eq!(closed_rx.try_recv().expect("closed"), (8, "oversize"));
        match peer.try_recv().expect("abort") {
            Message::McpRelayAbort { relay_id, reason } => {
                assert_eq!(relay_id, 5);
                assert_eq!(reason, "oversize");
            }
            other => unreachable!("unexpected {other:?}"),
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Open(u8, u8),
        WebClose(u8),
        LeafEnd(u8),
        Deliver(u8),
        Flood(u8),
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        prop_oneof![
            (0u8..12, 0u8..3).prop_map(|(id, ip)| Op::Open(id, ip)),
            (0u8..12).prop_map(Op::WebClose),
            (0u8..12).prop_map(Op::LeafEnd),
            (0u8..12).prop_map(Op::Deliver),
            (0u8..12).prop_map(Op::Flood),
        ]
    }

    proptest::proptest! {
        #[test]
        fn tunnel_table_size_equals_live_tunnels(ops in proptest::collection::vec(op(), 0..80)) {
            let mut table = TunnelTable::new(8, 3);
            let mut live: HashMap<u64, (mpsc::Receiver<Vec<u8>>, u8)> = HashMap::new();
            // Leaf task ended, web not told yet: the slot is still held.
            let mut ended: HashMap<u64, u8> = HashMap::new();
            for op in ops {
                match op {
                    Op::Open(id, ip) => {
                        let id = u64::from(id);
                        if table.slots.contains_key(&id) {
                            continue;
                        }
                        let ip_s = format!("ip{ip}");
                        let same = live.values().filter(|(_, i)| *i == ip).count()
                            + ended.values().filter(|i| **i == ip).count();
                        let expect_ok = live.len() + ended.len() < 8 && same < 3;
                        proptest::prop_assert_eq!(table.admit(&ip_s).is_ok(), expect_ok);
                        if expect_ok {
                            let (tx, rx) = mpsc::channel(TUNNEL_QUEUE_FOR_TEST);
                            table.insert(id, tx, ip_s);
                            live.insert(id, (rx, ip));
                        }
                    }
                    Op::WebClose(id) => {
                        let id = u64::from(id);
                        let held = live.remove(&id).is_some() | ended.remove(&id).is_some();
                        proptest::prop_assert_eq!(table.remove(id), held);
                    }
                    Op::LeafEnd(id) => {
                        let id = u64::from(id);
                        if let Some((_, ip)) = live.remove(&id) {
                            ended.insert(id, ip);
                        }
                    }
                    Op::Deliver(id) => {
                        let id = u64::from(id);
                        let got = table.deliver(id, vec![1]);
                        if ended.remove(&id).is_some() {
                            proptest::prop_assert_eq!(got, Some("closed"));
                        } else if let Some((rx, _)) = live.get_mut(&id) {
                            proptest::prop_assert_eq!(got, None);
                            proptest::prop_assert!(rx.try_recv().is_ok());
                        } else {
                            proptest::prop_assert_eq!(got, None);
                        }
                    }
                    Op::Flood(id) => {
                        let id = u64::from(id);
                        if live.contains_key(&id) {
                            let mut reason = None;
                            for _ in 0..=TUNNEL_QUEUE_FOR_TEST {
                                reason = table.deliver(id, vec![2]);
                                if reason.is_some() {
                                    break;
                                }
                            }
                            proptest::prop_assert_eq!(reason, Some("backpressure"));
                            live.remove(&id);
                        }
                    }
                }
                proptest::prop_assert_eq!(table.len(), live.len() + ended.len());
                proptest::prop_assert!(table.consistent());
                for ip in 0u8..3 {
                    let held = live.values().filter(|(_, i)| *i == ip).count()
                        + ended.values().filter(|i| **i == ip).count();
                    proptest::prop_assert_eq!(table.per_ip(&format!("ip{ip}")), held);
                }
                proptest::prop_assert_eq!(table.per_ip.values().sum::<usize>(), table.len());
            }
        }

        #[test]
        fn burst_delivers_in_order_or_closes(burst in 0usize..80) {
            let mut table = TunnelTable::new(1, 1);
            let (tx, mut rx) = mpsc::channel(crate::tunnel::TUNNEL_INBOUND_QUEUE);
            table.insert(1, tx, "a".into());
            let mut closed_at = None;
            for i in 0..burst {
                if let Some(reason) = table.deliver(1, (i as u32).to_le_bytes().to_vec()) {
                    proptest::prop_assert_eq!(reason, "backpressure");
                    closed_at = Some(i);
                    break;
                }
            }
            let delivered = closed_at.unwrap_or(burst);
            for i in 0..delivered {
                let got = rx.try_recv().expect("queued chunk");
                proptest::prop_assert_eq!(got, (i as u32).to_le_bytes().to_vec());
            }
            proptest::prop_assert_eq!(
                closed_at.is_some(),
                burst > crate::tunnel::TUNNEL_INBOUND_QUEUE
            );
            proptest::prop_assert_eq!(table.len() == 0, closed_at.is_some());
        }
    }

    const TUNNEL_QUEUE_FOR_TEST: usize = 4;

    #[tokio::test]
    async fn garbage_handshake_frees_the_slot_and_tells_web() {
        install_test_identity();
        let (leaf, peer) = IpcChannel::pair().expect("pair");
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let config = DataLoopConfig {
            max_tunnels: 1,
            max_tunnels_per_ip: 1,
            ..small_config()
        };
        tokio::spawn(data_ipc_loop(leaf, axum::Router::new(), config, rx));
        peer.send(&open(1, "198.51.100.9")).expect("open");
        peer.send(&Message::McpTunnelData {
            tunnel_id: 1,
            data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        })
        .expect("garbage");
        let got = closes(&peer, 1, Duration::from_secs(3)).await;
        assert_eq!(got.len(), 1, "one close for the garbage tunnel");
        assert_eq!(got[0].0, 1);
        assert!(
            got[0].1 == "handshake_failed" || got[0].1 == "closed",
            "{}",
            got[0].1
        );
        // The single slot is free again.
        peer.send(&open(2, "198.51.100.9")).expect("reopen");
        let again = closes(&peer, 1, Duration::from_millis(300)).await;
        assert!(
            again.iter().all(|(_, reason)| reason != "max_tunnels"),
            "{again:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn battle_256_idle_tunnels_time_out_and_free_every_slot() {
        install_test_identity();
        let (leaf, peer) = IpcChannel::pair().expect("pair");
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let config = DataLoopConfig {
            max_tunnels: 256,
            max_tunnels_per_ip: 256,
            ..small_config()
        };
        tokio::spawn(data_ipc_loop(leaf, axum::Router::new(), config, rx));
        for id in 0..256u64 {
            peer.send(&open(id, "198.51.100.10")).expect("open");
        }
        peer.send(&open(999, "198.51.100.10")).expect("overflow");
        let got = closes(&peer, 257, Duration::from_secs(30)).await;
        assert_eq!(got.len(), 257);
        assert!(got.contains(&(999, "max_tunnels".to_string())));
        let timed_out = got.iter().filter(|(_, r)| r == "handshake_timeout").count();
        assert_eq!(timed_out, 256);
        // A per-IP count left above zero would refuse part of this wave.
        for id in 1000..1256u64 {
            peer.send(&open(id, "198.51.100.10")).expect("after");
        }
        let after = closes(&peer, 256, Duration::from_secs(30)).await;
        assert_eq!(after.len(), 256);
        assert!(
            after.iter().all(|(_, r)| r == "handshake_timeout"),
            "every slot and the per-IP count came back: {after:?}"
        );
    }

    /// A reader that never drains: the frames are queued before the loop
    /// starts, so on this single-threaded runtime the serve task cannot
    /// run until the whole burst is delivered. Frame 33 overflows.
    #[tokio::test]
    async fn e2e_stalled_reader_closes_with_backpressure_exactly_once() {
        install_test_identity();
        let (leaf, peer) = IpcChannel::pair().expect("pair");
        peer.send(&open(7, "198.51.100.12")).expect("open");
        for _ in 0..=crate::tunnel::TUNNEL_INBOUND_QUEUE {
            peer.send(&Message::McpTunnelData {
                tunnel_id: 7,
                data: vec![0x16; 64],
            })
            .expect("data");
        }
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let config = DataLoopConfig {
            max_tunnels_per_ip: 1,
            ..small_config()
        };
        tokio::spawn(data_ipc_loop(leaf, axum::Router::new(), config, rx));

        let got = closes(&peer, 1, Duration::from_secs(5)).await;
        assert_eq!(got, vec![(7, "backpressure".to_string())]);
        let extra = closes(&peer, 1, Duration::from_millis(300)).await;
        assert!(
            extra.is_empty(),
            "the serve task must not close it twice: {extra:?}"
        );

        peer.send(&open(8, "198.51.100.12")).expect("reopen");
        let after = closes(&peer, 1, Duration::from_millis(300)).await;
        assert!(
            !after.iter().any(|(_, r)| r.starts_with("max_tunnels")),
            "the slot came back: {after:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn battle_thirty_two_floods_each_close_once() {
        install_test_identity();
        let (leaf, peer) = IpcChannel::pair().expect("pair");
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let config = DataLoopConfig {
            max_tunnels: 32,
            max_tunnels_per_ip: 32,
            ..small_config()
        };
        tokio::spawn(data_ipc_loop(leaf, axum::Router::new(), config, rx));
        let peer = Arc::new(peer);
        let sender = Arc::clone(&peer);
        std::thread::spawn(move || {
            for id in 0..32u64 {
                sender.send(&open(id, "198.51.100.11")).expect("open");
            }
            for round in 0..200u32 {
                for id in 0..32u64 {
                    let data = vec![(round % 251) as u8; 1024];
                    if sender
                        .send(&Message::McpTunnelData {
                            tunnel_id: id,
                            data,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
        })
        .join()
        .expect("flood thread");
        let got = closes(&peer, 32, Duration::from_secs(10)).await;
        let mut ids: Vec<u64> = got.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            32,
            "every flooded tunnel closes exactly once: {got:?}"
        );
        for (_, reason) in &got {
            assert!(
                ["backpressure", "handshake_failed", "closed"].contains(&reason.as_str()),
                "{reason}"
            );
        }
        let extra = closes(&peer, 1, Duration::from_millis(300)).await;
        assert!(extra.is_empty(), "no duplicate close: {extra:?}");
    }

    fn request(id: u64, auth: &str, body_len: u32) -> Message {
        Message::McpRelayRequest {
            relay_id: id,
            client_ip: "203.0.113.8".into(),
            authorization: SensitiveString::new(auth.into()),
            content_type: "application/json".into(),
            accept: "application/json".into(),
            mcp_session_id: None,
            mcp_protocol_version: Some("2025-03-26".into()),
            body_len,
        }
    }

    fn chunk(id: u64, seq: u32, last: bool, data: &[u8]) -> Message {
        Message::McpRelayBody {
            relay_id: id,
            seq,
            last,
            data: data.to_vec(),
        }
    }

    #[test]
    fn out_of_order_chunks_reassemble_per_relay() {
        let mut asm = RelayAssembler::default();
        assert!(asm.push(&request(1, "Bearer vbw_a", 5)).unwrap().is_none());
        assert!(asm.push(&request(2, "Bearer vbw_b", 3)).unwrap().is_none());
        assert!(asm.push(&chunk(1, 1, true, b"XY")).unwrap().is_none());
        assert!(asm.push(&chunk(2, 0, true, b"zzz")).unwrap().is_some());
        let done = asm.push(&chunk(1, 0, false, b"abc")).unwrap().unwrap();
        assert_eq!(done.relay_id, 1);
        assert_eq!(done.body, b"abcXY");
    }

    #[test]
    fn attack_relay_header_crlf_is_rejected() {
        let mut asm = RelayAssembler::default();
        let err = asm
            .push(&request(9, "Bearer vbw_a\r\nX-Injected: 1", 0))
            .unwrap_err();
        assert_eq!(err.1, AssembleError::Header);
    }

    #[test]
    fn oversize_body_is_rejected() {
        let mut asm = RelayAssembler::default();
        let huge = (crate::upstream_http::MAX_UPSTREAM_BODY_BYTES as u32).saturating_add(1);
        let err = asm.push(&request(3, "Bearer vbw_a", huge)).unwrap_err();
        assert_eq!(err.1, AssembleError::Oversize);
    }

    #[test]
    fn empty_body_completes_on_the_request() {
        let mut asm = RelayAssembler::default();
        let done = asm.push(&request(4, "Bearer vbw_a", 0)).unwrap().unwrap();
        assert!(done.body.is_empty());
    }

    #[test]
    fn shutdown_arm_returns_success_not_respawn() {
        let src = include_str!("data_pipe.rs");
        let prod = src.split("mod tests").next().unwrap_or(src);
        let shutdown_arm = prod
            .find("DataLoopPoll::Shutdown =>")
            .expect("shutdown arm");
        let respawn_arm = prod.find("DataLoopPoll::Respawn =>").expect("respawn arm");
        assert!(shutdown_arm < respawn_arm);
        let arm = &prod[shutdown_arm..respawn_arm];
        assert!(arm.contains("ExitCode::SUCCESS"));
        assert!(
            !arm.contains("EXIT_CODE_RESPAWN"),
            "a supervisor Shutdown must not ask the supervisor to respawn the leaf"
        );
    }

    proptest::proptest! {
        #[test]
        fn shutdown_dominates_a_terminal_recv(terminal in proptest::bool::ANY) {
            proptest::prop_assert_eq!(
                classify_data_poll(true, terminal),
                DataLoopPoll::Shutdown
            );
        }

        #[test]
        fn peer_close_respawns_only_without_shutdown(terminal in proptest::bool::ANY) {
            let poll = classify_data_poll(false, terminal);
            if terminal {
                proptest::prop_assert_eq!(poll, DataLoopPoll::Respawn);
            } else {
                proptest::prop_assert_eq!(poll, DataLoopPoll::Continue);
            }
        }
    }

    #[test]
    fn battle_classify_stable_under_threads() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                classify_data_poll(true, true) == DataLoopPoll::Shutdown
                    && classify_data_poll(false, true) == DataLoopPoll::Respawn
                    && classify_data_poll(false, false) == DataLoopPoll::Continue
            }));
        }
        for handle in handles {
            assert!(handle.join().expect("thread"));
        }
    }

    #[tokio::test]
    async fn shutdown_stops_data_ipc_loop_without_respawn() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let sender = tx.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = sender.send(());
        });
        let started = std::time::Instant::now();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(leaf, axum::Router::new(), small_config(), rx),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        drop(peer);
        drop(tx);
    }

    #[tokio::test]
    async fn peer_close_requests_respawn() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        drop(peer);
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(leaf, axum::Router::new(), small_config(), rx),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::from(EXIT_CODE_RESPAWN as u8));
    }

    #[tokio::test]
    async fn shutdown_wins_over_a_closed_data_pipe() {
        let (leaf, peer) = shared::ipc::IpcChannel::pair().unwrap();
        drop(peer);
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        tx.send(()).unwrap();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            data_ipc_loop(leaf, axum::Router::new(), small_config(), rx),
        )
        .await
        .expect("data loop timed out");
        assert_eq!(code, ExitCode::SUCCESS);
        drop(tx);
    }
}
