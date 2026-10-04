//! Hop-2 data pipe (web -> proxy-mcp).
//!
//! Distinct from the control pipe. One writer task, correlated by
//! `relay_id`. Bodies and tunnel bytes are chunked under
//! `MCP_PIPE_CHUNK_BYTES`.

use crate::error::{AppError, AppResult};
use shared::correlated_ipc::CorrelatedIpcCore;
use shared::ipc::{IpcChannel, IpcError};
use shared::messages::{MCP_PIPE_CHUNK_BYTES, Message, SensitiveString};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const DEFAULT_RELAY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct RelayRequest {
    pub client_ip: String,
    pub authorization: String,
    pub content_type: String,
    pub accept: String,
    pub mcp_session_id: Option<String>,
    pub mcp_protocol_version: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct RelayedHttp {
    pub status: u16,
    pub content_type: String,
    pub mcp_session_id: Option<String>,
    pub body: Vec<u8>,
}

/// Caps applied when a tunnel is registered.
#[derive(Debug, Clone, Copy)]
pub struct TunnelLimits {
    pub max_total: usize,
    pub max_per_ip: usize,
}

impl Default for TunnelLimits {
    fn default() -> Self {
        Self {
            max_total: 256,
            max_per_ip: 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRefused {
    Total,
    PerIp,
    PipeClosed,
}

struct Inflight {
    status: Option<u16>,
    content_type: String,
    mcp_session_id: Option<String>,
    body_len: u32,
    chunks: HashMap<u32, Vec<u8>>,
    waiter: Option<oneshot::Sender<AppResult<RelayedHttp>>>,
}

struct TunnelSlot {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    client_ip: String,
}

/// Registered tunnels plus a live count per client IP. Only `insert`
/// and `remove` write `per_ip`; an IP with no tunnel has no entry.
#[derive(Default)]
struct TunnelMap {
    slots: HashMap<u64, TunnelSlot>,
    per_ip: HashMap<String, usize>,
}

impl TunnelMap {
    fn len(&self) -> usize {
        self.slots.len()
    }

    fn count_for_ip(&self, client_ip: &str) -> usize {
        self.per_ip.get(client_ip).copied().unwrap_or(0)
    }

    fn get(&self, tunnel_id: u64) -> Option<&TunnelSlot> {
        self.slots.get(&tunnel_id)
    }

    fn insert(&mut self, tunnel_id: u64, slot: TunnelSlot) {
        self.remove(tunnel_id);
        *self.per_ip.entry(slot.client_ip.clone()).or_insert(0) += 1;
        self.slots.insert(tunnel_id, slot);
    }

    fn remove(&mut self, tunnel_id: u64) -> Option<TunnelSlot> {
        let slot = self.slots.remove(&tunnel_id)?;
        if let Some(count) = self.per_ip.get_mut(&slot.client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_ip.remove(&slot.client_ip);
            }
        }
        Some(slot)
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
}

pub struct ProxyMcpDataClient {
    core: CorrelatedIpcCore,
    next_id: AtomicU64,
    relay_timeout_ms: AtomicU64,
    inflight: StdMutex<HashMap<u64, Inflight>>,
    tunnels: StdMutex<TunnelMap>,
    writer_tx: mpsc::UnboundedSender<Message>,
}

/// Send `msg`. A message over `MAX_MESSAGE_SIZE` is reported and the
/// writer keeps going. Any other error means the pipe is gone.
pub(crate) fn write_or_drop(
    channel: &IpcChannel,
    msg: &Message,
    on_oversize: impl FnOnce(&Message),
) -> Result<(), IpcError> {
    match channel.send(msg) {
        Ok(()) => Ok(()),
        Err(IpcError::MessageTooLarge { size }) => {
            tracing::warn!(size, "MCP data message too large; dropped");
            on_oversize(msg);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

impl ProxyMcpDataClient {
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> std::io::Result<Arc<Self>> {
        let core = CorrelatedIpcCore::from_fds(read_fd, write_fd)?;
        let writer = core.channel_arc();
        let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Message>();
        let client = Arc::new(Self {
            core,
            next_id: AtomicU64::new(1),
            relay_timeout_ms: AtomicU64::new(DEFAULT_RELAY_TIMEOUT.as_millis() as u64),
            inflight: StdMutex::new(HashMap::new()),
            tunnels: StdMutex::new(TunnelMap::default()),
            writer_tx,
        });
        let weak: Weak<Self> = Arc::downgrade(&client);
        tokio::spawn(async move {
            while let Some(msg) = writer_rx.recv().await {
                let sent = write_or_drop(&writer, &msg, |dropped| {
                    if let Some(client) = weak.upgrade() {
                        client.on_dropped(dropped);
                    }
                });
                if let Err(e) = sent {
                    tracing::warn!(error = %e, "MCP data pipe write failed; writer stopped");
                    return;
                }
            }
        });
        Ok(client)
    }

    pub fn set_relay_timeout(&self, timeout: Duration) {
        self.relay_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    fn relay_timeout(&self) -> Duration {
        Duration::from_millis(self.relay_timeout_ms.load(Ordering::Relaxed))
    }

    /// The writer could not ship `msg`. Fail its relay or close its tunnel.
    fn on_dropped(&self, msg: &Message) {
        match msg {
            Message::McpRelayRequest { relay_id, .. } | Message::McpRelayBody { relay_id, .. } => {
                self.fail_relay(*relay_id, "relay message too large");
            }
            Message::McpTunnelOpen { tunnel_id, .. } | Message::McpTunnelData { tunnel_id, .. } => {
                self.close_tunnel(*tunnel_id, "oversize");
            }
            _ => {}
        }
    }

    fn fail_relay(&self, relay_id: u64, reason: &str) {
        let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(mut slot) = map.remove(&relay_id)
            && let Some(waiter) = slot.waiter.take()
        {
            let _ = waiter.send(Err(AppError::Internal(anyhow::anyhow!(
                "mcp relay aborted: {reason}"
            ))));
        }
    }

    pub async fn relay(&self, request: RelayRequest) -> AppResult<RelayedHttp> {
        let relay_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
            map.insert(
                relay_id,
                Inflight {
                    status: None,
                    content_type: String::new(),
                    mcp_session_id: None,
                    body_len: request.body.len() as u32,
                    chunks: HashMap::new(),
                    waiter: Some(tx),
                },
            );
        }
        self.writer_tx
            .send(Message::McpRelayRequest {
                relay_id,
                client_ip: request.client_ip.clone(),
                authorization: SensitiveString::new(request.authorization.clone()),
                content_type: request.content_type.clone(),
                accept: request.accept.clone(),
                mcp_session_id: request.mcp_session_id.clone(),
                mcp_protocol_version: request.mcp_protocol_version.clone(),
                body_len: request.body.len() as u32,
            })
            .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        let pieces: Vec<&[u8]> = request.body.chunks(MCP_PIPE_CHUNK_BYTES).collect();
        for (seq, chunk) in pieces.iter().enumerate() {
            self.writer_tx
                .send(Message::McpRelayBody {
                    relay_id,
                    seq: seq as u32,
                    last: seq + 1 == pieces.len(),
                    data: chunk.to_vec(),
                })
                .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        }
        match tokio::time::timeout(self.relay_timeout(), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(AppError::Internal(anyhow::anyhow!(
                "mcp relay waiter dropped"
            ))),
            Err(_) => {
                if let Ok(mut map) = self.inflight.lock() {
                    map.remove(&relay_id);
                }
                Err(AppError::Internal(anyhow::anyhow!("mcp relay timed out")))
            }
        }
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn tunnels_for_ip(&self, client_ip: &str) -> usize {
        self.tunnels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .count_for_ip(client_ip)
    }

    /// Id for a tunnel that is not registered yet (log before upgrade).
    pub fn reserve_tunnel_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Register `tunnel_id` and tell the leaf. The caps are checked
    /// under the same lock as the insert.
    pub fn open_tunnel(
        &self,
        tunnel_id: u64,
        client_ip: String,
        limits: TunnelLimits,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, TunnelRefused> {
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut map = self.tunnels.lock().unwrap_or_else(|p| p.into_inner());
            if map.len() >= limits.max_total {
                return Err(TunnelRefused::Total);
            }
            if map.count_for_ip(&client_ip) >= limits.max_per_ip {
                return Err(TunnelRefused::PerIp);
            }
            map.insert(
                tunnel_id,
                TunnelSlot {
                    tx,
                    client_ip: client_ip.clone(),
                },
            );
        }
        if self
            .writer_tx
            .send(Message::McpTunnelOpen {
                tunnel_id,
                client_ip,
            })
            .is_err()
        {
            self.forget_tunnel(tunnel_id);
            return Err(TunnelRefused::PipeClosed);
        }
        Ok(rx)
    }

    /// Forward client bytes, split so no message exceeds the pipe cap.
    pub fn send_tunnel(&self, tunnel_id: u64, data: Vec<u8>) -> AppResult<()> {
        for piece in data.chunks(MCP_PIPE_CHUNK_BYTES) {
            self.writer_tx
                .send(Message::McpTunnelData {
                    tunnel_id,
                    data: piece.to_vec(),
                })
                .map_err(|_| AppError::Internal(anyhow::anyhow!("mcp data pipe closed")))?;
        }
        Ok(())
    }

    fn forget_tunnel(&self, tunnel_id: u64) -> bool {
        self.tunnels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(tunnel_id)
            .is_some()
    }

    pub fn close_tunnel(&self, tunnel_id: u64, reason: &str) {
        if self.forget_tunnel(tunnel_id) {
            let _ = self.writer_tx.send(Message::McpTunnelClose {
                tunnel_id,
                reason: reason.to_string(),
            });
        }
    }

    pub async fn process_incoming(&self) -> AppResult<()> {
        self.core
            .process_loop(|msg| async {
                self.on_message(msg);
            })
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("mcp data pump: {e}")))
    }

    fn on_message(&self, msg: Message) {
        match msg {
            Message::McpRelayResponse {
                relay_id,
                status,
                content_type,
                mcp_session_id,
                body_len,
            } => {
                let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(slot) = map.get_mut(&relay_id) {
                    slot.status = Some(status);
                    slot.content_type = content_type;
                    slot.mcp_session_id = mcp_session_id;
                    slot.body_len = body_len;
                    if body_len == 0 {
                        Self::finish(&mut map, relay_id);
                    }
                }
            }
            Message::McpRelayBody {
                relay_id,
                seq,
                data,
                ..
            } => {
                let mut map = self.inflight.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(slot) = map.get_mut(&relay_id) {
                    slot.chunks.insert(seq, data);
                    let total: usize = slot.chunks.values().map(Vec::len).sum();
                    if slot.status.is_some() && total == slot.body_len as usize {
                        Self::finish(&mut map, relay_id);
                    }
                }
            }
            Message::McpTunnelData { tunnel_id, data } => {
                if let Ok(map) = self.tunnels.lock()
                    && let Some(slot) = map.get(tunnel_id)
                {
                    let _ = slot.tx.send(data);
                }
            }
            Message::McpTunnelClose { tunnel_id, .. } => {
                self.forget_tunnel(tunnel_id);
            }
            Message::McpRelayAbort { relay_id, reason } => {
                self.fail_relay(relay_id, &reason);
            }
            _ => {}
        }
    }

    fn finish(map: &mut HashMap<u64, Inflight>, relay_id: u64) {
        let Some(mut slot) = map.remove(&relay_id) else {
            return;
        };
        let Some(waiter) = slot.waiter.take() else {
            return;
        };
        let mut body = Vec::new();
        let mut seq = 0u32;
        while let Some(chunk) = slot.chunks.remove(&seq) {
            body.extend(chunk);
            seq += 1;
        }
        let _ = waiter.send(Ok(RelayedHttp {
            status: slot.status.unwrap_or(502),
            content_type: slot.content_type,
            mcp_session_id: slot.mcp_session_id,
            body,
        }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn drain(peer: &IpcChannel) -> Vec<Message> {
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match peer.try_recv() {
                Ok(msg) => out.push(msg),
                Err(IpcError::Io(e)) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        out
    }

    fn client() -> (Arc<ProxyMcpDataClient>, IpcChannel) {
        let (web_side, peer) = IpcChannel::pair().unwrap();
        let (r, w) = (web_side.read_fd(), web_side.write_fd());
        std::mem::forget(web_side);
        (ProxyMcpDataClient::new(r, w).unwrap(), peer)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_tunnel_splits_a_mebibyte_under_the_pipe_cap() {
        let (data, peer) = client();
        let reader = tokio::task::spawn_blocking(move || drain(&peer));
        let rx = data
            .open_tunnel(7, "198.51.100.1".into(), TunnelLimits::default())
            .unwrap();
        data.send_tunnel(7, vec![0xAB; 1_048_576]).unwrap();
        let msgs = reader.await.unwrap();
        let mut total = 0;
        for msg in &msgs {
            if let Message::McpTunnelData { data, .. } = msg {
                assert!(data.len() <= MCP_PIPE_CHUNK_BYTES);
                total += data.len();
            }
        }
        assert_eq!(total, 1_048_576);
        drop(rx);
    }

    #[test]
    fn write_or_drop_keeps_the_writer_alive_on_oversize() {
        let (a, b) = IpcChannel::pair().unwrap();
        let big = Message::McpTunnelData {
            tunnel_id: 1,
            data: vec![0; shared::ipc::MAX_MESSAGE_SIZE + 1],
        };
        let mut dropped = 0;
        assert!(write_or_drop(&a, &big, |_| dropped += 1).is_ok());
        assert_eq!(dropped, 1);
        let small = Message::McpTunnelClose {
            tunnel_id: 1,
            reason: "after".into(),
        };
        assert!(write_or_drop(&a, &small, |_| dropped += 1).is_ok());
        let got = drain(&b);
        assert!(matches!(
            got.as_slice(),
            [Message::McpTunnelClose { reason, .. }] if reason == "after"
        ));
    }

    #[tokio::test]
    async fn per_ip_and_total_caps_are_checked_on_open() {
        let (data, _peer) = client();
        let limits = TunnelLimits {
            max_total: 3,
            max_per_ip: 2,
        };
        assert!(data.open_tunnel(1, "a".into(), limits).is_ok());
        assert!(data.open_tunnel(2, "a".into(), limits).is_ok());
        assert_eq!(
            data.open_tunnel(3, "a".into(), limits).unwrap_err(),
            TunnelRefused::PerIp
        );
        assert!(data.open_tunnel(4, "b".into(), limits).is_ok());
        assert_eq!(
            data.open_tunnel(5, "c".into(), limits).unwrap_err(),
            TunnelRefused::Total
        );
        data.close_tunnel(1, "close");
        assert_eq!(data.tunnels_for_ip("a"), 1);
        assert!(data.open_tunnel(6, "a".into(), limits).is_ok());
    }

    #[tokio::test]
    async fn leaf_close_frees_the_slot_and_ends_the_stream() {
        let (data, peer) = client();
        let pump = Arc::clone(&data);
        tokio::spawn(async move {
            let _ = pump.process_incoming().await;
        });
        let mut rx = data
            .open_tunnel(9, "198.51.100.2".into(), TunnelLimits::default())
            .unwrap();
        peer.send(&Message::McpTunnelClose {
            tunnel_id: 9,
            reason: "handshake_failed".into(),
        })
        .unwrap();
        let end = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap();
        assert!(end.is_none());
        assert_eq!(data.tunnel_count(), 0);
    }

    fn per_ip_snapshot(data: &ProxyMcpDataClient) -> (HashMap<String, usize>, bool) {
        let map = data.tunnels.lock().unwrap();
        (map.per_ip.clone(), map.consistent())
    }

    #[tokio::test]
    async fn per_ip_counter_follows_web_and_leaf_closes() {
        let (data, _peer) = client();
        let limits = TunnelLimits::default();
        let _a1 = data.open_tunnel(1, "a".into(), limits).unwrap();
        let _a2 = data.open_tunnel(2, "a".into(), limits).unwrap();
        let _b3 = data.open_tunnel(3, "b".into(), limits).unwrap();
        assert_eq!((data.tunnels_for_ip("a"), data.tunnels_for_ip("b")), (2, 1));
        data.close_tunnel(1, "close");
        data.close_tunnel(1, "close");
        assert_eq!(
            data.tunnels_for_ip("a"),
            1,
            "a second close must not decrement"
        );
        data.on_message(Message::McpTunnelClose {
            tunnel_id: 2,
            reason: "handshake_failed".into(),
        });
        assert_eq!(data.tunnels_for_ip("a"), 0);
        let (per_ip, consistent) = per_ip_snapshot(&data);
        assert!(!per_ip.contains_key("a"), "zero entries are dropped");
        assert_eq!(per_ip.get("b"), Some(&1));
        assert!(consistent);
    }

    #[test]
    fn tunnel_map_reinsert_does_not_leak_the_old_ip() {
        let mut map = TunnelMap::default();
        let slot = |ip: &str| TunnelSlot {
            tx: mpsc::unbounded_channel().0,
            client_ip: ip.into(),
        };
        map.insert(1, slot("a"));
        map.insert(1, slot("b"));
        assert_eq!((map.count_for_ip("a"), map.count_for_ip("b")), (0, 1));
        assert!(map.remove(1).is_some());
        assert!(map.remove(1).is_none());
        assert!(map.per_ip.is_empty() && map.consistent());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn battle_sixty_four_tunnels_open_and_close_on_four_ips() {
        use std::sync::atomic::AtomicBool;
        let (data, peer) = client();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_reader = Arc::clone(&stop);
        let reader = tokio::task::spawn_blocking(move || {
            while !stop_reader.load(Ordering::SeqCst) {
                match peer.try_recv() {
                    Ok(_) => {}
                    Err(IpcError::Io(e)) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(64));
        let mut joins = Vec::new();
        for i in 0..64u64 {
            let data = Arc::clone(&data);
            let barrier = Arc::clone(&barrier);
            joins.push(tokio::spawn(async move {
                barrier.wait().await;
                let ip = format!("198.51.100.{}", i % 4);
                let id = data.reserve_tunnel_id();
                let rx = data
                    .open_tunnel(id, ip, TunnelLimits::default())
                    .expect("16 per IP fit under the cap");
                tokio::task::yield_now().await;
                if i % 2 == 0 {
                    data.close_tunnel(id, "close");
                } else {
                    data.on_message(Message::McpTunnelClose {
                        tunnel_id: id,
                        reason: "closed".into(),
                    });
                }
                drop(rx);
            }));
        }
        for join in joins {
            join.await.unwrap();
        }
        assert_eq!(data.tunnel_count(), 0);
        let (per_ip, consistent) = per_ip_snapshot(&data);
        assert!(per_ip.is_empty(), "{per_ip:?}");
        assert!(consistent);
        stop.store(true, Ordering::SeqCst);
        reader.await.unwrap();
    }

    #[derive(Debug, Clone)]
    enum Op {
        Open(u8, u8),
        WebClose(u8),
        LeafClose(u8),
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        prop_oneof![
            (0u8..12, 0u8..3).prop_map(|(id, ip)| Op::Open(id, ip)),
            (0u8..12).prop_map(Op::WebClose),
            (0u8..12).prop_map(Op::LeafClose),
        ]
    }

    proptest::proptest! {
        #[test]
        fn per_ip_counter_matches_a_model(ops in proptest::collection::vec(op(), 0..80)) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (data, _peer) = client();
                let limits = TunnelLimits { max_total: 8, max_per_ip: 3 };
                let mut model: HashMap<u64, u8> = HashMap::new();
                let mut streams = Vec::new();
                for op in ops {
                    match op {
                        Op::Open(id, ip) => {
                            let id = u64::from(id);
                            if model.contains_key(&id) {
                                continue;
                            }
                            let same = model.values().filter(|i| **i == ip).count();
                            let expect = if model.len() >= 8 {
                                Err(TunnelRefused::Total)
                            } else if same >= 3 {
                                Err(TunnelRefused::PerIp)
                            } else {
                                Ok(())
                            };
                            let got = data.open_tunnel(id, format!("ip{ip}"), limits);
                            proptest::prop_assert_eq!(got.as_ref().map(|_| ()).map_err(|e| *e), expect);
                            if let Ok(rx) = got {
                                model.insert(id, ip);
                                streams.push(rx);
                            }
                        }
                        Op::WebClose(id) => {
                            model.remove(&u64::from(id));
                            data.close_tunnel(u64::from(id), "close");
                        }
                        Op::LeafClose(id) => {
                            model.remove(&u64::from(id));
                            data.on_message(Message::McpTunnelClose {
                                tunnel_id: u64::from(id),
                                reason: "closed".into(),
                            });
                        }
                    }
                    let (per_ip, consistent) = per_ip_snapshot(&data);
                    proptest::prop_assert!(consistent);
                    proptest::prop_assert_eq!(per_ip.values().sum::<usize>(), model.len());
                    for ip in 0u8..3 {
                        let held = model.values().filter(|i| **i == ip).count();
                        proptest::prop_assert_eq!(data.tunnels_for_ip(&format!("ip{ip}")), held);
                    }
                }
                Ok(())
            })?;
        }

        #[test]
        fn tunnel_chunks_fit_and_concatenate(len in 0usize..1_048_576) {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut joined = Vec::new();
            for piece in input.chunks(MCP_PIPE_CHUNK_BYTES) {
                // Envelope overhead is a few bytes; 64 KiB of headroom remains.
                proptest::prop_assert!(piece.len() + 1024 <= shared::ipc::MAX_MESSAGE_SIZE);
                joined.extend_from_slice(piece);
            }
            proptest::prop_assert_eq!(joined, input);
        }
    }
}
