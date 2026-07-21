//! IACS PCAP recording over the ProxyIacs <-> Audit IPC pipe.
//!
//! The relay tees bytes to audit with blocking acknowledgement: each
//! batch is persisted (`fdatasync`) before the proxy forwards the
//! bytes to the peer.
//!
//! `ChannelRecorder::write_batch` enforces a 5-second ceiling on the
//! ack wait via `tokio::time::timeout`. If audit is wedged or the
//! IPC pipe loses a frame, the relay closes the channel cleanly
//! instead of remaining indefinitely blocked.

use shared::messages::{IacsRecordingDirection, Message};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tracing::warn;

/// Wall-clock ceiling on the wait for an `IacsRecordingDataAck`.
/// Defaults to 5 seconds; a slow reseau / overloaded audit will
/// surface as a recording error rather than a wedged relay task.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Routes `IacsRecordingDataAck` messages to waiting relay tasks.
#[derive(Default)]
pub struct AckRouter {
    pending: AsyncMutex<HashMap<(String, u32, u64), oneshot::Sender<()>>>,
}

impl AckRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(
        &self,
        session_id: &str,
        channel_id: u32,
        batch_seq: u64,
    ) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert((session_id.to_string(), channel_id, batch_seq), tx);
        rx
    }

    pub async fn complete(&self, session_id: &str, channel_id: u32, batch_seq: u64) {
        if let Some(tx) =
            self.pending
                .lock()
                .await
                .remove(&(session_id.to_string(), channel_id, batch_seq))
        {
            let _ = tx.send(());
        }
    }

    /// Drain a pending entry without signalling. Used when the
    /// caller times out so the router does not retain stale
    /// `oneshot::Sender`s indefinitely.
    pub async fn cancel(&self, session_id: &str, channel_id: u32, batch_seq: u64) {
        self.pending
            .lock()
            .await
            .remove(&(session_id.to_string(), channel_id, batch_seq));
    }

    #[cfg(test)]
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

/// Endpoints captured at `direct-tcpip` open time. The proxy
/// passes these to vauban-audit so the synthetic L3/L4 layer
/// (IPv4/IPv6 + TCP) wrapped around every captured chunk uses the
/// real client / server addresses (originator from RFC 4254 +
/// peer_addr of the brokered upstream fd).
#[derive(Debug, Clone)]
pub struct ChannelEndpoints {
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
}

/// Counters published to `ServiceState` so the supervisor / metrics
/// surface can observe recording health.
pub struct RecordingMetrics {
    pub ack_timeouts: AtomicU64,
    pub ack_dropped: AtomicU64,
    /// Max ack wait (ms) observed in the current 60 s window.
    pub ack_wait_ms_max: AtomicU64,
    wait_max_window_start: Mutex<Instant>,
}

impl Default for RecordingMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingMetrics {
    pub fn new() -> Self {
        Self {
            ack_timeouts: AtomicU64::new(0),
            ack_dropped: AtomicU64::new(0),
            ack_wait_ms_max: AtomicU64::new(0),
            wait_max_window_start: Mutex::new(Instant::now()),
        }
    }

    pub fn record_success_wait_ms(&self, ms: u64) {
        self.ack_wait_ms_max.fetch_max(ms, Ordering::SeqCst);
    }

    /// Snapshot the max ack wait for the current 60 s window. Resets the
    /// window when elapsed >= 60 s (called from `ServiceState::stats`).
    pub fn snapshot_ack_wait_ms_max(&self) -> u64 {
        if let Ok(mut start) = self.wait_max_window_start.lock()
            && start.elapsed() >= Duration::from_secs(60)
        {
            self.ack_wait_ms_max.store(0, Ordering::SeqCst);
            *start = Instant::now();
        }
        self.ack_wait_ms_max.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.ack_timeouts.load(Ordering::SeqCst),
            self.ack_dropped.load(Ordering::SeqCst),
            self.snapshot_ack_wait_ms_max(),
        )
    }

    #[cfg(test)]
    pub fn rewind_wait_window_for_test(&self, ago: Duration) {
        if let Ok(mut start) = self.wait_max_window_start.lock() {
            *start = Instant::now().checked_sub(ago).unwrap_or(Instant::now());
        }
    }
}

/// Shared handle wired into every authenticated SSH login handler.
#[derive(Clone)]
pub struct IacsRecordingHub {
    pub audit_tx: mpsc::UnboundedSender<Message>,
    pub ack_router: Arc<AckRouter>,
    pub metrics: Arc<RecordingMetrics>,
}

/// Session identity captured at SSH-auth time, forwarded to
/// vauban-audit in `IacsRecordingSessionStart` so `session.json`
/// records who / which key / from where / when -- even for logins
/// that never open a `direct-tcpip` channel.
#[derive(Debug, Clone)]
pub struct SessionStartInfo {
    pub user_uuid: String,
    pub asset_uuid: String,
    pub ews_fingerprint: String,
    pub peer_ip: String,
    pub authenticated_at_us: u64,
    pub connected_at_us: u64,
}

impl IacsRecordingHub {
    pub fn channel_recorder(&self, session_id: String, channel_id: u32) -> ChannelRecorder {
        ChannelRecorder {
            session_id,
            channel_id,
            batch_seq: Arc::new(AtomicU64::new(0)),
            audit_tx: self.audit_tx.clone(),
            ack_router: Arc::clone(&self.ack_router),
            metrics: Arc::clone(&self.metrics),
        }
    }

    pub fn send_channel_start(
        &self,
        session_id: &str,
        channel_id: u32,
        target_host: &str,
        target_port: u16,
        endpoints: ChannelEndpoints,
        connected_at_us: u64,
    ) {
        let _ = self.audit_tx.send(Message::IacsRecordingChannelStart {
            session_id: session_id.to_string(),
            channel_id,
            target_host: target_host.to_string(),
            target_port,
            opened_at_us: now_us(),
            client_ip: endpoints.client_ip,
            client_port: endpoints.client_port,
            server_ip: endpoints.server_ip,
            server_port: endpoints.server_port,
            connected_at_us,
        });
    }

    pub fn send_channel_end(&self, session_id: &str, channel_id: u32) {
        let _ = self.audit_tx.send(Message::IacsRecordingChannelEnd {
            session_id: session_id.to_string(),
            channel_id,
            closed_at_us: now_us(),
        });
    }

    /// Fire-and-forget `IacsRecordingSessionStart` at SSH-auth time.
    /// vauban-audit creates the session state and writes
    /// `session.json` immediately.
    pub fn send_session_start(&self, session_id: &str, info: SessionStartInfo) {
        let _ = self.audit_tx.send(Message::IacsRecordingSessionStart {
            session_id: session_id.to_string(),
            user_uuid: info.user_uuid,
            asset_uuid: info.asset_uuid,
            ews_fingerprint: info.ews_fingerprint,
            peer_ip: info.peer_ip,
            authenticated_at_us: info.authenticated_at_us,
            connected_at_us: info.connected_at_us,
        });
    }

    pub fn send_session_end(&self, session_id: &str, reason: &str) {
        let _ = self.audit_tx.send(Message::IacsRecordingSessionEnd {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
        });
    }
}

/// Per-`direct-tcpip` channel recorder (one PCAP file in audit).
#[derive(Clone)]
pub struct ChannelRecorder {
    session_id: String,
    channel_id: u32,
    batch_seq: Arc<AtomicU64>,
    audit_tx: mpsc::UnboundedSender<Message>,
    ack_router: Arc<AckRouter>,
    metrics: Arc<RecordingMetrics>,
}

impl ChannelRecorder {
    /// Persist a relay batch and wait for audit acknowledgement
    /// before returning. Bounded by [`ACK_TIMEOUT`]; on timeout the
    /// pending router entry is dropped, the metric is bumped, and
    /// an `io::Error` of kind `TimedOut` is returned. The relay
    /// task propagates the error -> the channel closes cleanly.
    pub async fn write_batch(
        &self,
        direction: IacsRecordingDirection,
        data: &[u8],
    ) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let seq = self.batch_seq.fetch_add(1, Ordering::SeqCst);
        let rx = self
            .ack_router
            .register(&self.session_id, self.channel_id, seq)
            .await;
        self.audit_tx
            .send(Message::IacsRecordingData {
                session_id: self.session_id.clone(),
                channel_id: self.channel_id,
                batch_seq: seq,
                direction,
                timestamp_us: now_us(),
                data: data.to_vec(),
            })
            .map_err(|e| std::io::Error::other(format!("audit channel closed: {e}")))?;
        let wait_start = Instant::now();
        match tokio::time::timeout(ACK_TIMEOUT, rx).await {
            Ok(Ok(())) => {
                let ms = wait_start.elapsed().as_millis() as u64;
                self.metrics.record_success_wait_ms(ms);
                Ok(())
            }
            Ok(Err(_)) => {
                self.metrics.ack_dropped.fetch_add(1, Ordering::SeqCst);
                warn!(
                    session_id = %self.session_id,
                    channel_id = self.channel_id,
                    batch_seq = seq,
                    "IACS recording ack dropped"
                );
                Err(std::io::Error::other("recording ack dropped"))
            }
            Err(_) => {
                self.ack_router
                    .cancel(&self.session_id, self.channel_id, seq)
                    .await;
                self.metrics.ack_timeouts.fetch_add(1, Ordering::SeqCst);
                warn!(
                    session_id = %self.session_id,
                    channel_id = self.channel_id,
                    batch_seq = seq,
                    timeout_secs = ACK_TIMEOUT.as_secs(),
                    "IACS recording ack timeout"
                );
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "recording ack timeout",
                ))
            }
        }
    }
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ack_router_delivers_to_waiter() {
        let router = AckRouter::new();
        let rx = router.register("s1", 1, 0).await;
        router.complete("s1", 1, 0).await;
        rx.await.unwrap();
    }

    #[tokio::test]
    async fn ack_router_ignores_unknown_key() {
        let router = AckRouter::new();
        router.complete("s1", 1, 99).await;
    }

    #[tokio::test]
    async fn ack_router_cancel_removes_pending_entry() {
        let router = AckRouter::new();
        let _rx = router.register("s1", 1, 0).await;
        assert_eq!(router.pending_count().await, 1);
        router.cancel("s1", 1, 0).await;
        assert_eq!(router.pending_count().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn write_batch_times_out_when_ack_never_arrives() {
        let metrics = Arc::new(RecordingMetrics::default());
        let ack_router = Arc::new(AckRouter::new());
        let (audit_tx, _audit_rx) = mpsc::unbounded_channel();
        let hub = IacsRecordingHub {
            audit_tx,
            ack_router: Arc::clone(&ack_router),
            metrics: Arc::clone(&metrics),
        };
        let recorder = hub.channel_recorder("s1".into(), 1);

        let task = tokio::spawn(async move {
            recorder
                .write_batch(IacsRecordingDirection::EwsToAsset, b"hello")
                .await
        });
        tokio::time::advance(ACK_TIMEOUT + Duration::from_secs(1)).await;
        let result = task.await.unwrap();
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(metrics.ack_timeouts.load(Ordering::SeqCst), 1);
        assert_eq!(ack_router.pending_count().await, 0);
    }

    #[tokio::test]
    async fn write_batch_succeeds_when_ack_arrives_before_timeout() {
        let metrics = Arc::new(RecordingMetrics::default());
        let ack_router = Arc::new(AckRouter::new());
        let (audit_tx, mut audit_rx) = mpsc::unbounded_channel();
        let hub = IacsRecordingHub {
            audit_tx,
            ack_router: Arc::clone(&ack_router),
            metrics: Arc::clone(&metrics),
        };
        let recorder = hub.channel_recorder("s1".into(), 1);

        let ack_router_for_acker = Arc::clone(&ack_router);
        tokio::spawn(async move {
            // Wait for the data message, then ack.
            if let Some(Message::IacsRecordingData {
                session_id,
                channel_id,
                batch_seq,
                ..
            }) = audit_rx.recv().await
            {
                ack_router_for_acker
                    .complete(&session_id, channel_id, batch_seq)
                    .await;
            }
        });
        recorder
            .write_batch(IacsRecordingDirection::EwsToAsset, b"hi")
            .await
            .unwrap();
        assert_eq!(metrics.ack_timeouts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn write_batch_bumps_ack_dropped_when_sender_dropped() {
        let metrics = Arc::new(RecordingMetrics::default());
        let ack_router = Arc::new(AckRouter::new());
        let (audit_tx, _audit_rx) = mpsc::unbounded_channel();
        let hub = IacsRecordingHub {
            audit_tx,
            ack_router: Arc::clone(&ack_router),
            metrics: Arc::clone(&metrics),
        };
        let recorder = hub.channel_recorder("s1".into(), 1);

        let task = tokio::spawn(async move {
            recorder
                .write_batch(IacsRecordingDirection::EwsToAsset, b"x")
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        ack_router.cancel("s1", 1, 0).await;
        let result = task.await.unwrap();
        assert!(result.is_err());
        assert_eq!(metrics.ack_dropped.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.ack_timeouts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn record_success_wait_ms_tracks_max_in_window() {
        let metrics = RecordingMetrics::new();
        metrics.record_success_wait_ms(12);
        metrics.record_success_wait_ms(48);
        metrics.record_success_wait_ms(30);
        assert_eq!(metrics.snapshot_ack_wait_ms_max(), 48);
    }

    #[test]
    fn snapshot_ack_wait_ms_max_resets_after_60s_window() {
        let metrics = RecordingMetrics::new();
        metrics.record_success_wait_ms(100);
        assert_eq!(metrics.snapshot_ack_wait_ms_max(), 100);
        metrics.rewind_wait_window_for_test(Duration::from_secs(61));
        assert_eq!(metrics.snapshot_ack_wait_ms_max(), 0);
        metrics.record_success_wait_ms(5);
        assert_eq!(metrics.snapshot_ack_wait_ms_max(), 5);
    }

    #[tokio::test]
    async fn write_batch_empty_payload_is_no_op() {
        let metrics = Arc::new(RecordingMetrics::default());
        let ack_router = Arc::new(AckRouter::new());
        let (audit_tx, _audit_rx) = mpsc::unbounded_channel();
        let hub = IacsRecordingHub {
            audit_tx,
            ack_router: Arc::clone(&ack_router),
            metrics: Arc::clone(&metrics),
        };
        let recorder = hub.channel_recorder("s1".into(), 1);
        recorder
            .write_batch(IacsRecordingDirection::EwsToAsset, b"")
            .await
            .unwrap();
        assert_eq!(ack_router.pending_count().await, 0);
    }
}
