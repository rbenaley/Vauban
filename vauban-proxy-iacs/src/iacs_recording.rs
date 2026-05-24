//! IACS PCAP recording over the ProxyIacs ↔ Audit IPC pipe.
//!
//! The relay tees bytes to audit with blocking acknowledgement: each batch
//! is persisted (fdatasync) before the proxy forwards the bytes to the peer.

use shared::messages::{IacsRecordingDirection, Message};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::warn;

/// Routes `IacsRecordingDataAck` messages to waiting relay tasks.
#[derive(Default)]
pub struct AckRouter {
    pending: Mutex<HashMap<(String, u32, u64), oneshot::Sender<()>>>,
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
        if let Some(tx) = self
            .pending
            .lock()
            .await
            .remove(&(session_id.to_string(), channel_id, batch_seq))
        {
            let _ = tx.send(());
        }
    }
}

/// Shared handle wired into every authenticated SSH login handler.
#[derive(Clone)]
pub struct IacsRecordingHub {
    pub audit_tx: mpsc::UnboundedSender<Message>,
    pub ack_router: Arc<AckRouter>,
}

impl IacsRecordingHub {
    pub fn channel_recorder(&self, session_id: String, channel_id: u32) -> ChannelRecorder {
        ChannelRecorder {
            session_id,
            channel_id,
            batch_seq: Arc::new(AtomicU64::new(0)),
            audit_tx: self.audit_tx.clone(),
            ack_router: Arc::clone(&self.ack_router),
        }
    }

    pub fn send_channel_start(
        &self,
        session_id: &str,
        channel_id: u32,
        target_host: &str,
        target_port: u16,
    ) {
        let _ = self.audit_tx.send(Message::IacsRecordingChannelStart {
            session_id: session_id.to_string(),
            channel_id,
            target_host: target_host.to_string(),
            target_port,
            opened_at_us: now_us(),
        });
    }

    pub fn send_channel_end(&self, session_id: &str, channel_id: u32) {
        let _ = self.audit_tx.send(Message::IacsRecordingChannelEnd {
            session_id: session_id.to_string(),
            channel_id,
            closed_at_us: now_us(),
        });
    }

    pub fn send_session_end(&self, session_id: &str) {
        let _ = self.audit_tx.send(Message::IacsRecordingSessionEnd {
            session_id: session_id.to_string(),
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
}

impl ChannelRecorder {
    /// Persist a relay batch and wait for audit acknowledgement before returning.
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
        match rx.await {
            Ok(()) => Ok(()),
            Err(_) => {
                warn!(
                    session_id = %self.session_id,
                    channel_id = self.channel_id,
                    batch_seq = seq,
                    "IACS recording ack dropped"
                );
                Err(std::io::Error::other("recording ack dropped"))
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
}
