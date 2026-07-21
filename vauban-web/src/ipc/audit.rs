//! IPC client for emitting audit events to vauban-audit.
//!
//! `vauban-web` is the richest source of security-relevant actions (auth, MFA,
//! user/policy/asset CRUD, session lifecycle, JIT approvals, authorization
//! denials). This client ships those as typed `AuditEvent`s over the
//! supervisor-created `Web -> Audit` pipe so they land in the tamper-evident
//! WORM log.
//!
//! Two emission modes:
//!
//! - [`AuditClient::emit`] -- fire-and-forget, bounded. The event is pushed
//!   onto an in-memory queue and written by a background task; if the queue is
//!   saturated (audit wedged) the event is dropped with an `error!` rather than
//!   blocking the request path. Use for high-volume, non-critical signals.
//! - [`AuditClient::emit_critical`] -- awaits a durable `AuditAck` from the
//!   audit service (the event is hash-chained to disk before the ack). An
//!   `AuditNack`, timeout, or transport failure is surfaced as an error so the
//!   caller can fail-closed. Use for auth/escalation and other security-
//!   critical events.
//!
//! Correlation: `AuditEvent`/`AuditAck`/`AuditNack` carry no `request_id`; they
//! correlate on `timestamp`. The client stamps each emission with a strictly
//! increasing Unix-millisecond value so concurrent criticals never collide.
//!
//! Transport drain uses [`CorrelatedIpcCore`] (INV-CORR-2). Critical acks use
//! [`PendingGuard`] / `request_with_key` semantics with a 5 s timeout
//! (INV-CORR-5); the actual write still goes through the mpsc writer so
//! frames never interleave.

use crate::ipc::correlated::CorrelatedIpcCore;
use shared::messages::{AuditEventType, Message};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, warn};

/// Bounded fire-and-forget queue depth. Beyond this, non-critical events are
/// dropped (with an `error!`) to protect the request path.
const EMIT_QUEUE_DEPTH: usize = 2048;

/// How long `emit_critical` waits for a durable ack before failing closed.
const CRITICAL_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// A fully-formed audit event ready to emit.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub source_ip: Option<IpAddr>,
    /// Structured JSON details (target, non-secret old/new values, ...).
    pub details: String,
}

impl AuditEvent {
    /// Convenience constructor.
    #[must_use]
    pub fn new(event_type: AuditEventType, details: impl Into<String>) -> Self {
        Self {
            event_type,
            user_id: None,
            session_id: None,
            source_ip: None,
            details: details.into(),
        }
    }

    #[must_use]
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user_id = Some(user.into());
        self
    }

    #[must_use]
    pub fn session(mut self, session: impl Into<String>) -> Self {
        self.session_id = Some(session.into());
        self
    }

    #[must_use]
    pub fn ip(mut self, ip: Option<IpAddr>) -> Self {
        self.source_ip = ip;
        self
    }
}

/// Async IPC client for emitting audit events to vauban-audit.
pub struct AuditClient {
    /// Bounded sender feeding the background writer task.
    tx: mpsc::Sender<Message>,
    core: CorrelatedIpcCore,
    /// Pending critical emissions, keyed by event timestamp. The bool is
    /// `true` on `AuditAck` (durably persisted), `false` on `AuditNack`.
    pending: StdMutex<HashMap<u64, oneshot::Sender<bool>>>,
    /// Strictly-increasing millisecond clock for unique correlation stamps.
    last_ts: AtomicU64,
}

impl AuditClient {
    /// Create a client over the supervisor-provided `Web -> Audit` pipe and
    /// spawn the background writer task.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Arc<Self>> {
        let core = CorrelatedIpcCore::from_fds(read_fd, write_fd)?;
        let (tx, mut rx) = mpsc::channel::<Message>(EMIT_QUEUE_DEPTH);

        // Background writer: the ONLY task that writes to the pipe, so frames
        // never interleave regardless of how many handlers emit concurrently.
        let writer_channel = core.channel_arc();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = writer_channel.send(&msg) {
                    error!(error = %e, "audit: failed to write event to pipe");
                }
            }
            debug!("audit writer task stopped (queue closed)");
        });

        Ok(Arc::new(Self {
            tx,
            core,
            pending: StdMutex::new(HashMap::new()),
            last_ts: AtomicU64::new(0),
        }))
    }

    /// Allocate a strictly-increasing millisecond timestamp.
    fn next_timestamp(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Bump past the last value so concurrent emissions stay unique.
        self.last_ts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev| {
                Some(now.max(prev + 1))
            })
            .unwrap_or(now)
    }

    fn build_message(&self, ts: u64, event: &AuditEvent) -> Message {
        Message::AuditEvent {
            timestamp: ts,
            event_type: event.event_type,
            user_id: event.user_id.clone(),
            session_id: event.session_id.clone(),
            source_ip: event.source_ip,
            details: event.details.clone(),
        }
    }

    /// Fire-and-forget emission. Never blocks the caller; drops (with an
    /// `error!`) if the bounded queue is saturated.
    pub fn emit(&self, event: AuditEvent) {
        let ts = self.next_timestamp();
        let msg = self.build_message(ts, &event);
        match self.tx.try_send(msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                error!(
                    event_type = ?event.event_type,
                    "audit: emit queue full; event DROPPED (audit service wedged?)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(
                    event_type = ?event.event_type,
                    "audit: emit channel closed; event DROPPED"
                );
            }
        }
    }

    /// Emit a security-critical event and await its durable `AuditAck`.
    ///
    /// Returns `Ok(())` only once the audit service has hash-chained the event
    /// to disk. An `AuditNack`, a 5 s timeout, or a transport failure is an
    /// error (the caller decides whether to fail the operation closed).
    ///
    /// Uses INV-CORR-1 PendingGuard + timestamp key (request_with_key
    /// semantics). The write still goes through the mpsc writer so it does
    /// not race other emits on the pipe.
    pub async fn emit_critical(&self, event: AuditEvent) -> Result<(), String> {
        let ts = self.next_timestamp();
        let msg = self.build_message(ts, &event);

        let (ack_tx, ack_rx) = oneshot::channel();
        let _guard = CorrelatedIpcCore::insert_pending(&self.pending, ts, ack_tx);

        if let Err(e) = self.tx.send(msg).await {
            return Err(format!("audit emit channel closed: {e}"));
        }

        match tokio::time::timeout(CRITICAL_ACK_TIMEOUT, ack_rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err("audit service NACKed the event".to_string()),
            Ok(Err(_)) => Err("audit ack channel dropped".to_string()),
            Err(_) => Err("audit ack timed out".to_string()),
        }
    }

    /// Drain ack/nack replies from the audit service. Run in a background task.
    pub async fn process_incoming(&self) -> Result<(), String> {
        self.core
            .process_loop(|msg| {
                self.handle_message(msg);
                async {}
            })
            .await
            .map_err(|e| e.to_string())
    }

    fn handle_message(&self, msg: Message) {
        match msg {
            Message::AuditAck { timestamp } => {
                // No pending entry => fire-and-forget emit; nothing to do.
                let _ = CorrelatedIpcCore::deliver(&self.pending, timestamp, true);
            }
            Message::AuditNack { timestamp, error } => {
                warn!(timestamp, %error, "audit: event NACKed by audit service");
                let _ = CorrelatedIpcCore::deliver(&self.pending, timestamp, false);
            }
            other => debug!(msg = ?other, "audit: ignoring unexpected reply"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::ipc::IpcChannel;

    /// Build a client over one end of a pipe pair, returning the audit-side
    /// channel (the "mock audit service") for the test to drive. The web-side
    /// fds are transferred into the client via `forget` to avoid a double
    /// close.
    fn client_with_mock() -> (Arc<AuditClient>, IpcChannel) {
        let (web_side, audit_side) = IpcChannel::pair().unwrap();
        let r = web_side.read_fd();
        let w = web_side.write_fd();
        std::mem::forget(web_side);
        let client = AuditClient::new(r, w).unwrap();
        (client, audit_side)
    }

    #[tokio::test]
    async fn next_timestamp_is_strictly_increasing() {
        let (client, _mock) = client_with_mock();
        let a = client.next_timestamp();
        let b = client.next_timestamp();
        let c = client.next_timestamp();
        assert!(a < b && b < c, "timestamps must be unique + increasing");
    }

    #[tokio::test]
    async fn emit_enqueues_event_for_the_writer() {
        let (client, mock) = client_with_mock();
        client.emit(AuditEvent::new(AuditEventType::AuthSuccess, "{}").user("alice"));

        // The background writer flushes it to the pipe; the mock reads it.
        let msg = tokio::task::spawn_blocking(move || mock.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Message::AuditEvent {
                event_type,
                user_id,
                ..
            } => {
                assert!(matches!(event_type, AuditEventType::AuthSuccess));
                assert_eq!(user_id.as_deref(), Some("alice"));
            }
            other => panic!("expected AuditEvent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_critical_resolves_on_ack() {
        let (client, mock) = client_with_mock();
        let reader = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = reader.process_incoming().await;
        });

        // Mock audit service: read the event, reply with a durable ack.
        let mock_task = tokio::task::spawn_blocking(move || {
            let msg = mock.recv().unwrap();
            if let Message::AuditEvent { timestamp, .. } = msg {
                mock.send(&Message::AuditAck { timestamp }).unwrap();
            } else {
                panic!("expected AuditEvent");
            }
        });

        let res = client
            .emit_critical(AuditEvent::new(AuditEventType::AuthFailure, "{}"))
            .await;
        mock_task.await.unwrap();
        assert!(res.is_ok(), "critical emit must succeed on ack: {res:?}");
    }

    #[tokio::test]
    async fn emit_critical_errors_on_nack() {
        let (client, mock) = client_with_mock();
        let reader = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = reader.process_incoming().await;
        });

        let mock_task = tokio::task::spawn_blocking(move || {
            let msg = mock.recv().unwrap();
            if let Message::AuditEvent { timestamp, .. } = msg {
                mock.send(&Message::AuditNack {
                    timestamp,
                    error: "disk full".to_string(),
                })
                .unwrap();
            }
        });

        let res = client
            .emit_critical(AuditEvent::new(AuditEventType::AuthFailure, "{}"))
            .await;
        mock_task.await.unwrap();
        assert!(res.is_err(), "critical emit must fail on nack");
    }
}
