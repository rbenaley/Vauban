// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! MCP audit + JSONL session recording (06 — Preuves).
//!
//! - Typed audit events over the supervisor `ProxyMcp -> Audit` pipe.
//!   A client-visible success waits until `send` on that pipe accepts the
//!   event. A full, closed, or timed-out pipe refuses the visit; the event
//!   stays at the head of a bounded queue and is not discarded.
//! - Per-session JSONL under `YYYY/MM/{uuid}/session.mcp.jsonl` (+ `meta.json`),
//!   via supervisor FD lease when wired (fail-closed; no local open escape),
//!   else local lab open when no lease channel.
//! - On terminate: blake3 → `meta.json` + `McpRecordingFinalized` WORM event.

#[cfg(test)]
use crate::mcp_recording::RecordingLeaseReq;
use crate::mcp_recording::{FinalizeStats, McpRecording, RecordingLeaseTx};
use serde_json::{Value, json};
use shared::json_redact::redact_sensitive_json;
use shared::messages::{AuditEventType, Message};
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Longest a full Audit queue may hold one WORM event before the visit is refused.
/// The event stays queued; it is not discarded.
pub const WORM_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// WORM events waiting for room in the Audit queue. A further event is refused
/// and does not enter.
pub const WORM_OVERFLOW_MAX: usize = 4096;

static WORM_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// WORM refusals in this process (heartbeat `ServiceStats`).
///
/// Each count is a visit the caller was told did not record. Accepted
/// events are not included.
pub fn worm_dropped_total() -> u64 {
    WORM_DROPPED_TOTAL.load(Ordering::Relaxed)
}

static JSONL_APPEND_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Security events (drift, escalation) that could not be appended to a
/// visit's JSONL (heartbeat `ServiceStats::recording_try_send_full`).
pub fn jsonl_append_failed_total() -> u64 {
    JSONL_APPEND_FAILED_TOTAL.load(Ordering::Relaxed)
}

pub const TOOL_CALL_PHASE_INTENT: &str = "intent";
pub const TOOL_CALL_PHASE_RESULT: &str = "result";

/// `outcome` of a `phase:"result"` tools/call line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallOutcome {
    Ok,
    UpstreamError,
    Timeout,
}

impl ToolCallOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::UpstreamError => "upstream_error",
            Self::Timeout => "timeout",
        }
    }
}

/// Objects/arrays are redacted in place; scalars are replaced by a digest.
fn redact_response(r: &Value) -> Value {
    match r {
        Value::Object(_) | Value::Array(_) => redact_sensitive_json(r),
        other => {
            let s = other.to_string();
            json!({
                "content_type": "application/json",
                "byte_length": s.len(),
                "sha256": blake3::hash(s.as_bytes()).to_hex().to_string(),
            })
        }
    }
}

/// Shared audit + recording hub cloned into axum / IPC tasks.
#[derive(Clone)]
pub struct McpAudit {
    inner: Arc<McpAuditInner>,
}

struct McpAuditInner {
    audit_tx: Option<mpsc::Sender<Message>>,
    recording: McpRecording,
    last_ts: AtomicU64,
    worm: Arc<WormOverflow>,
}

/// Events waiting for room on the Audit pipe, kept in emission order.
/// A caller is told only after `send` accepts the event. On timeout or a
/// closed pipe the event is put back at the head and every waiter is refused.
#[derive(Default)]
struct WormOverflow {
    state: Mutex<OverflowState>,
    dropped: AtomicU64,
    send_timeout_ms: AtomicU64,
}

struct Queued {
    event_type: AuditEventType,
    msg: Message,
    /// `None` once the original caller has already been refused. The event
    /// stays so a later drain can still deliver it.
    ack: Option<oneshot::Sender<Result<(), &'static str>>>,
}

#[derive(Default)]
struct OverflowState {
    queue: VecDeque<Queued>,
    running: bool,
}

impl WormOverflow {
    fn new() -> Arc<Self> {
        let w = Self::default();
        w.send_timeout_ms
            .store(WORM_SEND_TIMEOUT.as_millis() as u64, Ordering::Relaxed);
        Arc::new(w)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OverflowState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A caller was told the event is not recorded. The event itself stays queued.
    fn note_refused(&self, event_type: AuditEventType, why: &'static str) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let total = WORM_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        error!(?event_type, why, total, "MCP audit event refused");
    }

    fn park_locked(&self, st: &mut OverflowState, event_type: AuditEventType, msg: Message) {
        if st.queue.len() >= WORM_OVERFLOW_MAX {
            self.note_refused(event_type, "overflow full");
            return;
        }
        st.queue.push_back(Queued {
            event_type,
            msg,
            ack: None,
        });
        self.note_refused(event_type, "audit channel closed");
    }

    fn fail_waiters(&self, st: &mut OverflowState, why: &'static str) {
        for queued in &mut st.queue {
            if let Some(ack) = queued.ack.take() {
                let event_type = queued.event_type;
                let _ = ack.send(Err(why));
                self.note_refused(event_type, why);
            }
        }
    }

    async fn accept(
        self: &Arc<Self>,
        tx: &mpsc::Sender<Message>,
        event_type: AuditEventType,
        mut msg: Message,
    ) -> Result<(), &'static str> {
        let (ack_rx, start_drain) = {
            let mut st = self.lock();
            if st.queue.is_empty() && !st.running {
                match tx.try_send(msg) {
                    Ok(()) => return Ok(()),
                    Err(TrySendError::Closed(returned)) => {
                        self.park_locked(&mut st, event_type, returned);
                        return Err("audit channel closed");
                    }
                    Err(TrySendError::Full(returned)) => msg = returned,
                }
            }
            if st.queue.len() >= WORM_OVERFLOW_MAX {
                drop(st);
                self.note_refused(event_type, "overflow full");
                return Err("overflow full");
            }
            let (ack_tx, ack_rx) = oneshot::channel();
            st.queue.push_back(Queued {
                event_type,
                msg,
                ack: Some(ack_tx),
            });
            if st.running {
                (ack_rx, false)
            } else if tokio::runtime::Handle::try_current().is_err() {
                self.fail_waiters(&mut st, "no runtime to wait for room");
                return Err("no runtime to wait for room");
            } else {
                st.running = true;
                (ack_rx, true)
            }
        };
        if start_drain {
            let this = Arc::clone(self);
            let tx = tx.clone();
            tokio::spawn(async move { this.drain(tx).await });
        }
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(why)) => Err(why),
            Err(_closed) => Err("audit drain dropped the waiter"),
        }
    }

    async fn drain(self: &Arc<Self>, tx: mpsc::Sender<Message>) {
        let wait = Duration::from_millis(self.send_timeout_ms.load(Ordering::Relaxed));
        loop {
            let queued = {
                let mut st = self.lock();
                match st.queue.pop_front() {
                    Some(item) => item,
                    None => {
                        st.running = false;
                        return;
                    }
                }
            };
            match tokio::time::timeout(wait, tx.reserve()).await {
                Ok(Ok(permit)) => {
                    permit.send(queued.msg);
                    if let Some(ack) = queued.ack {
                        let _ = ack.send(Ok(()));
                    }
                }
                Ok(Err(_closed)) => {
                    let mut st = self.lock();
                    st.queue.push_front(queued);
                    self.fail_waiters(&mut st, "audit channel closed");
                    st.running = false;
                    return;
                }
                Err(_elapsed) => {
                    let mut st = self.lock();
                    st.queue.push_front(queued);
                    self.fail_waiters(&mut st, "timed out waiting for room");
                    st.running = false;
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    fn queued_len(&self) -> usize {
        self.lock().queue.len()
    }
}

impl McpAudit {
    pub fn from_env(lease_tx: Option<RecordingLeaseTx>) -> Self {
        Self::with_recording(McpRecording::from_env(lease_tx))
    }

    /// Hub over an explicit recording root, without the environment.
    #[cfg(test)]
    pub(crate) fn with_recording_dir(dir: std::path::PathBuf) -> Self {
        Self::with_recording(McpRecording::with_storage(dir, None))
    }

    /// Test helper: inject a recording hub (failing FD lease, temp dir, …).
    /// Also how `from_env` builds the production hub.
    pub(crate) fn with_recording(recording: McpRecording) -> Self {
        Self {
            inner: Arc::new(McpAuditInner {
                audit_tx: None,
                recording,
                last_ts: AtomicU64::new(0),
                worm: WormOverflow::new(),
            }),
        }
    }

    /// Test sink: a background thread accepts every audit message.
    /// Success-path tests need a reader or `emit_worm` refuses the visit.
    #[cfg(test)]
    pub(crate) fn attach_blackhole(self) -> Self {
        let (tx, mut rx) = mpsc::channel(256);
        std::thread::Builder::new()
            .name("mcp-audit-blackhole".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("audit blackhole runtime");
                rt.block_on(async move { while rx.recv().await.is_some() {} });
            })
            .expect("audit blackhole thread");
        self.with_audit_tx(tx)
    }

    /// Attach the Audit IPC writer. Replaces a hub that had no channel.
    pub fn with_audit_tx(self, tx: mpsc::Sender<Message>) -> Self {
        Self {
            inner: Arc::new(McpAuditInner {
                audit_tx: Some(tx),
                recording: self.inner.recording.clone(),
                last_ts: AtomicU64::new(self.inner.last_ts.load(Ordering::SeqCst)),
                worm: Arc::clone(&self.inner.worm),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn worm_dropped(&self) -> u64 {
        self.inner.worm.dropped.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn set_worm_send_timeout(&self, d: Duration) {
        self.inner
            .worm
            .send_timeout_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn recording(&self) -> &McpRecording {
        &self.inner.recording
    }

    pub fn recording_dir(&self) -> &Path {
        self.inner.recording.storage_base()
    }

    fn next_timestamp(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.inner
            .last_ts
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |prev| {
                Some(now.max(prev + 1))
            })
            .unwrap_or(now)
    }

    async fn emit_worm(
        &self,
        event_type: AuditEventType,
        user_id: Option<String>,
        session_id: Option<String>,
        details: Value,
    ) -> std::io::Result<()> {
        let Some(tx) = self.inner.audit_tx.clone() else {
            self.inner
                .worm
                .note_refused(event_type, "audit ipc not attached");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "audit ipc not attached",
            ));
        };
        let redacted = redact_sensitive_json(&details);
        let details_s = redacted.to_string();
        let msg = Message::AuditEvent {
            timestamp: self.next_timestamp(),
            event_type,
            user_id,
            session_id,
            source_ip: None,
            details: details_s,
        };
        self.inner
            .worm
            .accept(&tx, event_type, msg)
            .await
            .map_err(std::io::Error::other)
    }

    /// Append one redacted JSONL line and sync. Spec: sync before client success.
    pub fn append_jsonl(&self, session_id: &str, event: Value) -> std::io::Result<()> {
        self.inner.recording.append_jsonl(session_id, event)
    }

    /// Security events also reach the WORM log, so the relay goes on; a lost
    /// JSONL line is logged and counted, never silent.
    fn append_security_event(&self, session_id: &str, event: Value) {
        if let Err(e) = self.append_jsonl(session_id, event) {
            JSONL_APPEND_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
            error!(session_id, error = %e, "security event not appended to the visit JSONL");
        }
    }

    pub async fn record_session_opened(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        details: Value,
        open_unix: u64,
    ) -> std::io::Result<()> {
        if let Err(e) = self
            .inner
            .recording
            .open_session_at(session_id, open_unix)
            .await
        {
            error!(session_id, error = %e, "MCP recording open failed");
            return Err(e);
        }
        let mut ev = details;
        if let Value::Object(ref mut m) = ev {
            m.insert("ts".into(), json!(Self::rfc3339_now()));
            m.insert("session_id".into(), json!(session_id));
            m.insert("event".into(), json!("session_open"));
        }
        if let Err(e) = self.append_jsonl(session_id, ev.clone()) {
            error!(session_id, error = %e, "JSONL session_open write failed");
            self.inner.recording.abort_session(session_id);
            return Err(e);
        }
        self.emit_worm(
            AuditEventType::McpSessionOpened,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    fn rfc3339_now() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let h = rem / 3600;
        let m = (rem % 3600) / 60;
        let s = rem % 60;
        let (y, mo, d) = civil_from_days(days as i64);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
    }

    /// tools/call allow / deny / throttle. Returns Err if JSONL sync failed.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_tool_call(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        tool_name: &str,
        decision: &str,
        reason_code: &str,
        args: Option<&Value>,
        response: Option<&Value>,
    ) -> std::io::Result<()> {
        let args_r = args.map(redact_sensitive_json);
        let resp_r = response.map(redact_response);
        let event = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "tools/call",
            "tool_name": tool_name,
            "decision": decision,
            "reason_code": reason_code,
            "args": args_r,
            "response": resp_r,
        });
        self.append_jsonl(session_id, event.clone())?;

        let event_type = match decision {
            "deny" | "hitl_deny" | "suspended" => AuditEventType::McpToolCallDenied,
            "throttle" => AuditEventType::McpToolCallThrottled,
            "hitl_pending" => AuditEventType::McpHitlPending,
            "hitl_allow" => AuditEventType::McpToolCallAllowed,
            _ => AuditEventType::McpToolCallAllowed,
        };
        self.emit_worm(
            event_type,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            event,
        )
        .await?;
        Ok(())
    }

    /// Phase 1 of an allowed tools/call: synced before any upstream byte.
    /// Err → the caller must refuse without contacting the upstream.
    pub async fn record_tool_call_intent(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        tool_name: &str,
        decision: &str,
        args: Option<&Value>,
    ) -> std::io::Result<()> {
        let event = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "tools/call",
            "phase": TOOL_CALL_PHASE_INTENT,
            "tool_name": tool_name,
            "decision": decision,
            "args": args.map(redact_sensitive_json),
        });
        self.append_jsonl(session_id, event.clone())?;
        self.emit_worm(
            AuditEventType::McpToolCallAllowed,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            event,
        )
        .await?;
        Ok(())
    }

    /// Phase 2: what the upstream did with the call announced by the intent.
    pub async fn record_tool_call_result(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        tool_name: &str,
        outcome: ToolCallOutcome,
        reason_code: &str,
        response: Option<&Value>,
    ) -> std::io::Result<()> {
        let event = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "tools/call",
            "phase": TOOL_CALL_PHASE_RESULT,
            "tool_name": tool_name,
            "outcome": outcome.as_str(),
            "reason_code": reason_code,
            "response": response.map(redact_response),
        });
        self.append_jsonl(session_id, event.clone())?;
        if outcome != ToolCallOutcome::Ok {
            self.emit_worm(
                AuditEventType::McpToolCallUpstreamFailed,
                user_id.map(str::to_string),
                Some(session_id.to_string()),
                event,
            )
            .await?;
        }
        Ok(())
    }

    /// A live upstream definition no longer matches the approved
    /// fingerprint. The tool is already quarantined; JSONL and WORM record it.
    pub async fn record_tool_definition_drift(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        tool: &str,
        approved_fp: &str,
        live_fp: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_tool_definition_drift",
            "tool": tool,
            "approved_fp": approved_fp,
            "live_fp": live_fp,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpToolDefinitionDrift,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub fn record_method(
        &self,
        session_id: &str,
        method: &str,
        extra: Value,
    ) -> std::io::Result<()> {
        let mut event = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": method,
        });
        if let (Value::Object(dst), Value::Object(src)) = (&mut event, extra) {
            for (k, v) in src {
                dst.insert(k, v);
            }
        }
        self.append_jsonl(session_id, event)
    }

    pub async fn record_privilege_escalation(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        details: Value,
    ) -> std::io::Result<()> {
        let mut ev = details;
        if let Value::Object(ref mut m) = ev {
            m.insert("ts".into(), json!(Self::rfc3339_now()));
            m.insert("session_id".into(), json!(session_id));
            m.insert("event".into(), json!("privilege_escalation_attempt"));
            m.insert(
                "reason_code".into(),
                json!("mcp_privilege_escalation_attempt"),
            );
        }
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpPrivilegeEscalationAttempt,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    /// Envelope `alert` path: WORM `mcp_envelope_threshold` (dedup done by caller).
    pub async fn record_envelope_threshold(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        count: usize,
        max_calls: u32,
        window_seconds: u32,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_envelope_threshold",
            "count": count,
            "max_calls": max_calls,
            "window_seconds": window_seconds,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpEnvelopeThreshold,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub async fn record_session_suspended(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        reason: &str,
        actor_user_id: Option<&str>,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_session_suspended",
            "reason": reason,
            "actor_user_id": actor_user_id,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpSessionSuspended,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub async fn record_session_resumed(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        actor_user_id: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_session_resumed",
            "actor_user_id": actor_user_id,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpSessionResumed,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub async fn record_hitl_pending(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        tool: &str,
        args_blake3: &str,
        expires_at: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_hitl_pending",
            "pending_id": pending_id,
            "tool": tool,
            "args_blake3": args_blake3,
            "expires_at": expires_at,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlPending,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_hitl_decided(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        decision: &str,
        actor_user_id: &str,
        mandate_id: &str,
        sealed_digest: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_hitl_decided",
            "pending_id": pending_id,
            "decision": decision,
            "actor_user_id": actor_user_id,
            "mandate_id": mandate_id,
            "sealed_digest": sealed_digest,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlDecided,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub async fn record_hitl_expired(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        tool: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_hitl_expired",
            "pending_id": pending_id,
            "tool": tool,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlExpired,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    pub async fn record_clientinfo_drift(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pinned: &str,
        got: &str,
    ) -> std::io::Result<()> {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_clientinfo_drift",
            "pinned": pinned,
            "got": got,
        });
        self.append_security_event(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpClientinfoDrift,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        )
        .await?;
        Ok(())
    }

    /// Finalize JSONL + meta.json → WORM `McpRecordingFinalized`.
    pub fn finalize_recording(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        reason: &str,
        partial: bool,
    ) {
        let this = self.clone();
        let sid = session_id.to_string();
        let uid = user_id.map(str::to_string);
        let reason = reason.to_string();
        tokio::spawn(async move {
            let stats = this.inner.recording.finalize(&sid, &reason, partial).await;
            let Some(FinalizeStats {
                blake3_hex,
                cast_blake3_hex,
                relative_jsonl,
                relative_cast,
                relative_meta,
                total_bytes,
                total_events,
                partial,
                equivalence_verified,
            }) = stats
            else {
                debug!(session_id = %sid, "MCP finalize produced no stats (already finalized)");
                return;
            };
            let details = json!({
                "session_id": sid,
                "path": relative_jsonl,
                "cast_path": relative_cast,
                "meta_path": relative_meta,
                "blake3": blake3_hex,
                "cast_blake3": cast_blake3_hex,
                "equivalence_verified": equivalence_verified,
                "total_bytes": total_bytes,
                "total_events": total_events,
                "partial": partial,
                "reason": reason,
            });
            if let Err(e) = this
                .emit_worm(
                    AuditEventType::McpRecordingFinalized,
                    uid,
                    Some(sid.clone()),
                    details,
                )
                .await
            {
                error!(session_id = %sid, error = %e, "MCP recording WORM finalize refused");
            } else {
                info!(session_id = %sid, "MCP recording WORM finalize emitted");
            }
        });
    }
}

/// Days since Unix epoch → (year, month, day) Gregorian (Howard Hinnant).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Open Audit IPC FDs the same way proxy-ssh does.
pub fn open_audit_channel() -> Option<shared::ipc::IpcChannel> {
    let r: Option<RawFd> = std::env::var("VAUBAN_AUDIT_IPC_READ")
        .ok()
        .and_then(|s| s.parse().ok());
    let w: Option<RawFd> = std::env::var("VAUBAN_AUDIT_IPC_WRITE")
        .ok()
        .and_then(|s| s.parse().ok());
    match (r, w) {
        (Some(read_fd), Some(write_fd)) => {
            // SAFETY: FDs handed by supervisor; exclusive to this process.
            let ch = unsafe { shared::ipc::IpcChannel::from_raw_fds(read_fd, write_fd) };
            // SAFETY: single-threaded at boot before sandbox; matches proxy-ssh.
            unsafe {
                std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
                std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
            }
            info!("Audit IPC channel attached (MCP WORM events)");
            Some(ch)
        }
        _ => {
            warn!("VAUBAN_AUDIT_IPC_READ/WRITE not set — MCP session open will fail closed");
            None
        }
    }
}

/// Spawn the Audit IPC drain task; return an mpsc sender for emitters.
pub fn spawn_audit_writer(channel: shared::ipc::IpcChannel) -> mpsc::Sender<Message> {
    let (tx, mut rx) = mpsc::channel::<Message>(512);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = channel.send(&msg) {
                warn!(error = %e, "Failed to send MCP audit event to vauban-audit");
                break;
            }
        }
        debug!("MCP audit IPC writer task exiting");
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    #[tokio::test]
    async fn append_redacts_token_before_disk() {
        let dir =
            std::env::temp_dir().join(format!("vauban-mcp-audit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let audit = McpAudit::with_recording_dir(dir.clone()).attach_blackhole();
        audit
            .record_session_opened("sess-1", None, json!({}), 1_700_000_000)
            .await
            .unwrap();
        audit
            .record_tool_call(
                "sess-1",
                None,
                "read_file",
                "allow",
                "ok",
                Some(&json!({ "path": "a", "token": "SECRET" })),
                Some(&json!({ "content": "x", "api_key": "k" })),
            )
            .await
            .unwrap();
        // Find session.mcp.jsonl under YYYY/MM/sess-1/
        let found = walkdir_jsonl(&dir)
            .into_iter()
            .find(|p| p.parent().and_then(|d| d.file_name()) == Some("sess-1".as_ref()));
        let text = fs::read_to_string(found.expect("jsonl written")).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("\"api_key\":\"k\""));
        assert!(text.contains("***"));
        assert!(text.contains("\"decision\":\"allow\""));
        let _ = fs::remove_dir_all(&dir);
    }

    fn walkdir_jsonl(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(dir) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir_jsonl(&p));
            } else if p.file_name().and_then(|n| n.to_str()) == Some("session.mcp.jsonl") {
                out.push(p);
            }
        }
        out
    }

    async fn refusing_lease_audit() -> McpAudit {
        let (tx, mut rx) = mpsc::channel::<RecordingLeaseReq>(4);
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let _ = req.reply.send(Err("test lease refused".into()));
            }
        });
        let dir = std::env::temp_dir().join(format!(
            "vauban-mcp-lease-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rec = crate::mcp_recording::McpRecording::with_storage_base_and_lease(dir, tx);
        McpAudit::with_recording(rec)
    }

    #[tokio::test]
    async fn record_session_opened_fails_when_lease_refused() {
        let audit = refusing_lease_audit().await;
        let err = audit
            .record_session_opened("sess-f3", None, json!({}), 1_767_139_200)
            .await
            .expect_err("hop 1 must fail-closed if JSONL/cast cannot open");
        assert!(
            err.to_string().contains("lease") || err.kind() == std::io::ErrorKind::Other,
            "{err}"
        );
    }

    #[tokio::test]
    async fn record_tool_call_fails_when_lease_session_missing() {
        let audit = refusing_lease_audit().await;
        let err = audit
            .record_tool_call(
                "sess-f5",
                None,
                "delete_vm",
                "deny",
                "tool_not_allowed",
                None,
                None,
            )
            .await
            .expect_err("deny JSONL must fail-closed without an open recording");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vauban-mcp-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    async fn two_phase_audit(sid: &str) -> (McpAudit, mpsc::Receiver<Message>, std::path::PathBuf) {
        let dir = temp_dir("two-phase");
        let (tx, rx) = mpsc::channel(16);
        let audit = McpAudit::with_recording(
            crate::mcp_recording::McpRecording::with_storage_base(dir.clone()),
        )
        .with_audit_tx(tx);
        audit
            .record_session_opened(sid, Some("u1"), json!({}), 1_767_139_200)
            .await
            .unwrap();
        (audit, rx, dir)
    }

    fn worm_types(rx: &mut mpsc::Receiver<Message>) -> Vec<AuditEventType> {
        let mut out = Vec::new();
        while let Ok(Message::AuditEvent { event_type, .. }) = rx.try_recv() {
            out.push(event_type);
        }
        out
    }

    fn jsonl_lines(dir: &Path) -> Vec<Value> {
        let path = walkdir_jsonl(dir).into_iter().next().expect("jsonl");
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn outcome_labels() {
        assert_eq!(ToolCallOutcome::Ok.as_str(), "ok");
        assert_eq!(ToolCallOutcome::UpstreamError.as_str(), "upstream_error");
        assert_eq!(ToolCallOutcome::Timeout.as_str(), "timeout");
    }

    #[test]
    fn scalar_response_is_digested() {
        let r = redact_response(&json!("plain text"));
        assert_eq!(r["byte_length"], 12);
        assert!(r["sha256"].as_str().unwrap().len() == 64);
        assert_eq!(redact_response(&json!({"token": "t"}))["token"], "***");
    }

    #[tokio::test]
    async fn intent_then_ok_result_is_two_lines_one_worm_event() {
        let (audit, mut rx, dir) = two_phase_audit("sess-2p-ok").await;
        audit
            .record_tool_call_intent(
                "sess-2p-ok",
                Some("u1"),
                "create_task",
                "allow",
                Some(&json!({ "title": "x", "password": "p" })),
            )
            .await
            .unwrap();
        audit
            .record_tool_call_result(
                "sess-2p-ok",
                Some("u1"),
                "create_task",
                ToolCallOutcome::Ok,
                "ok",
                Some(&json!({ "result": { "ok": true } })),
            )
            .await
            .unwrap();
        let lines = jsonl_lines(&dir);
        let calls: Vec<&Value> = lines
            .iter()
            .filter(|l| l["event"] == "tools/call")
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["phase"], "intent");
        assert_eq!(calls[0]["decision"], "allow");
        assert_eq!(calls[0]["args"]["password"], "***");
        assert!(calls[0].get("response").is_none());
        assert_eq!(calls[1]["phase"], "result");
        assert_eq!(calls[1]["outcome"], "ok");
        assert_eq!(calls[1]["response"]["result"]["ok"], true);
        assert_eq!(
            worm_types(&mut rx),
            vec![
                AuditEventType::McpSessionOpened,
                AuditEventType::McpToolCallAllowed
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn failed_result_emits_upstream_failed_worm_event() {
        let (audit, mut rx, dir) = two_phase_audit("sess-2p-ko").await;
        let _ = worm_types(&mut rx);
        for outcome in [ToolCallOutcome::Timeout, ToolCallOutcome::UpstreamError] {
            audit
                .record_tool_call_result("sess-2p-ko", None, "t", outcome, "upstream_timeout", None)
                .await
                .unwrap();
        }
        assert_eq!(
            worm_types(&mut rx),
            vec![
                AuditEventType::McpToolCallUpstreamFailed,
                AuditEventType::McpToolCallUpstreamFailed
            ]
        );
        let outcomes: Vec<Value> = jsonl_lines(&dir)
            .into_iter()
            .filter(|l| l["phase"] == "result")
            .map(|l| l["outcome"].clone())
            .collect();
        assert_eq!(outcomes, vec![json!("timeout"), json!("upstream_error")]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn every_record_helper_writes_jsonl_and_worm() {
        let (audit, mut rx, dir) = two_phase_audit("sess-helpers").await;
        assert_eq!(audit.recording_dir(), dir.as_path());
        let sid = "sess-helpers";
        audit
            .record_privilege_escalation(sid, Some("u1"), json!({ "tool": "x" }))
            .await
            .unwrap();
        audit
            .record_privilege_escalation(sid, None, json!("not-an-object"))
            .await
            .unwrap();
        audit
            .record_envelope_threshold(sid, None, 5, 4, 60)
            .await
            .unwrap();
        audit
            .record_session_suspended(sid, None, "manual", Some("admin"))
            .await
            .unwrap();
        audit
            .record_session_resumed(sid, None, "admin")
            .await
            .unwrap();
        audit
            .record_hitl_pending(sid, None, "p1", "t", "b3", "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        audit
            .record_hitl_decided(sid, None, "p1", "approve", "admin", "m1", "d1")
            .await
            .unwrap();
        audit
            .record_hitl_expired(sid, None, "p2", "t")
            .await
            .unwrap();
        audit
            .record_clientinfo_drift(sid, None, "a/1", "b/2")
            .await
            .unwrap();
        audit.record_method(sid, "ping", json!({ "x": 1 })).unwrap();
        audit.record_method(sid, "ping", json!(null)).unwrap();
        let events: Vec<String> = jsonl_lines(&dir)
            .iter()
            .filter_map(|l| l["event"].as_str().map(str::to_string))
            .collect();
        for want in [
            "privilege_escalation_attempt",
            "mcp_envelope_threshold",
            "mcp_hitl_decided",
            "mcp_hitl_expired",
            "mcp_clientinfo_drift",
            "ping",
        ] {
            assert!(events.iter().any(|e| e == want), "{want} in {events:?}");
        }
        let types = worm_types(&mut rx);
        for want in [
            AuditEventType::McpPrivilegeEscalationAttempt,
            AuditEventType::McpEnvelopeThreshold,
            AuditEventType::McpSessionSuspended,
            AuditEventType::McpSessionResumed,
            AuditEventType::McpHitlPending,
            AuditEventType::McpHitlDecided,
            AuditEventType::McpHitlExpired,
            AuditEventType::McpClientinfoDrift,
        ] {
            assert!(types.contains(&want), "{want:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn worm_closed_or_detached_returns_promptly() {
        let (audit, rx) = worm_audit(1);
        emit(&audit).await.unwrap();
        drop(rx);
        let err = tokio::time::timeout(Duration::from_secs(2), emit(&audit))
            .await
            .expect("closed channel must not block the caller");
        assert!(err.is_err());
        assert!(
            audit.inner.worm.queued_len() >= 1,
            "refused event stays queued"
        );
        let err = McpAudit::from_env(None)
            .emit_worm(AuditEventType::McpHitlExpired, None, None, json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
    }

    fn worm_audit(cap: usize) -> (McpAudit, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(cap);
        let audit = McpAudit::with_recording(
            crate::mcp_recording::McpRecording::with_storage_base(temp_dir("worm")),
        )
        .with_audit_tx(tx);
        (audit, rx)
    }

    async fn emit(audit: &McpAudit) -> std::io::Result<()> {
        audit
            .emit_worm(AuditEventType::McpHitlExpired, None, None, json!({}))
            .await
    }

    async fn until(mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    /// A full Audit queue delays events, in order, instead of
    /// discarding them; once drained the fast path is used again.
    #[tokio::test]
    async fn worm_full_queue_waits_and_keeps_order() {
        let (audit, mut rx) = worm_audit(1);
        let writer = audit.clone();
        let emitter = tokio::spawn(async move {
            for _ in 0..4 {
                emit(&writer).await.unwrap();
            }
        });
        let mut stamps = Vec::new();
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(Message::AuditEvent { timestamp, .. })) => stamps.push(timestamp),
                other => panic!("expected AuditEvent, got {other:?}"),
            }
        }
        emitter.await.unwrap();
        assert!(stamps.windows(2).all(|w| w[0] < w[1]), "{stamps:?}");
        assert_eq!(audit.worm_dropped(), 0);
        let worm = Arc::clone(&audit.inner.worm);
        until(|| !worm.lock().running).await;
        emit(&audit).await.unwrap();
        assert!(rx.try_recv().is_ok(), "fast path after drain");
    }

    #[tokio::test]
    async fn worm_timeout_or_close_refuses_and_keeps_the_event() {
        let (audit, mut rx) = worm_audit(1);
        audit.set_worm_send_timeout(Duration::from_millis(30));
        emit(&audit).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), emit(&audit))
            .await
            .expect("timeout must return");
        assert!(err.is_err(), "full pipe refuses");
        assert!(audit.worm_dropped() >= 1);
        assert!(
            audit.inner.worm.queued_len() >= 1,
            "timed-out event stays at the head"
        );
        let _ = rx.recv().await;
        audit.set_worm_send_timeout(Duration::from_secs(5));
        let retry = {
            let audit = audit.clone();
            tokio::spawn(async move { emit(&audit).await })
        };
        assert!(
            rx.recv().await.is_some(),
            "kept event is sent once there is room"
        );
        assert!(rx.recv().await.is_some(), "the retry follows it");
        retry.await.unwrap().unwrap();

        let (audit, rx) = worm_audit(1);
        emit(&audit).await.unwrap();
        let pending = {
            let audit = audit.clone();
            tokio::spawn(async move { emit(&audit).await })
        };
        drop(rx);
        let err = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .expect("close must not block")
            .unwrap();
        assert!(err.is_err());
        assert!(audit.inner.worm.queued_len() >= 1);

        let (audit, rx) = worm_audit(1);
        drop(rx);
        let err = emit(&audit).await.unwrap_err();
        assert!(err.to_string().contains("closed"));
        assert_eq!(audit.worm_dropped(), 1, "closed channel on the fast path");
        assert_eq!(audit.inner.worm.queued_len(), 1, "parked, not discarded");
    }

    /// Emit `per` events from each of `tasks` tasks released together.
    /// Each call reports whether the audit pipe accepted it.
    async fn emit_race(audit: &McpAudit, tasks: usize, per: usize) -> Vec<std::io::Result<()>> {
        let barrier = Arc::new(tokio::sync::Barrier::new(tasks));
        let handles: Vec<_> = (0..tasks)
            .map(|t| {
                let (audit, barrier) = (audit.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    let mut out = Vec::with_capacity(per);
                    for i in 0..per {
                        out.push(
                            audit
                                .emit_worm(
                                    AuditEventType::McpHitlExpired,
                                    None,
                                    None,
                                    json!({ "t": t, "i": i }),
                                )
                                .await,
                        );
                        tokio::task::yield_now().await;
                    }
                    out
                })
            })
            .collect();
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.await.unwrap());
        }
        all
    }

    fn task_seq(msg: &Message) -> (u64, u64) {
        let Message::AuditEvent { details, .. } = msg else {
            panic!("expected AuditEvent, got {msg:?}");
        };
        let v: Value = serde_json::from_str(details).unwrap();
        (v["t"].as_u64().unwrap(), v["i"].as_u64().unwrap())
    }

    /// Battle: many emitters against a one-slot Audit queue. Nothing is
    /// refused while the reader keeps up, and each emitter's events arrive
    /// in the order it emitted them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn battle_worm_overflow_keeps_order_under_contention() {
        let (audit, mut rx) = worm_audit(1);
        let (tasks, per) = (8usize, 64usize);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < tasks * per {
                match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
                    Ok(Some(m)) => got.push(task_seq(&m)),
                    other => panic!("reader stalled after {}: {other:?}", got.len()),
                }
            }
            got
        });
        let results = emit_race(&audit, tasks, per).await;
        let got = reader.await.unwrap();
        assert!(results.iter().all(|r| r.is_ok()), "reader kept up");
        assert_eq!(audit.worm_dropped(), 0);
        let mut next = vec![0u64; tasks];
        for (t, i) in got {
            assert_eq!(i, next[t as usize], "task {t} reordered");
            next[t as usize] += 1;
        }
    }

    /// Battle: the reader drops the pipe mid-stream. Every emit either was
    /// accepted by `send` or the caller was refused. Refused events stay queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn battle_worm_closed_channel_refuses_without_discarding() {
        let (audit, mut rx) = worm_audit(1);
        let (tasks, per) = (8usize, 32usize);
        let reader = tokio::spawn(async move {
            let mut n = 0u64;
            while n < 40 {
                if rx.recv().await.is_none() {
                    break;
                }
                n += 1;
            }
            drop(rx);
            n
        });
        let results = emit_race(&audit, tasks, per).await;
        let delivered = reader.await.unwrap();
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let err = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(ok + err, tasks * per);
        assert!(err > 0, "closing the pipe must refuse the rest");
        assert!(delivered <= ok as u64);
        assert_eq!(audit.worm_dropped(), err as u64);
        assert_eq!(audit.inner.worm.queued_len(), err);
    }

    #[test]
    fn worm_overflow_refuses_without_entering() {
        let (audit, _rx) = worm_audit(1);
        fn block_on<F: std::future::Future>(fut: F) -> F::Output {
            let mut fut = std::pin::pin!(fut);
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(v) => v,
                std::task::Poll::Pending => panic!("no-runtime path must not wait"),
            }
        }
        block_on(emit(&audit)).unwrap();
        for _ in 0..WORM_OVERFLOW_MAX {
            assert!(block_on(emit(&audit)).is_err());
        }
        assert_eq!(audit.inner.worm.queued_len(), WORM_OVERFLOW_MAX);
        let before = audit.worm_dropped();
        assert!(
            block_on(emit(&audit)).is_err(),
            "a full queue does not take the new event"
        );
        assert_eq!(audit.inner.worm.queued_len(), WORM_OVERFLOW_MAX);
        assert_eq!(audit.worm_dropped(), before + 1);
    }

    #[test]
    fn worm_full_without_runtime_is_refused_and_kept() {
        let (audit, _rx) = worm_audit(1);
        fn block_on<F: std::future::Future>(fut: F) -> F::Output {
            let mut fut = std::pin::pin!(fut);
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(v) => v,
                std::task::Poll::Pending => panic!("no-runtime path must not wait"),
            }
        }
        block_on(emit(&audit)).unwrap();
        let err = block_on(emit(&audit)).unwrap_err();
        assert!(err.to_string().contains("runtime"));
        assert_eq!(audit.worm_dropped(), 1);
        assert_eq!(audit.inner.worm.queued_len(), 1);
        assert!(!audit.inner.worm.lock().running);
    }

    #[tokio::test]
    async fn worm_poisoned_overflow_lock_still_delivers() {
        let (audit, mut rx) = worm_audit(1);
        let worm = Arc::clone(&audit.inner.worm);
        let _ = std::thread::spawn(move || {
            let _g = worm.state.lock().unwrap();
            panic!("poison");
        })
        .join();
        emit(&audit).await.unwrap();
        assert_eq!(audit.worm_dropped(), 0, "a poisoned lock is recovered");
        assert!(rx.recv().await.is_some());
    }

    /// Source shape: a refused event is not cleared out of the queue, and
    /// production `emit_worm` does not return after a silent skip.
    #[test]
    fn worm_source_does_not_drop_a_queued_event() {
        let src = include_str!("audit.rs");
        let prod = src.split("mod tests").next().unwrap_or(src);
        assert!(!prod.contains("queue.clear()"));
        assert!(!prod.contains("WORM emit skipped"));
        assert!(src.contains("fn emit_worm"));
        assert!(src.contains("push_front(queued)"));
    }

    #[tokio::test]
    async fn session_open_fails_closed_when_jsonl_is_not_writable() {
        let (tx, mut rx) = mpsc::channel::<RecordingLeaseReq>(4);
        let base = temp_dir("ro-jsonl");
        let lease_base = base.clone();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let path = lease_base.join(&req.relative_path);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .unwrap();
                let read_only = req.relative_path.ends_with(".jsonl");
                let f = fs::OpenOptions::new()
                    .read(true)
                    .append(!read_only)
                    .open(&path)
                    .map_err(|e| e.to_string());
                let _ = req.reply.send(f);
            }
        });
        let audit = McpAudit::with_recording(
            crate::mcp_recording::McpRecording::with_storage_base_and_lease(base.clone(), tx),
        );
        audit
            .record_session_opened("sess-ro", None, json!({}), 1_767_139_200)
            .await
            .expect_err("session_open line must be synced");
        let err = audit
            .record_tool_call_intent("sess-ro", None, "t", "allow", None)
            .await
            .expect_err("recording aborted after failed session_open");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn finalize_emits_once_then_noops() {
        let (audit, mut rx, dir) = two_phase_audit("sess-fin").await;
        let _ = worm_types(&mut rx);
        audit.finalize_recording("sess-fin", Some("u1"), "terminate", false);
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap();
        assert!(matches!(
            first,
            Some(Message::AuditEvent {
                event_type: AuditEventType::McpRecordingFinalized,
                ..
            })
        ));
        let _ = fs::remove_dir_all(&dir);

        let (tx, mut rx) = mpsc::channel(4);
        let leased = refusing_lease_audit().await.with_audit_tx(tx);
        leased.finalize_recording("sess-fin", Some("u1"), "terminate", false);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "lease mode: finalize of a closed recording must not emit"
        );
    }

    #[test]
    fn audit_channel_from_env() {
        unsafe {
            std::env::remove_var("VAUBAN_AUDIT_IPC_READ");
            std::env::remove_var("VAUBAN_AUDIT_IPC_WRITE");
        }
        assert!(open_audit_channel().is_none());
    }

    #[tokio::test]
    async fn audit_writer_forwards_then_stops_on_broken_pipe() {
        let (ours, theirs) = shared::ipc::IpcChannel::pair().unwrap();
        let tx = spawn_audit_writer(theirs);
        let ev = || Message::AuditEvent {
            timestamp: 1,
            event_type: AuditEventType::McpHitlExpired,
            user_id: None,
            session_id: None,
            source_ip: None,
            details: "{}".into(),
        };
        tx.send(ev()).await.unwrap();
        let got = tokio::task::spawn_blocking(move || {
            let msg = loop {
                match ours.try_recv() {
                    Ok(m) => break m,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            };
            drop(ours);
            msg
        })
        .await
        .unwrap();
        assert!(matches!(got, Message::AuditEvent { .. }));
        let _ = tx.send(ev()).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), tx.closed())
            .await
            .expect("writer exits after the peer is gone");
    }

    #[tokio::test]
    async fn intent_and_result_fail_closed_without_recording() {
        let audit = refusing_lease_audit().await;
        let err = audit
            .record_tool_call_intent("sess-none", None, "t", "allow", None)
            .await
            .expect_err("intent must fail without an open recording");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let err = audit
            .record_tool_call_result("sess-none", None, "t", ToolCallOutcome::Ok, "ok", None)
            .await
            .expect_err("result must fail without an open recording");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// A random prefix is accepted, in order, only because `send` took it.
    /// Everything after the pipe is closed is an error and stays queued.
    #[test]
    fn proptest_worm_ok_is_a_send_and_accepted_order_holds() {
        use proptest::prelude::*;
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(32));
        runner
            .run(&(0usize..8, 1usize..6), |(before, after)| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let (audit, mut rx) = worm_audit(8);
                    for i in 0..before {
                        audit
                            .emit_worm(
                                AuditEventType::McpHitlExpired,
                                None,
                                None,
                                json!({ "i": i }),
                            )
                            .await
                            .unwrap();
                    }
                    let mut got = Vec::new();
                    while let Ok(Message::AuditEvent { details, .. }) = rx.try_recv() {
                        let v: Value = serde_json::from_str(&details).unwrap();
                        got.push(v["i"].as_u64().unwrap());
                    }
                    drop(rx);
                    let mut refused = 0usize;
                    for i in 0..after {
                        let err = audit
                            .emit_worm(
                                AuditEventType::McpHitlExpired,
                                None,
                                None,
                                json!({ "i": before + i }),
                            )
                            .await;
                        if err.is_err() {
                            refused += 1;
                        }
                    }
                    prop_assert_eq!(got, (0..before as u64).collect::<Vec<_>>());
                    prop_assert_eq!(refused, after);
                    prop_assert_eq!(audit.worm_dropped(), after as u64);
                    prop_assert_eq!(audit.inner.worm.queued_len(), after);
                    Ok(())
                })
            })
            .unwrap();
    }
}
