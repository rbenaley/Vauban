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
//! - Fire-and-forget typed [`AuditEvent`]s over the supervisor `ProxyMcp -> Audit`
//!   pipe (WORM hash-chain).
//! - Per-session JSONL under `YYYY/MM/{uuid}/session.mcp.jsonl` (+ `meta.json`),
//!   via supervisor FD lease when wired (fail-closed; no local open escape),
//!   else local lab open when no lease channel.
//! - On terminate: blake3 → `meta.json` + `McpRecordingFinalized` WORM event.

use crate::mcp_recording::{FinalizeStats, McpRecording, RecordingLeaseTx};
use serde_json::{Value, json};
use shared::json_redact::redact_sensitive_json;
use shared::messages::{AuditEventType, Message};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Shared audit + recording hub cloned into axum / IPC tasks.
#[derive(Clone)]
pub struct McpAudit {
    inner: Arc<McpAuditInner>,
}

struct McpAuditInner {
    audit_tx: Option<mpsc::Sender<Message>>,
    recording: McpRecording,
    last_ts: AtomicU64,
}

impl McpAudit {
    pub fn from_env(lease_tx: Option<RecordingLeaseTx>) -> Self {
        Self {
            inner: Arc::new(McpAuditInner {
                audit_tx: None,
                recording: McpRecording::from_env(lease_tx),
                last_ts: AtomicU64::new(0),
            }),
        }
    }

    /// Attach the Audit IPC writer. Replaces a hub that had no channel.
    pub fn with_audit_tx(self, tx: mpsc::Sender<Message>) -> Self {
        Self {
            inner: Arc::new(McpAuditInner {
                audit_tx: Some(tx),
                recording: self.inner.recording.clone(),
                last_ts: AtomicU64::new(self.inner.last_ts.load(Ordering::SeqCst)),
            }),
        }
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
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev| {
                Some(now.max(prev + 1))
            })
            .unwrap_or(now)
    }

    fn emit_worm(
        &self,
        event_type: AuditEventType,
        user_id: Option<String>,
        session_id: Option<String>,
        details: Value,
    ) {
        let Some(ref tx) = self.inner.audit_tx else {
            debug!(?event_type, "MCP audit IPC not attached; WORM emit skipped");
            return;
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
        if let Err(e) = tx.try_send(msg) {
            error!(?event_type, error = %e, "MCP audit event DROPPED (queue/channel)");
        }
    }

    /// Append one redacted JSONL line and sync. Spec: sync before client success.
    pub fn append_jsonl(&self, session_id: &str, event: Value) -> std::io::Result<()> {
        self.inner.recording.append_jsonl(session_id, event)
    }

    pub async fn record_session_opened(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        details: Value,
    ) {
        if let Err(e) = self.inner.recording.open_session(session_id).await {
            error!(session_id, error = %e, "MCP recording open failed");
        }
        let mut ev = details;
        if let Value::Object(ref mut m) = ev {
            m.insert("ts".into(), json!(Self::rfc3339_now()));
            m.insert("session_id".into(), json!(session_id));
            m.insert("event".into(), json!("session_open"));
        }
        if let Err(e) = self.append_jsonl(session_id, ev.clone()) {
            error!(session_id, error = %e, "JSONL session_open write failed");
        }
        self.emit_worm(
            AuditEventType::McpSessionOpened,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
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
    pub fn record_tool_call(
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
        let resp_r = response.map(|r| match r {
            Value::Object(_) | Value::Array(_) => redact_sensitive_json(r),
            other => {
                let s = other.to_string();
                json!({
                    "content_type": "application/json",
                    "byte_length": s.len(),
                    "sha256": blake3::hash(s.as_bytes()).to_hex().to_string(),
                })
            }
        });
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
        );
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

    pub fn record_privilege_escalation(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        details: Value,
    ) {
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
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpPrivilegeEscalationAttempt,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    /// Envelope `alert` path: WORM `mcp_envelope_threshold` (dedup done by caller).
    pub fn record_envelope_threshold(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        count: usize,
        max_calls: u32,
        window_seconds: u32,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_envelope_threshold",
            "count": count,
            "max_calls": max_calls,
            "window_seconds": window_seconds,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpEnvelopeThreshold,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    pub fn record_session_suspended(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        reason: &str,
        actor_user_id: Option<&str>,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_session_suspended",
            "reason": reason,
            "actor_user_id": actor_user_id,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpSessionSuspended,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    pub fn record_session_resumed(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        actor_user_id: &str,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_session_resumed",
            "actor_user_id": actor_user_id,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpSessionResumed,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    pub fn record_hitl_pending(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        tool: &str,
        args_blake3: &str,
        expires_at: &str,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_hitl_pending",
            "pending_id": pending_id,
            "tool": tool,
            "args_blake3": args_blake3,
            "expires_at": expires_at,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlPending,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_hitl_decided(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        decision: &str,
        actor_user_id: &str,
        mandate_id: &str,
        sealed_digest: &str,
    ) {
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
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlDecided,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    pub fn record_hitl_expired(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pending_id: &str,
        tool: &str,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_hitl_expired",
            "pending_id": pending_id,
            "tool": tool,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpHitlExpired,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
    }

    pub fn record_clientinfo_drift(
        &self,
        session_id: &str,
        user_id: Option<&str>,
        pinned: &str,
        got: &str,
    ) {
        let ev = json!({
            "ts": Self::rfc3339_now(),
            "session_id": session_id,
            "event": "mcp_clientinfo_drift",
            "pinned": pinned,
            "got": got,
        });
        let _ = self.append_jsonl(session_id, ev.clone());
        self.emit_worm(
            AuditEventType::McpClientinfoDrift,
            user_id.map(str::to_string),
            Some(session_id.to_string()),
            ev,
        );
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
                warn!(session_id = %sid, "MCP finalize produced no stats");
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
            this.emit_worm(
                AuditEventType::McpRecordingFinalized,
                uid,
                Some(sid.clone()),
                details,
            );
            info!(session_id = %sid, "MCP recording WORM finalize emitted");
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
            debug!("VAUBAN_AUDIT_IPC_READ/WRITE not set — MCP WORM emit disabled (JSONL still on)");
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
        unsafe {
            std::env::set_var("MCP_RECORDING_DIR", &dir);
        }
        let audit = McpAudit::from_env(None);
        audit.record_session_opened("sess-1", None, json!({})).await;
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
            .unwrap();
        // Find session.mcp.jsonl under YYYY/MM/sess-1/
        let found = walkdir_jsonl(&dir).into_iter().next();
        let text = fs::read_to_string(found.expect("jsonl written")).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("\"api_key\":\"k\""));
        assert!(text.contains("***"));
        assert!(text.contains("\"decision\":\"allow\""));
        let _ = fs::remove_dir_all(&dir);
        unsafe {
            std::env::remove_var("MCP_RECORDING_DIR");
        }
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
}
