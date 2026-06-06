//! Audit emission helpers.
//!
//! Thin wrappers over [`crate::ipc::AuditClient`] that tolerate a missing
//! client (dev/test runs without the supervisor): fire-and-forget emissions
//! become no-ops and critical emissions resolve `Ok(())` so they never wedge
//! the request path when no audit sink exists. In production the client is
//! always present and the fail-closed semantics of `emit_critical` apply.

use crate::AppState;
use crate::ipc::AuditEvent;
use tracing::debug;

/// Fire-and-forget audit emission. Never blocks; drops if the queue is full
/// (the client logs the drop) or if no audit client is wired (dev/test).
pub fn emit_audit(state: &AppState, event: AuditEvent) {
    match &state.audit_client {
        Some(client) => client.emit(event),
        None => debug!(event_type = ?event.event_type, "audit: no client; event not emitted (dev mode)"),
    }
}

/// Emit a security-critical audit event and await its durable ack.
///
/// In production (`audit_client` present) this returns `Ok(())` only after the
/// audit service has hash-chained the event to disk; an `AuditNack`/timeout is
/// an `Err`. Without a client (dev/test) it resolves `Ok(())`.
pub async fn emit_audit_critical(state: &AppState, event: AuditEvent) -> Result<(), String> {
    match &state.audit_client {
        Some(client) => client.emit_critical(event).await,
        None => {
            debug!(event_type = ?event.event_type, "audit: no client; critical event not emitted (dev mode)");
            Ok(())
        }
    }
}
