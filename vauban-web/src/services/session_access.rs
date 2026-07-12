//! VAUBAN Web - Session access service.
//!
//! SECURITY: single seam where every consumer of an existing
//! `proxy_sessions` row (HTML viewer page, WebSocket upgrade, JSON
//! metadata read, terminate) MUST go through. The service combines:
//!
//! 1. **Instance-level decision** (delegated to vauban-access via
//!    [`AccessIpcClient::verify_session_access`]): existence + status,
//!    ownership, and access-rule re-check (`is_active`, temporal
//!    validity, protocol coverage). This is the layer that
//!    fixes the IDOR audit findings (rdp_page, get_session,
//!    list_sessions, terminate, ws/sessions/*).
//!
//! 2. **Functional Casbin OR-overrides** (loaded once per request by
//!    [`crate::middleware::permissions`]): `sessions:supervise` for
//!    read paths (viewer/WS/metadata), `sessions:write` for the
//!    terminate path. These let staff and superusers shadow or kill
//!    a session they do not own.
//!
//! 3. **Response shaping, per surface**:
//!    - Web HTML / WebSocket consumers use [`verify`]:
//!      anti-enumeration shaping where every denial that is not a
//!      `Gone` collapses to a generic `Denied404`. A probe cannot
//!      distinguish "session does not exist", "session belongs to
//!      someone else" or "your access rule was revoked".
//!    - The M2M JSON API (`/api/v1`) uses [`verify_api`]: honest
//!      statuses per [`crate::services::api_response_invariants`]
//!      (callers hold a valid API key, so enumeration by
//!      unauthenticated probes is impossible) -- 404 only when the
//!      session does not exist, 403 when it exists but the caller is
//!      not authorized, 502 when the decision service is down.
//!
//! Direct `proxy_sessions::table.filter(uuid.eq(...))` lookups in
//! handlers are forbidden by
//! [`vauban-web/scripts/check_session_access_centralized.sh`]; only
//! this module is allowed to talk to the
//! [`AccessIpcClient::verify_session_access`] RPC. This guarantees
//! that any new handler that needs to consume a session is forced to
//! route through the same trio above.

use shared::messages::{SessionAccessDecision, SessionAccessIntent, SessionDenialReason};
use tracing::warn;

use crate::AppState;
use crate::auth::PermissionContext;
use crate::middleware::auth::AuthUser;

/// Final, response-ready outcome of a session-access decision.
///
/// HTTP status mapping (what every handler MUST observe to keep
/// anti-enumeration consistent across the bastion):
///
/// - [`Allowed`](Self::Allowed) — proceed.
/// - [`Denied404`](Self::Denied404) — render a generic 404. Used for
///   `NotFound`, `NotOwner`, `AccessRuleRevoked`, IPC errors, and
///   malformed UUIDs. NEVER surface the underlying reason to the
///   client.
/// - [`DeniedGone`](Self::DeniedGone) — render a 410 Gone (for HTTP)
///   or close the WS upgrade with code 1011/410 (for the WebSocket
///   path). Indicates a session that did exist but is no longer
///   connectable (`terminated`, `expired`, `disconnected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccessOutcome {
    Allowed,
    Denied404,
    DeniedGone,
}

impl SessionAccessOutcome {
    /// Convenience predicate for `if outcome.is_allowed() { ... }`.
    pub fn is_allowed(self) -> bool {
        matches!(self, SessionAccessOutcome::Allowed)
    }
}

/// Detailed, pre-shaping outcome of a session-access decision. This is
/// what the decision layer actually knows; the two response-shaping
/// surfaces derive from it:
///
/// - [`verify`] (web HTML / WS) collapses `DeniedForbidden` and
///   `Unavailable` into [`SessionAccessOutcome::Denied404`]
///   (anti-enumeration, unchanged behavior).
/// - [`verify_api`] (M2M JSON API) exposes the detail so handlers can
///   answer honestly per `api_response_invariants`:
///
/// | Variant           | API status |
/// |-------------------|------------|
/// | `Allowed`         | proceed    |
/// | `DeniedNotFound`  | 404        |
/// | `DeniedForbidden` | 403        |
/// | `DeniedGone`      | 410        |
/// | `Unavailable`     | 502        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccessDetail {
    Allowed,
    /// The session does not exist.
    DeniedNotFound,
    /// The session exists but the caller is not authorized (not the
    /// owner / access rule revoked, without the Casbin override).
    DeniedForbidden,
    /// The session existed but is no longer connectable.
    DeniedGone,
    /// The decision service (vauban-access IPC) is unreachable:
    /// fail-closed deny.
    Unavailable,
}

/// SECURITY: authoritative decision for any consumer of an existing
/// `proxy_sessions` row. See module docs for the layered rules.
///
/// Concretely, on top of the vauban-access decision:
///
/// | Intent          | OR-override applied to NotOwner / AccessRuleRevoked |
/// |-----------------|------------------------------------------------------|
/// | `OpenViewer`    | `perms.sessions_supervise`                           |
/// | `ConsumeWs`     | `perms.sessions_supervise`                           |
/// | `ReadMetadata`  | `perms.sessions_supervise`                           |
/// | `Terminate`     | `perms.sessions_write` (and the owner is **always**  |
/// |                 | allowed to terminate, regardless of access-rule)    |
///
/// `NotFound` is NEVER overridden: a probe cannot resurrect a
/// `404` into a `200` by holding `sessions:supervise` because the
/// underlying session does not exist either way.
///
/// `Gone` is intent-aware:
/// * `OpenViewer` / `ConsumeWs` -> `DeniedGone` (410). The
///   underlying TCP/RDP/SSH connection is dead; no override
///   resurrects it.
/// * `Terminate` -> `Allowed` (idempotent owner-cleanup; vauban-access
///   has already proven ownership by the time we observe `Gone`).
/// * `ReadMetadata` -> `Allowed` (historical metadata read; same
///   ordering invariant -- vauban-access does owner-check-first
///   for ReadMetadata too, so reaching this arm means the caller
///   is the owner). This is the regression-guard for the "View"
///   link on `/sessions` after a session disconnects: the audit
///   detail page (durations, bytes, justification, recording
///   link) MUST stay reachable to the operator who ran it.
///
/// Fail-closed: any IPC error is logged at `warn` level (with the
/// caller's UUID and the session UUID for correlation) and collapsed
/// to `Denied404`.
pub async fn verify(
    state: &AppState,
    session_uuid: &str,
    user: &AuthUser,
    perms: &PermissionContext,
    intent: SessionAccessIntent,
) -> SessionAccessOutcome {
    collapse_for_web(decide(state, session_uuid, user, perms, intent).await)
}

/// M2M JSON API variant of [`verify`]: same layered decision (single
/// seam), but the detailed outcome is exposed instead of the web
/// anti-enumeration collapse. Callers on `/api/v1` hold a valid API
/// key (the 401 gate ran upstream), so honest statuses apply -- see
/// [`crate::services::api_response_invariants`] (INV-API-3/4/6).
///
/// Same audit trail as [`verify`]: every denial emits a centralized
/// `AccessDenied` event.
pub async fn verify_api(
    state: &AppState,
    session_uuid: &str,
    user: &AuthUser,
    perms: &PermissionContext,
    intent: SessionAccessIntent,
) -> SessionAccessDetail {
    decide(state, session_uuid, user, perms, intent).await
}

/// Pure response-shaping for the web HTML / WebSocket surfaces:
/// anti-enumeration collapse. `DeniedForbidden` (exists but not
/// authorized) and `Unavailable` (fail-closed IPC error) are
/// indistinguishable from `DeniedNotFound` -- everything lands on the
/// generic 404 except the intent-gated `Gone` -> 410.
fn collapse_for_web(detail: SessionAccessDetail) -> SessionAccessOutcome {
    match detail {
        SessionAccessDetail::Allowed => SessionAccessOutcome::Allowed,
        SessionAccessDetail::DeniedNotFound
        | SessionAccessDetail::DeniedForbidden
        | SessionAccessDetail::Unavailable => SessionAccessOutcome::Denied404,
        SessionAccessDetail::DeniedGone => SessionAccessOutcome::DeniedGone,
    }
}

/// Shared decision core for [`verify`] and [`verify_api`]: IPC
/// round-trip, Casbin OR-overrides, audit emission. Response shaping
/// is the caller's job.
async fn decide(
    state: &AppState,
    session_uuid: &str,
    user: &AuthUser,
    perms: &PermissionContext,
    intent: SessionAccessIntent,
) -> SessionAccessDetail {
    let decision = match state
        .access_client
        .verify_session_access(session_uuid, &user.uuid, intent)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(
                session_uuid,
                user = %user.username,
                user_uuid = %user.uuid,
                ?intent,
                error = %e,
                "session_access::decide: IPC error, fail-closed deny",
            );
            emit_access_denied(state, session_uuid, user, intent, "ipc_error");
            return SessionAccessDetail::Unavailable;
        }
    };

    let detail = apply_casbin_override(decision, perms, intent);
    if !matches!(detail, SessionAccessDetail::Allowed) {
        emit_access_denied(state, session_uuid, user, intent, "session_access");
    }
    detail
}

/// Emit a centralized `AccessDenied` audit event for a refused session access.
/// Fire-and-forget: a denial flood (probing) must never block the request path.
fn emit_access_denied(
    state: &AppState,
    session_uuid: &str,
    user: &AuthUser,
    intent: SessionAccessIntent,
    reason: &str,
) {
    crate::services::emit_audit(
        state,
        crate::ipc::AuditEvent::new(
            shared::messages::AuditEventType::AccessDenied,
            format!(r#"{{"seam":"session_access","intent":"{intent:?}","reason":"{reason}"}}"#),
        )
        .user(user.uuid.to_string())
        .session(session_uuid.to_string()),
    );
}

/// Pure function combining the vauban-access decision with the
/// Casbin OR-overrides. Extracted so it can be unit-tested without
/// any IPC round-trip.
///
/// SECURITY contract:
///
/// - `Allowed` -> `Allowed`.
/// - `Denied(NotFound)` -> `DeniedNotFound` (NEVER overridden -- a
///   probe that holds `sessions:supervise` still cannot resurrect a
///   non-existent session into a 200).
/// - `Denied(Gone)` -> `DeniedGone` (NEVER overridden -- the session
///   used to exist but is no longer connectable).
/// - `Denied(NotOwner)` -> `Allowed` if the right Casbin override
///   holds for the intent, else `DeniedForbidden` (the session exists
///   but the caller may not touch it; the web surface collapses this
///   to 404 in [`collapse_for_web`], the API surface answers 403).
/// - `Denied(AccessRuleRevoked)` -> for `Terminate`, `Allowed` (owner
///   keeps the right to kill their own dying session) OR
///   `perms.sessions_write`; for the read-style intents, requires
///   `perms.sessions_supervise` (a supervisor may still observe an
///   in-flight session even if the access rule has been revoked --
///   useful for forensic shadowing). Refusals are `DeniedForbidden`.
fn apply_casbin_override(
    decision: SessionAccessDecision,
    perms: &PermissionContext,
    intent: SessionAccessIntent,
) -> SessionAccessDetail {
    match decision {
        SessionAccessDecision::Allowed => SessionAccessDetail::Allowed,
        SessionAccessDecision::Denied(SessionDenialReason::NotFound) => {
            SessionAccessDetail::DeniedNotFound
        }
        SessionAccessDecision::Denied(SessionDenialReason::Gone) => match intent {
            // Idempotent terminate: vauban-access has already proven
            // ownership when intent == Terminate (the handler swaps
            // the ownership check before the status check), so
            // reaching this arm means the caller IS the owner of an
            // already-gone session. We turn the call into a no-op
            // success so a double-click on the Terminate button does
            // not flash a misleading "Session not found" error to
            // the legitimate operator. Holders of `sessions:write`
            // get the same idempotency for symmetry with non-Gone
            // terminates.
            SessionAccessIntent::Terminate => SessionAccessDetail::Allowed,
            // Defense-in-depth twin of the Terminate branch above:
            // vauban-access already short-circuits ReadMetadata + Gone
            // to `Allowed` at the source so this arm is normally
            // unreachable, but if a future change ever surfaces a
            // `Denied(Gone)` for ReadMetadata we still want the owner
            // (proven by the owner-check-first ordering on the access
            // side) to read their historical session metadata rather
            // than be redirected with a misleading "not found"
            // flash. The `Gone` -> 410 collapse stays in effect for
            // the interactive intents (OpenViewer / ConsumeWs).
            SessionAccessIntent::ReadMetadata => SessionAccessDetail::Allowed,
            _ => SessionAccessDetail::DeniedGone,
        },
        SessionAccessDecision::Denied(SessionDenialReason::NotOwner) => match intent {
            SessionAccessIntent::Terminate => {
                if perms.sessions_write {
                    SessionAccessDetail::Allowed
                } else {
                    SessionAccessDetail::DeniedForbidden
                }
            }
            SessionAccessIntent::OpenViewer
            | SessionAccessIntent::ConsumeWs
            | SessionAccessIntent::ReadMetadata => {
                if perms.sessions_supervise {
                    SessionAccessDetail::Allowed
                } else {
                    SessionAccessDetail::DeniedForbidden
                }
            }
        },
        SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked) => match intent {
            SessionAccessIntent::Terminate => {
                // The owner is always allowed to terminate their own
                // session, even if the matching access rule was just
                // revoked -- otherwise a self-inflicted dangling
                // session could not be cleaned up by its creator.
                // The vauban-access layer already proved ownership
                // (it would have returned NotOwner instead if the
                // session belonged to someone else), so reaching this
                // arm means the caller is the owner.
                SessionAccessDetail::Allowed
            }
            SessionAccessIntent::OpenViewer
            | SessionAccessIntent::ConsumeWs
            | SessionAccessIntent::ReadMetadata => {
                // Fail-fast for the owner: a revoked access rule
                // immediately cuts further consumption (the whole
                // point of layer-3 of the audit). Supervisors can
                // still shadow.
                if perms.sessions_supervise {
                    SessionAccessDetail::Allowed
                } else {
                    SessionAccessDetail::DeniedForbidden
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms(supervise: bool, write: bool) -> PermissionContext {
        PermissionContext {
            sessions_supervise: supervise,
            sessions_write: write,
            ..PermissionContext::default()
        }
    }

    // --- Allowed passes through every intent untouched ---

    #[test]
    fn test_allowed_open_viewer() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Allowed,
                &perms(false, false),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::Allowed
        );
    }

    #[test]
    fn test_allowed_terminate() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Allowed,
                &perms(false, false),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- NotFound is NEVER overridden, even with full perms ---

    #[test]
    fn test_not_found_stays_not_found_even_with_supervise() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotFound),
                &perms(true, true),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::DeniedNotFound
        );
    }

    #[test]
    fn test_not_found_stays_not_found_for_terminate_with_write() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotFound),
                &perms(true, true),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::DeniedNotFound
        );
    }

    // --- Gone behaviour per intent ---

    #[test]
    fn test_gone_consumews_collapses_410_even_with_supervise() {
        // Interactive intents (OpenViewer / ConsumeWs) keep the
        // strict 410 collapse: the underlying connection is dead.
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::Gone),
                &perms(true, true),
                SessionAccessIntent::ConsumeWs,
            ),
            SessionAccessDetail::DeniedGone
        );
    }

    #[test]
    fn test_gone_open_viewer_collapses_410_even_with_supervise() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::Gone),
                &perms(true, true),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::DeniedGone
        );
    }

    #[test]
    fn test_gone_terminate_collapses_to_allowed_idempotency() {
        // Already-Gone Terminate is the idempotent owner-cleanup
        // path: vauban-access has proven ownership by the time we
        // reach this arm (owner-check-first ordering); we surface a
        // success so a double-click does not mislead the operator.
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::Gone),
                &perms(false, false),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::Allowed
        );
    }

    #[test]
    fn test_gone_read_metadata_collapses_to_allowed_for_owner() {
        // Defense-in-depth twin of the Terminate case: a Gone +
        // ReadMetadata reaching the service layer means the caller
        // is the owner (vauban-access already gates non-owners with
        // NotOwner before checking is_gone for ReadMetadata). We
        // surface Allowed so the historical detail page
        // (audit trace + recording link + bytes / commands) is
        // reachable even after the session has terminated. This is
        // the regression-guard for the "View" link flashing
        // "Session not found" right after a session disconnects.
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::Gone),
                &perms(false, false),
                SessionAccessIntent::ReadMetadata,
            ),
            SessionAccessDetail::Allowed
        );
    }

    #[test]
    fn test_gone_read_metadata_allowed_even_with_supervise() {
        // Twin of the previous: holding sessions:supervise must NOT
        // change the answer (Allowed already), keeping the override
        // matrix monotonic.
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::Gone),
                &perms(true, true),
                SessionAccessIntent::ReadMetadata,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- NotOwner: read paths need sessions_supervise ---

    #[test]
    fn test_not_owner_open_viewer_without_supervise_forbidden() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(false, true),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::DeniedForbidden
        );
    }

    #[test]
    fn test_not_owner_open_viewer_with_supervise_allowed() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(true, false),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::Allowed
        );
    }

    #[test]
    fn test_not_owner_consume_ws_with_supervise_allowed() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(true, false),
                SessionAccessIntent::ConsumeWs,
            ),
            SessionAccessDetail::Allowed
        );
    }

    #[test]
    fn test_not_owner_read_metadata_with_supervise_allowed() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(true, false),
                SessionAccessIntent::ReadMetadata,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- NotOwner: Terminate needs sessions_write, not supervise ---

    #[test]
    fn test_not_owner_terminate_with_supervise_only_forbidden() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(true, false),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::DeniedForbidden
        );
    }

    #[test]
    fn test_not_owner_terminate_with_write_allowed() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::NotOwner),
                &perms(false, true),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- AccessRuleRevoked: Terminate is owner-friendly ---

    #[test]
    fn test_revoked_terminate_owner_always_allowed() {
        // Even with no Casbin perms, the owner can clean up their own
        // dying session.
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
                &perms(false, false),
                SessionAccessIntent::Terminate,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- AccessRuleRevoked: read paths fail-fast unless supervisor ---

    #[test]
    fn test_revoked_open_viewer_fails_fast_without_supervise() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
                &perms(false, true),
                SessionAccessIntent::OpenViewer,
            ),
            SessionAccessDetail::DeniedForbidden
        );
    }

    #[test]
    fn test_revoked_consume_ws_fails_fast_without_supervise() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
                &perms(false, true),
                SessionAccessIntent::ConsumeWs,
            ),
            SessionAccessDetail::DeniedForbidden
        );
    }

    #[test]
    fn test_revoked_read_metadata_with_supervise_allowed() {
        assert_eq!(
            apply_casbin_override(
                SessionAccessDecision::Denied(SessionDenialReason::AccessRuleRevoked),
                &perms(true, false),
                SessionAccessIntent::ReadMetadata,
            ),
            SessionAccessDetail::Allowed
        );
    }

    // --- Web collapse: anti-enumeration shaping is UNCHANGED ---

    #[test]
    fn test_collapse_for_web_allowed_passes_through() {
        assert_eq!(
            collapse_for_web(SessionAccessDetail::Allowed),
            SessionAccessOutcome::Allowed
        );
    }

    #[test]
    fn test_collapse_for_web_not_found_is_404() {
        assert_eq!(
            collapse_for_web(SessionAccessDetail::DeniedNotFound),
            SessionAccessOutcome::Denied404
        );
    }

    #[test]
    fn test_collapse_for_web_forbidden_collapses_to_404() {
        // Anti-enumeration: on the web surface, "exists but not
        // yours" must stay indistinguishable from "does not exist".
        assert_eq!(
            collapse_for_web(SessionAccessDetail::DeniedForbidden),
            SessionAccessOutcome::Denied404
        );
    }

    #[test]
    fn test_collapse_for_web_unavailable_collapses_to_404() {
        // Fail-closed IPC error keeps the historical generic 404 on
        // the web surface.
        assert_eq!(
            collapse_for_web(SessionAccessDetail::Unavailable),
            SessionAccessOutcome::Denied404
        );
    }

    #[test]
    fn test_collapse_for_web_gone_stays_gone() {
        assert_eq!(
            collapse_for_web(SessionAccessDetail::DeniedGone),
            SessionAccessOutcome::DeniedGone
        );
    }
}
