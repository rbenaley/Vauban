//! Lot 0 policy recheck — mid-session access_rule / expires_at enforcement.
//!
//! Spec: `docs/specs/vauban-mcp/07-lot0-prerequis.md` (L0-1 … L0-8).
//! Plan fix 0.1: MFA/approval cut only on **false → true** delta
//! (`docs/specs/vauban-mcp/10-plan-correction.md` Phase 0).
//!
//! Every [`RECHECK_INTERVAL`] the task:
//! 1. Cuts sessions whose `expires_at` is past.
//! 2. Soft-fills legacy IACS rows with `expires_at IS NULL` once
//!    (`now + DEFAULT_IACS_SESSION_SECONDS`).
//! 3. Re-asks `vauban-access` (`CheckAccessByUuid`) for live IACS
//!    (and SSH/RDP active) sessions; deny → terminate.
//! 4. After [`ACCESS_FAILURE_CUTOFF`] consecutive Access IPC failures
//!    for a given session → terminate (fail-closed).
//!
//! User/EWS revocation stays in [`crate::services::iacs_tunnel::revocation`]
//! (faster 2 s poll). This module owns **access_rule** withdrawal.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::models::session::{ProxySession, SessionStatus, SessionType};
const DEFAULT_IACS_SESSION_SECONDS: i32 = 4 * 3600;
use crate::AppState;

/// Shared across the 30 s loop and instant [`notify`]-style callers so a
/// false→true MFA/approval flip is visible on the first post-mutation pass.
fn shared_policy_flags() -> &'static Mutex<PolicyFlagTracker> {
    static TRACKER: OnceLock<Mutex<PolicyFlagTracker>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(PolicyFlagTracker::default()))
}

/// Normative Lot 0 poll interval.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Consecutive Access IPC errors before fail-closed terminate.
pub const ACCESS_FAILURE_CUTOFF: u32 = 3;

#[derive(Debug, Default)]
pub(crate) struct FailureTracker {
    /// session uuid → consecutive Access IPC failures
    by_session: HashMap<Uuid, u32>,
}

impl FailureTracker {
    fn record_ok(&mut self, id: Uuid) {
        self.by_session.remove(&id);
    }

    /// Returns true when the session should be cut after this failure.
    fn record_err(&mut self, id: Uuid) -> bool {
        let n = self.by_session.entry(id).or_insert(0);
        *n = n.saturating_add(1);
        *n >= ACCESS_FAILURE_CUTOFF
    }

    fn forget(&mut self, id: Uuid) {
        self.by_session.remove(&id);
    }
}

/// Per-session snapshot of Access policy flags seen on the last successful
/// recheck. Used to detect **newly** required MFA/approval mid-flight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyFlags {
    pub require_mfa: bool,
    pub require_approval: bool,
}

#[derive(Debug, Default)]
pub(crate) struct PolicyFlagTracker {
    by_session: HashMap<Uuid, PolicyFlags>,
}

impl PolicyFlagTracker {
    /// Returns `Some(reason)` when MFA or approval flipped false→true.
    /// First observation baselines without cutting.
    fn evaluate_newly_required(&mut self, id: Uuid, current: PolicyFlags) -> Option<&'static str> {
        match self.by_session.insert(id, current) {
            None => None,
            Some(prev) => {
                if !prev.require_approval && current.require_approval {
                    Some("approval_now_required")
                } else if !prev.require_mfa && current.require_mfa {
                    Some("mfa_now_required")
                } else {
                    None
                }
            }
        }
    }

    fn forget(&mut self, id: Uuid) {
        self.by_session.remove(&id);
    }

    fn retain_live(&mut self, live: &std::collections::HashSet<Uuid>) {
        self.by_session.retain(|id, _| live.contains(id));
    }
}

/// Spawn the Lot 0 policy recheck loop.
pub fn spawn_policy_recheck(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RECHECK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        let mut failures = FailureTracker::default();
        loop {
            tick.tick().await;
            let mut flags = shared_policy_flags().lock().await;
            let (cut, filled) = run_once(&state, &mut failures, &mut flags).await;
            drop(flags);
            if cut > 0 || filled > 0 {
                tracing::info!(cut, filled, "policy_recheck: tick complete");
            }
        }
    })
}

/// Instant pass after an access-rule mutation (shares MFA/approval baseline
/// with the background loop).
pub(crate) async fn run_once_shared(
    state: &AppState,
    failures: &mut FailureTracker,
) -> (usize, usize) {
    let mut flags = shared_policy_flags().lock().await;
    run_once(state, failures, &mut flags).await
}

/// One deterministic pass (tests + watchdog).
pub(crate) async fn run_once(
    state: &AppState,
    failures: &mut FailureTracker,
    policy_flags: &mut PolicyFlagTracker,
) -> (usize, usize) {
    let mut cut = 0usize;
    let mut filled = 0usize;

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "policy_recheck: DB pool unavailable");
            return (0, 0);
        }
    };

    use crate::schema::{assets, proxy_sessions, users};

    // Live rows we must re-evaluate (IACS auth + SSH/RDP/MCP inflight +
    // ops-paused `suspended` so P6 membership/soft-delete still cuts).
    let mut statuses: Vec<&str> = Vec::new();
    statuses.extend_from_slice(&SessionStatus::IACS_OPEN_AS_STR);
    statuses.extend_from_slice(&SessionStatus::SSH_RDP_INFLIGHT_AS_STR);
    statuses.push("suspended");

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        ProxySession,
        Uuid, // user.uuid
        bool, // user.is_active
        bool, // user.is_deleted
        Uuid, // asset.uuid
    )> = match proxy_sessions::table
        .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
        .inner_join(assets::table.on(assets::id.eq(proxy_sessions::asset_id)))
        .filter(proxy_sessions::status.eq_any(statuses))
        .filter(assets::deleted_at.is_null())
        .select((
            ProxySession::as_select(),
            users::uuid,
            users::is_active,
            users::is_deleted,
            assets::uuid,
        ))
        .load::<(ProxySession, Uuid, bool, bool, Uuid)>(&mut conn)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "policy_recheck: load live sessions failed");
            return (0, 0);
        }
    };

    let now = Utc::now();
    let access = &state.access_client;
    let live_ids: std::collections::HashSet<Uuid> = rows.iter().map(|(s, ..)| s.uuid).collect();

    for (session, user_uuid, user_active, user_deleted, asset_uuid) in rows {
        let sid = session.uuid;
        let user_uuid_s = user_uuid.to_string();
        let asset_uuid_s = asset_uuid.to_string();

        // Soft-deleted or inactive user → cut (P6-2 belt; IACS watchdog
        // also covers inactive for IACS).
        if user_deleted || !user_active {
            let reason = if user_deleted {
                "user_deleted"
            } else {
                "user_disabled"
            };
            if terminate(state, &session, reason).await {
                failures.forget(sid);
                policy_flags.forget(sid);
                cut += 1;
            }
            continue;
        }

        // Soft-fill legacy IACS NULL expires_at once (L0-4 migration soft).
        if session.session_type == SessionType::IacsTunnel && session.expires_at.is_none() {
            let new_exp = now + ChronoDuration::seconds(i64::from(DEFAULT_IACS_SESSION_SECONDS));
            match diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq(sid)))
                .set((
                    proxy_sessions::expires_at.eq(Some(new_exp)),
                    proxy_sessions::max_session_duration.eq(Some(DEFAULT_IACS_SESSION_SECONDS)),
                ))
                .execute(&mut conn)
                .await
            {
                Ok(n) if n > 0 => {
                    filled += 1;
                    tracing::info!(
                        session_uuid = %sid,
                        expires_at = %new_exp,
                        "policy_recheck: soft-filled legacy IACS expires_at"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(session_uuid = %sid, error = %e, "policy_recheck: soft-fill failed");
                }
            }
            // Re-load horizon for this tick: treat as newly set.
            if now >= new_exp {
                if terminate(state, &session, "expired").await {
                    failures.forget(sid);
                    policy_flags.forget(sid);
                    cut += 1;
                }
                continue;
            }
        } else if let Some(exp) = session.expires_at
            && now >= exp
        {
            if terminate(state, &session, "expired").await {
                failures.forget(sid);
                policy_flags.forget(sid);
                cut += 1;
            }
            continue;
        }

        let protocol = match session.session_type {
            SessionType::Ssh => "ssh",
            SessionType::Rdp => "rdp",
            SessionType::IacsTunnel => shared::access_guard::PROTOCOL_IACS_TUNNEL,
            SessionType::Mcp => "mcp",
        };

        match access
            .check_access_by_uuid(&user_uuid_s, &asset_uuid_s, protocol)
            .await
        {
            Ok(result) if result.allowed => {
                failures.record_ok(sid);
                // Tighten expires_at if rule duration shrank (L0-8).
                if let Some(rule_secs) = result.max_session_duration {
                    let anchor = session.connected_at.unwrap_or(session.created_at);
                    let rule_exp = anchor + ChronoDuration::seconds(i64::from(rule_secs));
                    let should_advance = match session.expires_at {
                        None => true,
                        Some(cur) => rule_exp < cur,
                    };
                    if should_advance {
                        let _ = diesel::update(
                            proxy_sessions::table.filter(proxy_sessions::uuid.eq(sid)),
                        )
                        .set((
                            proxy_sessions::expires_at.eq(Some(rule_exp)),
                            proxy_sessions::max_session_duration.eq(Some(rule_secs)),
                        ))
                        .execute(&mut conn)
                        .await;
                        // MCP proxy keeps a local expires_at — push shrink now.
                        if session.session_type == SessionType::Mcp
                            && let Some(ref proxy) = state.proxy_mcp
                        {
                            let req = crate::ipc::McpSessionUpdateRequest {
                                session_id: sid.to_string(),
                                allowed_tools: None,
                                tool_constraints_json: "{}".to_string(),
                                envelope_max_calls:
                                    crate::services::mcp_session::ENVELOPE_MAX_CALLS,
                                envelope_window_seconds:
                                    crate::services::mcp_session::ENVELOPE_WINDOW_SECONDS,
                                // Empty = do not clobber live on_exceed (e.g. suspend).
                                envelope_on_exceed: String::new(),
                                expires_at: Some(
                                    rule_exp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                                ),
                            };
                            let _ = proxy.update_session(req);
                        }
                        if now >= rule_exp && terminate(state, &session, "duration_reduced").await {
                            failures.forget(sid);
                            policy_flags.forget(sid);
                            cut += 1;
                        }
                    }
                }
                // MFA/approval: cut only on false→true mid-flight (Phase 0 / 0.1).
                // Baseline on first observation so stable require_mfa rules do not
                // kill every live session every 30 s.
                let flags = PolicyFlags {
                    require_mfa: result.require_mfa,
                    require_approval: result.require_approval,
                };
                if let Some(reason) = policy_flags.evaluate_newly_required(sid, flags)
                    && terminate(state, &session, reason).await
                {
                    failures.forget(sid);
                    policy_flags.forget(sid);
                    cut += 1;
                }
            }
            Ok(_) => {
                // Access denied — rule withdrawn / no longer matches.
                if terminate(state, &session, "access_revoked").await {
                    failures.forget(sid);
                    policy_flags.forget(sid);
                    cut += 1;
                }
            }
            Err(e) => {
                tracing::warn!(
                    session_uuid = %sid,
                    error = %e,
                    "policy_recheck: Access IPC error"
                );
                if failures.record_err(sid)
                    && terminate(state, &session, "access_unreachable").await
                {
                    failures.forget(sid);
                    policy_flags.forget(sid);
                    cut += 1;
                }
            }
        }
    }

    // Drop tracker entries for sessions no longer live (avoid unbounded growth).
    failures.by_session.retain(|id, _| live_ids.contains(id));
    policy_flags.retain_live(&live_ids);

    (cut, filled)
}

async fn terminate(state: &AppState, session: &ProxySession, reason: &str) -> bool {
    match crate::services::session_termination::terminate_live_session(state, session, reason).await
    {
        Ok(_) => {
            tracing::info!(
                session_uuid = %session.uuid,
                reason,
                session_type = ?session.session_type,
                "policy_recheck: session terminated"
            );
            let _ =
                crate::services::session_termination::broadcast_session_list_updates(state).await;
            true
        }
        Err(e) => {
            tracing::warn!(
                session_uuid = %session.uuid,
                error = %e,
                reason,
                "policy_recheck: terminate failed"
            );
            false
        }
    }
}

/// Resolve duration for a new IACS open: rule duration or default 4 h.
pub fn iacs_session_duration_secs(rule_max: Option<i32>) -> i32 {
    match rule_max {
        Some(s) if s > 0 => s,
        _ => DEFAULT_IACS_SESSION_SECONDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_duration_when_rule_absent() {
        assert_eq!(iacs_session_duration_secs(None), 14_400);
        assert_eq!(iacs_session_duration_secs(Some(0)), 14_400);
        assert_eq!(iacs_session_duration_secs(Some(-1)), 14_400);
        assert_eq!(iacs_session_duration_secs(Some(7200)), 7200);
    }

    #[test]
    fn failure_tracker_cuts_at_three() {
        let mut t = FailureTracker::default();
        let id = Uuid::nil();
        assert!(!t.record_err(id));
        assert!(!t.record_err(id));
        assert!(t.record_err(id));
        t.record_ok(id);
        assert!(!t.record_err(id));
    }

    #[test]
    fn recheck_interval_is_thirty_seconds() {
        assert_eq!(RECHECK_INTERVAL, Duration::from_secs(30));
        assert_eq!(ACCESS_FAILURE_CUTOFF, 3);
    }

    #[test]
    fn policy_flags_baseline_does_not_cut() {
        let mut t = PolicyFlagTracker::default();
        let id = Uuid::nil();
        assert!(
            t.evaluate_newly_required(
                id,
                PolicyFlags {
                    require_mfa: true,
                    require_approval: true,
                },
            )
            .is_none()
        );
        // Stable flags → no cut.
        assert!(
            t.evaluate_newly_required(
                id,
                PolicyFlags {
                    require_mfa: true,
                    require_approval: true,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn policy_flags_false_to_true_cuts() {
        let mut t = PolicyFlagTracker::default();
        let id = Uuid::nil();
        assert!(
            t.evaluate_newly_required(id, PolicyFlags::default())
                .is_none()
        );
        assert_eq!(
            t.evaluate_newly_required(
                id,
                PolicyFlags {
                    require_mfa: true,
                    require_approval: false,
                },
            ),
            Some("mfa_now_required")
        );
        // Still true → no re-cut.
        assert!(
            t.evaluate_newly_required(
                id,
                PolicyFlags {
                    require_mfa: true,
                    require_approval: false,
                },
            )
            .is_none()
        );
        assert_eq!(
            t.evaluate_newly_required(
                id,
                PolicyFlags {
                    require_mfa: true,
                    require_approval: true,
                },
            ),
            Some("approval_now_required")
        );
    }
}
