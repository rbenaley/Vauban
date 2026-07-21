//! IACS tunnel revocation watchdog.
//!
//! `vauban-access` mutates `ews.disabled_at` / `ews.offboarded_at`
//! and `users.is_active` from a separate process; the
//! `vauban-proxy-iacs` sshd needs to learn about those mutations
//! within seconds and revoke any live tunnel that should no longer
//! exist. The watchdog polls the DB on a short interval (default
//! 2 s) and dispatches `IacsTunnelTerminate` over IPC.
//!
//! We poll instead of using `LISTEN`/`NOTIFY` for two reasons:
//!
//!   1. The vauban-access process does not own the cross-process
//!      bus and would need a new IPC message just for this signal.
//!   2. A 2 s revocation window is acceptable for the IACS use
//!      case (industrial poll cycles are typically 100 ms-1 s; a
//!      2 s revocation window costs at most a few extra Modbus
//!      frames after disabling an EWS).
//!
//! The watchdog also enforces `waiting_client_ttl_seconds`: a
//! `proxy_sessions` row that has been waiting for an EWS to call
//! in for longer than the TTL is flipped to `expired`. For
//! `ews_connected` rows the SSH login itself lives in proxy-iacs
//! and must be cut via IPC as well.
//!
//! Pinned by [`vauban-web/tests/web/iacs_revocation_watchdog_test.rs`](../../../../tests/web/iacs_revocation_watchdog_test.rs).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::config::IacsTunnelConfig;
use crate::db::DbPool;
use crate::ipc::ProxyIacsClient;

/// Flip every live IACS `proxy_sessions` row to `terminated`.
///
/// Deprecated for production boot: prefer
/// [`super::boot_reconcile::reconcile_iacs_from_proxy_snapshot`], which
/// asks proxy-iacs for a live snapshot and rehydrates matching rows.
/// Kept for tests and as the fail-closed empty-snapshot semantics
/// (terminate every live row when the proxy is unreachable).
pub async fn reconcile_orphaned_iacs_tunnels_on_boot(pool: &DbPool) -> Result<usize, String> {
    use diesel_async::RunQueryDsl;

    let mut conn = pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();

    let terminated = diesel::update(
        crate::schema::proxy_sessions::table
            .filter(crate::schema::proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(crate::schema::proxy_sessions::status.eq_any([
                "tunnel_active",
                "ews_connected",
                "waiting_client",
            ])),
    )
    .set((
        crate::schema::proxy_sessions::status.eq("terminated"),
        crate::schema::proxy_sessions::disconnected_at.eq(Some(now)),
        crate::schema::proxy_sessions::updated_at.eq(now),
    ))
    .execute(&mut conn)
    .await
    .map_err(|e| e.to_string())?;

    if terminated > 0 {
        tracing::info!(
            terminated,
            "iacs_tunnel: reconciled orphaned IACS proxy_sessions rows after service boot"
        );
    }

    Ok(terminated)
}

/// One pass of the watchdog. Returns `(closed, transitions)` --
/// the number of live tunnels revoked (DB flip + IPC attempt) and
/// the number of session rows transitioned by TTL
/// (e.g. waiting_client -> expired). Public so the test suite can
/// drive a single tick deterministically without relying on tokio
/// time.
///
/// When `proxy_iacs` is `None`, revoke / TTL DB mutations still run
/// but IPC terminates are skipped (logged). Production always wires
/// a client under the supervisor.
pub async fn run_once(
    pool: &DbPool,
    cfg: &IacsTunnelConfig,
    proxy_iacs: Option<&Arc<ProxyIacsClient>>,
) -> (usize, usize) {
    run_once_with_proxy(pool, cfg, proxy_iacs).await
}

/// Alias kept for call sites / tests that name the IPC-aware path
/// explicitly. Identical to [`run_once`].
pub async fn run_once_with_proxy(
    pool: &DbPool,
    cfg: &IacsTunnelConfig,
    proxy_iacs: Option<&Arc<ProxyIacsClient>>,
) -> (usize, usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "iacs_tunnel watchdog: DB pool unavailable, skipping tick");
            return (0, 0);
        }
    };

    let mut closed_now: usize = 0;
    let mut transitions: usize = 0;

    // 1) Revoke live tunnels whose EWS / user is no longer valid.
    //    proxy-iacs holds the canonical live SSH state; we flip the
    //    DB row and fire `IacsTunnelTerminate` so the relay dies.
    {
        use crate::schema::{ews, proxy_sessions, users};

        let to_revoke: Vec<(Uuid, Option<Uuid>)> = proxy_sessions::table
            .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
            .left_join(ews::table.on(ews::uuid.nullable().eq(proxy_sessions::ews_uuid)))
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(proxy_sessions::status.eq_any(["ews_connected", "tunnel_active"]))
            .filter(
                users::is_active
                    .eq(false)
                    .or(ews::disabled_at.is_not_null())
                    .or(ews::offboarded_at.is_not_null()),
            )
            .select((proxy_sessions::uuid, proxy_sessions::ews_uuid))
            .load::<(Uuid, Option<Uuid>)>(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "iacs_tunnel watchdog: revoke query failed");
                e
            })
            .unwrap_or_default();

        for (sess_uuid, ews_uuid_opt) in to_revoke {
            let updated = diesel::update(
                proxy_sessions::table
                    .filter(proxy_sessions::uuid.eq(sess_uuid))
                    .filter(proxy_sessions::status.eq_any(["ews_connected", "tunnel_active"])),
            )
            .set((
                proxy_sessions::status.eq("terminated"),
                proxy_sessions::disconnected_at.eq(Some(Utc::now())),
            ))
            .execute(&mut conn)
            .await
            .unwrap_or(0);

            if updated == 0 {
                continue;
            }

            closed_now += 1;
            if let Some(ews_uuid) = ews_uuid_opt {
                let _ = append_tunnel_closed_audit(&mut conn, ews_uuid, sess_uuid, "revoked").await;
            }

            dispatch_terminate(proxy_iacs, &sess_uuid, "revoked");
            tracing::info!(
                session_uuid = %sess_uuid,
                "iacs_tunnel watchdog: tunnel closed by revocation"
            );
        }
    }

    // 2) Waiting-state TTL: `waiting_client` (anchored on
    //    `created_at`) AND `ews_connected` (anchored on
    //    `connected_at`). Snapshot ews_connected kills BEFORE the
    //    status flip so we can still IPC-terminate them.
    let ttl_kills: Vec<Uuid> = if cfg.waiting_client_ttl_seconds > 0 {
        use crate::schema::proxy_sessions;
        let now = Utc::now();
        #[allow(clippy::type_complexity)]
        let candidates: Vec<(
            Uuid,
            String,
            chrono::DateTime<Utc>,
            Option<chrono::DateTime<Utc>>,
        )> = proxy_sessions::table
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(proxy_sessions::status.eq_any(["waiting_client", "ews_connected"]))
            .select((
                proxy_sessions::uuid,
                proxy_sessions::status,
                proxy_sessions::created_at,
                proxy_sessions::connected_at,
            ))
            .load(&mut conn)
            .await
            .unwrap_or_default();

        let expired: Vec<(Uuid, String)> = candidates
            .into_iter()
            .filter(|(_, status, created_at, connected_at)| {
                should_expire(
                    status,
                    *created_at,
                    *connected_at,
                    now,
                    cfg.waiting_client_ttl_seconds,
                )
            })
            .map(|(uuid, status, ..)| (uuid, status))
            .collect();

        let mut ipc_targets = Vec::new();
        if !expired.is_empty() {
            let uuids: Vec<Uuid> = expired.iter().map(|(u, _)| *u).collect();
            transitions += uuids.len();
            let _ = diesel::update(
                proxy_sessions::table
                    .filter(proxy_sessions::uuid.eq_any(&uuids))
                    .filter(proxy_sessions::status.eq_any(["waiting_client", "ews_connected"])),
            )
            .set((
                proxy_sessions::status.eq("expired"),
                proxy_sessions::disconnected_at.eq(Some(Utc::now())),
            ))
            .execute(&mut conn)
            .await;
            for (sess_uuid, status) in &expired {
                tracing::info!(
                    session_uuid = %sess_uuid,
                    ttl_secs = cfg.waiting_client_ttl_seconds,
                    "iacs_tunnel watchdog: waiting session expired"
                );
                if status == "ews_connected" {
                    ipc_targets.push(*sess_uuid);
                }
            }
        }
        ipc_targets
    } else {
        Vec::new()
    };

    for sess_uuid in ttl_kills {
        dispatch_terminate(proxy_iacs, &sess_uuid, "expired");
    }

    (closed_now, transitions)
}

fn dispatch_terminate(
    proxy_iacs: Option<&Arc<ProxyIacsClient>>,
    sess_uuid: &Uuid,
    reason: &'static str,
) {
    let Some(client) = proxy_iacs else {
        tracing::debug!(
            session_uuid = %sess_uuid,
            reason,
            "iacs_tunnel watchdog: no proxy-iacs client; skip IacsTunnelTerminate"
        );
        return;
    };
    if let Err(e) = client.terminate_tunnel(&sess_uuid.to_string(), reason) {
        tracing::warn!(
            session_uuid = %sess_uuid,
            reason,
            error = %e,
            "iacs_tunnel watchdog: IacsTunnelTerminate IPC send failed"
        );
    } else {
        tracing::info!(
            session_uuid = %sess_uuid,
            reason,
            "iacs_tunnel watchdog: IacsTunnelTerminate dispatched to proxy-iacs"
        );
    }
}

/// Pure reap predicate for the waiting-state TTL: should `status`
/// (one of the two waiting states) be flipped to `expired` at `now`?
///
/// Anchors mirror the lifecycle semantics:
///
/// * `waiting_client` -- `created_at` (the operator clicked Connect
///   and the EWS never called in);
/// * `ews_connected` -- `connected_at` (the SSH handshake succeeded;
///   the TTL RESTARTS at auth so the operator gets a fresh window to
///   open the first channel). A NULL `connected_at` (defensive: the
///   transition always sets it) falls back to `created_at` so the
///   row can never become unreapable.
///
/// Every other status returns `false` -- reaping is exclusively a
/// waiting-state concern. `ttl_seconds == 0` disables the reap.
///
/// The strict `<` mirrors the historical SQL predicate
/// (`created_at < now - ttl`) and the countdown seed derivation in
/// [`super::countdown::remaining_waiting_seconds`]: a row whose
/// countdown still shows a positive value is never reapable.
pub fn should_expire(
    status: &str,
    created_at: chrono::DateTime<Utc>,
    connected_at: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
    ttl_seconds: u32,
) -> bool {
    if ttl_seconds == 0 {
        return false;
    }
    let anchor = match status {
        "waiting_client" => created_at,
        "ews_connected" => connected_at.unwrap_or(created_at),
        _ => return false,
    };
    anchor < now - chrono::Duration::seconds(i64::from(ttl_seconds))
}

async fn append_tunnel_closed_audit(
    conn: &mut diesel_async::AsyncPgConnection,
    ews_uuid: Uuid,
    session_uuid: Uuid,
    cause: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::ews;
    use diesel_async::RunQueryDsl;
    // Look up the EWS metadata snapshot fields. If the EWS row
    // was hard-deleted (cascade) we still emit the audit row
    // with placeholder names so the trail survives.
    let meta: Option<(String, String, Option<i32>)> = ews::table
        .filter(ews::uuid.eq(ews_uuid))
        .select((
            ews::name,
            ews::public_key_fingerprint,
            ews::user_id.nullable(),
        ))
        .first(conn)
        .await
        .optional()?;
    let (ews_name, fp, owner_id) =
        meta.unwrap_or_else(|| ("<deleted>".to_string(), "0".repeat(64), None));
    diesel::sql_query(
        "INSERT INTO ews_audit_log \
         (ews_uuid, event, actor_user_id, actor_username, \
          target_user_id, target_username, ews_name, public_key_fingerprint, \
          decision_reason, created_at) \
         VALUES ($1, 'tunnel_closed', NULL, 'iacs_tunnel_watchdog', \
                 $2, 'system', $3, $4, $5, NOW())",
    )
    .bind::<diesel::sql_types::Uuid, _>(ews_uuid)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Integer>, _>(owner_id)
    .bind::<diesel::sql_types::Text, _>(&ews_name)
    .bind::<diesel::sql_types::Text, _>(&fp)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(format!(
        "session_uuid={} cause={}",
        session_uuid, cause
    )))
    .execute(conn)
    .await?;
    Ok(())
}

/// Spawn the long-running watchdog task without a proxy-iacs client.
/// Terminates are skipped (logged); useful only for DB-side TTL
/// reaping in constrained test setups.
pub fn spawn_watchdog(pool: DbPool, cfg: IacsTunnelConfig) -> tokio::task::JoinHandle<()> {
    spawn_watchdog_with_proxy_iacs(pool, cfg, None)
}

/// Spawn the revocation / TTL watchdog. When `proxy_iacs` is
/// `Some`, revoke and expired-`ews_connected` decisions are
/// dispatched as `IacsTunnelTerminate` IPC messages. proxy-iacs
/// emits a matching `IacsTunnelClosed` notification when the relay
/// actually ends, which vauban-web handles in
/// [`crate::ipc::proxy_iacs`].
pub fn spawn_watchdog_with_proxy_iacs(
    pool: DbPool,
    cfg: IacsTunnelConfig,
    proxy_iacs: Option<Arc<ProxyIacsClient>>,
) -> tokio::task::JoinHandle<()> {
    let interval = Duration::from_secs(cfg.revocation_poll_interval_seconds.max(1) as u64);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate tick at start.
        tick.tick().await;
        loop {
            tick.tick().await;
            let (closed, transitions) =
                run_once_with_proxy(&pool, &cfg, proxy_iacs.as_ref()).await;
            if closed > 0 || transitions > 0 {
                tracing::debug!(closed, transitions, "iacs_tunnel watchdog: tick complete");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;

    fn at(secs: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    // ---------------------------------------------------------------
    // Battle-tested edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_should_expire_disabled_ttl_never_reaps() {
        assert!(!should_expire(
            "waiting_client",
            at(0),
            None,
            at(i64::from(u32::MAX)),
            0
        ));
        assert!(!should_expire(
            "ews_connected",
            at(0),
            Some(at(0)),
            at(1_000_000),
            0
        ));
    }

    #[test]
    fn test_should_expire_waiting_client_anchors_on_created_at() {
        // 300 s TTL, created at t=1000: reapable strictly after t=1300.
        assert!(!should_expire(
            "waiting_client",
            at(1_000),
            None,
            at(1_300),
            300
        ));
        assert!(should_expire(
            "waiting_client",
            at(1_000),
            None,
            at(1_301),
            300
        ));
        // A fresh ews-auth anchor must NOT extend the waiting_client
        // window (the anchor is status-driven, not a max()).
        assert!(should_expire(
            "waiting_client",
            at(1_000),
            Some(at(2_000)),
            at(1_301),
            300
        ));
    }

    #[test]
    fn test_should_expire_ews_connected_anchors_on_connected_at() {
        // Auth at t=2000 RESTARTS the 300 s window even though the
        // row was created at t=1000.
        assert!(!should_expire(
            "ews_connected",
            at(1_000),
            Some(at(2_000)),
            at(2_300),
            300
        ));
        assert!(should_expire(
            "ews_connected",
            at(1_000),
            Some(at(2_000)),
            at(2_301),
            300
        ));
    }

    #[test]
    fn test_should_expire_ews_connected_null_anchor_falls_back_to_created_at() {
        // Defensive: the transition always sets connected_at, but a
        // NULL must not make the row immortal.
        assert!(should_expire(
            "ews_connected",
            at(1_000),
            None,
            at(1_301),
            300
        ));
        assert!(!should_expire(
            "ews_connected",
            at(1_000),
            None,
            at(1_299),
            300
        ));
    }

    #[test]
    fn test_should_expire_other_statuses_are_never_reaped() {
        for status in [
            "tunnel_active",
            "terminated",
            "expired",
            "active",
            "pending",
            "",
            "garbage",
        ] {
            assert!(
                !should_expire(status, at(0), Some(at(0)), at(i64::from(u32::MAX)), 1),
                "status {status:?} must never be TTL-reaped"
            );
        }
    }

    // ---------------------------------------------------------------
    // Invariant-based (proptest)
    // ---------------------------------------------------------------

    const TS_RANGE: std::ops::RangeInclusive<i64> = -1_000_000_000_000..=1_000_000_000_000;

    proptest! {
        /// `ttl == 0` disables the reap for every status and every
        /// instant tuple.
        #[test]
        fn prop_disabled_ttl_never_reaps(
            status in "[a-z_]{0,16}",
            created in TS_RANGE,
            connected in proptest::option::of(TS_RANGE),
            now in TS_RANGE,
        ) {
            prop_assert!(!should_expire(
                &status,
                at(created),
                connected.map(at),
                at(now),
                0
            ));
        }

        /// Lock-step with the status-page countdown: a strictly
        /// positive `remaining_waiting_seconds` (same anchor) implies
        /// the row is NOT reapable, and a reapable row always renders
        /// a zero countdown.
        #[test]
        fn prop_reap_iff_countdown_reached_zero(
            waiting in proptest::bool::ANY,
            created in TS_RANGE,
            connected in TS_RANGE,
            now in TS_RANGE,
            ttl in 1u32..,
        ) {
            let (status, anchor) = if waiting {
                ("waiting_client", at(created))
            } else {
                ("ews_connected", at(connected))
            };
            let reap = should_expire(
                status,
                at(created),
                Some(at(connected)),
                at(now),
                ttl,
            );
            let remaining = super::super::countdown::remaining_waiting_seconds(
                anchor,
                at(now),
                ttl,
            )
            .expect("enabled TTL yields Some");
            if remaining > 0 {
                prop_assert!(
                    !reap,
                    "countdown shows {remaining}s left but the watchdog would reap"
                );
            }
            if reap {
                prop_assert_eq!(
                    remaining, 0,
                    "a reapable row must render a zero countdown"
                );
            }
        }

        /// Reaping is monotone in `now`: once reapable, a row stays
        /// reapable at every later instant (no flapping).
        #[test]
        fn prop_reap_is_monotone_in_now(
            waiting in proptest::bool::ANY,
            created in TS_RANGE,
            connected in proptest::option::of(TS_RANGE),
            now in TS_RANGE,
            delta in 0i64..=1_000_000,
            ttl in 1u32..,
        ) {
            let status = if waiting { "waiting_client" } else { "ews_connected" };
            let before = should_expire(
                status,
                at(created),
                connected.map(at),
                at(now),
                ttl,
            );
            let after = should_expire(
                status,
                at(created),
                connected.map(at),
                at(now + delta),
                ttl,
            );
            prop_assert!(!before || after, "reap decision regressed as time passed");
        }

        /// The `ews_connected` anchor NEVER reaps before the full TTL
        /// has elapsed since auth: the operator always gets the whole
        /// window to open the first channel, regardless of how long
        /// the pre-auth wait lasted.
        #[test]
        fn prop_ews_connected_gets_the_full_window_after_auth(
            created in TS_RANGE,
            auth_delay in 0i64..=1_000_000,
            elapsed_frac in 0.0f64..=1.0,
            ttl in 1u32..=u32::MAX / 4,
        ) {
            let connected = created + auth_delay;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let elapsed = (f64::from(ttl) * elapsed_frac) as i64;
            // Strictly inside the window (elapsed <= ttl): never reap.
            prop_assert!(!should_expire(
                "ews_connected",
                at(created),
                Some(at(connected)),
                at(connected + elapsed),
                ttl
            ));
            // Strictly past the window: always reap.
            prop_assert!(should_expire(
                "ews_connected",
                at(created),
                Some(at(connected)),
                at(connected + i64::from(ttl) + 1),
                ttl
            ));
        }
    }
}
