//! IACS tunnel revocation watchdog.
//!
//! `vauban-access` mutates `ews.disabled_at` / `ews.offboarded_at`
//! and `users.is_active` from a separate process; the in-process
//! IACS sshd needs to learn about those mutations within seconds
//! and revoke any live tunnel that should no longer exist.
//!
//! We poll the DB on a short interval (default 2 s) instead of
//! using `LISTEN`/`NOTIFY` for two reasons:
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
//! in for longer than the TTL is flipped to `expired` and removed
//! from the registry (the registry is empty for `waiting_client`
//! rows but we still want a no-op clean-up so a future refactor
//! that pre-allocates handles cannot leak them).
//!
//! Pinned by [`vauban-web/tests/web/iacs_revocation_watchdog_test.rs`](../../../../tests/web/iacs_revocation_watchdog_test.rs).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use super::registry::TunnelRegistry;
use crate::config::IacsTunnelConfig;
use crate::db::DbPool;
use crate::ipc::ProxyIacsClient;

/// One pass of the watchdog. Returns `(closed, transitions)` --
/// the number of live tunnels closed and the number of session
/// rows transitioned (e.g. waiting_client -> expired). Public so
/// the test suite can drive a single tick deterministically
/// without relying on tokio time.
pub async fn run_once(
    registry: &TunnelRegistry,
    pool: &DbPool,
    cfg: &IacsTunnelConfig,
) -> (usize, usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "iacs_tunnel watchdog: DB pool unavailable, skipping tick");
            return (0, 0);
        }
    };

    // 1) Snapshot the live registry. Cloning each handle is cheap
    //    (Arc bump), and we want to release the registry lock
    //    before the DB roundtrips.
    let live = registry.snapshot();
    let live_uuids: Vec<Uuid> = live.iter().map(|h| h.session_uuid).collect();

    let mut closed_now: usize = 0;
    let mut transitions: usize = 0;

    if !live_uuids.is_empty() {
        // 2) Find which live tunnels MUST be revoked. A tunnel is
        //    revoked if EITHER:
        //      a) its `ews_uuid` row is disabled or offboarded,
        //      b) its owning user is `is_active = false`,
        //      c) the corresponding `proxy_sessions` row is no
        //         longer `tunnel_active` (admin force-terminate
        //         via the existing `/api/sessions/{uuid}/terminate`
        //         flow; the watchdog double-checks the registry).
        use crate::schema::{ews, proxy_sessions, users};

        // Sub-query: live (registry) sessions whose state in the DB
        // implies "must close".
        let to_revoke: Vec<(Uuid, String)> = proxy_sessions::table
            .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
            .left_join(ews::table.on(ews::uuid.nullable().eq(proxy_sessions::ews_uuid)))
            .filter(proxy_sessions::uuid.eq_any(&live_uuids))
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .select((proxy_sessions::uuid, proxy_sessions::status))
            .filter(
                users::is_active
                    .eq(false)
                    .or(ews::disabled_at.is_not_null())
                    .or(ews::offboarded_at.is_not_null())
                    .or(proxy_sessions::status
                        .ne_all(["waiting_client".to_string(), "tunnel_active".to_string()])),
            )
            .load::<(Uuid, String)>(&mut conn)
            .await
            .unwrap_or_default();

        for (sess_uuid, _status) in to_revoke {
            if let Some(handle) = registry.close_and_remove(&sess_uuid) {
                tracing::info!(
                    session_uuid = %sess_uuid,
                    ews_uuid = %handle.ews_uuid,
                    user_uuid = %handle.user_uuid,
                    "iacs_tunnel watchdog: tunnel closed by revocation"
                );
                closed_now += 1;
                // Also flip the row so a subsequent reconnect
                // attempt cannot succeed (the auth gate already
                // checks `status='waiting_client'`, but we want
                // forensic clarity that the tunnel was revoked).
                let _ = diesel::update(
                    proxy_sessions::table.filter(proxy_sessions::uuid.eq(sess_uuid)),
                )
                .set((
                    proxy_sessions::status.eq("terminated"),
                    proxy_sessions::disconnected_at.eq(Some(Utc::now())),
                ))
                .execute(&mut conn)
                .await;
                let _ =
                    append_tunnel_closed_audit(&mut conn, handle.ews_uuid, sess_uuid, "revoked")
                        .await;
            }
        }
    }

    // 3) waiting_client TTL. Independent of the live registry --
    //    `waiting_client` rows have no russh handler attached yet
    //    so the registry is empty for them.
    if cfg.waiting_client_ttl_seconds > 0 {
        use crate::schema::proxy_sessions;
        let cutoff = Utc::now() - chrono::Duration::seconds(cfg.waiting_client_ttl_seconds as i64);
        let expired: Vec<Uuid> = proxy_sessions::table
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(proxy_sessions::status.eq("waiting_client"))
            .filter(proxy_sessions::created_at.lt(cutoff))
            .select(proxy_sessions::uuid)
            .load(&mut conn)
            .await
            .unwrap_or_default();
        if !expired.is_empty() {
            transitions += expired.len();
            let _ =
                diesel::update(proxy_sessions::table.filter(proxy_sessions::uuid.eq_any(&expired)))
                    .set((
                        proxy_sessions::status.eq("expired"),
                        proxy_sessions::disconnected_at.eq(Some(Utc::now())),
                    ))
                    .execute(&mut conn)
                    .await;
            for sess_uuid in expired {
                tracing::info!(
                    session_uuid = %sess_uuid,
                    ttl_secs = cfg.waiting_client_ttl_seconds,
                    "iacs_tunnel watchdog: waiting_client expired"
                );
            }
        }
    }

    (closed_now, transitions)
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

/// Spawn the long-running watchdog task. Returns the join handle
/// so the caller can supervise (production main keeps it alive
/// for the duration of the process; tests use `run_once`).
pub fn spawn_watchdog(
    registry: TunnelRegistry,
    pool: DbPool,
    cfg: IacsTunnelConfig,
) -> tokio::task::JoinHandle<()> {
    spawn_watchdog_with_proxy_iacs(registry, pool, cfg, None)
}

/// Same as [`spawn_watchdog`] but also forwards revocation-driven
/// terminations to `vauban-proxy-iacs` over IPC.
///
/// Lot 5: when the production proxy-iacs IPC is wired, the in-process
/// `TunnelRegistry` is empty (the russh sshd lives in proxy-iacs); the
/// revocation watchdog therefore needs a separate channel to force-
/// close a live tunnel. We use the new `IacsTunnelTerminate` IPC verb
/// for that, fire-and-forget. proxy-iacs emits a matching
/// `IacsTunnelClosed` notification when the relay actually ends, which
/// vauban-web handles in [`crate::ipc::proxy_iacs`].
pub fn spawn_watchdog_with_proxy_iacs(
    registry: TunnelRegistry,
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
                run_once_with_proxy(&registry, &pool, &cfg, proxy_iacs.as_ref()).await;
            if closed > 0 || transitions > 0 {
                tracing::debug!(closed, transitions, "iacs_tunnel watchdog: tick complete");
            }
        }
    })
}

/// Same as [`run_once`] but also relays revocation events to
/// proxy-iacs over IPC when the optional client is provided. The
/// SQL is replicated rather than threaded through `run_once` to
/// keep the public test surface (`run_once`) backwards-compatible.
pub async fn run_once_with_proxy(
    registry: &TunnelRegistry,
    pool: &DbPool,
    cfg: &IacsTunnelConfig,
    proxy_iacs: Option<&Arc<ProxyIacsClient>>,
) -> (usize, usize) {
    // The in-process `TunnelRegistry` is the legacy authority. When
    // `proxy_iacs` is `Some`, we additionally pull every
    // `tunnel_active` row from the DB and relay the IPC kill --
    // proxy-iacs holds the canonical live state and only it can
    // actually close the russh channel.
    let (closed, transitions) = run_once(registry, pool, cfg).await;

    if let Some(client) = proxy_iacs {
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(_) => return (closed, transitions),
        };
        use crate::schema::{ews, proxy_sessions, users};
        // Same predicate as run_once but operates on rows that are
        // STILL `tunnel_active` (the in-process flow already flipped
        // them; the proxy-iacs flow has not).
        let to_kill: Vec<(Uuid, String)> = proxy_sessions::table
            .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
            .left_join(ews::table.on(ews::uuid.nullable().eq(proxy_sessions::ews_uuid)))
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(proxy_sessions::status.eq("tunnel_active"))
            .filter(
                users::is_active
                    .eq(false)
                    .or(ews::disabled_at.is_not_null())
                    .or(ews::offboarded_at.is_not_null()),
            )
            .select((proxy_sessions::uuid, proxy_sessions::status))
            .load::<(Uuid, String)>(&mut conn)
            .await
            .unwrap_or_default();
        for (sess_uuid, _) in to_kill {
            if let Err(e) = client.terminate_tunnel(&sess_uuid.to_string(), "revoked") {
                tracing::warn!(
                    session_uuid = %sess_uuid,
                    error = %e,
                    "iacs_tunnel watchdog: IacsTunnelTerminate IPC send failed"
                );
            } else {
                tracing::info!(
                    session_uuid = %sess_uuid,
                    "iacs_tunnel watchdog: terminate IPC dispatched to proxy-iacs"
                );
            }
        }
    }

    (closed, transitions)
}
