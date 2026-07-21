//! IACS boot resync: proxy snapshot is the authority for "alive".
//!
//! After a web-only restart, `proxy_sessions` rows may be stale
//! (`terminated`) while tunnels still live in `vauban-proxy-iacs`, or
//! live in the DB while the proxy was restarted empty. Boot asks the
//! proxy for [`shared::messages::IacsTunnelSnapshotResponse`], then
//! applies a pure plan ([`reconcile_iacs_boot`]) that:
//!
//! - **Rehydrates** DB rows that match a proxy entry (including
//!   previously terminated rows);
//! - **Terminates** DB-live rows missing from the proxy;
//! - **Terminates** proxy tunnels whose UUID has no DB row
//!   (fail-closed orphan).

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::{
    IACS_SNAPSHOT_PHASE_EWS_CONNECTED, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
    IACS_SNAPSHOT_PHASE_WAITING_CLIENT, IacsTunnelSnapshotEntry,
};
use uuid::Uuid;

use crate::db::DbPool;
use crate::ipc::ProxyIacsClient;

/// One action produced by [`reconcile_iacs_boot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootAction {
    Rehydrate {
        session_id: Uuid,
        phase: u8,
        peer_ip: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
    },
    TerminateDb {
        session_id: Uuid,
    },
    TerminateProxy {
        session_id: Uuid,
    },
}

/// Minimal DB row view for the pure reconcile function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbLiveRow {
    pub session_id: Uuid,
    /// Any status; live detection uses [`is_live_status`].
    pub status: String,
}

/// Counters returned by [`apply_boot_reconcile_plan`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootReconcileStats {
    pub rehydrated: usize,
    pub terminated_db: usize,
    pub terminated_proxy: usize,
}

/// Map a frozen snapshot phase to the `proxy_sessions.status` string.
pub fn phase_to_status(phase: u8) -> &'static str {
    match phase {
        IACS_SNAPSHOT_PHASE_WAITING_CLIENT => "waiting_client",
        IACS_SNAPSHOT_PHASE_EWS_CONNECTED => "ews_connected",
        IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE => "tunnel_active",
        // Unknown phases collapse to waiting_client (fail-safe
        // lower bound); the proxy only emits 0/1/2.
        _ => "waiting_client",
    }
}

pub fn is_live_status(status: &str) -> bool {
    matches!(status, "waiting_client" | "ews_connected" | "tunnel_active")
}

/// Pure: proxy is authority for "alive".
///
/// Idempotence: when a DB row already matches the proxy phase status
/// and is live, no `Rehydrate` is emitted for that UUID. Re-applying
/// a plan after the DB has been synced therefore yields an empty
/// plan (given the same proxy snapshot).
pub fn reconcile_iacs_boot(
    db_rows: &[DbLiveRow],
    proxy_entries: &[IacsTunnelSnapshotEntry],
) -> Vec<BootAction> {
    let mut db_by_id: HashMap<Uuid, &DbLiveRow> = HashMap::new();
    for row in db_rows {
        db_by_id.insert(row.session_id, row);
    }

    let mut proxy_ids: HashSet<Uuid> = HashSet::new();
    let mut actions = Vec::new();

    for entry in proxy_entries {
        let Ok(session_id) = Uuid::parse_str(&entry.session_id) else {
            continue;
        };
        proxy_ids.insert(session_id);
        match db_by_id.get(&session_id) {
            None => actions.push(BootAction::TerminateProxy { session_id }),
            Some(row) => {
                let target = phase_to_status(entry.phase);
                let needs_rehydrate = !is_live_status(&row.status) || row.status != target;
                if needs_rehydrate {
                    actions.push(BootAction::Rehydrate {
                        session_id,
                        phase: entry.phase,
                        peer_ip: entry.peer_ip.clone(),
                        bytes_in: entry.bytes_in,
                        bytes_out: entry.bytes_out,
                    });
                }
            }
        }
    }

    for row in db_rows {
        if is_live_status(&row.status) && !proxy_ids.contains(&row.session_id) {
            actions.push(BootAction::TerminateDb {
                session_id: row.session_id,
            });
        }
    }

    actions
}

/// Load IACS rows needed for boot reconcile: every live status, plus
/// any `terminated`/`expired` UUID present in the proxy snapshot
/// (so a terminated row can be rehydrated).
pub async fn load_iacs_rows_for_reconcile(
    pool: &DbPool,
    proxy_session_ids: &[Uuid],
) -> Result<Vec<DbLiveRow>, String> {
    use crate::schema::proxy_sessions;

    let mut conn = pool.get().await.map_err(|e| e.to_string())?;

    let live: Vec<(Uuid, String)> = proxy_sessions::table
        .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
        .filter(proxy_sessions::status.eq_any([
            "waiting_client",
            "ews_connected",
            "tunnel_active",
        ]))
        .select((proxy_sessions::uuid, proxy_sessions::status))
        .load::<(Uuid, String)>(&mut conn)
        .await
        .map_err(|e| e.to_string())?;

    let mut rows: Vec<DbLiveRow> = live
        .into_iter()
        .map(|(session_id, status)| DbLiveRow { session_id, status })
        .collect();

    let live_ids: HashSet<Uuid> = rows.iter().map(|r| r.session_id).collect();
    let need_lookup: Vec<Uuid> = proxy_session_ids
        .iter()
        .copied()
        .filter(|id| !live_ids.contains(id))
        .collect();

    if !need_lookup.is_empty() {
        let extra: Vec<(Uuid, String)> = proxy_sessions::table
            .filter(proxy_sessions::session_type.eq("iacs_tunnel"))
            .filter(proxy_sessions::uuid.eq_any(&need_lookup))
            .select((proxy_sessions::uuid, proxy_sessions::status))
            .load::<(Uuid, String)>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        for (session_id, status) in extra {
            rows.push(DbLiveRow { session_id, status });
        }
    }

    Ok(rows)
}

/// Apply a reconcile plan to the DB and (for orphans) the proxy.
///
/// `proxy_iacs` may be `None` when the plan contains only DB actions
/// (tests). `TerminateProxy` entries are skipped (and counted as
/// failures via warn) when no client is wired.
pub async fn apply_boot_reconcile_plan(
    pool: &DbPool,
    proxy_iacs: Option<&ProxyIacsClient>,
    plan: &[BootAction],
) -> Result<BootReconcileStats, String> {
    use crate::schema::proxy_sessions;

    let mut stats = BootReconcileStats::default();
    let mut conn = pool.get().await.map_err(|e| e.to_string())?;
    let now = Utc::now();

    for action in plan {
        match action {
            BootAction::Rehydrate {
                session_id,
                phase,
                peer_ip,
                bytes_in,
                bytes_out,
            } => {
                let status = phase_to_status(*phase);
                let parsed_peer = peer_ip
                    .as_deref()
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok());

                let updated = match parsed_peer {
                    Some(ip) => diesel::update(
                        proxy_sessions::table.filter(proxy_sessions::uuid.eq(*session_id)),
                    )
                    .set((
                        proxy_sessions::status.eq(status),
                        proxy_sessions::disconnected_at
                            .eq(None::<chrono::DateTime<chrono::Utc>>),
                        proxy_sessions::client_ip.eq(ipnetwork::IpNetwork::from(ip)),
                        proxy_sessions::bytes_received.eq(*bytes_in as i64),
                        proxy_sessions::bytes_sent.eq(*bytes_out as i64),
                        proxy_sessions::updated_at.eq(now),
                    ))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?,
                    None => diesel::update(
                        proxy_sessions::table.filter(proxy_sessions::uuid.eq(*session_id)),
                    )
                    .set((
                        proxy_sessions::status.eq(status),
                        proxy_sessions::disconnected_at
                            .eq(None::<chrono::DateTime<chrono::Utc>>),
                        proxy_sessions::bytes_received.eq(*bytes_in as i64),
                        proxy_sessions::bytes_sent.eq(*bytes_out as i64),
                        proxy_sessions::updated_at.eq(now),
                    ))
                    .execute(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?,
                };
                if updated > 0 {
                    stats.rehydrated += 1;
                }
            }
            BootAction::TerminateDb { session_id } => {
                let updated = diesel::update(
                    proxy_sessions::table
                        .filter(proxy_sessions::uuid.eq(*session_id))
                        .filter(proxy_sessions::status.eq_any([
                            "waiting_client",
                            "ews_connected",
                            "tunnel_active",
                        ])),
                )
                .set((
                    proxy_sessions::status.eq("terminated"),
                    proxy_sessions::disconnected_at.eq(Some(now)),
                    proxy_sessions::updated_at.eq(now),
                ))
                .execute(&mut conn)
                .await
                .map_err(|e| e.to_string())?;
                if updated > 0 {
                    stats.terminated_db += 1;
                }
            }
            BootAction::TerminateProxy { session_id } => {
                let Some(client) = proxy_iacs else {
                    tracing::warn!(
                        session_id = %session_id,
                        "iacs_tunnel: boot TerminateProxy skipped (no proxy client)"
                    );
                    continue;
                };
                match client.terminate_tunnel(&session_id.to_string(), "boot_orphan") {
                    Ok(()) => stats.terminated_proxy += 1,
                    Err(e) => {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %e,
                            "iacs_tunnel: boot TerminateProxy IPC failed"
                        );
                    }
                }
            }
        }
    }

    Ok(stats)
}

/// Full boot path: snapshot from proxy, plan, apply.
///
/// On snapshot timeout/error: log and treat entries as empty
/// (fail-closed -- terminate every live DB row).
pub async fn reconcile_iacs_from_proxy_snapshot(
    pool: &DbPool,
    proxy: &ProxyIacsClient,
) -> Result<BootReconcileStats, String> {
    let entries = match proxy.snapshot_tunnels().await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(
                error = %e,
                "iacs_tunnel: boot snapshot failed — fail-closed empty snapshot \
                 (live DB rows will be terminated)"
            );
            Vec::new()
        }
    };

    let proxy_ids: Vec<Uuid> = entries
        .iter()
        .filter_map(|e| Uuid::parse_str(&e.session_id).ok())
        .collect();

    let db_rows = load_iacs_rows_for_reconcile(pool, &proxy_ids).await?;
    let plan = reconcile_iacs_boot(&db_rows, &entries);
    apply_boot_reconcile_plan(pool, Some(proxy), &plan).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE;

    fn entry(id: Uuid, phase: u8) -> IacsTunnelSnapshotEntry {
        IacsTunnelSnapshotEntry {
            session_id: id.to_string(),
            phase,
            peer_ip: None,
            bytes_in: 0,
            bytes_out: 0,
            user_uuid: Uuid::new_v4().to_string(),
            asset_uuid: Uuid::new_v4().to_string(),
            ews_uuid: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn reconcile_terminates_db_live_missing_from_proxy() {
        let id = Uuid::new_v4();
        let plan = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "tunnel_active".into(),
            }],
            &[],
        );
        assert_eq!(plan, vec![BootAction::TerminateDb { session_id: id }]);
    }

    #[test]
    fn reconcile_terminates_proxy_unknown_to_db() {
        let id = Uuid::new_v4();
        let plan = reconcile_iacs_boot(&[], &[entry(id, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE)]);
        assert_eq!(plan, vec![BootAction::TerminateProxy { session_id: id }]);
    }

    #[test]
    fn reconcile_rehydrates_terminated_row() {
        let id = Uuid::new_v4();
        let plan = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "terminated".into(),
            }],
            &[entry(id, IACS_SNAPSHOT_PHASE_EWS_CONNECTED)],
        );
        assert_eq!(
            plan,
            vec![BootAction::Rehydrate {
                session_id: id,
                phase: IACS_SNAPSHOT_PHASE_EWS_CONNECTED,
                peer_ip: None,
                bytes_in: 0,
                bytes_out: 0,
            }]
        );
    }

    #[test]
    fn reconcile_skips_already_matching_live() {
        let id = Uuid::new_v4();
        let plan = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "tunnel_active".into(),
            }],
            &[entry(id, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE)],
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn reconcile_applies_proxy_phase_even_if_lower() {
        // Proxy authority: if proxy says waiting_client while DB says
        // tunnel_active, still rehydrate to waiting_client.
        let id = Uuid::new_v4();
        let plan = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "tunnel_active".into(),
            }],
            &[entry(id, IACS_SNAPSHOT_PHASE_WAITING_CLIENT)],
        );
        assert_eq!(
            plan,
            vec![BootAction::Rehydrate {
                session_id: id,
                phase: IACS_SNAPSHOT_PHASE_WAITING_CLIENT,
                peer_ip: None,
                bytes_in: 0,
                bytes_out: 0,
            }]
        );
    }

    #[test]
    fn reconcile_idempotent_after_sync() {
        let id = Uuid::new_v4();
        let proxy = vec![entry(id, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE)];
        let plan1 = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "terminated".into(),
            }],
            &proxy,
        );
        assert_eq!(plan1.len(), 1);
        // After rehydrate the DB matches; recomputing yields empty.
        let plan2 = reconcile_iacs_boot(
            &[DbLiveRow {
                session_id: id,
                status: "tunnel_active".into(),
            }],
            &proxy,
        );
        assert!(plan2.is_empty());
    }

    #[test]
    fn phase_to_status_frozen_mapping() {
        assert_eq!(phase_to_status(0), "waiting_client");
        assert_eq!(phase_to_status(1), "ews_connected");
        assert_eq!(phase_to_status(2), "tunnel_active");
    }
}
