//! Property tests for IACS boot reconcile (`reconcile_iacs_boot`).
//!
//! Proxy is the authority for "alive". The pure planner must:
//! - terminate DB-live UUIDs missing from the proxy;
//! - terminate proxy UUIDs with no DB row;
//! - rehydrate when status differs or the row is not live;
//! - emit nothing when already in sync (idempotence).

use proptest::prelude::*;
use shared::messages::{
    IACS_SNAPSHOT_PHASE_EWS_CONNECTED, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
    IACS_SNAPSHOT_PHASE_WAITING_CLIENT, IacsTunnelSnapshotEntry,
};
use uuid::Uuid;
use vauban_web::services::iacs_tunnel::{
    BootAction, DbLiveRow, is_iacs_open, phase_to_status, reconcile_iacs_boot,
};

#[derive(Debug, Clone)]
struct Case {
    db: Vec<DbLiveRow>,
    proxy: Vec<IacsTunnelSnapshotEntry>,
}

fn status_strat() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("waiting_client".to_string()),
        Just("ews_connected".to_string()),
        Just("tunnel_active".to_string()),
        Just("terminated".to_string()),
        Just("expired".to_string()),
    ]
}

fn phase_strat() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(IACS_SNAPSHOT_PHASE_WAITING_CLIENT),
        Just(IACS_SNAPSHOT_PHASE_EWS_CONNECTED),
        Just(IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE),
    ]
}

fn entry(id: Uuid, phase: u8) -> IacsTunnelSnapshotEntry {
    IacsTunnelSnapshotEntry {
        session_id: id.to_string(),
        phase,
        peer_ip: None,
        bytes_in: 0,
        bytes_out: 0,
        user_uuid: Uuid::nil().to_string(),
        asset_uuid: Uuid::nil().to_string(),
        ews_uuid: Uuid::nil().to_string(),
    }
}

fn case_strat() -> impl Strategy<Value = Case> {
    // Up to 6 distinct UUIDs partitioned into db-only / proxy-only / both.
    prop::collection::vec(any::<u128>(), 0..=6).prop_flat_map(|seeds| {
        let ids: Vec<Uuid> = seeds.into_iter().map(Uuid::from_u128).collect();
        let n = ids.len();
        (
            prop::collection::vec(status_strat(), n..=n),
            prop::collection::vec(phase_strat(), n..=n),
            prop::collection::vec(any::<bool>(), n..=n), // in_db
            prop::collection::vec(any::<bool>(), n..=n), // in_proxy
        )
            .prop_map(move |(statuses, phases, in_db, in_proxy)| {
                let mut db = Vec::new();
                let mut proxy = Vec::new();
                for i in 0..n {
                    if in_db[i] {
                        db.push(DbLiveRow {
                            session_id: ids[i],
                            status: statuses[i].clone(),
                        });
                    }
                    if in_proxy[i] {
                        proxy.push(entry(ids[i], phases[i]));
                    }
                }
                Case { db, proxy }
            })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn terminate_db_iff_live_and_absent_from_proxy(case in case_strat()) {
        let plan = reconcile_iacs_boot(&case.db, &case.proxy);
        let proxy_ids: std::collections::HashSet<Uuid> = case
            .proxy
            .iter()
            .filter_map(|e| Uuid::parse_str(&e.session_id).ok())
            .collect();
        for row in &case.db {
            let should = is_iacs_open(&row.status) && !proxy_ids.contains(&row.session_id);
            let has = plan.iter().any(|a| {
                matches!(a, BootAction::TerminateDb { session_id } if *session_id == row.session_id)
            });
            prop_assert_eq!(has, should, "TerminateDb mismatch for {}", row.session_id);
        }
    }

    #[test]
    fn terminate_proxy_iff_no_db_row(case in case_strat()) {
        let plan = reconcile_iacs_boot(&case.db, &case.proxy);
        let db_ids: std::collections::HashSet<Uuid> =
            case.db.iter().map(|r| r.session_id).collect();
        for e in &case.proxy {
            let Ok(id) = Uuid::parse_str(&e.session_id) else {
                continue;
            };
            let should = !db_ids.contains(&id);
            let has = plan.iter().any(|a| {
                matches!(a, BootAction::TerminateProxy { session_id } if *session_id == id)
            });
            prop_assert_eq!(has, should, "TerminateProxy mismatch for {}", id);
        }
    }

    #[test]
    fn rehydrate_iff_row_exists_and_status_differs(case in case_strat()) {
        let plan = reconcile_iacs_boot(&case.db, &case.proxy);
        let db_by: std::collections::HashMap<Uuid, &DbLiveRow> =
            case.db.iter().map(|r| (r.session_id, r)).collect();
        for e in &case.proxy {
            let Ok(id) = Uuid::parse_str(&e.session_id) else {
                continue;
            };
            let Some(row) = db_by.get(&id) else {
                prop_assert!(
                    !plan.iter().any(|a| {
                        matches!(a, BootAction::Rehydrate { session_id, .. } if *session_id == id)
                    }),
                    "no Rehydrate without DB row"
                );
                continue;
            };
            let target = phase_to_status(e.phase);
            let should = !is_iacs_open(&row.status) || row.status != target;
            let has = plan.iter().any(|a| {
                matches!(a, BootAction::Rehydrate { session_id, .. } if *session_id == id)
            });
            prop_assert_eq!(has, should, "Rehydrate mismatch for {}", id);
        }
    }

    #[test]
    fn idempotent_when_already_synced(case in case_strat()) {
        // Build a synced DB view from the proxy snapshot + keep
        // non-proxy db rows as terminated (not live).
        let proxy_ids: std::collections::HashSet<Uuid> = case
            .proxy
            .iter()
            .filter_map(|e| Uuid::parse_str(&e.session_id).ok())
            .collect();
        let mut synced_db: Vec<DbLiveRow> = case
            .proxy
            .iter()
            .filter_map(|e| {
                let id = Uuid::parse_str(&e.session_id).ok()?;
                Some(DbLiveRow {
                    session_id: id,
                    status: phase_to_status(e.phase).to_string(),
                })
            })
            .collect();
        for row in &case.db {
            if !proxy_ids.contains(&row.session_id) {
                synced_db.push(DbLiveRow {
                    session_id: row.session_id,
                    status: "terminated".into(),
                });
            }
        }
        let plan = reconcile_iacs_boot(&synced_db, &case.proxy);
        prop_assert!(
            plan.is_empty(),
            "synced state must yield empty plan, got {plan:?}"
        );
    }

    #[test]
    fn never_emits_both_terminate_db_and_rehydrate_for_same_uuid(case in case_strat()) {
        let plan = reconcile_iacs_boot(&case.db, &case.proxy);
        let mut seen_rehydrate = std::collections::HashSet::new();
        let mut seen_term_db = std::collections::HashSet::new();
        for a in &plan {
            match a {
                BootAction::Rehydrate { session_id, .. } => {
                    seen_rehydrate.insert(*session_id);
                }
                BootAction::TerminateDb { session_id } => {
                    seen_term_db.insert(*session_id);
                }
                BootAction::TerminateProxy { .. } => {}
            }
        }
        for id in seen_rehydrate.intersection(&seen_term_db) {
            prop_assert!(
                false,
                "uuid {id} cannot be both Rehydrate and TerminateDb"
            );
        }
    }
}
