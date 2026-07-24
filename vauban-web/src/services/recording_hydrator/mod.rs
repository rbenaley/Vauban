//! Recording integrity hydrator — web orchestration + trait adapters.
//!
//! The pure pipeline lives in `vauban-web-evidence::hydrator`; this module
//! wires Diesel, supervisor FD passing, and WebSocket notifications.

mod adapters;

use std::sync::Arc;
use std::time::Duration;

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tokio::task::JoinHandle;
use tracing::{debug, error};
use vauban_web_evidence::hydrator::{self, HydratorDb};

pub use adapters::{
    BroadcastNotify, DieselHydratorDb, SupervisorMetaFd, WebRecordingHydrator,
    build_recording_hydrator, session_kind_from_session_type,
};
pub use hydrator::{
    FORMAT_ASCIICAST_V2, FORMAT_FMP4_DASH, FORMAT_FMP4_FLAT, FORMAT_PCAP_BUNDLE, HasSegmentHash,
    HydrationError, HydrationReport, IntegrityBundle, RECORDING_HYDRATED_EVENT,
    RECORDING_HYDRATED_RETRY_SECS, TASK_NAME, aggregate_rdp_blake3, is_valid_blake3_hex,
    meta_relative_for, recording_detail_ws_filter_matches, recording_dir_for_session,
    recording_hydrated_json_payload,
};

/// Concrete web hydrator (Diesel + supervisor + broadcast notify).
pub type RecordingHydrator = WebRecordingHydrator;

use crate::AppState;
use crate::models::session::SessionType;

pub fn parse_meta(session_type: SessionType, buf: &str) -> Result<IntegrityBundle, String> {
    hydrator::parse_meta(session_kind_from_session_type(session_type), buf)
}

pub async fn mark_finalized_corrupt(
    pool: &crate::db::DbPool,
    session_id: i32,
) -> Result<(), String> {
    DieselHydratorDb::new(pool.clone())
        .mark_finalized_corrupt(session_id)
        .await
}

pub async fn mark_finalized_legacy_flat(
    pool: &crate::db::DbPool,
    session_id: i32,
) -> Result<(), String> {
    DieselHydratorDb::new(pool.clone())
        .mark_finalized_legacy_flat(session_id)
        .await
}

pub fn enqueue_hydration_by_uuid(
    state: &AppState,
    session_uuid: ::uuid::Uuid,
    grace: Duration,
) -> JoinHandle<()> {
    let supervisor = match state.supervisor.as_ref() {
        Some(s) => Arc::clone(s),
        None => {
            debug!(
                session_uuid = %session_uuid,
                "hydration enqueue skipped: supervisor IPC unavailable (dev mode)"
            );
            return tokio::spawn(async {});
        }
    };
    if !state.config.recording.hydration_enabled {
        debug!(
            session_uuid = %session_uuid,
            "hydration enqueue skipped: recording.hydration_enabled = false"
        );
        return tokio::spawn(async {});
    }
    let pool = state.db_pool.clone();
    let storage_base = state.config.recording.storage_path.clone();
    let batch_size = state.config.recording.hydration_batch_size;
    let missing_meta_grace =
        Duration::from_secs(state.config.recording.hydration_missing_meta_grace_secs);
    let broadcast = state.broadcast.clone();
    debug!(
        session_uuid = %session_uuid,
        grace_secs = grace.as_secs(),
        "enqueue_hydration_by_uuid: scheduled"
    );
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        let id_result: Result<Option<i32>, String> = async {
            use crate::schema::proxy_sessions::dsl;
            let mut conn = pool.get().await.map_err(|e| format!("pool: {e}"))?;
            dsl::proxy_sessions
                .filter(dsl::uuid.eq(session_uuid))
                .select(dsl::id)
                .first::<i32>(&mut conn)
                .await
                .optional()
                .map_err(|e| format!("select id by uuid: {e}"))
        }
        .await;
        let id = match id_result {
            Ok(Some(i)) => i,
            Ok(None) => {
                debug!(session_uuid = %session_uuid, "enqueue_hydration_by_uuid: session not found, skipping");
                return;
            }
            Err(e) => {
                error!(session_uuid = %session_uuid, error = %e, "enqueue_hydration_by_uuid: lookup failed");
                return;
            }
        };
        let hydrator = build_recording_hydrator(
            pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            Some(broadcast),
        );
        match hydrator.hydrate_session_id(id).await {
            Ok(report) => {
                if report.scanned == 0 {
                    debug!(
                        session_uuid = %session_uuid,
                        "enqueue_hydration_by_uuid: nothing to do (already finalized or not recorded)"
                    );
                }
            }
            Err(e) => {
                error!(session_uuid = %session_uuid, error = %e, "enqueue_hydration_by_uuid: hydrate_session_id failed");
            }
        }
    })
}

pub fn enqueue_hydration(state: &AppState, session_id: i32, grace: Duration) -> JoinHandle<()> {
    let supervisor = match state.supervisor.as_ref() {
        Some(s) => Arc::clone(s),
        None => {
            debug!(
                session_id,
                "hydration enqueue skipped: supervisor IPC unavailable (dev mode)"
            );
            return tokio::spawn(async {});
        }
    };
    if !state.config.recording.hydration_enabled {
        debug!(
            session_id,
            "hydration enqueue skipped: recording.hydration_enabled = false"
        );
        return tokio::spawn(async {});
    }
    let pool = state.db_pool.clone();
    let storage_base = state.config.recording.storage_path.clone();
    let batch_size = state.config.recording.hydration_batch_size;
    let missing_meta_grace =
        Duration::from_secs(state.config.recording.hydration_missing_meta_grace_secs);
    let broadcast = state.broadcast.clone();
    debug!(
        session_id,
        grace_secs = grace.as_secs(),
        "enqueue_hydration: scheduled"
    );
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        let hydrator = build_recording_hydrator(
            pool,
            supervisor,
            batch_size,
            storage_base,
            missing_meta_grace,
            Some(broadcast),
        );
        match hydrator.hydrate_session_id(session_id).await {
            Ok(report) => {
                if report.scanned == 0 {
                    debug!(
                        session_id,
                        "enqueue_hydration: nothing to do (already finalized or not recorded)"
                    );
                }
            }
            Err(e) => {
                error!(session_id, error = %e, "enqueue_hydration: hydrate_session_id failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    fn fn_body(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("signature `{signature}` not found in source"));
        let tail = &source[start..];
        let open = tail
            .find('{')
            .unwrap_or_else(|| panic!("no `{{` after signature `{signature}`"));
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        tail[..end].to_string()
    }

    #[test]
    fn enqueue_hydration_passes_live_broadcast_to_constructor() {
        let src = include_str!("mod.rs");
        for sig in [
            "pub fn enqueue_hydration(",
            "pub fn enqueue_hydration_by_uuid(",
        ] {
            let body = fn_body(src, sig);
            assert!(
                body.contains("state.broadcast.clone()"),
                "{sig}: must clone state.broadcast before the spawn"
            );
            assert!(
                body.contains("Some(broadcast)"),
                "{sig}: must pass `Some(broadcast)` to build_recording_hydrator"
            );
        }
    }

    #[test]
    fn constructor_wires_broadcast_notify() {
        let src = include_str!("adapters.rs");
        assert!(
            src.contains("broadcast.map(|b| Arc::new(BroadcastNotify::new(b)))"),
            "build_recording_hydrator must wrap BroadcastService in BroadcastNotify"
        );
    }
}
