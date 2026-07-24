//! Web-side adapters for the evidence hydrator traits.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tokio::io::AsyncReadExt;
use tracing::debug;
use uuid::Uuid;
use vauban_web_evidence::hydrator::{
    self, FORMAT_FMP4_FLAT, HydratorDb, IntegrityBundle, MetaFd, MetaFdOutcome, MetaOpen, Notify,
    PendingCandidate, RECORDING_HYDRATED_RETRY_SECS, SessionKind, recording_hydrated_json_payload,
};

use crate::db::DbPool;
use crate::ipc::SupervisorClient;
use crate::models::session::SessionType;
use crate::services::broadcast::{BroadcastService, WsChannel, WsMessage};

pub fn session_kind_from_session_type(session_type: SessionType) -> SessionKind {
    match session_type {
        SessionType::Ssh => SessionKind::Ssh,
        SessionType::Rdp => SessionKind::Rdp,
        SessionType::IacsTunnel => SessionKind::Iacs,
    }
}

pub struct DieselHydratorDb {
    pool: DbPool,
}

impl DieselHydratorDb {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HydratorDb for DieselHydratorDb {
    async fn load_pending_candidates(
        &self,
        batch_size: i64,
    ) -> Result<Vec<PendingCandidate>, String> {
        use crate::schema::proxy_sessions::dsl;

        let mut conn = self.pool.get().await.map_err(|e| format!("pool: {e}"))?;
        type CandidateRow = (
            i32,
            Uuid,
            SessionType,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        );
        let rows: Vec<CandidateRow> = dsl::proxy_sessions
            .filter(dsl::is_recorded.eq(true))
            .filter(dsl::recording_path.is_not_null())
            .filter(dsl::recording_finalized_at.is_null())
            .order(dsl::created_at.asc())
            .limit(batch_size)
            .select((
                dsl::id,
                dsl::uuid,
                dsl::session_type,
                dsl::recording_path,
                dsl::disconnected_at,
                dsl::created_at,
            ))
            .load(&mut conn)
            .await
            .map_err(|e| format!("select: {e}"))?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(id, uuid, session_type, recording_path, disconnected_at, created_at)| {
                    Some(PendingCandidate {
                        id,
                        uuid,
                        session_kind: session_kind_from_session_type(session_type),
                        recording_path: recording_path?,
                        disconnected_at,
                        created_at,
                    })
                },
            )
            .collect())
    }

    async fn load_pending_by_id(
        &self,
        session_id: i32,
    ) -> Result<Option<PendingCandidate>, String> {
        use crate::schema::proxy_sessions::dsl;

        let mut conn = self.pool.get().await.map_err(|e| format!("pool: {e}"))?;
        type CandidateRow = (
            i32,
            Uuid,
            SessionType,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        );
        let row: Option<CandidateRow> = dsl::proxy_sessions
            .filter(dsl::id.eq(session_id))
            .filter(dsl::is_recorded.eq(true))
            .filter(dsl::recording_path.is_not_null())
            .filter(dsl::recording_finalized_at.is_null())
            .select((
                dsl::id,
                dsl::uuid,
                dsl::session_type,
                dsl::recording_path,
                dsl::disconnected_at,
                dsl::created_at,
            ))
            .first(&mut conn)
            .await
            .optional()
            .map_err(|e| format!("select by id: {e}"))?;

        Ok(row.and_then(
            |(id, uuid, session_type, recording_path, disconnected_at, created_at)| {
                Some(PendingCandidate {
                    id,
                    uuid,
                    session_kind: session_kind_from_session_type(session_type),
                    recording_path: recording_path?,
                    disconnected_at,
                    created_at,
                })
            },
        ))
    }

    async fn persist_bundle(
        &self,
        session_id: i32,
        bundle: &IntegrityBundle,
    ) -> Result<(), String> {
        use crate::schema::proxy_sessions::dsl;
        let mut conn = self.pool.get().await.map_err(|e| format!("pool: {e}"))?;
        let now: DateTime<Utc> = Utc::now();
        let updated = diesel::update(
            dsl::proxy_sessions
                .filter(dsl::id.eq(session_id))
                .filter(dsl::recording_finalized_at.is_null()),
        )
        .set((
            dsl::recording_blake3.eq(&bundle.blake3_hex),
            dsl::recording_size_bytes.eq(bundle.size_bytes),
            dsl::recording_duration_ms.eq(bundle.duration_ms),
            dsl::recording_event_count.eq(bundle.event_count),
            dsl::recording_format.eq(&bundle.format),
            dsl::recording_width.eq(bundle.width),
            dsl::recording_height.eq(bundle.height),
            dsl::recording_segment_count.eq(bundle.segment_count),
            dsl::recording_codec.eq(bundle.codec.as_deref()),
            dsl::recording_finalized_at.eq(now),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| format!("update: {e}"))?;
        if updated == 0 {
            debug!(session_id, "hydrator: row already finalized concurrently");
        }
        Ok(())
    }

    async fn mark_finalized_corrupt(&self, session_id: i32) -> Result<(), String> {
        use crate::schema::proxy_sessions::dsl;
        let mut conn = self.pool.get().await.map_err(|e| format!("pool: {e}"))?;
        let now: DateTime<Utc> = Utc::now();
        diesel::update(
            dsl::proxy_sessions
                .filter(dsl::id.eq(session_id))
                .filter(dsl::recording_finalized_at.is_null()),
        )
        .set((dsl::recording_finalized_at.eq(now),))
        .execute(&mut conn)
        .await
        .map_err(|e| format!("update: {e}"))?;
        Ok(())
    }

    async fn mark_finalized_legacy_flat(&self, session_id: i32) -> Result<(), String> {
        use crate::schema::proxy_sessions::dsl;
        let mut conn = self.pool.get().await.map_err(|e| format!("pool: {e}"))?;
        let now: DateTime<Utc> = Utc::now();
        diesel::update(
            dsl::proxy_sessions
                .filter(dsl::id.eq(session_id))
                .filter(dsl::recording_finalized_at.is_null()),
        )
        .set((
            dsl::recording_format.eq(FORMAT_FMP4_FLAT),
            dsl::recording_finalized_at.eq(now),
        ))
        .execute(&mut conn)
        .await
        .map_err(|e| format!("update: {e}"))?;
        Ok(())
    }
}

pub struct SupervisorMetaFd {
    supervisor: Arc<SupervisorClient>,
}

impl SupervisorMetaFd {
    pub fn new(supervisor: Arc<SupervisorClient>) -> Self {
        Self { supervisor }
    }
}

#[async_trait]
impl MetaFd for SupervisorMetaFd {
    async fn read_meta(
        &self,
        session_uuid: &Uuid,
        meta_relative: &str,
    ) -> Result<MetaFdOutcome, String> {
        let result = self
            .supervisor
            .request_recording_file(&session_uuid.to_string(), meta_relative)
            .await
            .map_err(|e| format!("supervisor: {e}"))?;

        if !result.success {
            return Ok(MetaFdOutcome::Missing);
        }

        let std_file = match result.file {
            Some(f) => f,
            None => return Ok(MetaFdOutcome::Missing),
        };

        let mut tokio_file = tokio::fs::File::from_std(std_file);
        let mut buf = String::new();
        tokio_file
            .read_to_string(&mut buf)
            .await
            .map_err(|e| format!("read meta.json: {e}"))?;
        Ok(MetaFdOutcome::Found(MetaOpen { json: buf }))
    }
}

pub struct BroadcastNotify {
    broadcast: BroadcastService,
}

impl BroadcastNotify {
    pub fn new(broadcast: BroadcastService) -> Self {
        Self { broadcast }
    }
}

#[async_trait]
impl Notify for BroadcastNotify {
    async fn recording_hydrated(&self, session_uuid: &Uuid) {
        let payload = recording_hydrated_json_payload(session_uuid);
        match self
            .broadcast
            .send(
                &WsChannel::Notifications,
                WsMessage::new("jit-notification", payload.clone()),
            )
            .await
        {
            Ok(0) => {
                debug!(
                    session_uuid = %session_uuid,
                    "hydrator: WS notify had zero receivers; will retry"
                );
            }
            Ok(_) => {}
            Err(()) => {
                debug!(
                    session_uuid = %session_uuid,
                    "hydrator: WS notify failed (channel absent); will retry"
                );
            }
        }

        let b_retry = self.broadcast.clone();
        let uuid = *session_uuid;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(RECORDING_HYDRATED_RETRY_SECS)).await;
            if let Err(()) = b_retry
                .send(
                    &WsChannel::Notifications,
                    WsMessage::new("jit-notification", payload),
                )
                .await
            {
                debug!(
                    session_uuid = %uuid,
                    "hydrator: WS notify retry failed (still no subscriber); ignoring"
                );
            }
        });
    }
}

pub type WebRecordingHydrator =
    hydrator::RecordingHydrator<DieselHydratorDb, SupervisorMetaFd, BroadcastNotify>;

pub fn build_recording_hydrator(
    pool: DbPool,
    supervisor: Arc<SupervisorClient>,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    broadcast: Option<BroadcastService>,
) -> WebRecordingHydrator {
    hydrator::RecordingHydrator::new(
        DieselHydratorDb::new(pool),
        SupervisorMetaFd::new(supervisor),
        batch_size,
        storage_base,
        missing_meta_grace,
        broadcast.map(|b| Arc::new(BroadcastNotify::new(b))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use vauban_web_evidence::hydrator::recording_detail_ws_filter_matches;

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

    #[tokio::test]
    async fn broadcast_notify_emits_on_notifications_channel() {
        let svc = BroadcastService::new();
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;
        let uuid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        BroadcastNotify::new(svc.clone())
            .recording_hydrated(&uuid)
            .await;
        let payload = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("WS message must arrive within 200ms")
            .expect("subscriber must not be closed");
        assert!(payload.contains(r#"id="jit-notification""#));
        assert!(payload.contains("hx-swap-oob"));
        assert!(payload.contains(r#""type":"recording_hydrated""#));
        assert!(payload.contains("11111111-2222-3333-4444-555555555555"));
    }

    #[tokio::test]
    async fn broadcast_notify_retries_for_late_subscribers() {
        let svc = BroadcastService::new();
        let uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        BroadcastNotify::new(svc.clone())
            .recording_hydrated(&uuid)
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;

        let payload = tokio::time::timeout(
            Duration::from_secs(RECORDING_HYDRATED_RETRY_SECS + 1),
            rx.recv(),
        )
        .await
        .expect("late subscriber must receive the retry push")
        .expect("subscriber must not be closed");
        assert!(recording_detail_ws_filter_matches(&payload, &uuid));
    }

    #[tokio::test]
    async fn battle_live_subscriber_receives_immediate_and_retry() {
        let svc = BroadcastService::new();
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;
        let uuid = Uuid::new_v4();
        BroadcastNotify::new(svc.clone())
            .recording_hydrated(&uuid)
            .await;

        let first = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("immediate push")
            .expect("open");
        assert!(recording_detail_ws_filter_matches(&first, &uuid));

        let second = tokio::time::timeout(
            Duration::from_secs(RECORDING_HYDRATED_RETRY_SECS + 1),
            rx.recv(),
        )
        .await
        .expect("retry push")
        .expect("open");
        assert!(recording_detail_ws_filter_matches(&second, &uuid));
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn battle_concurrent_subscribers_all_see_hydration() {
        let svc = BroadcastService::new();
        let mut rxs = Vec::new();
        for _ in 0..8 {
            rxs.push(svc.subscribe(&WsChannel::Notifications).await);
        }
        let uuid = Uuid::new_v4();
        BroadcastNotify::new(svc).recording_hydrated(&uuid).await;

        for (i, rx) in rxs.iter_mut().enumerate() {
            let payload = tokio::time::timeout(Duration::from_millis(300), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("subscriber {i} missed immediate push"))
                .expect("open");
            assert!(
                recording_detail_ws_filter_matches(&payload, &uuid),
                "subscriber {i} payload must match detail filter"
            );
        }
    }

    #[tokio::test]
    async fn broadcast_notify_payload_carries_no_pii() {
        let svc = BroadcastService::new();
        let mut rx = svc.subscribe(&WsChannel::Notifications).await;
        let uuid = Uuid::nil();
        BroadcastNotify::new(svc.clone())
            .recording_hydrated(&uuid)
            .await;
        let payload = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        for key in &[
            "username",
            "user_id",
            "email",
            "asset_name",
            "hostname",
            "ip",
            "address",
            "credential",
        ] {
            assert!(
                !payload.contains(key),
                "WS hydration payload must not carry `{key}`"
            );
        }
    }

    #[test]
    fn broadcast_notify_schedules_late_subscriber_retry() {
        let body = fn_body(
            include_str!("adapters.rs"),
            "async fn recording_hydrated(&self, session_uuid: &Uuid)",
        );
        assert!(body.contains("RECORDING_HYDRATED_RETRY_SECS"));
        assert!(body.contains("tokio::spawn"));
        assert!(body.contains("recording_hydrated_json_payload"));
    }

    #[test]
    fn broadcast_notify_uses_stable_wire_contract() {
        let body = fn_body(
            include_str!("adapters.rs"),
            "async fn recording_hydrated(&self, session_uuid: &Uuid)",
        );
        assert!(body.contains("WsChannel::Notifications"));
        assert!(body.contains(r#""jit-notification""#));
        assert!(body.contains("recording_hydrated_json_payload"));
    }
}
