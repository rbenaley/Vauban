//! Trait seams for the recording integrity hydrator (no Diesel / IPC / broadcast).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::pipeline::IntegrityBundle;

/// Session kind for meta.json parsing (orthogonal to web `SessionType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Ssh,
    Rdp,
    Iacs,
}

/// Row selected for hydration (`recording_finalized_at IS NULL`).
#[derive(Debug, Clone)]
pub struct PendingCandidate {
    pub id: i32,
    pub uuid: Uuid,
    pub session_kind: SessionKind,
    pub recording_path: String,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Contents of a successfully opened `meta.json`.
#[derive(Debug, Clone)]
pub struct MetaOpen {
    pub json: String,
}

/// Outcome of a supervisor FD read for `meta.json`.
#[derive(Debug, Clone)]
pub enum MetaFdOutcome {
    Found(MetaOpen),
    Missing,
}

#[async_trait]
pub trait HydratorDb: Send + Sync {
    async fn load_pending_candidates(
        &self,
        batch_size: i64,
    ) -> Result<Vec<PendingCandidate>, String>;
    async fn load_pending_by_id(&self, session_id: i32)
    -> Result<Option<PendingCandidate>, String>;
    async fn persist_bundle(&self, session_id: i32, bundle: &IntegrityBundle)
    -> Result<(), String>;
    async fn mark_finalized_corrupt(&self, session_id: i32) -> Result<(), String>;
    async fn mark_finalized_legacy_flat(&self, session_id: i32) -> Result<(), String>;
}

#[async_trait]
pub trait MetaFd: Send + Sync {
    async fn read_meta(
        &self,
        session_uuid: &Uuid,
        meta_relative: &str,
    ) -> Result<MetaFdOutcome, String>;
}

#[async_trait]
pub trait Notify: Send + Sync {
    async fn recording_hydrated(&self, session_uuid: &Uuid);
}
