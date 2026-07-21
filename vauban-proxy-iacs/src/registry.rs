//! In-memory registry of live IACS tunnel sessions, owned by
//! `vauban-proxy-iacs`.
//!
//! Identical contract to the legacy in-process registry that used to
//! live inside `vauban-web::services::iacs_tunnel`, minus the Mutex-on-
//! `peer_addr` (the proxy task that opens the tunnel knows the peer
//! address from the russh `Server::new_client` callback at construction
//! time, so we no longer need a write-after-the-fact slot).
//!
//! Concurrency: `DashMap` provides per-shard locking; we never hold a
//! lock across an `await`. The handle's close signal flows through
//! `closed` (set exactly once) and `notify` (woken from any clone).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use shared::messages::{
    IACS_SNAPSHOT_PHASE_EWS_CONNECTED, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE,
    IACS_SNAPSHOT_PHASE_WAITING_CLIENT, IacsTunnelSnapshotEntry,
};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::auth::PendingSessions;

/// Reference-counted handle to a live IACS tunnel.
#[allow(dead_code)] // Several fields are surfaced via WS / audit in Lot 5
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    pub session_uuid: Uuid,
    pub user_uuid: Uuid,
    pub asset_uuid: Uuid,
    pub ews_uuid: Uuid,
    pub peer_addr: Option<std::net::SocketAddr>,
    pub bytes_in: Arc<AtomicU64>,
    pub bytes_out: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
    /// One-shot guard for [`Self::flush_into`]: the per-channel byte
    /// counters may be folded into the per-EWS-login totals exactly
    /// once, whether the relay teardown task or the handler `Drop`
    /// gets there first (July 2026: `Drop` used to read the totals
    /// BEFORE the teardown flush landed, so `IacsTunnelClosed`
    /// reported `(0, 0)` and the status page reset its counters to
    /// zero at disconnect).
    flushed: Arc<AtomicBool>,
}

impl TunnelHandle {
    pub fn new(
        session_uuid: Uuid,
        user_uuid: Uuid,
        asset_uuid: Uuid,
        ews_uuid: Uuid,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            session_uuid,
            user_uuid,
            asset_uuid,
            ews_uuid,
            peer_addr,
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            flushed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Idempotent. Marks the tunnel for shutdown and wakes every
    /// task waiting on `wait_close`.
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn wait_close(&self) {
        let notified = self.notify.notified();
        if self.is_closed() {
            return;
        }
        notified.await;
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
        )
    }

    /// Fold this channel's byte counters into the per-EWS-login
    /// totals, EXACTLY ONCE (idempotent across callers).
    ///
    /// Two racers may attempt the flush: the relay teardown task
    /// (after `tokio::join!` on both copy directions) and the
    /// handler `Drop` (when the EWS SSH connection dies while the
    /// teardown is still in flight). Whoever swaps the guard first
    /// performs the `fetch_add`; the loser is a no-op. Without the
    /// guard the totals would either double-count (both flush) or
    /// under-count everything (`Drop` reads the totals before the
    /// teardown flush lands -- the `IacsTunnelClosed { 0, 0 }` bug).
    ///
    /// Call AFTER [`Self::close`]: the stats ticker skips closed
    /// handles, so ordering close-then-flush makes a double-count
    /// (bytes in the totals AND in a still-counted live handle)
    /// unrepresentable at sampling time.
    pub fn flush_into(&self, total_in: &AtomicUsize, total_out: &AtomicUsize) {
        if self.flushed.swap(true, Ordering::SeqCst) {
            return;
        }
        let (b_in, b_out) = self.counters();
        total_in.fetch_add(b_in as usize, Ordering::SeqCst);
        total_out.fetch_add(b_out as usize, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelRegistry {
    inner: Arc<DashMap<Uuid, TunnelHandle>>,
}

/// Lightweight identity retained after `PendingTunnel` is consumed at
/// `auth_publickey`, so boot snapshots can still report
/// `(user, asset, ews)` for an `ews_connected` login that has no
/// `TunnelRegistry` entry yet.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub user_uuid: Uuid,
    pub asset_uuid: Uuid,
    pub ews_uuid: Uuid,
    pub peer_ip: Option<String>,
}

/// Keyed map of `russh::server::Handle` for every authenticated EWS
/// SSH session, indexed by its `session_uuid`.
///
/// Background: the proxy needs to FORCE-disconnect the SSH session
/// when an operator clicks "Terminate" on `/sessions/active`. The
/// `TunnelRegistry` only carries per-channel byte counters and a
/// close `Notify`; closing it does not propagate to the russh
/// session itself, so the EWS would keep its `ssh -L` tunnel open
/// and silently re-connect on the next `accept()`. The russh
/// `Handle` (returned by `Session::handle()`) is the only seam that
/// can dispatch a `Disconnect::ByApplication` message to the EWS
/// from outside a Handler callback.
///
/// Lifecycle:
///   - INSERT in `Handler::auth_succeeded` (the earliest callback
///     where both the resolved `PendingTunnel.session_uuid` and the
///     `Session` reference are simultaneously available).
///   - REMOVE in the Handler's `Drop` impl (idempotent: `remove` on
///     a missing key is a no-op).
///   - LOOKUP in `Message::IacsTunnelTerminate` so the proxy can
///     call `handle.disconnect(...)` to tear down the SSH session
///     even when no `direct-tcpip` channel is currently open
///     (e.g. session in `Waiting_client` after auth but before the
///     first local TCP `accept()` on the EWS).
///
/// The handle is `Clone + Debug` (russh contract) so the DashMap
/// stores an owned copy and lookups never block writers.
///
/// `close_reasons` carries the audit close cause across the forced-
/// disconnect seam: the `IacsTunnelTerminate` IPC handler records
/// the reason (`admin_terminate` / `expired` / `revoked`) BEFORE
/// dispatching `Handle::disconnect`, and the Handler's `Drop` takes
/// it back when emitting `IacsRecordingSessionEnd`. A voluntary EWS
/// disconnect never populated the map, so `take_close_reason`
/// returns `None` and the Drop falls back to `ews_disconnect`.
///
/// `meta` is populated in the same `auth_succeeded` callback (from
/// the accepted `PendingTunnel`) and cleared with `remove`, so boot
/// `IacsTunnelSnapshot*` responses can rehydrate DB rows for
/// `ews_connected` sessions that have not yet opened a channel.
#[derive(Debug, Default, Clone)]
pub struct SessionHandles {
    inner: Arc<DashMap<Uuid, russh::server::Handle>>,
    close_reasons: Arc<DashMap<Uuid, String>>,
    meta: Arc<DashMap<Uuid, SessionMeta>>,
}

#[allow(dead_code)] // Several methods surface in Lot 5 (terminate / WS pusher)
impl TunnelRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, handle: TunnelHandle) -> Option<TunnelHandle> {
        self.inner.insert(handle.session_uuid, handle)
    }

    pub fn get(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        self.inner.get(session_uuid).map(|r| r.clone())
    }

    pub fn remove(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        self.inner.remove(session_uuid).map(|(_, v)| v)
    }

    pub fn close_and_remove(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        let handle = self.inner.remove(session_uuid).map(|(_, v)| v);
        if let Some(h) = &handle {
            h.close();
        }
        handle
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn snapshot(&self) -> Vec<TunnelHandle> {
        self.inner.iter().map(|r| r.clone()).collect()
    }
}

#[allow(dead_code)] // surfaced via terminate IPC + tests
impl SessionHandles {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            close_reasons: Arc::new(DashMap::new()),
            meta: Arc::new(DashMap::new()),
        }
    }

    /// Record the audit close cause of a forced disconnect. Called
    /// by the `IacsTunnelTerminate` IPC handler BEFORE
    /// `Handle::disconnect` so the Handler `Drop` (which fires when
    /// russh tears the session down) can attribute the close.
    pub fn set_close_reason(&self, session_uuid: Uuid, reason: &str) {
        self.close_reasons.insert(session_uuid, reason.to_string());
    }

    /// Take (and clear) the recorded close cause. `None` for a
    /// voluntary EWS disconnect.
    pub fn take_close_reason(&self, session_uuid: &Uuid) -> Option<String> {
        self.close_reasons.remove(session_uuid).map(|(_, v)| v)
    }

    /// Idempotent: a second `insert` for the same session_uuid
    /// REPLACES the previous handle. Replacement is not expected in
    /// production (one Handler per SSH session), but keeping it
    /// no-warn protects us against future reconnect / refactor
    /// edge cases.
    pub fn insert(&self, session_uuid: Uuid, handle: russh::server::Handle) {
        self.inner.insert(session_uuid, handle);
    }

    /// Store identity for boot snapshot rehydrate. Called from
    /// `auth_succeeded` alongside [`Self::insert`]. Cleared by
    /// [`Self::remove`].
    pub fn insert_meta(&self, session_uuid: Uuid, meta: SessionMeta) {
        self.meta.insert(session_uuid, meta);
    }

    pub fn get_meta(&self, session_uuid: &Uuid) -> Option<SessionMeta> {
        self.meta.get(session_uuid).map(|r| r.clone())
    }

    pub fn get(&self, session_uuid: &Uuid) -> Option<russh::server::Handle> {
        self.inner.get(session_uuid).map(|r| r.clone())
    }

    /// Keys currently holding a russh handle (authenticated logins).
    pub fn session_uuids(&self) -> Vec<Uuid> {
        self.inner.iter().map(|r| *r.key()).collect()
    }

    /// Idempotent: `remove` of a missing key is a no-op. Also clears
    /// the matching `SessionMeta`. Close-reason slots stay until
    /// [`Self::take_close_reason`] (Handler `Drop` reads them AFTER
    /// `remove`).
    pub fn remove(&self, session_uuid: &Uuid) -> Option<russh::server::Handle> {
        self.meta.remove(session_uuid);
        self.inner.remove(session_uuid).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Build the boot-resync snapshot: union of pending / authenticated /
/// active tunnels with `phase = max` across sources.
///
/// SECURITY: never copies `PendingTunnel::session_token` or
/// `ews_pubkey_fp` into the wire entries.
pub async fn build_tunnel_snapshot(
    pending: &PendingSessions,
    session_handles: &SessionHandles,
    registry: &TunnelRegistry,
) -> Vec<IacsTunnelSnapshotEntry> {
    #[derive(Default)]
    struct Acc {
        phase: u8,
        peer_ip: Option<String>,
        bytes_in: u64,
        bytes_out: u64,
        user_uuid: Option<Uuid>,
        asset_uuid: Option<Uuid>,
        ews_uuid: Option<Uuid>,
    }

    let mut map: HashMap<Uuid, Acc> = HashMap::new();

    for p in pending.snapshot().await {
        let acc = map.entry(p.session_uuid).or_default();
        // Pending is the first pass and WAITING_CLIENT == 0 (== Acc::default().phase),
        // so `.max(WAITING_CLIENT)` is a no-op; assign explicitly for clarity.
        acc.phase = IACS_SNAPSHOT_PHASE_WAITING_CLIENT;
        acc.user_uuid = Some(p.user_uuid);
        acc.asset_uuid = Some(p.asset_uuid);
        acc.ews_uuid = Some(p.ews_uuid);
        // Intentionally omit p.session_token and p.ews_pubkey_fp.
    }

    for uuid in session_handles.session_uuids() {
        let acc = map.entry(uuid).or_default();
        acc.phase = acc.phase.max(IACS_SNAPSHOT_PHASE_EWS_CONNECTED);
        if let Some(meta) = session_handles.get_meta(&uuid) {
            acc.user_uuid = Some(meta.user_uuid);
            acc.asset_uuid = Some(meta.asset_uuid);
            acc.ews_uuid = Some(meta.ews_uuid);
            if acc.peer_ip.is_none() {
                acc.peer_ip = meta.peer_ip;
            }
        }
    }

    for h in registry.snapshot() {
        let acc = map.entry(h.session_uuid).or_default();
        acc.phase = acc.phase.max(IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE);
        acc.user_uuid = Some(h.user_uuid);
        acc.asset_uuid = Some(h.asset_uuid);
        acc.ews_uuid = Some(h.ews_uuid);
        acc.peer_ip = h.peer_addr.map(|sa| sa.ip().to_string());
        let (bin, bout) = h.counters();
        acc.bytes_in = bin;
        acc.bytes_out = bout;
    }

    let mut entries: Vec<IacsTunnelSnapshotEntry> = map
        .into_iter()
        .map(|(session_uuid, acc)| IacsTunnelSnapshotEntry {
            session_id: session_uuid.to_string(),
            phase: acc.phase,
            peer_ip: acc.peer_ip,
            bytes_in: acc.bytes_in,
            bytes_out: acc.bytes_out,
            user_uuid: acc
                .user_uuid
                .map(|u| u.to_string())
                .unwrap_or_default(),
            asset_uuid: acc
                .asset_uuid
                .map(|u| u.to_string())
                .unwrap_or_default(),
            ews_uuid: acc.ews_uuid.map(|u| u.to_string()).unwrap_or_default(),
        })
        .collect();
    entries.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> TunnelHandle {
        TunnelHandle::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
        )
    }

    #[test]
    fn close_is_idempotent() {
        let h = handle();
        h.close();
        h.close();
        assert!(h.is_closed());
    }

    #[tokio::test]
    async fn wait_close_returns_immediately_when_already_closed() {
        let h = handle();
        h.close();
        h.wait_close().await;
    }

    #[test]
    fn registry_insert_and_get_round_trip() {
        let reg = TunnelRegistry::new();
        let h = handle();
        let uuid = h.session_uuid;
        assert!(reg.insert(h.clone()).is_none());
        assert_eq!(reg.get(&uuid).expect("must be present").session_uuid, uuid);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_close_and_remove_closes_handle() {
        let reg = TunnelRegistry::new();
        let h = handle();
        let uuid = h.session_uuid;
        reg.insert(h);
        let removed = reg.close_and_remove(&uuid).expect("present");
        assert!(removed.is_closed());
        assert!(reg.is_empty());
    }

    /// The `IacsTunnelClosed { 0, 0 }` regression: two racers (relay
    /// teardown + handler Drop) flushing the same handle MUST
    /// accumulate its bytes exactly once.
    #[test]
    fn flush_into_is_one_shot_across_racers() {
        let h = handle();
        h.bytes_in.store(1500, Ordering::Relaxed);
        h.bytes_out.store(300, Ordering::Relaxed);
        let total_in = AtomicUsize::new(0);
        let total_out = AtomicUsize::new(0);

        h.flush_into(&total_in, &total_out);
        h.flush_into(&total_in, &total_out);
        // A clone shares the same one-shot guard (same channel).
        h.clone().flush_into(&total_in, &total_out);

        assert_eq!(total_in.load(Ordering::SeqCst), 1500);
        assert_eq!(total_out.load(Ordering::SeqCst), 300);
    }

    /// Distinct channels (distinct handles) accumulate independently
    /// into the same login totals.
    #[test]
    fn flush_into_accumulates_across_distinct_channels() {
        let total_in = AtomicUsize::new(0);
        let total_out = AtomicUsize::new(0);
        for bytes in [100u64, 200, 300] {
            let h = handle();
            h.bytes_in.store(bytes, Ordering::Relaxed);
            h.bytes_out.store(bytes * 2, Ordering::Relaxed);
            h.flush_into(&total_in, &total_out);
        }
        assert_eq!(total_in.load(Ordering::SeqCst), 600);
        assert_eq!(total_out.load(Ordering::SeqCst), 1200);
    }

    #[test]
    fn session_handles_starts_empty_and_reports_len_zero() {
        let s = SessionHandles::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.get(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn session_handles_remove_of_missing_key_is_noop() {
        let s = SessionHandles::new();
        // No panic, no error: a terminate IPC arriving after the
        // handler's Drop already removed the entry MUST be a no-op
        // (idempotency contract of the SessionHandles API).
        assert!(s.remove(&Uuid::new_v4()).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn session_handles_session_uuids_lists_keys() {
        let s = SessionHandles::new();
        assert!(s.session_uuids().is_empty());
        let u = Uuid::new_v4();
        s.insert_meta(
            u,
            SessionMeta {
                user_uuid: Uuid::new_v4(),
                asset_uuid: Uuid::new_v4(),
                ews_uuid: Uuid::new_v4(),
                peer_ip: None,
            },
        );
        // meta alone does not count as an authenticated handle.
        assert!(s.session_uuids().is_empty());
        s.remove(&u);
        assert!(s.get_meta(&u).is_none());
    }

    #[tokio::test]
    async fn build_tunnel_snapshot_unions_pending_and_registry() {
        use crate::auth::PendingTunnel;
        use std::time::{Duration, Instant};

        let pending = PendingSessions::new();
        let handles = SessionHandles::new();
        let registry = TunnelRegistry::new();

        let pending_uuid = Uuid::new_v4();
        let user = Uuid::new_v4();
        let asset = Uuid::new_v4();
        let ews = Uuid::new_v4();
        pending
            .insert(PendingTunnel {
                session_uuid: pending_uuid,
                user_uuid: user,
                asset_uuid: asset,
                ews_uuid: ews,
                ews_pubkey_fp: "a".repeat(64),
                asset_host: "10.0.0.1".into(),
                asset_port: 502,
                industrial_protocol: "modbus".into(),
                session_token: b"SECRET_TOKEN_BYTES_MUST_NOT_LEAK".to_vec(),
                deadline: Instant::now() + Duration::from_secs(60),
            })
            .await;

        let active_uuid = Uuid::new_v4();
        let h = TunnelHandle::new(
            active_uuid,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Some("203.0.113.10:1234".parse().unwrap()),
        );
        h.bytes_in.store(11, Ordering::Relaxed);
        h.bytes_out.store(22, Ordering::Relaxed);
        registry.insert(h);

        // Meta without a russh handle is invisible to session_uuids();
        // phase=1 is covered by auth_succeeded insert_meta + handshake
        // e2e. Here we pin pending + registry and the no-token contract.
        let entries = build_tunnel_snapshot(&pending, &handles, &registry).await;
        assert_eq!(entries.len(), 2, "pending + registry");

        let pending_entry = entries
            .iter()
            .find(|e| e.session_id == pending_uuid.to_string())
            .expect("pending entry");
        assert_eq!(pending_entry.phase, IACS_SNAPSHOT_PHASE_WAITING_CLIENT);
        assert_eq!(pending_entry.user_uuid, user.to_string());
        assert_eq!(pending_entry.bytes_in, 0);
        assert!(pending_entry.peer_ip.is_none());

        let active_entry = entries
            .iter()
            .find(|e| e.session_id == active_uuid.to_string())
            .expect("active entry");
        assert_eq!(active_entry.phase, IACS_SNAPSHOT_PHASE_TUNNEL_ACTIVE);
        assert_eq!(active_entry.bytes_in, 11);
        assert_eq!(active_entry.bytes_out, 22);
        assert_eq!(active_entry.peer_ip.as_deref(), Some("203.0.113.10"));

        // SECURITY pin: no token bytes appear in any string field.
        let blob = format!("{entries:?}");
        assert!(
            !blob.contains("SECRET_TOKEN_BYTES_MUST_NOT_LEAK"),
            "snapshot must never copy session_token bytes"
        );
    }

    /// Source pin: the snapshot builder body must never reference
    /// token/fp fields as assignment targets on the wire entry.
    #[test]
    fn build_tunnel_snapshot_source_never_copies_token_or_pubkey() {
        let src = include_str!("registry.rs");
        let start = src
            .find("pub async fn build_tunnel_snapshot")
            .expect("build_tunnel_snapshot present");
        let body = &src[start..];
        let end = body
            .find("\npub ")
            .or_else(|| body.find("\n#[cfg(test)]"))
            .unwrap_or(body.len());
        let fn_body = &body[..end];
        assert!(
            !fn_body.contains("session_token:")
                && !fn_body.contains("ews_pubkey_fp:"),
            "build_tunnel_snapshot must not assign session_token / \
             ews_pubkey_fp onto snapshot entries"
        );
        // Reading them only to explicitly discard is documented; the
        // wire struct construction uses IacsTunnelSnapshotEntry {{ ... }}
        // without those fields.
        assert!(
            fn_body.contains("IacsTunnelSnapshotEntry"),
            "builder must construct IacsTunnelSnapshotEntry"
        );
    }
}
