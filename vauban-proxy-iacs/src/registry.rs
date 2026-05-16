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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::sync::Notify;
use uuid::Uuid;

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
}

#[derive(Debug, Default, Clone)]
pub struct TunnelRegistry {
    inner: Arc<DashMap<Uuid, TunnelHandle>>,
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
#[derive(Debug, Default, Clone)]
pub struct SessionHandles {
    inner: Arc<DashMap<Uuid, russh::server::Handle>>,
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
        }
    }

    /// Idempotent: a second `insert` for the same session_uuid
    /// REPLACES the previous handle. Replacement is not expected in
    /// production (one Handler per SSH session), but keeping it
    /// no-warn protects us against future reconnect / refactor
    /// edge cases.
    pub fn insert(&self, session_uuid: Uuid, handle: russh::server::Handle) {
        self.inner.insert(session_uuid, handle);
    }

    pub fn get(&self, session_uuid: &Uuid) -> Option<russh::server::Handle> {
        self.inner.get(session_uuid).map(|r| r.clone())
    }

    /// Idempotent: `remove` of a missing key is a no-op.
    pub fn remove(&self, session_uuid: &Uuid) -> Option<russh::server::Handle> {
        self.inner.remove(session_uuid).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
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
}
