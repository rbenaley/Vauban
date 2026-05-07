//! In-memory registry of live IACS tunnel sessions.
//!
//! The registry is the single seam between the russh server (which
//! owns the SSH side of every tunnel) and the rest of `vauban-web`:
//!
//!   * the axum `terminate` handler asks the registry to close a
//!     tunnel by `session_uuid`,
//!   * the revocation watchdog (lot L4) calls `close()` for every
//!     `proxy_sessions` row whose owning EWS or user just got
//!     disabled / offboarded,
//!   * the WebSocket fan-out (lot L5) reads the live byte counters
//!     to push to the status page.
//!
//! `DashMap` is the right primitive here -- writes (open / close /
//! update counter) and reads (status page polls) are both per-row
//! and the workload is dominated by short critical sections; we
//! never hold a lock across an await point.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use tokio::sync::Notify;
use uuid::Uuid;

/// Reference-counted handle to a live tunnel. Cloned freely between
/// the server task, the relay tasks, the WS pusher, and the status
/// handler. The actual close signal flows through `closed` (set
/// exactly once) and the `notify` (woken from any clone).
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    pub session_uuid: Uuid,
    /// `Some(addr)` once the EWS has handshaked and we have a
    /// peer IP to display on the status page.
    pub peer_addr: Arc<Mutex<Option<std::net::SocketAddr>>>,
    /// EWS uuid pinned at session creation (so the watchdog can
    /// look up the owning EWS without a DB hit).
    pub ews_uuid: Uuid,
    /// User uuid pinned at session creation.
    pub user_uuid: Uuid,
    /// Bytes the bastion forwarded TO the IACS asset (relay
    /// "outbound", direction EWS → asset).
    pub bytes_out: Arc<AtomicU64>,
    /// Bytes the bastion forwarded BACK to the EWS (relay
    /// "inbound", direction asset → EWS).
    pub bytes_in: Arc<AtomicU64>,
    /// Soft close flag. The server reads this in tight loops to
    /// decide whether to drain its channels and disconnect.
    /// `close()` flips it and wakes `notify`; the relay tasks
    /// observe and tear down.
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl TunnelHandle {
    /// Construct a fresh handle. Defaults: not closed, no peer
    /// addr, zero counters.
    pub fn new(session_uuid: Uuid, ews_uuid: Uuid, user_uuid: Uuid) -> Self {
        Self {
            session_uuid,
            peer_addr: Arc::new(Mutex::new(None)),
            ews_uuid,
            user_uuid,
            bytes_out: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
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

    /// Suspends until `close()` is called. Safe to call multiple
    /// times concurrently.
    pub async fn wait_close(&self) {
        let notified = self.notify.notified();
        if self.is_closed() {
            return;
        }
        notified.await;
    }

    /// Read counters as a `(in, out)` pair (atomic snapshot).
    pub fn counters(&self) -> (u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
        )
    }
}

/// Concurrent registry of live IACS tunnels. Wrapped in an `Arc` so
/// it can be threaded through the `AppState` and accessed by the
/// russh handler, the watchdog, the WS fan-out, and the axum
/// terminate route without lock contention beyond per-shard
/// `DashMap` locking.
#[derive(Debug, Default, Clone)]
pub struct TunnelRegistry {
    inner: Arc<DashMap<Uuid, TunnelHandle>>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Register a new tunnel handle. Returns the previously
    /// registered handle (if any) so the caller can decide whether
    /// it was a true duplicate -- under the L4 SERIALIZABLE
    /// transition this should never happen, but the registry is
    /// the last line of defence.
    pub fn insert(&self, handle: TunnelHandle) -> Option<TunnelHandle> {
        self.inner.insert(handle.session_uuid, handle)
    }

    pub fn get(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        self.inner.get(session_uuid).map(|r| r.clone())
    }

    /// Remove the handle without closing the tunnel. The caller
    /// is responsible for closing it first; this is a pure
    /// bookkeeping operation, used at the end of `handle_session`
    /// when the russh task is exiting.
    pub fn remove(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        self.inner.remove(session_uuid).map(|(_, v)| v)
    }

    /// Close-and-remove. Returns the (already closed) handle so
    /// the caller can inspect counters one last time.
    pub fn close_and_remove(&self, session_uuid: &Uuid) -> Option<TunnelHandle> {
        let handle = self.inner.remove(session_uuid).map(|(_, v)| v);
        if let Some(h) = &handle {
            h.close();
        }
        handle
    }

    /// Number of live tunnels. Used by quotas (lot L4 / L6) and
    /// observability.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate (snapshot of cloned handles -- no lock held across
    /// the iteration, safe for the watchdog to filter on
    /// `ews_uuid`).
    pub fn snapshot(&self) -> Vec<TunnelHandle> {
        self.inner.iter().map(|r| r.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> TunnelHandle {
        TunnelHandle::new(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
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

    #[tokio::test]
    async fn wait_close_wakes_when_close_called() {
        let h = handle();
        let cloned = h.clone();
        let waiter = tokio::spawn(async move { cloned.wait_close().await });
        tokio::task::yield_now().await;
        h.close();
        waiter.await.expect("waiter must complete");
    }

    #[test]
    fn registry_insert_and_get_round_trip() {
        let reg = TunnelRegistry::new();
        let h = handle();
        let uuid = h.session_uuid;
        assert!(reg.insert(h.clone()).is_none());
        let got = reg.get(&uuid).expect("must be present");
        assert_eq!(got.session_uuid, uuid);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_close_and_remove_closes_handle() {
        let reg = TunnelRegistry::new();
        let h = handle();
        let uuid = h.session_uuid;
        reg.insert(h.clone());
        let removed = reg.close_and_remove(&uuid).expect("present");
        assert!(removed.is_closed());
        assert!(reg.get(&uuid).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn snapshot_is_a_disconnected_clone() {
        let reg = TunnelRegistry::new();
        for _ in 0..3 {
            reg.insert(handle());
        }
        assert_eq!(reg.snapshot().len(), 3);
        // Mutating the registry after the snapshot does not
        // change the snapshot.
        let snap = reg.snapshot();
        reg.close_and_remove(&snap[0].session_uuid);
        assert_eq!(reg.len(), 2);
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn counters_round_trip() {
        let h = handle();
        h.bytes_in.fetch_add(123, Ordering::Relaxed);
        h.bytes_out.fetch_add(456, Ordering::Relaxed);
        assert_eq!(h.counters(), (123, 456));
    }
}
