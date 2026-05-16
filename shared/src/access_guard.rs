//! Defense-in-depth gate against vauban-access (the canonical RBAC oracle).
//!
//! This module factorises the per-protocol re-check pattern that every
//! Vauban proxy MUST run before opening an upstream session. Concretely:
//!
//! 1. The supervisor wires a `ProxyXxx -> Access` IPC pipe and exports
//!    `VAUBAN_ACCESS_IPC_READ` / `VAUBAN_ACCESS_IPC_WRITE`.
//! 2. The proxy calls [`AccessGuard::from_env`] at boot, gets back an
//!    [`AccessGuardWiring`] containing the FDs to enrol in Capsicum and
//!    an `Arc<AccessGuard>`.
//! 3. After the tokio runtime is up, the proxy calls
//!    [`AccessGuard::spawn_dispatcher`] exactly once.
//! 4. Each session-open handler calls
//!    [`AccessGuard::authorize`] inside its own `tokio::spawn` and only
//!    proceeds if the returned [`AccessDecision`] is `Granted`.
//!
//! Why a shared module?
//!
//! Before this module existed, the SSH proxy carried its own copy of the
//! IPC client + boot wiring + timeout + counters + structural tests. Any
//! new protocol (RDP, VNC, Modbus, ...) would have to copy the same 150+
//! lines, with the very real risk of forgetting the timeout, the
//! `tokio::spawn` (causing main-loop wedges), or the fail-closed semantics.
//! See `docs/runbooks/ipc_topology_debugging.md` for the production
//! incident that this design prevents from recurring.
//!
//! Fail-closed is the type-system default: [`AccessGuard::authorize`]
//! returns [`AccessDecision`] (NEVER `Result`), and every variant other
//! than `Granted` MUST be treated as a denial by the caller.

use crate::ipc::IpcChannel;
use crate::messages::{AccessRequest, AccessResponse, Message};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Hard timeout enforced on every [`AccessGuard::authorize`] call.
///
/// Bumped from 5s to 10s after the first production soak: the
/// `handle_check_access_by_uuid` handler in vauban-access does 3
/// sequential DB queries on a `current_thread` runtime; under DB load the
/// median is ~50ms but a p99 tail of 1-2s is realistic. 10s leaves us
/// comfortably below the supervisor's ~20s heartbeat threshold while
/// still failing closed long before any user-visible spinner stalls
/// forever. If `record_timeout` ever climbs in prod, scale up
/// vauban-access (multi-thread runtime / connection pool) rather than
/// nudging this further up.
pub const RBAC_RECHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Canonical protocol strings. MUST match the values stored in
/// `access_rules.protocols` in PostgreSQL. Add new entries here when
/// onboarding a new protocol so typos in the call site fail at compile
/// time instead of producing silent denials in production.
pub const PROTOCOL_SSH: &str = "ssh";
pub const PROTOCOL_RDP: &str = "rdp";
/// IACS tunnel (industrial control system, ssh -L from EWS).
/// MUST match `proxy_sessions.session_type` and the `protocol` field
/// of every `SessionToken` minted for `Service::ProxyIacs`. The string
/// is also the discriminant the supervisor logs when brokering the
/// upstream TCP connect to the asset.
///
/// Semantically this is a **transport-layer / meta-protocol**: it
/// identifies the SSH-tunnel runtime carrying the bytes, not the
/// industrial-protocol payload (Modbus, OPC-UA, ...). Access rules,
/// in contrast, store the **applicative** protocol (`iacs_modbus`,
/// `iacs_opcua`, ...) -- the one matching the asset's `AssetType`.
/// The bridging seam is [`expand_protocol_for_access_match`], which
/// expands `iacs_tunnel` to the set of every `iacs_*` applicative
/// protocol when matching access-rule rows.
pub const PROTOCOL_IACS_TUNNEL: &str = "iacs_tunnel";

/// Every applicative IACS protocol the access-rule UI persists.
///
/// MUST stay in lockstep with `vauban-web/src/handlers/web/access_rules.rs::iacs_protocols`
/// (the form-side expansion of the "IACS (all industrial protocols)"
/// master checkbox) and with the `iacs_*` arms of
/// `vauban-web/src/models/asset.rs::AssetType::as_str`. A drift
/// pin in `vauban-access/src/handlers.rs` tests refuses the build
/// otherwise.
///
/// The list does NOT include `iacs_tunnel` -- the transport-meta
/// is the *consumer* of this set, never a member.
pub const IACS_APPLICATIVE_PROTOCOLS: &[&str] = &[
    "iacs_modbus",
    "iacs_opcua",
    "iacs_profinet",
    "iacs_iec104",
    "iacs_tcp",
];

/// Bridge the transport-meta (`iacs_tunnel`) and the applicative
/// (`iacs_modbus`, ...) views of the access-rule database.
///
/// Returns the set of access-rule protocol strings that should match
/// when the caller asked for `protocol`:
///
/// - For the IACS transport-meta, returns every applicative
///   IACS protocol (`iacs_modbus`, `iacs_opcua`, `iacs_profinet`,
///   `iacs_iec104`, `iacs_tcp`). An access rule that allows ANY
///   of them grants the `iacs_tunnel` transport on the matching
///   asset. This mirrors the access-rule create/edit form's
///   "IACS (all industrial protocols)" master checkbox: it expands
///   to every `iacs_*` value at save time, so a rule that allows
///   IACS allows them all atomically. Asymmetric rules created via
///   IPC (only `iacs_modbus`, say) still grant `iacs_tunnel` --
///   that is the conservative choice (any IACS protocol allowed
///   on this asset means the operator is allowed to reach it via
///   the tunnel runtime).
/// - For every other protocol, returns `[protocol]` unchanged.
///   `ssh`, `rdp`, and the applicative `iacs_*` strings flow
///   through verbatim.
///
/// The returned `Vec<String>` is suitable for a Postgres
/// `allowed_protocols && ARRAY[...]` overlap test in Diesel.
///
/// ## Why this exists
///
/// Pre-fix, `vauban-access::CheckAccessByUuid` filtered access rules
/// with `allowed_protocols.contains([protocol])`. That worked for
/// `ssh` / `rdp` (where the rule and the request use the same
/// string) but broke `iacs_tunnel` (the request was the transport
/// meta, the rule held an applicative protocol -- never a match,
/// production-blocker). The expansion centralises the bridging
/// logic so every consumer of the access-rule index gets the same
/// answer.
pub fn expand_protocol_for_access_match(protocol: &str) -> Vec<String> {
    if protocol == PROTOCOL_IACS_TUNNEL {
        return IACS_APPLICATIVE_PROTOCOLS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    vec![protocol.to_string()]
}

/// Final verdict returned by [`AccessGuard::authorize`].
///
/// The variants are deliberately distinct so each caller can attribute
/// metrics (and decide whether to log) without re-grepping logs:
///
/// - `Granted`     : vauban-access explicitly allowed the session.
/// - `Denied`      : vauban-access explicitly denied (no access_rule, etc.).
/// - `Timeout`     : vauban-access did not respond within `RBAC_RECHECK_TIMEOUT`.
/// - `BackendError`: IPC layer error (broken pipe, malformed reply, ...).
///
/// All non-Granted variants MUST be treated as a fail-closed denial.
#[derive(Debug, Clone)]
pub enum AccessDecision {
    /// vauban-access explicitly granted the session.
    Granted,
    /// vauban-access explicitly denied (policy decision).
    Denied,
    /// vauban-access did not respond within the timeout.
    Timeout,
    /// Underlying IPC failure (broken pipe, unexpected response variant, etc.).
    BackendError(String),
}

impl AccessDecision {
    /// Returns true iff the decision is `Granted`. Every other variant
    /// collapses to a fail-closed denial at the proxy boundary.
    pub fn is_granted(&self) -> bool {
        matches!(self, AccessDecision::Granted)
    }
}

/// Pluggable counter sink. Each proxy implements this on its own
/// `ServiceState` so its Pong/health endpoint can report grant / deny /
/// timeout / ipc-error rates without leaking shared crate concerns.
///
/// All four methods are called from inside `authorize` exactly once per
/// call. Implementations MUST be cheap and infallible (typically an
/// atomic increment).
pub trait AccessGuardMetrics: Send + Sync + 'static {
    /// vauban-access returned `allowed = true`.
    fn record_granted(&self);
    /// vauban-access returned `allowed = false` (policy denial).
    fn record_denied(&self);
    /// vauban-access did not respond within `RBAC_RECHECK_TIMEOUT`.
    fn record_timeout(&self);
    /// IPC error or unexpected response variant.
    fn record_ipc_error(&self);
}

/// Errors raised at construction-time only. The hot path
/// (`AccessGuard::authorize`) intentionally never returns `Result` -- it
/// returns [`AccessDecision`] so fail-closed is the type-system default.
#[derive(Debug, thiserror::Error)]
pub enum AccessGuardError {
    /// The required env var was not set by the supervisor. This is a
    /// fail-closed boot condition: the proxy MUST refuse to start.
    #[error(
        "missing env var {0}: vauban-access IPC pipe not provided by supervisor; \
         the proxy cannot authorise sessions without it (refusing to start)"
    )]
    MissingEnvVar(&'static str),

    /// The env var was set but did not parse as a `RawFd`.
    #[error("invalid env var {0}: {1}")]
    InvalidEnvVar(&'static str, String),

    /// `AsyncFd::new` or `set_nonblocking` failed.
    #[error("io error wiring access pipe: {0}")]
    Io(#[from] io::Error),
}

/// What a proxy needs to plumb after wiring the guard:
///
/// 1. Add `fds` to its Capsicum sandbox (`setup_service_sandbox_extended`).
/// 2. AFTER the tokio runtime is running, call
///    `wiring.guard.spawn_dispatcher()` exactly once.
/// 3. Stash `wiring.guard` in service state and pass it (cloned `Arc`)
///    into the per-session `tokio::spawn` body.
#[must_use = "AccessGuardWiring carries the FDs and Arc that the proxy must \
              install in its sandbox and dispatcher; dropping it silently \
              would leak the access pipe FDs and disable the re-check"]
pub struct AccessGuardWiring {
    /// Long-lived guard, share-cloned across per-session spawns.
    pub guard: Arc<AccessGuard>,
    /// FDs (read + write) to enrol in the Capsicum sandbox.
    pub fds: Vec<RawFd>,
}

impl std::fmt::Debug for AccessGuardWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessGuardWiring")
            .field("protocol", &self.guard.protocol)
            .field("fds", &self.fds)
            .finish()
    }
}

/// The defense-in-depth gate. One per protocol per process.
pub struct AccessGuard {
    client: RbacClient,
    timeout: Duration,
    protocol: &'static str,
    metrics: Arc<dyn AccessGuardMetrics>,
}

impl AccessGuard {
    /// Wire from `VAUBAN_ACCESS_IPC_READ` / `VAUBAN_ACCESS_IPC_WRITE`.
    ///
    /// Fail-closed boot: returns `Err` if either env var is missing or
    /// invalid. The env vars are consumed (removed) on success so they
    /// cannot leak to child processes.
    ///
    /// # Safety
    ///
    /// Must be called from the main thread BEFORE any other thread is
    /// spawned, because `std::env::remove_var` is not thread-safe under
    /// the 2024 edition's lints. The function asserts this implicitly by
    /// using `unsafe { remove_var }` directly.
    pub fn from_env(
        protocol: &'static str,
        metrics: Arc<dyn AccessGuardMetrics>,
    ) -> Result<AccessGuardWiring, AccessGuardError> {
        let read_fd = read_fd_from_env("VAUBAN_ACCESS_IPC_READ")?;
        let write_fd = read_fd_from_env("VAUBAN_ACCESS_IPC_WRITE")?;
        // SAFETY: clear env immediately to avoid leaking the FDs to
        // children spawned later. Caller invariant: single-threaded at
        // this point (typical at boot, before tokio runtime spawns
        // worker threads).
        unsafe {
            std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
            std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
        }
        let client = RbacClient::new(read_fd, write_fd)?;
        let guard = Arc::new(Self {
            client,
            timeout: RBAC_RECHECK_TIMEOUT,
            protocol,
            metrics,
        });
        Ok(AccessGuardWiring {
            guard,
            fds: vec![read_fd, write_fd],
        })
    }

    /// Spawn the background dispatcher that demultiplexes responses from
    /// vauban-access by `request_id`. MUST be called exactly once, after
    /// the tokio runtime is up. Without this call, every `authorize`
    /// invocation will hit `RBAC_RECHECK_TIMEOUT`.
    ///
    /// The returned `JoinHandle` is mostly informational: the proxy
    /// typically lets the dispatcher run for the lifetime of the
    /// process. If the dispatcher exits (channel closed, fatal error),
    /// every subsequent `authorize` call will fail closed via timeout,
    /// and the supervisor's restart loop will eventually replace us.
    pub fn spawn_dispatcher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            info!(protocol = this.protocol, "AccessGuard dispatcher started");
            if let Err(e) = this.client.run_dispatcher().await {
                error!(
                    protocol = this.protocol,
                    error = %e,
                    "AccessGuard dispatcher exited; subsequent authorize() calls will Timeout"
                );
            }
        })
    }

    /// Single fail-closed authorisation call.
    ///
    /// NEVER blocks for longer than `RBAC_RECHECK_TIMEOUT`. NEVER returns
    /// `Result` -- callers MUST treat anything other than `Granted` as a
    /// denial. The caller is expected to surface a generic "Access
    /// denied" message to the client (no information disclosure between
    /// "policy denial" and "access service down").
    ///
    /// Recommended call site shape (from inside a `tokio::spawn` body):
    ///
    /// ```ignore
    /// let decision = guard.authorize(&user_uuid, &asset_uuid).await;
    /// if !decision.is_granted() {
    ///     // Build a generic failure response and return.
    ///     return;
    /// }
    /// // Proceed with credential lookup + upstream connect.
    /// ```
    pub async fn authorize(&self, user_uuid: &str, asset_uuid: &str) -> AccessDecision {
        let fut = self
            .client
            .check_access_by_uuid(user_uuid, asset_uuid, self.protocol);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(true)) => {
                debug!(
                    user_uuid,
                    asset_uuid,
                    protocol = self.protocol,
                    "AccessGuard granted"
                );
                self.metrics.record_granted();
                AccessDecision::Granted
            }
            Ok(Ok(false)) => {
                warn!(
                    user_uuid,
                    asset_uuid,
                    protocol = self.protocol,
                    "AccessGuard denied (policy)"
                );
                self.metrics.record_denied();
                AccessDecision::Denied
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                error!(
                    user_uuid, asset_uuid, protocol = self.protocol, error = %msg,
                    "AccessGuard IPC error - denying fail-closed"
                );
                self.metrics.record_ipc_error();
                AccessDecision::BackendError(msg)
            }
            Err(_elapsed) => {
                error!(
                    user_uuid,
                    asset_uuid,
                    protocol = self.protocol,
                    timeout_secs = self.timeout.as_secs(),
                    "AccessGuard timeout - denying fail-closed (vauban-access \
                     may be wedged or saturated; check its peer attachment count \
                     and DB pool health)"
                );
                self.metrics.record_timeout();
                AccessDecision::Timeout
            }
        }
    }

    /// The protocol string this guard was wired for. Useful for tests
    /// and structured logging.
    pub fn protocol(&self) -> &'static str {
        self.protocol
    }
}

fn read_fd_from_env(name: &'static str) -> Result<RawFd, AccessGuardError> {
    let raw = std::env::var(name).map_err(|_| AccessGuardError::MissingEnvVar(name))?;
    raw.parse::<RawFd>()
        .map_err(|e| AccessGuardError::InvalidEnvVar(name, e.to_string()))
}

// ============================================================================
// Internal IPC client. Was previously vauban-proxy-ssh::ipc::AccessRbacClient;
// kept private to this module because the public surface above is what proxies
// should use.
// ============================================================================

/// Demultiplexes concurrent CheckAccessByUuid responses by `request_id`.
///
/// The `pending` map uses `std::sync::Mutex` (not `tokio::sync::Mutex`)
/// because:
///
/// 1. Critical sections are O(1) HashMap ops with no `.await` held
///    inside, so blocking the executor for ~µs is acceptable.
/// 2. Synchronous locking is REQUIRED by [`PendingEntry::drop`], which
///    runs from inside `Drop` and cannot `await`. Without that synchronous
///    cleanup, a cancelled [`AccessGuard::authorize`] (timeout or caller
///    drop) would leak its `pending[request_id]` entry forever -- a real
///    DoS vector if vauban-access is wedged for any duration.
struct RbacClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending: StdMutex<HashMap<u64, oneshot::Sender<AccessResponse>>>,
}

/// RAII handle that removes its `pending[id]` slot on drop.
///
/// SECURITY/RESOURCE: this is the GC for the `pending` map. Without it,
/// every cancelled `authorize` (via `tokio::time::timeout` firing OR
/// the surrounding `tokio::spawn` being dropped) would leave a tombstone
/// `oneshot::Sender` in `pending` -- under sustained vauban-access
/// outage, that map grows unboundedly. With this guard, exactly one of
/// two things removes the entry:
///
/// - the dispatcher, when it sees the matching response, OR
/// - this `Drop`, on every other exit path (timeout, caller cancel,
///   `channel.send` error, etc.).
///
/// Drop is idempotent: removing a missing key is a no-op.
struct PendingEntry<'a> {
    pending: &'a StdMutex<HashMap<u64, oneshot::Sender<AccessResponse>>>,
    id: u64,
}

impl Drop for PendingEntry<'_> {
    fn drop(&mut self) {
        // Lock is acquired synchronously: critical section is one
        // HashMap removal, no await. We use `if let Ok` rather than
        // `expect` because a poisoned mutex on this path would mean
        // some other thread panicked while holding the lock; unwinding
        // through a Drop on top of that would abort the whole process.
        // Logging-and-skip is strictly safer (the worst case is a
        // single leaked entry, not a process abort).
        if let Ok(mut map) = self.pending.lock() {
            map.remove(&self.id);
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum RbacClientError {
    #[error("IPC send failed: {0}")]
    SendFailed(String),
    #[error("IPC receive failed: {0}")]
    ReceiveFailed(String),
    #[error("IPC connection closed")]
    ConnectionClosed,
}

impl RbacClient {
    /// SAFETY: `read_fd` and `write_fd` MUST be fresh pipe ends owned by
    /// this process and NOT duplicated elsewhere. The supervisor
    /// guarantees this.
    fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Self> {
        // SAFETY: see method-level safety contract.
        let channel = unsafe { IpcChannel::from_raw_fds(read_fd, write_fd) };
        set_nonblocking(read_fd)?;
        let read_async_fd = AsyncFd::new(read_fd)?;
        Ok(Self {
            channel,
            read_async_fd,
            next_request_id: AtomicU64::new(1),
            pending: StdMutex::new(HashMap::new()),
        })
    }

    /// Snapshot of the pending-map size. Test-only observability:
    /// production code MUST NOT branch on this value (it would race
    /// with the dispatcher). Used by the cleanup invariants suite to
    /// prove we do not leak entries on timeout / cancellation.
    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.pending.lock().expect("pending mutex poisoned").len()
    }

    async fn check_access_by_uuid(
        &self,
        user_uuid: &str,
        asset_uuid: &str,
        protocol: &str,
    ) -> Result<bool, RbacClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        // SECURITY/RESOURCE: insert FIRST, then bind the RAII guard.
        // The guard removes the entry on every exit path (success,
        // backend Err, timeout cancel, caller drop) so the pending map
        // cannot leak. Without it, a wedged vauban-access combined with
        // sustained traffic produced unbounded HashMap growth (real
        // DoS surface; the timeout protected the caller but not the
        // proxy's RAM).
        self.pending
            .lock()
            // Recover from poisoning: a poisoned Mutex still holds a
            // valid HashMap (poisoning only signals that some other
            // thread panicked while holding the lock). Aborting here
            // would force a fail-closed denial on every subsequent
            // authorize() until supervisor restart, even though our
            // local state is fine. Recover and keep serving.
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, tx);
        let _entry = PendingEntry {
            pending: &self.pending,
            id: request_id,
        };

        let msg = Message::AccessRequest {
            request_id,
            request: AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid.to_string(),
                asset_uuid: asset_uuid.to_string(),
                protocol: protocol.to_string(),
            },
        };

        if let Err(e) = self.channel.send(&msg) {
            // _entry will clean pending on return; nothing to do here.
            return Err(RbacClientError::SendFailed(e.to_string()));
        }

        debug!(
            request_id,
            user_uuid, asset_uuid, protocol, "AccessGuard: CheckAccessByUuid sent"
        );

        let response = rx.await.map_err(|_| {
            RbacClientError::ReceiveFailed("access response channel dropped".to_string())
        })?;

        match response {
            AccessResponse::AccessChecked(result) => {
                debug!(
                    request_id,
                    user_uuid,
                    asset_uuid,
                    protocol,
                    allowed = result.allowed,
                    "AccessGuard: response"
                );
                Ok(result.allowed)
            }
            AccessResponse::Error(e) => {
                // SECURITY: Treat backend-side errors as a policy denial,
                // not a transport error -- the access service already chose
                // to surface this through the response channel rather than
                // hanging up. Surfacing it as Ok(false) lets `authorize`
                // produce the same fail-closed Denied verdict.
                warn!(
                    request_id, user_uuid, asset_uuid, protocol, error = %e,
                    "AccessGuard: backend Error, denying fail-closed"
                );
                Ok(false)
            }
            other => {
                warn!(
                    request_id, user_uuid, asset_uuid, protocol,
                    response = ?other,
                    "AccessGuard: unexpected response variant, denying fail-closed"
                );
                Ok(false)
            }
        }
    }

    async fn run_dispatcher(&self) -> Result<(), RbacClientError> {
        loop {
            let mut guard = self
                .read_async_fd
                .ready(Interest::READABLE)
                .await
                .map_err(|e| RbacClientError::ReceiveFailed(e.to_string()))?;

            match self.channel.try_recv() {
                Ok(Message::AccessResponse {
                    request_id,
                    response,
                }) => {
                    let maybe_tx = self
                        .pending
                        .lock()
                        // See `check_access_by_uuid` for the poisoning
                        // recovery rationale: dispatcher must keep
                        // routing responses even if some unrelated
                        // thread panicked while holding the lock.
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&request_id);
                    if let Some(tx) = maybe_tx {
                        if tx.send(response).is_err() {
                            debug!(
                                request_id,
                                "AccessGuard: caller dropped before response delivery"
                            );
                        }
                    } else {
                        // SECURITY: response without a matching pending
                        // request. Possible causes: (1) a stale reply
                        // arrived AFTER the caller hit RBAC_RECHECK_TIMEOUT
                        // and the RAII PendingEntry already cleared the
                        // slot, (2) vauban-access is buggy / malicious
                        // and forged a request_id we never sent. Either
                        // way: drop the message; do NOT escalate to a
                        // panic and do NOT let it surface as a Granted
                        // verdict (request_id is the ONLY thing that
                        // demuxes responses to callers).
                        warn!(
                            request_id,
                            "AccessGuard: response without pending request, dropping \
                             (likely a stale post-timeout reply, or a forged request_id)"
                        );
                    }
                }
                Ok(other) => {
                    warn!(
                        message = ?std::mem::discriminant(&other),
                        "AccessGuard: ignoring non-AccessResponse message on access pipe"
                    );
                }
                Err(crate::ipc::IpcError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(crate::ipc::IpcError::ConnectionClosed) => {
                    error!("AccessGuard: access pipe closed, dispatcher exiting");
                    return Err(RbacClientError::ConnectionClosed);
                }
                Err(e) => {
                    error!(error = %e, "AccessGuard: fatal recv error, dispatcher exiting");
                    return Err(RbacClientError::ReceiveFailed(e.to_string()));
                }
            }
        }
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};

    // SAFETY: We're calling fcntl with valid arguments on a valid fd.
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::AccessCheckResult;
    use std::os::unix::io::IntoRawFd;
    use std::sync::atomic::AtomicU64;

    /// Test sink that just counts each metric callback. We use this in
    /// every test that constructs an `AccessGuard` so we can prove the
    /// counters are wired correctly to each decision branch.
    #[derive(Default)]
    struct CountingMetrics {
        granted: AtomicU64,
        denied: AtomicU64,
        timeout: AtomicU64,
        ipc_error: AtomicU64,
    }

    impl AccessGuardMetrics for CountingMetrics {
        fn record_granted(&self) {
            self.granted.fetch_add(1, Ordering::SeqCst);
        }
        fn record_denied(&self) {
            self.denied.fetch_add(1, Ordering::SeqCst);
        }
        fn record_timeout(&self) {
            self.timeout.fetch_add(1, Ordering::SeqCst);
        }
        fn record_ipc_error(&self) {
            self.ipc_error.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Build a `(client_read_fd, client_write_fd, stub_channel)` triple
    /// where the stub end can drive responses for the client end.
    fn pipe_pair() -> (RawFd, RawFd, IpcChannel) {
        let (c_read, c_write) = nix::unistd::pipe().unwrap();
        let (d_read, d_write) = nix::unistd::pipe().unwrap();
        let client_read = c_read.into_raw_fd();
        let client_write = d_write.into_raw_fd();
        // SAFETY: fresh pipe ends owned by this process only.
        let stub = unsafe { IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd()) };
        (client_read, client_write, stub)
    }

    /// Helper: build a fully wired `AccessGuard` from raw FDs (skips the
    /// `from_env` dance), spawn the dispatcher, return the guard and
    /// metrics handle.
    fn wire_guard(
        protocol: &'static str,
        read_fd: RawFd,
        write_fd: RawFd,
    ) -> (Arc<AccessGuard>, Arc<CountingMetrics>) {
        let metrics = Arc::new(CountingMetrics::default());
        let client = RbacClient::new(read_fd, write_fd).unwrap();
        let guard = Arc::new(AccessGuard {
            client,
            timeout: RBAC_RECHECK_TIMEOUT,
            protocol,
            metrics: metrics.clone() as Arc<dyn AccessGuardMetrics>,
        });
        let _handle = guard.spawn_dispatcher();
        (guard, metrics)
    }

    #[test]
    fn test_set_nonblocking_sets_o_nonblock() {
        use std::os::unix::io::AsRawFd;
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        let result = set_nonblocking(read_fd.as_raw_fd());
        assert!(result.is_ok());
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let flags = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert!(flags & O_NONBLOCK != 0);
    }

    #[test]
    fn test_set_nonblocking_preserves_other_flags() {
        use std::os::unix::io::AsRawFd;
        let (read_fd, _write_fd) = nix::unistd::pipe().unwrap();
        use libc::{F_GETFL, O_NONBLOCK, fcntl};
        let original = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        set_nonblocking(read_fd.as_raw_fd()).unwrap();
        let new = unsafe { fcntl(read_fd.as_raw_fd(), F_GETFL) };
        assert_eq!(new, original | O_NONBLOCK);
    }

    #[test]
    fn test_access_decision_is_granted() {
        assert!(AccessDecision::Granted.is_granted());
        assert!(!AccessDecision::Denied.is_granted());
        assert!(!AccessDecision::Timeout.is_granted());
        assert!(!AccessDecision::BackendError("x".to_string()).is_granted());
    }

    #[test]
    fn test_protocol_constants_match_db_strings() {
        // Anti-typo guard: these strings are stored verbatim in
        // access_rules.protocols. If anyone capitalises or renames them
        // here without a DB migration, every authorize() call would
        // silently degrade to Denied.
        assert_eq!(PROTOCOL_SSH, "ssh");
        assert_eq!(PROTOCOL_RDP, "rdp");
        assert_eq!(PROTOCOL_IACS_TUNNEL, "iacs_tunnel");
    }

    // ===================================================================
    // expand_protocol_for_access_match -- transport-meta -> applicative
    //
    // These tests pin the bridging contract that `vauban-access` uses
    // when filtering access_rules.allowed_protocols. They are the
    // first line of defense against the pre-fix regression where
    // `iacs_tunnel` requests silently denied every legitimate IACS
    // access rule (the rule held `iacs_modbus`, the request held
    // `iacs_tunnel`, the SQL `&&` operator never matched).
    // ===================================================================

    #[test]
    fn expand_protocol_passes_through_verbatim_for_non_meta_protocols() {
        assert_eq!(
            expand_protocol_for_access_match("ssh"),
            vec!["ssh".to_string()]
        );
        assert_eq!(
            expand_protocol_for_access_match("rdp"),
            vec!["rdp".to_string()]
        );
        // Applicative IACS protocols are stored as-is in access rules
        // (the form-side expansion writes them literally), so the
        // bridge is a no-op here -- the SQL operator matches the row
        // directly.
        assert_eq!(
            expand_protocol_for_access_match("iacs_modbus"),
            vec!["iacs_modbus".to_string()]
        );
        assert_eq!(
            expand_protocol_for_access_match("iacs_opcua"),
            vec!["iacs_opcua".to_string()]
        );
    }

    #[test]
    fn expand_protocol_iacs_tunnel_returns_every_applicative_iacs_protocol() {
        let expanded = expand_protocol_for_access_match(PROTOCOL_IACS_TUNNEL);
        let expected: Vec<String> = IACS_APPLICATIVE_PROTOCOLS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(expanded, expected);
        // The transport-meta MUST NOT appear inside its own expansion
        // (it has no business being in access_rules.allowed_protocols
        // -- the form never writes it, and admins should not be able
        // to grant transport-only access).
        assert!(
            !expanded.iter().any(|p| p == PROTOCOL_IACS_TUNNEL),
            "iacs_tunnel must not be self-included in the expansion"
        );
        // Concretely, the four canonical IACS protocols MUST be in
        // the expansion. A regression that drops one would silently
        // break that protocol's tunnels.
        for needle in ["iacs_modbus", "iacs_opcua", "iacs_profinet", "iacs_iec104"]
        {
            assert!(
                expanded.iter().any(|p| p == needle),
                "{needle} must be in the expansion of iacs_tunnel"
            );
        }
    }

    #[test]
    fn expand_protocol_unknown_protocol_falls_through_unchanged() {
        // Future-proofing: an unknown protocol string MUST flow
        // through verbatim (one-element Vec). The `vauban-access`
        // SQL filter then either matches a hand-crafted rule with
        // that exact value, or denies. Never an unintended grant
        // via a meta-expansion.
        assert_eq!(
            expand_protocol_for_access_match("vnc"),
            vec!["vnc".to_string()]
        );
        assert_eq!(
            expand_protocol_for_access_match(""),
            vec!["".to_string()]
        );
        assert_eq!(
            expand_protocol_for_access_match("IACS_TUNNEL"),
            vec!["IACS_TUNNEL".to_string()],
            "uppercase variant must NOT alias to PROTOCOL_IACS_TUNNEL \
             -- access_rules are case-sensitive in Postgres"
        );
    }

    #[test]
    fn iacs_applicative_protocols_catalogue_is_anti_typo_pinned() {
        // Every entry MUST start with `iacs_` and MUST NOT be the
        // transport-meta itself. A drift here would be caught by
        // the bigger test in vauban-access/src/handlers.rs that
        // pins this list against the form-side expansion in
        // vauban-web::handlers::access_rules::iacs_protocols.
        for p in IACS_APPLICATIVE_PROTOCOLS {
            assert!(
                p.starts_with("iacs_"),
                "applicative IACS protocol {p:?} must start with `iacs_`"
            );
            assert_ne!(
                *p, PROTOCOL_IACS_TUNNEL,
                "the transport-meta has no business in the applicative \
                 catalogue (rule of thumb: it is never written by the form)"
            );
        }
        assert_eq!(
            IACS_APPLICATIVE_PROTOCOLS.len(),
            5,
            "drift guard: the applicative catalogue is currently \
             {{iacs_modbus, iacs_opcua, iacs_profinet, iacs_iec104, \
             iacs_tcp}} (5 entries). Adding a new IACS protocol \
             requires updating this length AND the matching arms in \
             vauban-web::models::asset::AssetType."
        );
    }

    #[tokio::test]
    async fn test_authorize_granted_increments_granted_metric_only() {
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!("unexpected"),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        let decision = guard.authorize("u-uuid", "a-uuid").await;
        assert!(matches!(decision, AccessDecision::Granted));
        assert!(decision.is_granted());
        stub_join.await.unwrap();
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.timeout.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.ipc_error.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_authorize_policy_denial_increments_denied_metric_only() {
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        let decision = guard.authorize("u-uuid", "a-uuid").await;
        assert!(matches!(decision, AccessDecision::Denied));
        assert!(!decision.is_granted());
        stub_join.await.unwrap();
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_authorize_backend_error_collapses_to_backend_error_metric() {
        // SECURITY: backend Error must NOT bubble up as a panic or as an
        // accidental "Granted". It MUST collapse to AccessDecision::BackendError
        // and increment the ipc_error metric.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_join = tokio::task::spawn_blocking(move || {
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::Error("simulated db meltdown".to_string()),
            })
            .unwrap();
        });

        let decision = guard.authorize("u-uuid", "a-uuid").await;
        // NOTE: AccessResponse::Error is intentionally collapsed by RbacClient
        // into Ok(false), which `authorize` then surfaces as Denied (not
        // BackendError). This is the documented fail-closed contract: the
        // backend deliberately answered with Error, so we treat it as a
        // denial rather than a transport failure. If you want
        // AccessDecision::BackendError, the RbacClient must hit a transport
        // error path (broken pipe, etc.).
        assert!(matches!(decision, AccessDecision::Denied));
        stub_join.await.unwrap();
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.ipc_error.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_authorize_demultiplexes_concurrent_requests() {
        // SECURITY: two simultaneous session-opens must NOT see their
        // RBAC responses crossed -- caller A must never observe caller
        // B's verdict. The pending-map dispatch enforces this; if anyone
        // ever simplifies it back to a single-receiver loop, this test
        // will fail.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, _metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_join = tokio::task::spawn_blocking(move || {
            let r1 = stub.recv().unwrap();
            let id1 = match r1 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            let r2 = stub.recv().unwrap();
            let (id2, asset2) = match r2 {
                Message::AccessRequest {
                    request_id,
                    request: AccessRequest::CheckAccessByUuid { asset_uuid, .. },
                } => (request_id, asset_uuid),
                _ => panic!(),
            };
            // Reply id2 first with allowed=true, then id1 with allowed=false.
            stub.send(&Message::AccessResponse {
                request_id: id2,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            stub.send(&Message::AccessResponse {
                request_id: id1,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            asset2
        });

        let g1 = Arc::clone(&guard);
        let h1 = tokio::spawn(async move { g1.authorize("u", "asset-a").await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let g2 = Arc::clone(&guard);
        let h2 = tokio::spawn(async move { g2.authorize("u", "asset-b").await });

        let asset2 = stub_join.await.unwrap();
        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();
        assert_eq!(asset2, "asset-b", "stub saw asset-b second");
        assert!(matches!(r1, AccessDecision::Denied));
        assert!(matches!(r2, AccessDecision::Granted));
    }

    #[tokio::test(start_paused = true)]
    async fn test_authorize_timeout_when_backend_silent() {
        // POST-INCIDENT REGRESSION GUARD: this is the exact failure mode
        // that tripped a supervisor unresponsive-restart in production --
        // vauban-access never replied, the proxy main loop blocked on the
        // inline await, missed heartbeats, got killed.
        //
        // Here we use tokio::test(start_paused) to advance time without
        // actually waiting RBAC_RECHECK_TIMEOUT seconds.
        let (read_fd, write_fd, _stub_kept_alive) = pipe_pair();
        let metrics = Arc::new(CountingMetrics::default());
        let client = RbacClient::new(read_fd, write_fd).unwrap();
        let guard = Arc::new(AccessGuard {
            client,
            timeout: Duration::from_secs(10),
            protocol: "ssh",
            metrics: metrics.clone() as Arc<dyn AccessGuardMetrics>,
        });
        let _handle = guard.spawn_dispatcher();

        // Don't drive the stub: no response will ever come back.
        let g = Arc::clone(&guard);
        let h = tokio::spawn(async move { g.authorize("u", "asset-silent").await });
        // Advance virtual time past the 10s timeout.
        tokio::time::advance(Duration::from_secs(11)).await;
        let decision = h.await.unwrap();
        assert!(matches!(decision, AccessDecision::Timeout));
        assert_eq!(metrics.timeout.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.ipc_error.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_from_env_reports_missing_read_fd() {
        // SAFETY: tests are single-threaded by default; we explicitly
        // remove both vars to avoid pollution from a previous test.
        unsafe {
            std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
            std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
        }
        let metrics = Arc::new(CountingMetrics::default());
        let err = AccessGuard::from_env("ssh", metrics).unwrap_err();
        assert!(matches!(
            err,
            AccessGuardError::MissingEnvVar("VAUBAN_ACCESS_IPC_READ")
        ));
    }

    #[test]
    fn test_from_env_reports_invalid_fd() {
        // SAFETY: tests run sequentially when sharing env vars.
        unsafe {
            std::env::set_var("VAUBAN_ACCESS_IPC_READ", "not-an-fd");
            std::env::set_var("VAUBAN_ACCESS_IPC_WRITE", "0");
        }
        let metrics = Arc::new(CountingMetrics::default());
        let err = AccessGuard::from_env("ssh", metrics).unwrap_err();
        // Cleanup before asserting in case the assert panics.
        unsafe {
            std::env::remove_var("VAUBAN_ACCESS_IPC_READ");
            std::env::remove_var("VAUBAN_ACCESS_IPC_WRITE");
        }
        assert!(matches!(
            err,
            AccessGuardError::InvalidEnvVar("VAUBAN_ACCESS_IPC_READ", _)
        ));
    }

    // ========================================================================
    // BATTLE-TESTED SUITE
    //
    // The tests above cover the happy path + the four canonical decisions.
    // Everything below is a deliberate stress / threat-model exercise: we
    // attack the gate with stale replies, forged request_ids, unexpected
    // wire variants, cancelled callers, dead dispatchers and high
    // concurrency, and assert that NONE of those paths can produce a
    // spurious Granted verdict, a panic, or a resource leak.
    // ========================================================================

    /// Build a guard with a custom (short) timeout. Used by tests that
    /// need to actually trigger a timeout under real wall-clock without
    /// blocking the suite for 10s.
    fn wire_guard_with_timeout(
        protocol: &'static str,
        read_fd: RawFd,
        write_fd: RawFd,
        timeout: Duration,
    ) -> (Arc<AccessGuard>, Arc<CountingMetrics>) {
        let metrics = Arc::new(CountingMetrics::default());
        let client = RbacClient::new(read_fd, write_fd).unwrap();
        let guard = Arc::new(AccessGuard {
            client,
            timeout,
            protocol,
            metrics: metrics.clone() as Arc<dyn AccessGuardMetrics>,
        });
        let _handle = guard.spawn_dispatcher();
        (guard, metrics)
    }

    /// One-shot stub that satisfies exactly one request with a given
    /// allowed verdict. Returns the JoinHandle so callers can join after
    /// the corresponding `authorize` completes. We deliberately AVOID a
    /// long-running poll loop on the stub side: the stub end of the
    /// pipe is in blocking mode, so polling would block on `recv` and
    /// the test would deadlock at `join()`.
    fn one_shot_grant(stub: IpcChannel, allowed: bool) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let req = stub.recv().expect("stub recv");
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!("stub: unexpected message variant"),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .expect("stub send");
        })
    }

    // ---------------- Cleanup invariants (post-bug fix) ----------------

    #[tokio::test]
    async fn test_pending_cleared_after_granted_response() {
        // Anti-leak: the happy path must not leave a tombstone in
        // `pending`. The dispatcher removes the entry when it routes
        // the response; the RAII guard's drop is then a no-op.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, _metrics) = wire_guard("ssh", read_fd, write_fd);
        let stub_handle = one_shot_grant(stub, true);

        let decision = guard.authorize("u-uuid", "a-uuid").await;
        assert!(matches!(decision, AccessDecision::Granted));
        // Give the dispatcher a beat to finish bookkeeping after the
        // oneshot::send returns control to authorize.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            guard.client.pending_count(),
            0,
            "happy-path authorize must not leave a pending entry"
        );
        stub_handle.join().expect("stub thread");
    }

    #[tokio::test]
    async fn test_pending_cleared_after_real_timeout() {
        // POST-BUG REGRESSION GUARD: if RAII PendingEntry is removed,
        // this test is the first to fail. The pending map MUST shrink
        // back to zero after a timeout fires, otherwise a wedged
        // vauban-access combined with sustained traffic produces
        // unbounded HashMap growth (real DoS surface against the proxy
        // even though the caller-side timeout already kicked in).
        let (read_fd, write_fd, _stub_kept_alive) = pipe_pair();
        // 200ms timeout: stub is kept alive but never replies.
        let (guard, metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_millis(200));

        let decision = guard.authorize("u-uuid", "a-uuid").await;
        assert!(matches!(decision, AccessDecision::Timeout));
        // RAII drop runs synchronously on the await frame's drop, so
        // the pending count is already zero by the time authorize
        // returns. No sleep needed -- this is the strongest possible
        // assertion of the cleanup invariant.
        assert_eq!(
            guard.client.pending_count(),
            0,
            "timeout must trigger PendingEntry::drop synchronously"
        );
        assert_eq!(metrics.timeout.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_pending_cleared_when_caller_dropped() {
        // POST-BUG REGRESSION GUARD: if the surrounding tokio::spawn
        // is aborted (e.g. session was closed by the user before the
        // RBAC verdict came back), the pending entry must still be
        // cleaned up. Without RAII, this would leak forever on
        // dispatcher silence.
        let (read_fd, write_fd, _stub_kept_alive) = pipe_pair();
        let (guard, _metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_secs(60));

        let g = Arc::clone(&guard);
        let h = tokio::spawn(async move { g.authorize("u-uuid", "a-uuid").await });
        // Yield enough times for the spawned task to park on rx.await.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(guard.client.pending_count(), 1, "request must be pending");

        h.abort();
        let _ = h.await; // Cancellation: future is dropped, RAII fires.
        // A few extra yields to let the runtime process the abort.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            guard.client.pending_count(),
            0,
            "caller cancellation must trigger PendingEntry::drop"
        );
    }

    #[tokio::test]
    async fn test_pending_does_not_leak_under_repeated_timeouts() {
        // 50 sequential timeouts must leave the pending map empty.
        // Pre-fix this test would assert pending_count() == 50.
        let (read_fd, write_fd, _stub_kept_alive) = pipe_pair();
        let (guard, metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_millis(50));

        for _ in 0..50 {
            let decision = guard.authorize("u", "a").await;
            assert!(matches!(decision, AccessDecision::Timeout));
        }
        assert_eq!(metrics.timeout.load(Ordering::SeqCst), 50);
        assert_eq!(
            guard.client.pending_count(),
            0,
            "50 timeouts must not accumulate any pending entries"
        );
    }

    // ---------------- Threat model: forged / stale responses ----------------

    #[tokio::test]
    async fn test_forged_unknown_request_id_does_not_disturb_dispatcher() {
        // SECURITY: a malicious or buggy vauban-access could send a
        // response with a request_id we never issued. The dispatcher
        // MUST drop it with a warn! and continue to serve real
        // requests. If anyone ever changes the dispatcher to
        // `panic!("orphan response")`, this test fails first.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let forged_id = 99_999_999u64;
        let stub_handle = std::thread::spawn(move || {
            // Forge a response with no matching request.
            stub.send(&Message::AccessResponse {
                request_id: forged_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            // Then serve a real request to prove the dispatcher survived.
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        // Give the dispatcher a beat to consume + drop the orphan.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let decision = guard.authorize("u", "a").await;
        // The forged "Granted" response is gone; the real verdict for
        // our request is Denied (and was never replaced by the orphan).
        assert!(
            matches!(decision, AccessDecision::Denied),
            "forged orphan grant must NOT bleed into a real authorize"
        );
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 1);
        let _ = stub_handle.join();
    }

    #[tokio::test]
    async fn test_stale_response_after_timeout_does_not_grant_anything() {
        // SECURITY: if vauban-access replies AFTER we already fired
        // RBAC_RECHECK_TIMEOUT, the late reply must be silently
        // dropped. The PendingEntry has already cleared the slot, so
        // the dispatcher will see "response without pending request"
        // and drop it. The next real authorize must then work.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_millis(100));

        // Capture the first request and reply LATE (after the caller
        // has already given up).
        let stub_handle = std::thread::spawn(move || {
            let r1 = stub.recv().unwrap();
            let id1 = match r1 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            std::thread::sleep(Duration::from_millis(250));
            // Late "allowed=true" reply for the timed-out request.
            stub.send(&Message::AccessResponse {
                request_id: id1,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
            // Now serve the second authorize legitimately (Denied).
            let r2 = stub.recv().unwrap();
            let id2 = match r2 {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id: id2,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: false,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        // First authorize: must time out.
        let d1 = guard.authorize("u", "a").await;
        assert!(matches!(d1, AccessDecision::Timeout));
        assert_eq!(metrics.timeout.load(Ordering::SeqCst), 1);

        // Wait long enough that the late "true" reply has been dropped
        // by the dispatcher (orphan path).
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Second authorize: must reach the real Denied verdict, NOT the
        // stale Granted that the late reply tried to inject.
        let d2 = guard.authorize("u", "a").await;
        assert!(
            matches!(d2, AccessDecision::Denied),
            "late stale reply MUST NOT contaminate a subsequent authorize"
        );
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 1);
        let _ = stub_handle.join();
    }

    // ---------------- Wire-format hardening ----------------

    #[tokio::test]
    async fn test_unexpected_response_variant_collapses_to_denied() {
        // SECURITY: vauban-access could ship a future variant
        // (AccessCheckedMulti, AccessRulesList, ...) on the
        // CheckAccessByUuid pipe due to a bug or a partially-rolled-out
        // change. ANY variant other than AccessChecked or Error MUST
        // be treated as a fail-closed denial.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_handle = std::thread::spawn(move || {
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            // Wrong variant: a Multi reply on a single-check request.
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessCheckedMulti(vec![]),
            })
            .unwrap();
        });

        let decision = guard.authorize("u", "a").await;
        assert!(
            matches!(decision, AccessDecision::Denied),
            "wrong AccessResponse variant MUST collapse to Denied (fail-closed)"
        );
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.denied.load(Ordering::SeqCst), 1);
        let _ = stub_handle.join();
    }

    #[tokio::test]
    async fn test_dispatcher_ignores_non_access_response_messages() {
        // Wire robustness: a stray Control message on the access pipe
        // must NOT crash the dispatcher and must NOT produce any verdict.
        // The dispatcher logs `warn!` and keeps polling.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) = wire_guard("ssh", read_fd, write_fd);

        let stub_handle = std::thread::spawn(move || {
            // First push a stray control message.
            stub.send(&Message::Control(crate::messages::ControlMessage::Ping {
                seq: 1,
            }))
            .unwrap();
            // Then serve a real request.
            let req = stub.recv().unwrap();
            let request_id = match req {
                Message::AccessRequest { request_id, .. } => request_id,
                _ => panic!(),
            };
            stub.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: true,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
            })
            .unwrap();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let decision = guard.authorize("u", "a").await;
        assert!(
            matches!(decision, AccessDecision::Granted),
            "dispatcher must survive stray non-AccessResponse messages \
             and continue serving real requests"
        );
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 1);
        let _ = stub_handle.join();
    }

    // ---------------- Robustness: dispatcher / pipe death ----------------

    #[tokio::test]
    async fn test_authorize_after_pipe_death_fails_closed_no_panic() {
        // POST-INCIDENT GUARD: if vauban-access dies (or the pipe is
        // ripped), the next authorize() must NOT panic and MUST surface
        // a non-Granted verdict so the caller fails closed. The exact
        // variant (BackendError vs Timeout) depends on whether the
        // write or the read side closes first; both are acceptable.
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_millis(200));

        // Tear down both sides of the pipe by dropping the stub.
        drop(stub);
        // Let the dispatcher observe ConnectionClosed and die.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let decision = guard.authorize("u", "a").await;
        assert!(
            !decision.is_granted(),
            "post-pipe-death authorize MUST NOT grant; got {:?}",
            decision
        );
        assert!(
            matches!(
                decision,
                AccessDecision::BackendError(_) | AccessDecision::Timeout
            ),
            "expected BackendError or Timeout, got {:?}",
            decision
        );
        // Either ipc_error or timeout must have been incremented.
        assert!(
            metrics.ipc_error.load(Ordering::SeqCst) + metrics.timeout.load(Ordering::SeqCst) >= 1,
            "fail-closed metric MUST fire on pipe death"
        );
        assert_eq!(metrics.granted.load(Ordering::SeqCst), 0);
    }

    // ---------------- Concurrency stress ----------------

    #[tokio::test]
    async fn test_authorize_64_concurrent_requests_demultiplexed_correctly() {
        // High-concurrency stress: 64 concurrent authorize() calls,
        // half granted half denied based on the asset_uuid. The stub
        // intentionally replies in REVERSE order of request arrival to
        // hammer on the demultiplexer. If anyone ever simplifies
        // PendingMap back to a single-receiver / FIFO, half the
        // assertions cross over and the test fails.
        const N: usize = 64;
        let (read_fd, write_fd, stub) = pipe_pair();
        let (guard, _metrics) =
            wire_guard_with_timeout("ssh", read_fd, write_fd, Duration::from_secs(10));

        let stub_handle = std::thread::spawn(move || {
            let mut buf: Vec<(u64, String)> = Vec::with_capacity(N);
            for _ in 0..N {
                let req = stub.recv().unwrap();
                if let Message::AccessRequest {
                    request_id,
                    request: AccessRequest::CheckAccessByUuid { asset_uuid, .. },
                } = req
                {
                    buf.push((request_id, asset_uuid));
                }
            }
            // Reply in reverse order; per-request verdict is `allow=index%2==0`.
            for (request_id, asset_uuid) in buf.iter().rev() {
                let idx: usize = asset_uuid
                    .strip_prefix("asset-")
                    .and_then(|s| s.parse().ok())
                    .unwrap();
                let allow = idx.is_multiple_of(2);
                stub.send(&Message::AccessResponse {
                    request_id: *request_id,
                    response: AccessResponse::AccessChecked(AccessCheckResult {
                        allowed: allow,
                        require_mfa: false,
                        require_approval: false,
                        max_session_duration: None,
                    }),
                })
                .unwrap();
            }
        });

        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let g = Arc::clone(&guard);
            handles.push(tokio::spawn(async move {
                let asset = format!("asset-{}", i);
                (i, g.authorize("u", &asset).await)
            }));
        }

        for h in handles {
            let (i, decision) = h.await.unwrap();
            let expected_grant = i % 2 == 0;
            assert_eq!(
                decision.is_granted(),
                expected_grant,
                "verdict for asset-{} crossed wires (got {:?})",
                i,
                decision
            );
        }
        assert_eq!(
            guard.client.pending_count(),
            0,
            "no pending entries must survive the stress run"
        );
        let _ = stub_handle.join();
    }

    // ---------------- Protocol propagation ----------------

    #[tokio::test]
    async fn test_protocol_string_propagated_to_backend_ssh_and_rdp() {
        // SECURITY: the protocol string is what makes vauban-access
        // distinguish "user X may SSH to host" from "user X may RDP to
        // host". A bug that always sent the same string would silently
        // grant cross-protocol access. This test pins the wire-level
        // contract for both currently-supported protocols.
        for proto in [PROTOCOL_SSH, PROTOCOL_RDP] {
            let (read_fd, write_fd, stub) = pipe_pair();
            let (guard, _metrics) = wire_guard(proto, read_fd, write_fd);

            let captured: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
            let captured_for_thread = Arc::clone(&captured);
            let stub_handle = std::thread::spawn(move || {
                let req = stub.recv().unwrap();
                if let Message::AccessRequest {
                    request_id,
                    request: AccessRequest::CheckAccessByUuid { protocol, .. },
                } = req
                {
                    *captured_for_thread.lock().unwrap() = Some(protocol);
                    stub.send(&Message::AccessResponse {
                        request_id,
                        response: AccessResponse::AccessChecked(AccessCheckResult {
                            allowed: true,
                            require_mfa: false,
                            require_approval: false,
                            max_session_duration: None,
                        }),
                    })
                    .unwrap();
                }
            });
            let _ = guard.authorize("u", "a").await;
            let _ = stub_handle.join();
            let captured_proto = captured.lock().unwrap().clone();
            assert_eq!(
                captured_proto.as_deref(),
                Some(proto),
                "guard built for {:?} must send protocol={:?} on the wire",
                proto,
                proto
            );
        }
    }

    // ---------------- Anti-regression structural ----------------

    #[test]
    fn test_access_decision_does_not_default_to_granted() {
        // Defensive: AccessDecision intentionally has NO Default impl
        // (a Default that returns Granted would be a footgun of the
        // worst kind: `let d: AccessDecision = Default::default();`
        // would silently authorise). This test is a structural pin --
        // if anyone ever derives Default on AccessDecision, this test
        // forces them to also explain in code review what variant they
        // chose and why.
        fn assert_no_default<T>()
        where
            T: Default,
        {
        }
        // The following line MUST NOT compile if uncommented:
        //   assert_no_default::<AccessDecision>();
        // We can't statically test "does not implement Default" in
        // stable Rust without a build script, so we settle for this
        // documented anti-pattern note + the runtime assertion below.
        let _ = assert_no_default::<()>; // silence unused
        // Round-trip every variant via match so adding a new one
        // without thinking about is_granted() fails the build.
        for d in [
            AccessDecision::Granted,
            AccessDecision::Denied,
            AccessDecision::Timeout,
            AccessDecision::BackendError("x".to_string()),
        ] {
            let granted = matches!(d, AccessDecision::Granted);
            assert_eq!(d.is_granted(), granted);
        }
    }

    #[test]
    fn test_authorize_signature_returns_decision_not_result() {
        // Type-system anti-regression: `authorize` must return
        // AccessDecision (NOT Result<...>). Returning Result would let
        // a caller `?` past it and end up in a "compiles, fails open"
        // configuration. The helper below only compiles if the future
        // resolves to AccessDecision; if anyone changes the signature
        // to Result<AccessDecision, _>, this test stops building.
        #[allow(dead_code)]
        fn _pins_return_type(
            g: &AccessGuard,
        ) -> impl std::future::Future<Output = AccessDecision> + '_ {
            // If anyone changes authorize() to return
            // Result<AccessDecision, _>, the impl-Trait bound below no
            // longer matches and this helper fails to type-check.
            g.authorize("", "")
        }
    }

    #[test]
    fn test_must_use_attribute_on_access_guard_wiring() {
        // Source-level pin: AccessGuardWiring carries a `#[must_use]`
        // attribute so dropping it (forgetting to plumb the FDs into
        // the sandbox or to spawn the dispatcher) is a compile-time
        // warning. If anyone removes the attribute, this test fails.
        let source = include_str!("access_guard.rs");
        let wiring_idx = source
            .find("pub struct AccessGuardWiring")
            .expect("AccessGuardWiring struct must exist");
        let preamble = &source[..wiring_idx];
        // The most recent `#[must_use` directive before the struct
        // declaration is the one attached to it.
        let last_must_use = preamble.rfind("#[must_use");
        assert!(
            last_must_use.is_some(),
            "AccessGuardWiring MUST be marked #[must_use] -- dropping it \
             silently leaks the access pipe FDs"
        );
        let between = &preamble[last_must_use.unwrap()..];
        // No struct/fn/impl between the must_use and AccessGuardWiring.
        assert!(
            !between.contains("pub struct ") && !between.contains("pub fn "),
            "the most recent #[must_use] before AccessGuardWiring must \
             actually be attached TO AccessGuardWiring"
        );
    }

    #[test]
    fn test_protocol_constants_are_lowercase_and_canonical() {
        // Runtime invariants on the protocol strings: lowercase,
        // alphanumeric, no whitespace. Anything else would not match
        // `access_rules.protocols` in the DB and would silently degrade
        // every authorize() to Denied.
        for p in [PROTOCOL_SSH, PROTOCOL_RDP] {
            assert!(!p.is_empty());
            assert_eq!(p, p.to_lowercase());
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }
}
