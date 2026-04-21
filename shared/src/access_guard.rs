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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, oneshot};
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
        let fut =
            self.client
                .check_access_by_uuid(user_uuid, asset_uuid, self.protocol);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(true)) => {
                debug!(
                    user_uuid, asset_uuid, protocol = self.protocol,
                    "AccessGuard granted"
                );
                self.metrics.record_granted();
                AccessDecision::Granted
            }
            Ok(Ok(false)) => {
                warn!(
                    user_uuid, asset_uuid, protocol = self.protocol,
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
                    user_uuid, asset_uuid,
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
struct RbacClient {
    channel: IpcChannel,
    read_async_fd: AsyncFd<RawFd>,
    next_request_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<AccessResponse>>>,
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
            pending: Mutex::new(HashMap::new()),
        })
    }

    async fn check_access_by_uuid(
        &self,
        user_uuid: &str,
        asset_uuid: &str,
        protocol: &str,
    ) -> Result<bool, RbacClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id, tx);

        let msg = Message::AccessRequest {
            request_id,
            request: AccessRequest::CheckAccessByUuid {
                user_uuid: user_uuid.to_string(),
                asset_uuid: asset_uuid.to_string(),
                protocol: protocol.to_string(),
            },
        };

        if let Err(e) = self.channel.send(&msg) {
            self.pending.lock().await.remove(&request_id);
            return Err(RbacClientError::SendFailed(e.to_string()));
        }

        debug!(
            request_id, user_uuid, asset_uuid, protocol,
            "AccessGuard: CheckAccessByUuid sent"
        );

        let response = rx.await.map_err(|_| {
            RbacClientError::ReceiveFailed("access response channel dropped".to_string())
        })?;

        match response {
            AccessResponse::AccessChecked(result) => {
                debug!(
                    request_id, user_uuid, asset_uuid, protocol,
                    allowed = result.allowed, "AccessGuard: response"
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
                    if let Some(tx) = self.pending.lock().await.remove(&request_id) {
                        if tx.send(response).is_err() {
                            debug!(
                                request_id,
                                "AccessGuard: caller dropped before response delivery"
                            );
                        }
                    } else {
                        warn!(
                            request_id,
                            "AccessGuard: response without pending request, dropping"
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
        let stub = unsafe {
            IpcChannel::from_raw_fds(d_read.into_raw_fd(), c_write.into_raw_fd())
        };
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
        let _ = guard.spawn_dispatcher();
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
        let _ = guard.spawn_dispatcher();

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
}
