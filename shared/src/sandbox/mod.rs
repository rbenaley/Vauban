//! Multi-OS process sandbox abstraction.
//!
//! Vauban runs every de-privileged service inside an OS sandbox. FreeBSD
//! (the officially supported production target) uses Capsicum; we also
//! provide best-effort sandboxes for Linux (Landlock + seccomp-bpf) and
//! OpenBSD (pledge + unveil) so operators on those platforms are not left
//! unconfined.
//!
//! # Design: describe intent, not mechanism
//!
//! The three backends do not share a control unit (Capsicum is per-fd,
//! Landlock is per-path, seccomp is per-syscall, pledge is per-promise).
//! The only common denominator is the *intent*: "this service holds an IPC
//! pipe it reads/writes", "it receives fds via SCM_RIGHTS", "it accepts on
//! this listener", "it writes into this directory". Callers therefore build
//! a [`SandboxProfile`] of [`Resource`]s and call [`enter_sandbox`]; each
//! backend projects the intent onto its native primitive.
//!
//! # Lifecycle invariant
//!
//! Every backend is irreversible and order-sensitive: open every resource,
//! set every fd flag (e.g. `O_NONBLOCK`), THEN call [`enter_sandbox`] once.
//! [`enter_sandbox`] consumes the profile by value (commit-once) and returns
//! an [`Entered`] witness that the service main loop / `serve()` is expected
//! to take, so "run the service without sandboxing" is a compile error.

use std::os::unix::io::RawFd;
use std::path::PathBuf;
use thiserror::Error;

pub mod profiles;

#[cfg(target_os = "freebsd")]
mod capsicum;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "freebsd", target_os = "linux", target_os = "openbsd")))]
mod noop;
#[cfg(target_os = "openbsd")]
mod openbsd;

/// Errors raised while applying a sandbox.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Entering the irreversible sandbox mode failed.
    #[error("Failed to enter sandbox: {0}")]
    EnterFailed(std::io::Error),

    /// Restricting the rights on a pre-opened resource failed.
    #[error("Failed to limit resource rights: {0}")]
    LimitFailed(std::io::Error),

    /// The sandbox mechanism is required (production) but unavailable on
    /// this kernel. The service MUST refuse to start (fail-closed).
    #[error("Sandbox required but unavailable on this platform/kernel: {0}")]
    Unavailable(String),
}

/// Result type for sandbox operations.
pub type Result<T> = std::result::Result<T, SandboxError>;

/// How strictly the sandbox must be applied.
///
/// `BestEffort` (default) downgrades gracefully (with a `warn!`) when the
/// kernel lacks the mechanism -- appropriate for development. `Required`
/// makes [`enter_sandbox`] fail-closed (return [`SandboxError::Unavailable`])
/// rather than run unconfined -- appropriate for production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxRequirement {
    /// Degrade gracefully if the mechanism is unavailable (dev).
    #[default]
    BestEffort,
    /// Fail-closed if the mechanism is unavailable (prod).
    Required,
}

/// The intent-level resources a service holds across the sandbox boundary.
///
/// This enum is crate-internal on purpose: every backend matches on it
/// EXHAUSTIVELY (no `_ =>` arm). Adding a variant therefore fails to
/// compile until all backends handle it. Pinned at runtime by
/// [`Resource::COUNT`] and the `all_variants_*` drift tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resource {
    /// Bidirectional IPC pipe (read + write).
    IpcPipe(RawFd),
    /// Unix socket that receives fds via SCM_RIGHTS (recvmsg, no write).
    FdReceiver(RawFd),
    /// Already-connected socket (DB, cache): read/write, never `connect()`.
    ConnectedSocket(RawFd),
    /// Pre-bound listening socket: `accept()` + inherited read/write.
    Listener(RawFd),
    /// Writable directory. Carries BOTH representations: the dir fd
    /// (Capsicum `openat`/`mkdirat`) and the path (Landlock / unveil).
    WritableDir { fd: RawFd, path: PathBuf },
    /// Read-only path (Landlock / unveil; no Capsicum equivalent).
    ReadablePath(PathBuf),
}

impl Resource {
    /// Number of `Resource` variants. Kept in lock-step with the enum by
    /// `resource_count_matches_all_variants`. Consumed by the drift tests
    /// (hence `dead_code`-allowed on non-test builds).
    #[allow(dead_code)]
    pub(crate) const COUNT: usize = 6;

    /// The mechanism-agnostic kind, used for profile drift checks.
    pub(crate) fn kind(&self) -> profiles::ResourceKind {
        use profiles::ResourceKind as K;
        match self {
            Resource::IpcPipe(_) => K::IpcPipe,
            Resource::FdReceiver(_) => K::FdReceiver,
            Resource::ConnectedSocket(_) => K::ConnectedSocket,
            Resource::Listener(_) => K::Listener,
            Resource::WritableDir { .. } => K::WritableDir,
            Resource::ReadablePath(_) => K::ReadablePath,
        }
    }
}

/// A declarative, additive description of what a service needs across the
/// sandbox boundary. The builder is **monotone**: it can only add
/// resources, never relax a restriction (mirrors Capsicum/Landlock/pledge
/// monotonicity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxProfile {
    resources: Vec<Resource>,
    requirement: SandboxRequirement,
    /// On FreeBSD/Capsicum, whether to call `cap_rights_limit` on each fd.
    /// `true` by default. A network server (vauban-web) sets this to
    /// `false` because tokio/axum require a hard-to-enumerate right set on
    /// the listener; it relies on `cap_enter()` as the wall instead.
    capsicum_limit_fds: bool,
}

impl Default for SandboxProfile {
    fn default() -> Self {
        Self {
            resources: Vec::new(),
            requirement: SandboxRequirement::default(),
            capsicum_limit_fds: true,
        }
    }
}

impl SandboxProfile {
    /// A new, empty profile (`compute_only`): the tightest sandbox, holding
    /// no resource beyond what is added. Used by CPU-only services.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the fail-closed requirement (prod vs dev).
    #[must_use]
    pub fn requirement(mut self, requirement: SandboxRequirement) -> Self {
        self.requirement = requirement;
        self
    }

    /// Add a bidirectional IPC pipe fd (read + write).
    #[must_use]
    pub fn ipc_pipe(mut self, fd: RawFd) -> Self {
        self.resources.push(Resource::IpcPipe(fd));
        self
    }

    /// Add several IPC pipe fds at once.
    #[must_use]
    pub fn ipc_pipes(mut self, fds: &[RawFd]) -> Self {
        for &fd in fds {
            self.resources.push(Resource::IpcPipe(fd));
        }
        self
    }

    /// Add an SCM_RIGHTS fd-receiver socket (recvmsg only).
    #[must_use]
    pub fn fd_receiver(mut self, fd: RawFd) -> Self {
        self.resources.push(Resource::FdReceiver(fd));
        self
    }

    /// Add an already-connected socket (DB / cache).
    #[must_use]
    pub fn connected_socket(mut self, fd: RawFd) -> Self {
        self.resources.push(Resource::ConnectedSocket(fd));
        self
    }

    /// Add a pre-bound listening socket the service `accept()`s on.
    #[must_use]
    pub fn listener(mut self, fd: RawFd) -> Self {
        self.resources.push(Resource::Listener(fd));
        self
    }

    /// Add a writable directory (both dir fd and path).
    #[must_use]
    pub fn writable_dir(mut self, fd: RawFd, path: PathBuf) -> Self {
        self.resources.push(Resource::WritableDir { fd, path });
        self
    }

    /// Add a read-only path (Landlock / unveil only).
    #[must_use]
    pub fn readable_path(mut self, path: PathBuf) -> Self {
        self.resources.push(Resource::ReadablePath(path));
        self
    }

    /// Disable Capsicum per-fd rights limiting (still calls `cap_enter`).
    ///
    /// For network servers whose runtime (tokio/axum) needs a right set
    /// that is impractical to enumerate on the listener; the wall is
    /// `cap_enter()` itself. No effect on Linux/OpenBSD backends.
    #[must_use]
    pub fn without_capsicum_fd_limiting(mut self) -> Self {
        self.capsicum_limit_fds = false;
        self
    }

    /// The declared resources (crate-internal: backends consume this).
    pub(crate) fn resources(&self) -> &[Resource] {
        &self.resources
    }

    /// Whether the Capsicum backend should limit per-fd rights. Consumed by
    /// the FreeBSD backend (hence `dead_code`-allowed on other targets).
    #[allow(dead_code)]
    pub(crate) fn capsicum_limit_fds(&self) -> bool {
        self.capsicum_limit_fds
    }

    /// The fail-closed requirement.
    pub(crate) fn required(&self) -> bool {
        matches!(self.requirement, SandboxRequirement::Required)
    }

    /// The multiset of resource kinds, sorted, for profile drift checks.
    #[must_use]
    pub fn kinds(&self) -> Vec<profiles::ResourceKind> {
        let mut k: Vec<_> = self.resources.iter().map(Resource::kind).collect();
        k.sort_unstable();
        k
    }
}

/// Zero-sized witness proving the sandbox was committed.
///
/// Returned by [`enter_sandbox`] and the `setup_service_sandbox*` helpers.
/// Thread it into the service main loop / `serve()` so that running the
/// service without entering the sandbox is a compile error. Cannot be
/// constructed outside this module.
#[must_use = "the Entered token gates the service main loop: thread it into run()/serve() so the sandbox cannot be skipped"]
#[derive(Debug)]
pub struct Entered {
    /// `true` when a real OS sandbox was committed (Capsicum, Landlock+seccomp,
    /// pledge+unveil). `false` on development platforms where the noop backend
    /// runs unconfined after the noop backend's development-only warning.
    active: bool,
}

impl Entered {
    /// Whether an OS sandbox mechanism was actually applied.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Construct the witness. Crate-internal: only a backend `commit` may mint one.
    pub(crate) fn witness(active: bool) -> Self {
        Entered { active }
    }
}

/// Log that the service main loop is about to start.
///
/// When [`Entered::is_active`] is true, prefixes with `Entered sandbox`.
/// On development platforms (noop backend) only the tail is logged at INFO;
/// the noop backend already warned that the process is unconfined.
pub fn log_main_loop_start(sealed: &Entered, message: &str) {
    if sealed.is_active() {
        tracing::info!("Entered sandbox, {message}");
    } else {
        tracing::info!("{message}");
    }
}

/// A per-OS sandbox mechanism.
///
/// `restrict` is called once per declared [`Resource`] (every backend
/// matches the resource EXHAUSTIVELY, accumulating native rules); `commit`
/// then enters the irreversible sandbox mode and mints the [`Entered`]
/// witness. Backends are driven uniformly by [`run_backend`].
pub(crate) trait SandboxBackend: Sized {
    /// Accumulate the native restriction for one resource.
    fn restrict(&mut self, resource: &Resource) -> Result<()>;

    /// Commit the accumulated restrictions and enter the sandbox.
    ///
    /// `required` reflects [`SandboxRequirement::Required`]: a backend whose
    /// mechanism is unavailable MUST return [`SandboxError::Unavailable`]
    /// when `required` is set (fail-closed), rather than enter unconfined.
    fn commit(self, required: bool) -> Result<Entered>;
}

/// Drive a backend over a profile: restrict every resource, then commit.
pub(crate) fn run_backend<B: SandboxBackend>(
    mut backend: B,
    profile: &SandboxProfile,
) -> Result<Entered> {
    for resource in profile.resources() {
        backend.restrict(resource)?;
    }
    backend.commit(profile.required())
}

/// Apply `profile` and enter the OS sandbox (irreversible, commit-once).
///
/// Consumes the profile by value so a profile cannot be reused after entry.
/// Dispatches to the per-OS backend at compile time.
pub fn enter_sandbox(profile: SandboxProfile) -> Result<Entered> {
    dispatch(profile)
}

#[cfg(target_os = "freebsd")]
fn dispatch(profile: SandboxProfile) -> Result<Entered> {
    capsicum::apply(profile)
}

#[cfg(target_os = "linux")]
fn dispatch(profile: SandboxProfile) -> Result<Entered> {
    linux::apply(profile)
}

#[cfg(target_os = "openbsd")]
fn dispatch(profile: SandboxProfile) -> Result<Entered> {
    openbsd::apply(profile)
}

#[cfg(not(any(target_os = "freebsd", target_os = "linux", target_os = "openbsd")))]
fn dispatch(profile: SandboxProfile) -> Result<Entered> {
    noop::apply(profile)
}

// ============================================================================
// Backward-compatible helpers (stable call surface for the services).
//
// These keep the exact fd -> rights mapping the codebase relied on before
// the multi-OS refactor, so the FreeBSD production behavior is unchanged.
// They now return the `Entered` witness (typestate).
// ============================================================================

/// Setup sandbox for a service with typical IPC pipes (+ optional DB socket).
pub fn setup_service_sandbox(ipc_fds: &[RawFd], db_fd: Option<RawFd>) -> Result<Entered> {
    setup_service_sandbox_extended(ipc_fds, db_fd, None)
}

/// Like [`setup_service_sandbox`], plus SCM_RIGHTS fd-receiver sockets.
pub fn setup_service_sandbox_extended(
    ipc_fds: &[RawFd],
    db_fd: Option<RawFd>,
    fd_receiver_fds: Option<&[RawFd]>,
) -> Result<Entered> {
    setup_service_sandbox_with_listeners(ipc_fds, db_fd, fd_receiver_fds, None)
}

/// Like [`setup_service_sandbox_extended`], plus pre-bound listening sockets
/// the service `accept()`s on after entering the sandbox.
pub fn setup_service_sandbox_with_listeners(
    ipc_fds: &[RawFd],
    db_fd: Option<RawFd>,
    fd_receiver_fds: Option<&[RawFd]>,
    listener_fds: Option<&[RawFd]>,
) -> Result<Entered> {
    let mut profile = SandboxProfile::new().ipc_pipes(ipc_fds);
    if let Some(fd) = db_fd {
        profile = profile.connected_socket(fd);
    }
    for &fd in fd_receiver_fds.unwrap_or(&[]) {
        profile = profile.fd_receiver(fd);
    }
    for &fd in listener_fds.unwrap_or(&[]) {
        profile = profile.listener(fd);
    }
    enter_sandbox(profile)
}

#[cfg(test)]
mod tests {
    use super::profiles::ResourceKind;
    use super::*;

    #[test]
    fn resource_count_matches_all_variants() {
        // If a Resource variant is added, bump COUNT and handle it in every
        // backend (the exhaustive match will refuse to compile otherwise).
        let sample = [
            Resource::IpcPipe(0),
            Resource::FdReceiver(0),
            Resource::ConnectedSocket(0),
            Resource::Listener(0),
            Resource::WritableDir {
                fd: 0,
                path: PathBuf::from("/x"),
            },
            Resource::ReadablePath(PathBuf::from("/x")),
        ];
        assert_eq!(sample.len(), Resource::COUNT);
        // Every sample maps to a distinct kind.
        let mut kinds: Vec<_> = sample.iter().map(Resource::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), Resource::COUNT);
    }

    #[test]
    fn profile_builder_is_additive_and_ordered() {
        let p = SandboxProfile::new()
            .ipc_pipe(3)
            .connected_socket(4)
            .listener(5)
            .fd_receiver(6);
        assert_eq!(p.resources().len(), 4);
        // Empty profile is the tightest: no resource.
        assert!(SandboxProfile::new().resources().is_empty());
    }

    #[test]
    fn empty_profile_is_compute_only() {
        let p = SandboxProfile::new();
        assert!(p.kinds().is_empty());
        assert!(p.capsicum_limit_fds());
        assert!(!p.required());
    }

    #[test]
    fn requirement_round_trips() {
        let p = SandboxProfile::new().requirement(SandboxRequirement::Required);
        assert!(p.required());
    }

    #[test]
    fn compat_helpers_build_expected_kinds() {
        // setup_service_sandbox_with_listeners maps fds the same way the
        // pre-refactor code did. We can only inspect the profile shape here
        // (entering the sandbox is a real syscall, exercised in the
        // behavioral tests).
        let mut profile = SandboxProfile::new().ipc_pipes(&[3, 4]);
        profile = profile.connected_socket(5);
        profile = profile.fd_receiver(6);
        profile = profile.listener(7);
        let mut expected = vec![
            ResourceKind::IpcPipe,
            ResourceKind::IpcPipe,
            ResourceKind::ConnectedSocket,
            ResourceKind::FdReceiver,
            ResourceKind::Listener,
        ];
        expected.sort_unstable();
        assert_eq!(profile.kinds(), expected);
    }

    /// Unique, sorted resource kinds of a profile.
    fn unique_kinds(p: &SandboxProfile) -> Vec<ResourceKind> {
        let mut k = p.kinds();
        k.dedup();
        k
    }

    fn sorted(kinds: &[ResourceKind]) -> Vec<ResourceKind> {
        let mut v = kinds.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// PROFILE DRIFT: the resource shape each service-builder produces MUST
    /// match its canonical catalogue in `profiles.rs`. If a service starts
    /// passing a new fd kind, the catalogue (and the seccomp/pledge deltas
    /// derived from it) must be updated in lock-step or this fails.
    #[test]
    fn service_builders_match_canonical_catalogues() {
        use super::profiles;

        // auth: IPC pipes + fd receiver (LDAPS broker hand-off).
        let auth = SandboxProfile::new().ipc_pipes(&[3, 4]).fd_receiver(5);
        assert_eq!(unique_kinds(&auth), sorted(profiles::AUTH_KINDS));

        // vault / audit: IPC pipes only.
        let vault = SandboxProfile::new().ipc_pipes(&[3, 4]);
        assert_eq!(unique_kinds(&vault), sorted(profiles::VAULT_KINDS));
        assert_eq!(unique_kinds(&vault), sorted(profiles::AUDIT_KINDS));

        // access: IPC pipes + connected DB socket.
        let access = setup_profile_only(&[3, 4], Some(5), None, None);
        assert_eq!(unique_kinds(&access), sorted(profiles::ACCESS_KINDS));

        // proxy-ssh / proxy-rdp: IPC pipes + fd receiver.
        let ssh = setup_profile_only(&[3, 4], None, Some(&[5]), None);
        assert_eq!(unique_kinds(&ssh), sorted(profiles::PROXY_SSH_KINDS));
        assert_eq!(unique_kinds(&ssh), sorted(profiles::PROXY_RDP_KINDS));

        // proxy-iacs: IPC pipes + fd receiver + listener.
        let iacs = setup_profile_only(&[3, 4], None, Some(&[5]), Some(&[6]));
        assert_eq!(unique_kinds(&iacs), sorted(profiles::PROXY_IACS_KINDS));

        // web: listener only.
        let web = profiles::web_server(3);
        assert_eq!(unique_kinds(&web), sorted(profiles::WEB_KINDS));
    }

    /// Mirror of `setup_service_sandbox_with_listeners` profile construction,
    /// WITHOUT entering the sandbox (no real syscall).
    fn setup_profile_only(
        ipc_fds: &[RawFd],
        db_fd: Option<RawFd>,
        fd_receiver_fds: Option<&[RawFd]>,
        listener_fds: Option<&[RawFd]>,
    ) -> SandboxProfile {
        let mut profile = SandboxProfile::new().ipc_pipes(ipc_fds);
        if let Some(fd) = db_fd {
            profile = profile.connected_socket(fd);
        }
        for &fd in fd_receiver_fds.unwrap_or(&[]) {
            profile = profile.fd_receiver(fd);
        }
        for &fd in listener_fds.unwrap_or(&[]) {
            profile = profile.listener(fd);
        }
        profile
    }

    /// MONOTONICITY: the empty profile is the tightest possible (no resource,
    /// nothing granted). The builder is additive only -- there is no method
    /// to relax a previously-granted right (pinned structurally by
    /// `check_sandbox_gate.sh`).
    #[test]
    fn empty_profile_is_the_tightest() {
        let empty = SandboxProfile::new();
        assert!(empty.resources().is_empty());
        // Adding a resource strictly grows the profile (never shrinks).
        let grown = empty.clone().listener(3);
        assert!(grown.resources().len() > empty.resources().len());
    }
}
