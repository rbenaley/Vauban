//! Linux sandbox backend: `PR_SET_NO_NEW_PRIVS` + Landlock (path-based FS
//! confinement, conceptually closest to Capsicum's object model) +
//! seccomp-bpf (syscall allowlist).
//!
//! # Scope / caveats (best-effort, not an officially supported target)
//!
//! * The seccomp allowlist is a UNION of a common base (tokio runtime + std
//!   + allocator) and per-resource deltas. The base list is necessarily
//!   approximate and MUST be validated on real hardware (x86_64 + aarch64)
//!   -- a missing syscall surfaces as a hard `EPERM` at runtime. This is the
//!   "enumerate the runtime syscalls" effort flagged in the design doc.
//! * The filter is installed with `apply_filter_all_threads` (TSYNC) so all
//!   tokio worker threads are covered. Landlock `restrict_self` confines the
//!   calling thread; FS confinement for worker threads is carried by the
//!   seccomp `openat` deny (defense-in-depth).
//! * Denied syscalls return `EPERM` (mirrors Capsicum's errno semantics)
//!   rather than killing the process, which also keeps the behavioral
//!   negative tests in-process.

use super::{Entered, Resource, Result, SandboxBackend, SandboxError, SandboxProfile};
use std::collections::BTreeSet;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, path_beneath_rules,
};
use seccompiler::{SeccompAction, SeccompFilter};

struct LinuxBackend {
    /// Sub-trees granted read + write + create.
    writable_paths: Vec<PathBuf>,
    /// Sub-trees granted read-only access.
    readable_paths: Vec<PathBuf>,
    /// Per-resource seccomp syscall deltas (unioned with the base set).
    extra_syscalls: BTreeSet<i64>,
}

impl LinuxBackend {
    fn new() -> Self {
        Self {
            writable_paths: Vec::new(),
            readable_paths: Vec::new(),
            extra_syscalls: BTreeSet::new(),
        }
    }
}

/// Common syscalls used by the tokio runtime, std and the allocator,
/// regardless of which resources a service holds.
fn base_syscalls() -> Vec<i64> {
    let mut s = vec![
        libc::SYS_read,
        libc::SYS_write,
        // Vectored I/O: tokio / hyper / rustls write TLS records (and read
        // request bodies) with readv/writev, not just read/write. Missing
        // writev surfaces as EPERM mid-TLS-handshake (ServerHello never
        // reaches the wire), which the client sees as "unexpected eof".
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_futex,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_sched_yield,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_ppoll,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_create1,
        libc::SYS_eventfd2,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        // Rust std `File::metadata()` issues statx (AT_EMPTY_PATH) on an
        // already-open fd on modern Linux and only falls back to fstat on
        // ENOSYS, not EPERM. Without statx, serving a supervisor-passed
        // recording fd fails with "read file metadata: EPERM".
        libc::SYS_statx,
        // Seeking a (supervisor-passed) file fd to serve HTTP Range
        // requests needs lseek; it is generic enough to live in the base
        // rather than only the WritableDir/ReadablePath deltas.
        libc::SYS_lseek,
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_membarrier,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_restart_syscall,
        // tokio may spawn worker threads after entering the sandbox.
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
    // Arch-specific epoll/poll variants (the legacy numbers do not exist on
    // aarch64, so they must be cfg-gated to keep the crate compiling there).
    #[cfg(target_arch = "x86_64")]
    s.extend_from_slice(&[libc::SYS_epoll_wait, libc::SYS_poll]);
    #[cfg(target_arch = "aarch64")]
    s.extend_from_slice(&[libc::SYS_epoll_pwait]);
    s
}

fn map_err(context: &str, e: impl std::fmt::Display) -> SandboxError {
    SandboxError::EnterFailed(std::io::Error::other(format!("{context}: {e}")))
}

impl SandboxBackend for LinuxBackend {
    fn restrict(&mut self, resource: &Resource) -> Result<()> {
        // EXHAUSTIVE match (no `_ =>`): a new Resource variant fails to
        // compile until handled here.
        match resource {
            // IPC pipes / connected sockets / fd-receiver sockets are
            // pre-opened; read/write/recvmsg are in the base set. No new
            // socket(), connect(), or bind() is ever allowed.
            Resource::IpcPipe(_) | Resource::ConnectedSocket(_) | Resource::FdReceiver(_) => {}
            // A pre-bound listener needs accept4 to admit connections.
            Resource::Listener(_) => {
                self.extra_syscalls.insert(libc::SYS_accept4);
            }
            // A writable directory needs path-creating syscalls + a Landlock
            // grant on the sub-tree.
            Resource::WritableDir { path, .. } => {
                self.extra_syscalls.insert(libc::SYS_openat);
                self.extra_syscalls.insert(libc::SYS_mkdirat);
                self.extra_syscalls.insert(libc::SYS_unlinkat);
                self.extra_syscalls.insert(libc::SYS_renameat2);
                self.extra_syscalls.insert(libc::SYS_ftruncate);
                self.extra_syscalls.insert(libc::SYS_fsync);
                self.extra_syscalls.insert(libc::SYS_fdatasync);
                self.extra_syscalls.insert(libc::SYS_lseek);
                self.extra_syscalls.insert(libc::SYS_getdents64);
                self.writable_paths.push(path.clone());
            }
            // A read-only path needs openat + a read-only Landlock grant.
            Resource::ReadablePath(path) => {
                self.extra_syscalls.insert(libc::SYS_openat);
                self.extra_syscalls.insert(libc::SYS_lseek);
                self.extra_syscalls.insert(libc::SYS_getdents64);
                self.readable_paths.push(path.clone());
            }
        }
        Ok(())
    }

    fn commit(self, required: bool) -> Result<Entered> {
        // 1. NO_NEW_PRIVS: mandatory for an unprivileged seccomp filter and
        //    a hard prerequisite either way. Fail-closed if it fails.
        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is always memory-safe.
        let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if nnp != 0 {
            return Err(map_err(
                "prctl(PR_SET_NO_NEW_PRIVS)",
                std::io::Error::last_os_error(),
            ));
        }

        // 2. Landlock: deny-all FS, then grant the declared sub-trees.
        if let Err(e) = self.apply_landlock(required) {
            if required {
                return Err(e);
            }
            tracing::warn!(error = %e, "Landlock not fully enforced (best-effort)");
        }

        // 3. seccomp allowlist (installed LAST so the landlock syscalls
        //    above are not themselves filtered). TSYNC across all threads.
        self.apply_seccomp(required)?;

        Ok(Entered::witness(true))
    }
}

impl LinuxBackend {
    fn apply_landlock(&self, required: bool) -> Result<()> {
        let abi = ABI::V2;
        let writable = AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir;
        let readable = AccessFs::ReadFile | AccessFs::ReadDir;

        let compat = if required {
            CompatLevel::HardRequirement
        } else {
            CompatLevel::BestEffort
        };

        let mut ruleset = Ruleset::default()
            .set_compatibility(compat)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| map_err("landlock handle_access", e))?
            .create()
            .map_err(|e| map_err("landlock create", e))?;

        if !self.writable_paths.is_empty() {
            ruleset = ruleset
                .add_rules(path_beneath_rules(&self.writable_paths, writable))
                .map_err(|e| map_err("landlock add writable rules", e))?;
        }
        if !self.readable_paths.is_empty() {
            ruleset = ruleset
                .add_rules(path_beneath_rules(&self.readable_paths, readable))
                .map_err(|e| map_err("landlock add readable rules", e))?;
        }

        let status = ruleset
            .no_new_privs(true)
            .restrict_self()
            .map_err(|e| map_err("landlock restrict_self", e))?;

        if required && matches!(status.ruleset, RulesetStatus::NotEnforced) {
            return Err(SandboxError::Unavailable(
                "Landlock not enforced by the kernel (FS confinement required)".into(),
            ));
        }
        Ok(())
    }

    fn apply_seccomp(&self, _required: bool) -> Result<()> {
        let mut allowed: BTreeSet<i64> = base_syscalls().into_iter().collect();
        allowed.extend(self.extra_syscalls.iter().copied());

        // Allowlist: every listed syscall is unconditionally allowed; any
        // other (socket, connect, bind, execve, open, ...) returns EPERM.
        let rules = allowed.into_iter().map(|sc| (sc, Vec::new())).collect();

        let arch = std::env::consts::ARCH
            .try_into()
            .map_err(|e| map_err("seccomp target arch", e))?;

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            arch,
        )
        .map_err(|e| map_err("seccomp filter build", e))?;

        let program: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e| map_err("seccomp filter compile", e))?;

        seccompiler::apply_filter_all_threads(&program)
            .map_err(|e| map_err("seccomp apply_filter_all_threads", e))?;
        Ok(())
    }
}

pub(crate) fn apply(profile: SandboxProfile) -> Result<Entered> {
    super::run_backend(LinuxBackend::new(), &profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Resource;

    fn backend_after(resources: &[Resource]) -> LinuxBackend {
        let mut b = LinuxBackend::new();
        for r in resources {
            b.restrict(r).unwrap();
        }
        b
    }

    #[test]
    fn openat_only_when_path_resource_present() {
        let none = backend_after(&[Resource::IpcPipe(3), Resource::Listener(4)]);
        assert!(!none.extra_syscalls.contains(&libc::SYS_openat));

        let with_dir = backend_after(&[Resource::WritableDir {
            fd: 3,
            path: PathBuf::from("/x"),
        }]);
        assert!(with_dir.extra_syscalls.contains(&libc::SYS_openat));
        assert_eq!(with_dir.writable_paths.len(), 1);
    }

    #[test]
    fn accept4_only_when_listener_present() {
        let none = backend_after(&[Resource::IpcPipe(3)]);
        assert!(!none.extra_syscalls.contains(&libc::SYS_accept4));

        let listener = backend_after(&[Resource::Listener(4)]);
        assert!(listener.extra_syscalls.contains(&libc::SYS_accept4));
    }

    #[test]
    fn base_syscalls_nonempty_and_have_core_io() {
        let base = base_syscalls();
        assert!(base.contains(&libc::SYS_read));
        assert!(base.contains(&libc::SYS_write));
        assert!(base.contains(&libc::SYS_futex));
    }
}
