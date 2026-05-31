//! OpenBSD sandbox backend: `unveil` (filesystem visibility) + `pledge`
//! (promise-based syscall restriction), via `libc`.
//!
//! Pattern: accumulate the set of `pledge` promises and the per-path
//! `unveil` grants while visiting the declared resources, then commit by
//! calling every `unveil`, locking the unveil list with `unveil(NULL, NULL)`,
//! and finally `pledge`. `unveil` MUST precede `pledge` (we never request the
//! `unveil` promise, so the visibility set is sealed at commit time).

use super::{Entered, Resource, Result, SandboxBackend, SandboxError, SandboxProfile};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

struct OpenBSDBackend {
    promises: BTreeSet<&'static str>,
    unveils: Vec<(PathBuf, &'static str)>,
}

impl OpenBSDBackend {
    fn new() -> Self {
        let mut promises = BTreeSet::new();
        // "stdio" is the baseline promise required for any useful process.
        promises.insert("stdio");
        Self {
            promises,
            unveils: Vec::new(),
        }
    }
}

fn map_errno(context: &str) -> SandboxError {
    SandboxError::EnterFailed(std::io::Error::other(format!(
        "{context}: {}",
        std::io::Error::last_os_error()
    )))
}

impl SandboxBackend for OpenBSDBackend {
    fn restrict(&mut self, resource: &Resource) -> Result<()> {
        // EXHAUSTIVE match (no `_ =>`): a new Resource variant fails to
        // compile until handled here.
        match resource {
            // Pre-opened pipe / connected socket: "stdio" already covers
            // read/write on inherited descriptors.
            Resource::IpcPipe(_) | Resource::ConnectedSocket(_) => {}
            // Receiving descriptors via SCM_RIGHTS needs "recvfd".
            Resource::FdReceiver(_) => {
                self.promises.insert("recvfd");
            }
            // A pre-bound listener accepts inbound connections ("inet").
            Resource::Listener(_) => {
                self.promises.insert("inet");
            }
            // A writable directory needs rpath/wpath/cpath + unveil "rwc".
            Resource::WritableDir { path, .. } => {
                self.promises.insert("rpath");
                self.promises.insert("wpath");
                self.promises.insert("cpath");
                self.unveils.push((path.clone(), "rwc"));
            }
            // A read-only path needs rpath + unveil "r".
            Resource::ReadablePath(path) => {
                self.promises.insert("rpath");
                self.unveils.push((path.clone(), "r"));
            }
        }
        Ok(())
    }

    fn commit(self, required: bool) -> Result<Entered> {
        // 1. unveil every declared path BEFORE pledge.
        for (path, perms) in &self.unveils {
            let c_path = CString::new(path.as_os_str().as_bytes())
                .map_err(|e| map_err_str("unveil path NUL", e))?;
            let c_perms = CString::new(*perms).map_err(|e| map_err_str("unveil perms NUL", e))?;
            // SAFETY: both pointers are valid NUL-terminated C strings.
            let rc = unsafe { libc::unveil(c_path.as_ptr(), c_perms.as_ptr()) };
            if rc != 0 {
                let err = map_errno("unveil");
                if required {
                    return Err(err);
                }
                tracing::warn!(error = %err, path = %path.display(), "unveil failed (best-effort)");
            }
        }
        // Lock the unveil list (no further unveil possible without the
        // "unveil" promise, which we never request).
        if !self.unveils.is_empty() {
            // SAFETY: unveil(NULL, NULL) is the documented "finalize" call.
            let rc = unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) };
            if rc != 0 && required {
                return Err(map_errno("unveil(NULL, NULL) lock"));
            }
        }

        // 2. pledge LAST. Promises are space-separated; execpromises = NULL
        //    leaves exec disabled (we never grant the "exec" promise).
        let joined = self.promises.iter().copied().collect::<Vec<_>>().join(" ");
        let c_promises =
            CString::new(joined.as_str()).map_err(|e| map_err_str("pledge promises NUL", e))?;
        // SAFETY: c_promises is a valid NUL-terminated C string; NULL
        // execpromises is documented as "leave unchanged".
        let rc = unsafe { libc::pledge(c_promises.as_ptr(), std::ptr::null()) };
        if rc != 0 {
            let err = map_errno("pledge");
            if required {
                return Err(err);
            }
            tracing::warn!(error = %err, "pledge failed (best-effort)");
            return Ok(Entered::witness(false));
        }

        Ok(Entered::witness(true))
    }
}

fn map_err_str(context: &str, e: impl std::fmt::Display) -> SandboxError {
    SandboxError::EnterFailed(std::io::Error::other(format!("{context}: {e}")))
}

pub(crate) fn apply(profile: SandboxProfile) -> Result<Entered> {
    super::run_backend(OpenBSDBackend::new(), &profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Resource;

    fn backend_after(resources: &[Resource]) -> OpenBSDBackend {
        let mut b = OpenBSDBackend::new();
        for r in resources {
            b.restrict(r).unwrap();
        }
        b
    }

    #[test]
    fn baseline_promise_is_stdio() {
        assert!(OpenBSDBackend::new().promises.contains("stdio"));
    }

    #[test]
    fn listener_adds_inet_promise() {
        let b = backend_after(&[Resource::Listener(3)]);
        assert!(b.promises.contains("inet"));
    }

    #[test]
    fn fd_receiver_adds_recvfd_promise() {
        let b = backend_after(&[Resource::FdReceiver(3)]);
        assert!(b.promises.contains("recvfd"));
    }

    #[test]
    fn writable_dir_adds_rwc_promises_and_unveil() {
        let b = backend_after(&[Resource::WritableDir {
            fd: 3,
            path: PathBuf::from("/x"),
        }]);
        assert!(b.promises.contains("rpath"));
        assert!(b.promises.contains("wpath"));
        assert!(b.promises.contains("cpath"));
        assert_eq!(b.unveils.len(), 1);
        assert_eq!(b.unveils[0].1, "rwc");
    }

    #[test]
    fn readable_path_is_read_only_unveil() {
        let b = backend_after(&[Resource::ReadablePath(PathBuf::from("/etc/x"))]);
        assert!(b.promises.contains("rpath"));
        assert!(!b.promises.contains("wpath"));
        assert_eq!(b.unveils[0].1, "r");
    }
}
