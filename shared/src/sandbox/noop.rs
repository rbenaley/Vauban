//! No-op sandbox backend for development platforms with no supported
//! mechanism (e.g. macOS). It applies NO confinement.
//!
//! Security contract:
//! * `SandboxRequirement::BestEffort` -> emit a `warn!` and continue
//!   unconfined (developer convenience).
//! * `SandboxRequirement::Required` -> fail-closed
//!   ([`SandboxError::Unavailable`]): a production boot MUST NOT run
//!   unconfined.
//!
//! This is the ONLY backend permitted to log "without sandbox" (pinned by
//! `check_sandbox_gate.sh`).

use super::{Entered, Resource, Result, SandboxBackend, SandboxError, SandboxProfile};

struct NoopBackend {
    resources: usize,
}

impl SandboxBackend for NoopBackend {
    fn restrict(&mut self, _resource: &Resource) -> Result<()> {
        self.resources += 1;
        Ok(())
    }

    fn commit(self, required: bool) -> Result<Entered> {
        if required {
            return Err(SandboxError::Unavailable(format!(
                "no sandbox mechanism on target_os = {}; refusing to boot a \
                 Required sandbox unconfined",
                std::env::consts::OS
            )));
        }
        tracing::warn!(
            target_os = std::env::consts::OS,
            resources = self.resources,
            "Running without sandbox: no supported mechanism on this platform \
             (development only)"
        );
        Ok(Entered::witness(false))
    }
}

pub(crate) fn apply(profile: SandboxProfile) -> Result<Entered> {
    super::run_backend(NoopBackend { resources: 0 }, &profile)
}

#[cfg(test)]
mod tests {
    use super::super::SandboxRequirement;
    use super::*;

    #[test]
    fn best_effort_enters_unconfined() {
        let p = SandboxProfile::new().ipc_pipe(3);
        assert!(apply(p).is_ok());
    }

    #[test]
    fn required_fails_closed() {
        let p = SandboxProfile::new().requirement(SandboxRequirement::Required);
        let err = apply(p).unwrap_err();
        assert!(matches!(err, SandboxError::Unavailable(_)));
    }
}
