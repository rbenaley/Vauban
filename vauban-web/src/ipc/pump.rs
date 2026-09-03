//! IPC pump lifecycle: a dead peer is a respawn, not a silent degrade.

use shared::pipe_store::EXIT_CODE_RESPAWN;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info};

/// Process-wide latch set when a pump (or sandboxed DB loss) wants exit 100.
pub static RESPAWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Latch a recoverable respawn for `fn main` to honor as exit 100.
pub fn request_respawn() {
    RESPAWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Shared context for every `process_incoming` task.
#[derive(Clone)]
pub struct PumpCtx {
    pub server_handle: axum_server::Handle<SocketAddr>,
    pub shutdown: Arc<AtomicBool>,
    pub respawn_requested: Arc<AtomicBool>,
}

/// Decision after an IPC pump future completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpExit {
    Quiet,
    RequestRespawn,
}

/// Pure policy: supervisor-initiated shutdown is quiet; any other end
/// requests a linked respawn.
pub fn pump_exit_policy(shutdown_requested: bool, _ended: bool) -> PumpExit {
    if shutdown_requested {
        PumpExit::Quiet
    } else {
        PumpExit::RequestRespawn
    }
}

/// Map the respawn latch to the process exit code.
pub fn web_exit_code(respawn_requested: bool) -> std::process::ExitCode {
    if respawn_requested {
        std::process::ExitCode::from(EXIT_CODE_RESPAWN as u8)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// Spawn a pump that applies [`pump_exit_policy`] when the future ends.
pub fn spawn_ipc_pump<F, E>(name: &'static str, fut: F, ctx: PumpCtx)
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::spawn(async move {
        let result = fut.await;
        let shutdown = ctx.shutdown.load(Ordering::SeqCst);
        match pump_exit_policy(shutdown, true) {
            PumpExit::Quiet => {
                info!(pump = name, "IPC pump ended during shutdown");
            }
            PumpExit::RequestRespawn => {
                error!(pump = name, error = %result_err(&result), "IPC pump ended, requesting respawn");
                ctx.respawn_requested.store(true, Ordering::SeqCst);
                request_respawn();
                ctx.server_handle
                    .graceful_shutdown(Some(Duration::from_secs(10)));
            }
        }
    });
}

fn result_err<E: std::fmt::Display>(result: &Result<(), E>) -> String {
    match result {
        Ok(()) => "pump returned Ok".to_string(),
        Err(e) => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pump_exit_policy_table() {
        assert_eq!(pump_exit_policy(true, true), PumpExit::Quiet);
        assert_eq!(pump_exit_policy(true, false), PumpExit::Quiet);
        assert_eq!(pump_exit_policy(false, true), PumpExit::RequestRespawn);
        assert_eq!(pump_exit_policy(false, false), PumpExit::RequestRespawn);
    }

    #[test]
    fn web_exit_code_maps_flag() {
        assert_eq!(
            web_exit_code(true),
            std::process::ExitCode::from(EXIT_CODE_RESPAWN as u8)
        );
        assert_eq!(web_exit_code(false), std::process::ExitCode::SUCCESS);
    }
}
