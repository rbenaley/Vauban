//! Re-export of [`shared::correlated_ipc`] plus web-layer AppError mapping.
//!
//! The AsyncFd core lives in `shared` so AccessGuard's `RbacClient` and
//! the seven web peers share one implementation. `SupervisorClient` uses
//! [`PendingGuard`] / insert helpers only (sync poll + SCM_RIGHTS).

pub use shared::correlated_ipc::{
    CorrelatedIpcCore, CorrelatedIpcError, PendingGuard, deliver_or_warn, set_nonblocking,
};

use crate::error::AppError;

/// Map [`CorrelatedIpcError`] into web [`AppError::Ipc`].
///
/// Inherent methods cannot live on the shared type (orphan rule); peers
/// `use crate::ipc::CorrelatedIpcErrorExt`.
pub trait CorrelatedIpcErrorExt {
    fn into_app_ipc(self) -> AppError;
}

impl CorrelatedIpcErrorExt for CorrelatedIpcError {
    fn into_app_ipc(self) -> AppError {
        AppError::Ipc(self.to_string())
    }
}
