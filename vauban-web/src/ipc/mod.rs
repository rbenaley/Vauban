/// VAUBAN Web - IPC clients module.
///
/// Provides clients for inter-process communication with Vauban services
/// (auth, rbac, vault, audit) via Unix pipes created by the supervisor.
pub mod clients;

pub use clients::*;
