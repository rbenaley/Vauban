/// VAUBAN Web - Background tasks module.
///
/// Periodic tasks for pushing real-time updates to WebSocket clients,
/// cleaning up expired data, and ACME certificate management.
pub mod acme;
pub mod cleanup;
pub mod dashboard;

pub use acme::start_acme_monitoring;
pub use cleanup::start_cleanup_tasks;
pub use dashboard::*;
