/// VAUBAN Web - Background tasks module.
///
/// Periodic tasks for pushing real-time updates to WebSocket clients,
/// cleaning up expired data, and ACME certificate management.
pub mod acme;
pub mod cleanup;
pub mod dashboard;

pub use acme::{
    CertExpiry, CertInfo, extract_cert_info, extract_cert_info_from_pem, start_acme_monitoring,
};
pub use cleanup::start_cleanup_tasks;
pub use dashboard::*;
