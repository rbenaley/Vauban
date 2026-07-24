//! VAUBAN Web - IPC clients module.
//!
//! Provides clients for inter-process communication with Vauban services
//! (auth, access, vault, audit, proxy-ssh, proxy-rdp) via Unix pipes created
//! by the supervisor.
pub mod access;
pub mod admin;
pub mod audit;
pub mod auth;
pub mod clients;
pub mod correlated;
pub mod proxy_iacs;
pub mod proxy_rdp;
pub mod proxy_ssh;
pub mod supervisor;
pub mod vault;

pub use correlated::{
    CorrelatedIpcCore, CorrelatedIpcError, CorrelatedIpcErrorExt, PendingGuard, deliver_or_warn,
};

pub use access::{AccessIpcClient, IssuedSessionToken};
pub use audit::{AuditClient, AuditEvent, CRITICAL_ACK_TIMEOUT_SECS};
pub use auth::AuthIpcClient;
pub use clients::*;
pub use proxy_iacs::{IacsTunnelOpenRequest, IacsTunnelOpened, ProxyIacsClient};
pub use proxy_rdp::{CertFetchIdentity, ProxyRdpClient, RdpSessionOpenRequest, RdpSessionOpened};
pub use proxy_ssh::{
    HostKeyFetchIdentity, ProxySshClient, SshSessionOpenRequest, SshSessionOpened,
};
pub use supervisor::{SupervisorClient, TlsCertData};
pub use vault::VaultCryptoClient;
