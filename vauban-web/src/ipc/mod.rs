/// VAUBAN Web - IPC clients module.
///
/// Provides clients for inter-process communication with Vauban services
/// (auth, rbac, vault, audit, proxy-ssh, proxy-rdp) via Unix pipes created by the supervisor.
pub mod auth;
pub mod clients;
pub mod proxy_rdp;
pub mod proxy_ssh;
pub mod rbac;
pub mod supervisor;
pub mod vault;

pub use auth::AuthIpcClient;
pub use clients::*;
pub use proxy_rdp::{ProxyRdpClient, RdpSessionOpenRequest, RdpSessionOpened};
pub use proxy_ssh::{ProxySshClient, SshSessionOpenRequest, SshSessionOpened};
pub use rbac::RbacIpcClient;
pub use supervisor::{SupervisorClient, TlsCertData};
pub use vault::VaultCryptoClient;