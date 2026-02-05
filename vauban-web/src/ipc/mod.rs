/// VAUBAN Web - IPC clients module.
///
/// Provides clients for inter-process communication with Vauban services
/// (auth, rbac, vault, audit, proxy-ssh) via Unix pipes created by the supervisor.
pub mod clients;
pub mod proxy_ssh;
pub mod supervisor;

pub use clients::*;
pub use proxy_ssh::{ProxySshClient, SshSessionOpenRequest, SshSessionOpened};
pub use supervisor::SupervisorClient;