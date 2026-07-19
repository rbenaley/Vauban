//! IACS tunnel sshd hosted in-process within `vauban-web`.
//!
//! ## Surface
//!
//! ```text
//!  EWS ──ssh -L LP:127.0.0.1:LP <session_uuid>@bastion -p 22322 -N──▶
//!                                                       │
//!                                  ┌────────────────────┴───────┐
//!                                  │  iacs_tunnel::server task   │
//!                                  │  (russh::server::Server)    │
//!                                  └────────────────────┬───────┘
//!                                                       │
//!                                       open direct-tcpip(target_addr)
//!                                                       │
//!                                          ┌────────────▼───────┐
//!                                          │ relay (bidir copy) │
//!                                          │ + byte counters    │
//!                                          └────────────────────┘
//! ```
//!
//! No new service, no new IPC. The sshd is a `tokio::spawn`ed task
//! owned by the axum runtime. A `catch_unwind` boundary on each
//! accepted connection keeps a malformed packet from one client
//! from taking down the runtime.
//!
//! ## Surface boundaries (lints + tests)
//!
//! Defence-in-depth: the russh `Handler` rejects every channel
//! type that is not `direct-tcpip` (shell, exec, subsystem,
//! pty, tcpip-forward, streamlocal, x11, second direct-tcpip).
//! The
//! [`vauban-web/scripts/check_iacs_proxy_no_shell.sh`](../../../../scripts/check_iacs_proxy_no_shell.sh)
//! lint pins the source-level absence of any allow path; the
//! adversarial test suite
//! [`vauban-web/tests/web/iacs_tunnel_handler_test.rs`](../../../../tests/web/iacs_tunnel_handler_test.rs)
//! pins the runtime contract.

pub mod auth;
pub mod countdown;
pub mod port_mapping;
pub mod registry;
pub mod relay;
pub mod revocation;
pub mod server;

pub use countdown::{format_countdown_label, remaining_waiting_seconds};
pub use port_mapping::derive_local_forward_port;
pub use registry::{TunnelHandle, TunnelRegistry};
pub use revocation::{
    reconcile_orphaned_iacs_tunnels_on_boot, run_once as watchdog_run_once, run_once_with_proxy,
    spawn_watchdog, spawn_watchdog_with_proxy_iacs,
};
pub use server::{
    IacsTunnelHandler, IacsTunnelServer, spawn_iacs_tunnel_server,
    spawn_iacs_tunnel_server_with_broadcast,
};
