//! Drop a real IPC pair: the HTTP server stops and respawn is latched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::correlated_ipc::CorrelatedIpcCore;
use shared::ipc::IpcChannel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use vauban_web::ipc::{PumpCtx, spawn_ipc_pump};

#[tokio::test]
async fn e2e_pump_death_stops_dummy_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblock");
    let handle = axum_server::Handle::new();
    let handle_for_server = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .expect("from_tcp")
            .handle(handle_for_server)
            .serve(axum::Router::new().into_make_service())
            .await
    });

    let (web_side, peer) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let core = CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core");

    let shutdown = Arc::new(AtomicBool::new(false));
    let respawn = Arc::new(AtomicBool::new(false));
    spawn_ipc_pump(
        "e2e",
        async move { core.process_loop(|_| async {}).await },
        PumpCtx {
            server_handle: handle,
            shutdown,
            respawn_requested: Arc::clone(&respawn),
        },
    );

    drop(peer);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server must stop")
        .expect("join")
        .expect("serve");
    assert!(
        respawn.load(Ordering::SeqCst),
        "pump death must latch respawn_requested"
    );
}
