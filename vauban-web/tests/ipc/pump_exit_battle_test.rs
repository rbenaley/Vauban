//! Seven pumps dropped together must latch respawn once and not panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use shared::correlated_ipc::CorrelatedIpcCore;
use shared::ipc::IpcChannel;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use vauban_web::ipc::{PumpCtx, spawn_ipc_pump};

fn pair_core() -> (CorrelatedIpcCore, IpcChannel) {
    let (web_side, peer_side) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let core = CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core");
    (core, peer_side)
}

#[tokio::test]
async fn battle_seven_pumps_drop_together() {
    let handle = axum_server::Handle::<SocketAddr>::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let respawn = Arc::new(AtomicBool::new(false));
    let ctx = PumpCtx {
        server_handle: handle.clone(),
        shutdown,
        respawn_requested: Arc::clone(&respawn),
    };

    let mut peers = Vec::new();
    for i in 0..7 {
        let (core, peer) = pair_core();
        peers.push(peer);
        let name = match i {
            0 => "p0",
            1 => "p1",
            2 => "p2",
            3 => "p3",
            4 => "p4",
            5 => "p5",
            _ => "p6",
        };
        spawn_ipc_pump(
            name,
            async move { core.process_loop(|_| async {}).await },
            ctx.clone(),
        );
    }

    let n = peers.len();
    let barrier = Arc::new(Barrier::new(n));
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut joins = Vec::new();
    for peer in peers {
        let barrier = Arc::clone(&barrier);
        let dropped = Arc::clone(&dropped);
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            drop(peer);
            dropped.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for j in joins {
        j.join().expect("dropper");
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 7);

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        respawn.load(Ordering::SeqCst),
        "at least one dead pump must request respawn"
    );
}
