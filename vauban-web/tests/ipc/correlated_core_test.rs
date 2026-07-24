//! Integration + battle tests for [`vauban_web::ipc::CorrelatedIpcCore`].
//!
//! Complements the unit tests in `shared/src/correlated_ipc.rs`. Covers
//! concurrent correlation, late replies after timeout, and the
//! structural lint script.

use shared::ipc::IpcChannel;
use shared::messages::{IacsTunnelSnapshotEntry, Message};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::thread;
use std::time::Duration;
use tokio::sync::oneshot;
use vauban_web::ipc::{CorrelatedIpcCore, CorrelatedIpcError};

fn pair_core() -> (Arc<CorrelatedIpcCore>, IpcChannel) {
    let (web_side, peer_side) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let core = Arc::new(CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core"));
    (core, peer_side)
}

fn spawn_echo(peer: IpcChannel) {
    thread::spawn(move || {
        loop {
            match peer.recv() {
                Ok(Message::IacsTunnelSnapshotRequest { request_id }) => {
                    let _ = peer.send(&Message::IacsTunnelSnapshotResponse {
                        request_id,
                        entries: vec![IacsTunnelSnapshotEntry {
                            session_id: format!("s-{request_id}"),
                            phase: 1,
                            peer_ip: None,
                            bytes_in: 0,
                            bytes_out: 0,
                            user_uuid: "u".into(),
                            asset_uuid: "a".into(),
                            ews_uuid: "e".into(),
                        }],
                    });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

#[tokio::test]
async fn battle_timeout_then_late_reply_does_not_panic_or_leak() {
    let (core, peer) = pair_core();
    let pending: Arc<StdMutex<HashMap<u64, oneshot::Sender<Vec<IacsTunnelSnapshotEntry>>>>> =
        Arc::new(StdMutex::new(HashMap::new()));

    // Peer answers after 200 ms — longer than our 50 ms timeout.
    thread::spawn(move || {
        if let Ok(Message::IacsTunnelSnapshotRequest { request_id }) = peer.recv() {
            thread::sleep(Duration::from_millis(200));
            let _ = peer.send(&Message::IacsTunnelSnapshotResponse {
                request_id,
                entries: vec![],
            });
        }
    });

    let pump = {
        let core = Arc::clone(&core);
        let pending = Arc::clone(&pending);
        tokio::spawn(async move {
            let _ = core
                .process_loop(|msg| {
                    let pending = Arc::clone(&pending);
                    async move {
                        if let Message::IacsTunnelSnapshotResponse {
                            request_id,
                            entries,
                        } = msg
                        {
                            CorrelatedIpcCore::deliver(&pending, request_id, entries);
                        }
                    }
                })
                .await;
        })
    };

    tokio::task::yield_now().await;
    let id = core.alloc_id();
    let msg = Message::IacsTunnelSnapshotRequest { request_id: id };
    let err = core
        .request(&pending, id, &msg, Some(Duration::from_millis(50)))
        .await
        .expect_err("timeout");
    assert!(matches!(err, CorrelatedIpcError::Timeout));
    assert!(pending.lock().unwrap().is_empty());

    // Late reply arrives; pump must not panic.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(pending.lock().unwrap().is_empty());
    pump.abort();
}

#[tokio::test]
async fn battle_concurrent_requests_bijection() {
    let (core, peer) = pair_core();
    spawn_echo(peer);
    let pending: Arc<StdMutex<HashMap<u64, oneshot::Sender<Vec<IacsTunnelSnapshotEntry>>>>> =
        Arc::new(StdMutex::new(HashMap::new()));

    let pump = {
        let core = Arc::clone(&core);
        let pending = Arc::clone(&pending);
        tokio::spawn(async move {
            let _ = core
                .process_loop(|msg| {
                    let pending = Arc::clone(&pending);
                    async move {
                        if let Message::IacsTunnelSnapshotResponse {
                            request_id,
                            entries,
                        } = msg
                        {
                            CorrelatedIpcCore::deliver(&pending, request_id, entries);
                        }
                    }
                })
                .await;
        })
    };
    tokio::task::yield_now().await;

    let mut handles = Vec::new();
    for _ in 0..16 {
        let core = Arc::clone(&core);
        let pending = Arc::clone(&pending);
        handles.push(tokio::spawn(async move {
            let id = core.alloc_id();
            let msg = Message::IacsTunnelSnapshotRequest { request_id: id };
            let entries = core
                .request(&pending, id, &msg, Some(Duration::from_secs(3)))
                .await
                .expect("ok");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].session_id, format!("s-{id}"));
            id
        }));
    }
    let mut ids = Vec::new();
    for h in handles {
        ids.push(h.await.expect("join"));
    }
    ids.sort_unstable();
    let mut uniq = ids.clone();
    uniq.dedup();
    assert_eq!(ids.len(), uniq.len(), "request ids must be unique");
    assert!(pending.lock().unwrap().is_empty());
    pump.abort();
}

#[tokio::test]
async fn battle_double_response_second_is_noop() {
    let pending: StdMutex<HashMap<u64, oneshot::Sender<u64>>> = StdMutex::new(HashMap::new());
    let (tx, rx) = oneshot::channel();
    let guard = CorrelatedIpcCore::insert_pending(&pending, 1, tx);
    assert!(CorrelatedIpcCore::deliver(&pending, 1, 10));
    assert!(!CorrelatedIpcCore::deliver(&pending, 1, 20));
    assert_eq!(rx.await.unwrap(), 10);
    drop(guard);
}

#[test]
fn check_ipc_correlated_core_script_passes() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/check_ipc_correlated_core.sh");
    assert!(script.exists(), "lint script must exist");
    let out = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .expect("run lint");
    assert!(
        out.status.success(),
        "check_ipc_correlated_core.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
