//! Battle tests for CorrelatedIpc alignment (0.9.31).
//!
//! Complements `correlated_core_test` and AccessGuard unit suites:
//! AccessGuard pending GC under load is covered in
//! `shared::access_guard` tests; SupervisorClient GC lives in
//! `supervisor.rs` unit tests (`battle_*_send_fail_clears_pending`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::ipc::IpcChannel;
use shared::messages::{AccessCheckResult, AccessRequest, AccessResponse, Message};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vauban_web::ipc::CorrelatedIpcCore;

/// AccessGuard-shaped pipe: concurrent CheckAccessByUuid with shuffled
/// replies still demux correctly via CorrelatedIpcCore (bijection).
#[tokio::test]
async fn battle_access_shaped_concurrent_check_access_bijection() {
    let (web_side, peer_side) = IpcChannel::pair().expect("pair");
    let read_fd = web_side.read_fd();
    let write_fd = web_side.write_fd();
    std::mem::forget(web_side);
    let core = Arc::new(CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core"));
    let pending: Arc<
        std::sync::Mutex<
            std::collections::HashMap<u64, tokio::sync::oneshot::Sender<AccessResponse>>,
        >,
    > = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let n = 8usize;
    thread::spawn(move || {
        let mut ids = Vec::with_capacity(n);
        for _ in 0..n {
            match peer_side.recv() {
                Ok(Message::AccessRequest { request_id, .. }) => ids.push(request_id),
                Ok(_) => {}
                Err(_) => return,
            }
        }
        // reverse order
        for request_id in ids.into_iter().rev() {
            let _ = peer_side.send(&Message::AccessResponse {
                request_id,
                response: AccessResponse::AccessChecked(AccessCheckResult {
                    allowed: request_id % 2 == 0,
                    require_mfa: false,
                    require_approval: false,
                    max_session_duration: None,
                }),
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
                        if let Message::AccessResponse {
                            request_id,
                            response,
                        } = msg
                        {
                            CorrelatedIpcCore::deliver(&pending, request_id, response);
                        }
                    }
                })
                .await;
        })
    };

    tokio::task::yield_now().await;

    let mut handles = Vec::new();
    for _ in 0..n {
        let core = Arc::clone(&core);
        let pending = Arc::clone(&pending);
        handles.push(tokio::spawn(async move {
            let id = core.alloc_id();
            let msg = Message::AccessRequest {
                request_id: id,
                request: AccessRequest::CheckAccessByUuid {
                    user_uuid: "u".into(),
                    asset_uuid: "a".into(),
                    protocol: "ssh".into(),
                },
            };
            let resp = core
                .request(&pending, id, &msg, Some(Duration::from_secs(5)))
                .await
                .expect("response");
            (id, resp)
        }));
    }

    for h in handles {
        let (id, resp) = h.await.expect("join");
        match resp {
            AccessResponse::AccessChecked(r) => {
                assert_eq!(r.allowed, id % 2 == 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(pending.lock().unwrap().is_empty());
    pump.abort();
}

#[test]
fn battle_supervisor_source_pins_scm_rights_unchanged() {
    let source = include_str!("../../src/ipc/supervisor.rs");
    assert!(
        source.contains("recv_fd"),
        "recording file path must still use recv_fd / SCM_RIGHTS"
    );
    assert!(source.contains("RecordingFileResponse"));
    assert!(source.contains("supervisor-ipc"));
}
