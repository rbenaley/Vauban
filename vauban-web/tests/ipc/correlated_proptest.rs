//! Property tests for correlated IPC request/response bijection.

use proptest::prelude::*;
use shared::ipc::IpcChannel;
use shared::messages::{IacsTunnelSnapshotEntry, Message};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::thread;
use std::time::Duration;
use tokio::sync::oneshot;
use vauban_web::ipc::CorrelatedIpcCore;

fn snapshot_entry(request_id: u64) -> IacsTunnelSnapshotEntry {
    IacsTunnelSnapshotEntry {
        session_id: format!("s-{request_id}"),
        phase: 0,
        peer_ip: None,
        bytes_in: request_id,
        bytes_out: request_id.wrapping_mul(2),
        user_uuid: "u".into(),
        asset_uuid: "a".into(),
        ews_uuid: "e".into(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// N concurrent snapshot requests with shuffled reply order still
    /// deliver the payload bound to each request_id (bijection).
    #[test]
    fn concurrent_shuffled_replies_preserve_bijection(
        n in 2usize..=12,
        seed in any::<u64>(),
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("rt");

        rt.block_on(async move {
            let (web_side, peer_side) = IpcChannel::pair().expect("pair");
            let read_fd = web_side.read_fd();
            let write_fd = web_side.write_fd();
            std::mem::forget(web_side);
            let core = Arc::new(CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core"));
            let pending: Arc<
                StdMutex<HashMap<u64, oneshot::Sender<Vec<IacsTunnelSnapshotEntry>>>>,
            > = Arc::new(StdMutex::new(HashMap::new()));

            thread::spawn(move || {
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    match peer_side.recv() {
                        Ok(Message::IacsTunnelSnapshotRequest { request_id }) => {
                            ids.push(request_id);
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                let mut order = ids;
                let mut state = seed;
                for i in (1..order.len()).rev() {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1);
                    let j = (state as usize) % (i + 1);
                    order.swap(i, j);
                }
                for request_id in order {
                    let _ = peer_side.send(&Message::IacsTunnelSnapshotResponse {
                        request_id,
                        entries: vec![snapshot_entry(request_id)],
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

            let mut handles = Vec::new();
            for _ in 0..n {
                let core = Arc::clone(&core);
                let pending = Arc::clone(&pending);
                handles.push(tokio::spawn(async move {
                    let id = core.alloc_id();
                    let msg = Message::IacsTunnelSnapshotRequest { request_id: id };
                    let entries = core
                        .request(&pending, id, &msg, Some(Duration::from_secs(5)))
                        .await
                        .expect("response");
                    (id, entries)
                }));
            }

            for h in handles {
                let (id, entries) = h.await.expect("join");
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].session_id, format!("s-{id}"));
                assert_eq!(entries[0].bytes_in, id);
            }
            assert!(pending.lock().unwrap().is_empty());
            pump.abort();
        });
    }
}
