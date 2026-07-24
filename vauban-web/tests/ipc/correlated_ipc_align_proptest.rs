//! Property tests for CorrelatedIpc alignment (PendingGuard + id allotment).

use proptest::prelude::*;
use shared::ipc::IpcChannel;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex as StdMutex;
use tokio::sync::oneshot;
use vauban_web::ipc::CorrelatedIpcCore;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Drop of PendingGuard always removes the slot (INV-CORR-1).
    #[test]
    fn pending_guard_drop_always_removes(id in 1u64..10_000) {
        let pending: StdMutex<HashMap<u64, oneshot::Sender<u64>>> =
            StdMutex::new(HashMap::new());
        let (tx, _rx) = oneshot::channel();
        {
            let _guard = CorrelatedIpcCore::insert_pending(&pending, id, tx);
            prop_assert!(pending.lock().unwrap().contains_key(&id));
        }
        prop_assert!(
            pending.lock().unwrap().is_empty(),
            "Drop must GC pending[{id}]"
        );
    }

    /// alloc_id produces unique monotonic ids over a generated window.
    #[test]
    fn alloc_id_window_has_no_collisions(n in 2usize..=64) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let (web_side, peer_side) = IpcChannel::pair().expect("pair");
            let read_fd = web_side.read_fd();
            let write_fd = web_side.write_fd();
            std::mem::forget(web_side);
            std::mem::forget(peer_side);
            let core = CorrelatedIpcCore::from_fds(read_fd, write_fd).expect("core");
            let mut seen = HashSet::new();
            let mut prev = 0u64;
            for _ in 0..n {
                let id = core.alloc_id();
                prop_assert!(id > prev);
                prop_assert!(seen.insert(id));
                prev = id;
            }
            Ok(())
        })?;
    }

    /// Late deliver after Drop is a no-op (INV-CORR-3).
    #[test]
    fn late_deliver_after_guard_drop_is_noop(id in 1u64..1000) {
        let pending: StdMutex<HashMap<u64, oneshot::Sender<u64>>> =
            StdMutex::new(HashMap::new());
        let (tx, _rx) = oneshot::channel();
        {
            let _guard = CorrelatedIpcCore::insert_pending(&pending, id, tx);
        }
        prop_assert!(!CorrelatedIpcCore::deliver(&pending, id, 42));
        prop_assert!(pending.lock().unwrap().is_empty());
    }
}
