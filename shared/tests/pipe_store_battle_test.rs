//! Contention / volume: 1000 successive `replace` cycles must not leak
//! or close live supervisor copies.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::messages::Service;
use shared::pipe_store::{PipeKind, PipeStore};

fn full_mini_topology() -> Vec<(Service, Service, PipeKind)> {
    vec![
        (Service::Web, Service::ProxySsh, PipeKind::Control),
        (Service::Web, Service::ProxyRdp, PipeKind::Control),
        (Service::Web, Service::Auth, PipeKind::Control),
        (Service::Web, Service::Access, PipeKind::Control),
        (Service::Web, Service::Audit, PipeKind::Control),
        (Service::ProxySsh, Service::Access, PipeKind::Control),
        (Service::ProxyRdp, Service::Access, PipeKind::Control),
        (Service::ProxySsh, Service::Audit, PipeKind::Control),
        (Service::ProxyRdp, Service::Audit, PipeKind::Control),
    ]
}

fn open_fd_count() -> usize {
    match std::fs::read_dir("/dev/fd") {
        Ok(iter) => iter.count(),
        Err(_) => {
            let mut n = 0usize;
            for fd in 0..1024 {
                if shared::pipe_store::fd_is_open(fd) {
                    n += 1;
                }
            }
            n
        }
    }
}

#[test]
fn battle_replace_cycles_keep_fd_count_stable() {
    let topology = full_mini_topology();
    let mut store = PipeStore::new(&topology).expect("new");
    let edges: Vec<_> = store.edges().collect();

    for &(from, to, kind) in &edges {
        store.replace(from, to, kind).expect("warmup replace");
    }
    let baseline = open_fd_count();
    assert!(baseline > 0, "should observe open fds after warmup");

    for _ in 0..1000 {
        for &(from, to, kind) in &edges {
            store.replace(from, to, kind).expect("replace");
        }
    }

    let after = open_fd_count();
    assert_eq!(
        after, baseline,
        "fd count must stay stable across 1000 replace cycles (was {baseline}, now {after})"
    );
    assert_eq!(store.len(), topology.len());
    for fd in store.all_raw_fds() {
        assert!(
            shared::pipe_store::fd_is_open(fd),
            "live store fd {fd} must still be open"
        );
    }
}

#[test]
fn battle_data_edge_replace_under_concurrent_derive() {
    use std::sync::{Arc, Barrier, Mutex};
    let store = PipeStore::new(&[
        (Service::Web, Service::ProxyMcp, PipeKind::Control),
        (Service::Web, Service::ProxyMcp, PipeKind::Data),
    ])
    .expect("new");
    let barrier = Arc::new(Barrier::new(9));
    let store = Arc::new(Mutex::new(store));
    let mut joins = Vec::new();
    for i in 0..8 {
        let barrier = Arc::clone(&barrier);
        let store = Arc::clone(&store);
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..50 {
                let guard = store.lock().expect("lock");
                let derived = guard.derive_service_pipes();
                let web = derived.get(&Service::Web).expect("web");
                assert_eq!(web.outgoing.len(), 1);
                assert_eq!(web.outgoing_data.len(), 1);
                assert_ne!(web.outgoing[0].1, web.outgoing_data[0].1, "reader {i}");
            }
        }));
    }
    let barrier_w = Arc::clone(&barrier);
    let store_w = Arc::clone(&store);
    joins.push(std::thread::spawn(move || {
        barrier_w.wait();
        for _ in 0..50 {
            let mut guard = store_w.lock().expect("lock");
            guard
                .replace(Service::Web, Service::ProxyMcp, PipeKind::Data)
                .expect("replace data");
        }
    }));
    for join in joins {
        join.join().expect("thread");
    }
    let guard = store.lock().expect("lock");
    assert_eq!(guard.len(), 2);
}
