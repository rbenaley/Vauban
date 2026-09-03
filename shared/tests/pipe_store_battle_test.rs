//! Contention / volume: 1000 successive `replace` cycles must not leak
//! or close live supervisor copies.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::messages::Service;
use shared::pipe_store::PipeStore;

fn full_mini_topology() -> Vec<(Service, Service)> {
    vec![
        (Service::Web, Service::ProxySsh),
        (Service::Web, Service::ProxyRdp),
        (Service::Web, Service::Auth),
        (Service::Web, Service::Access),
        (Service::Web, Service::Audit),
        (Service::ProxySsh, Service::Access),
        (Service::ProxyRdp, Service::Access),
        (Service::ProxySsh, Service::Audit),
        (Service::ProxyRdp, Service::Audit),
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

    for &(from, to) in &edges {
        store.replace(from, to).expect("warmup replace");
    }
    let baseline = open_fd_count();
    assert!(baseline > 0, "should observe open fds after warmup");

    for _ in 0..1000 {
        for &(from, to) in &edges {
            store.replace(from, to).expect("replace");
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
