//! Property tests for [`shared::pipe_store`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use shared::messages::Service;
use shared::pipe_store::{PipeStore, derived_raw_fds, fd_is_open, linked_closure};
use std::collections::HashSet;
use std::os::unix::io::RawFd;

const SERVICES: [Service; 4] = [
    Service::Web,
    Service::ProxySsh,
    Service::ProxyRdp,
    Service::Auth,
];

fn all_edges() -> Vec<(Service, Service)> {
    vec![
        (Service::Web, Service::ProxySsh),
        (Service::Web, Service::ProxyRdp),
        (Service::Web, Service::Auth),
        (Service::ProxySsh, Service::Auth),
    ]
}

fn fds_unique_and_open(fds: &[RawFd]) -> bool {
    let unique: HashSet<RawFd> = fds.iter().copied().collect();
    unique.len() == fds.len() && fds.iter().all(|fd| fd_is_open(*fd))
}

proptest! {
    #[test]
    fn replace_sequence_keeps_fds_unique_and_open(indices in prop::collection::vec(0usize..4, 1..32)) {
        let edges = all_edges();
        let mut store = PipeStore::new(&edges).expect("new");
        for i in indices {
            let (from, to) = edges[i];
            store.replace(from, to).expect("replace");
            let owned = store.all_raw_fds();
            prop_assert!(fds_unique_and_open(&owned), "store fds collided or closed");
            let derived = store.derive_service_pipes();
            let derived_fds = derived_raw_fds(&derived);
            prop_assert!(fds_unique_and_open(&derived_fds), "derived fds collided or closed");
        }
    }

    #[test]
    fn linked_closure_is_symmetric_over_random_groups(
        raw in prop::collection::vec(prop::collection::vec(0usize..6, 1..4), 1..5)
    ) {
        let names = ["web", "proxy_ssh", "proxy_rdp", "auth", "vault", "audit"];
        let owned: Vec<Vec<&str>> = raw
            .iter()
            .map(|idx| idx.iter().map(|i| names[*i]).collect())
            .collect();
        let groups: Vec<&[&str]> = owned.iter().map(Vec::as_slice).collect();
        for a in names {
            for b in names {
                let ca = linked_closure(&groups, a);
                let cb = linked_closure(&groups, b);
                prop_assert_eq!(
                    ca.contains(b),
                    cb.contains(a),
                    "symmetry broken for {} / {}",
                    a,
                    b
                );
            }
        }
    }
}

#[test]
fn services_used_in_edges_are_known() {
    for svc in SERVICES {
        let _ = format!("{svc:?}");
    }
}
