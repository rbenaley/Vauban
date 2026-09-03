//! Replay the production incident: replace(web,rdp) then replace(web,ssh)
//! must leave two distinct live pipes that still carry real `Message`s.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shared::messages::{ControlMessage, Message, Service};
use shared::pipe_store::{PipeStore, derived_raw_fds};

fn send_ping(store: &PipeStore, from: Service, to: Service, seq: u64) {
    let (from_ch, to_ch) = store.get(from, to).expect("pair");
    from_ch
        .send(&Message::Control(ControlMessage::Ping { seq }))
        .expect("send");
    match to_ch.recv().expect("recv") {
        Message::Control(ControlMessage::Ping { seq: got }) => {
            assert_eq!(got, seq, "{from:?} -> {to:?}");
        }
        other => panic!("unexpected {other:?} on {from:?} -> {to:?}"),
    }
}

#[test]
fn e2e_two_successive_replaces_keep_distinct_live_pipes() {
    let mut store = PipeStore::new(&[
        (Service::Web, Service::ProxyRdp),
        (Service::Web, Service::ProxySsh),
    ])
    .expect("new");

    let (rdp_from, rdp_to) = store.get(Service::Web, Service::ProxyRdp).expect("rdp");
    let old_rdp = (
        rdp_from.read_fd(),
        rdp_from.write_fd(),
        rdp_to.read_fd(),
        rdp_to.write_fd(),
    );
    let (ssh_from, ssh_to) = store.get(Service::Web, Service::ProxySsh).expect("ssh");
    let old_ssh = (
        ssh_from.read_fd(),
        ssh_from.write_fd(),
        ssh_to.read_fd(),
        ssh_to.write_fd(),
    );

    store
        .replace(Service::Web, Service::ProxyRdp)
        .expect("replace rdp");
    store
        .replace(Service::Web, Service::ProxySsh)
        .expect("replace ssh");

    let (rdp_from, rdp_to) = store.get(Service::Web, Service::ProxyRdp).expect("rdp");
    let new_rdp = (
        rdp_from.read_fd(),
        rdp_from.write_fd(),
        rdp_to.read_fd(),
        rdp_to.write_fd(),
    );
    let (ssh_from, ssh_to) = store.get(Service::Web, Service::ProxySsh).expect("ssh");
    let new_ssh = (
        ssh_from.read_fd(),
        ssh_from.write_fd(),
        ssh_to.read_fd(),
        ssh_to.write_fd(),
    );

    assert_ne!(new_rdp, old_rdp, "rdp pair must be new");
    assert_ne!(new_ssh, old_ssh, "ssh pair must be new");
    assert_ne!(
        rdp_from.read_fd(),
        ssh_from.read_fd(),
        "web->rdp and web->ssh must not share a read fd (prod collision)"
    );
    assert_ne!(
        rdp_from.write_fd(),
        ssh_from.write_fd(),
        "web->rdp and web->ssh must not share a write fd"
    );

    send_ping(&store, Service::Web, Service::ProxyRdp, 11);
    send_ping(&store, Service::Web, Service::ProxySsh, 22);

    let derived = store.derive_service_pipes();
    let derived_fds = derived_raw_fds(&derived);
    let live = [
        new_rdp.0, new_rdp.1, new_rdp.2, new_rdp.3, new_ssh.0, new_ssh.1, new_ssh.2, new_ssh.3,
    ];
    for fd in live {
        assert!(
            derived_fds.contains(&fd),
            "derived table must reference live fd {fd}"
        );
    }
    let old = [
        old_rdp.0, old_rdp.1, old_rdp.2, old_rdp.3, old_ssh.0, old_ssh.1, old_ssh.2, old_ssh.3,
    ];
    for fd in old {
        if !live.contains(&fd) {
            assert!(
                !derived_fds.contains(&fd),
                "stale fd {fd} must not remain in the derived table"
            );
        }
    }
}
