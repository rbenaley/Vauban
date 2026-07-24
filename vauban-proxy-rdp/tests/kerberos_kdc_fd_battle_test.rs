//! Battle pins: concurrent demux surfaces (KDC vs recording vs asset)
//! must not share pending maps.

#![allow(clippy::expect_used)]

#[test]
fn kdc_lease_demux_is_isolated_from_asset_and_recording() {
    let main_rs = include_str!("../src/main.rs");
    assert!(main_rs.contains("pending_connections"));
    assert!(main_rs.contains("pending_recording_leases"));
    assert!(main_rs.contains("supervisor_relay.complete"));

    let kdc_arm = main_rs
        .find("Message::KerberosKdcResponse")
        .expect("KDC response arm");
    let arm = &main_rs[kdc_arm..kdc_arm + 700];
    assert!(
        arm.contains("recv_fd_timed"),
        "KDC success must take FD from SCM_RIGHTS"
    );
    assert!(
        !arm.contains("pending_connections"),
        "KDC must not insert into asset pending_connections"
    );
    assert!(
        !arm.contains("pending_recording_leases"),
        "KDC must not use recording lease map"
    );
}

#[test]
fn supervisor_logs_fd_leased_not_payload_round_trip() {
    let sup = include_str!("../../vauban-supervisor/src/main.rs");
    assert!(
        sup.contains("Kerberos KDC FD leased to proxy_rdp"),
        "supervisor success log must reflect FD lease"
    );
    assert!(
        !sup.contains("Kerberos KDC relay round-trip complete"),
        "legacy payload-relay success log must be gone"
    );
}

#[test]
fn two_network_requests_each_lease_a_fresh_fd() {
    // CredSSP issues AS-REQ then TGS-REQ as sequential NetworkRequests;
    // each call path must go through kdc_round_trip (fresh lease).
    let session = include_str!("../src/session.rs");
    let count = session.matches("kdc_round_trip").count();
    assert!(
        count >= 2,
        "kdc_round_trip must appear in relay impl + NetworkClient (got {count})"
    );
    assert!(
        session.contains("fetch_add(1"),
        "each lease must allocate a fresh request_id"
    );
}
