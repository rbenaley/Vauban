//! Property / framing pins for Kerberos KDC FD-pass (source-level).
//!
//! Behavioral framed I/O lives in `session.rs` unit tests (binary crate
//! has no `lib` target). This file pins the public constants and wire
//! shape that those unit tests rely on.

#![allow(clippy::expect_used)]

#[test]
fn max_kdc_reply_is_256_kib() {
    let session = include_str!("../src/session.rs");
    assert!(
        session.contains("pub const MAX_KDC_REPLY: usize = 256 * 1024"),
        "MAX_KDC_REPLY must stay 256 KiB (IPC frame budget fence)"
    );
}

#[test]
fn framed_round_trip_helper_bounds_reply() {
    let session = include_str!("../src/session.rs");
    let idx = session
        .find("fn kdc_framed_round_trip")
        .expect("kdc_framed_round_trip");
    let body = &session[idx..idx + 1_200];
    assert!(body.contains("MAX_KDC_REPLY"));
    assert!(body.contains("to_be_bytes") || body.contains("from_be_bytes"));
    assert!(body.contains("read_exact"));
    assert!(body.contains("write_all"));
}

#[test]
fn request_data_field_is_default_empty_on_lease() {
    let session = include_str!("../src/session.rs");
    let idx = session
        .find("let request = Message::KerberosKdcRequest")
        .expect("KerberosKdcRequest construction in kdc_round_trip");
    let ctor = &session[idx..idx + 400];
    assert!(
        ctor.contains("SensitiveBytes::default()"),
        "lease request must send empty data"
    );
    assert!(
        !ctor.contains("SensitiveBytes::new("),
        "lease request must not pack sspi payload into IPC data"
    );
}
