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
    assert!(
        body.contains("decode_kdc_reply_len"),
        "I/O path must fence reply length via decode_kdc_reply_len"
    );
    assert!(body.contains("read_exact"));
    assert!(body.contains("write_all"));
    assert!(
        session.contains("fn encode_kdc_request_frame"),
        "pure encode helper must exist for framing proptest"
    );
    assert!(
        session.contains("fn decode_kdc_reply_len"),
        "pure decode helper must exist for framing proptest"
    );
    assert!(
        session.contains("MAX_KDC_REPLY"),
        "decode fence must reference MAX_KDC_REPLY"
    );
}

#[test]
fn lease_request_carries_a_realm_and_no_payload() {
    let session = include_str!("../src/session.rs");
    let idx = session
        .find("let request = Message::KerberosKdcLeaseRequest")
        .expect("KerberosKdcLeaseRequest construction in kdc_round_trip");
    let ctor = &session[idx..];
    let ctor = &ctor[..ctor.find("};").expect("ctor end")];
    assert!(
        ctor.contains("realm: realm.as_str().to_string()"),
        "lease request must carry the validated realm"
    );
    assert!(
        !ctor.contains("SensitiveBytes") && !ctor.contains("data"),
        "lease request must not pack sspi payload into IPC"
    );
    assert!(
        !session.contains("Message::KerberosKdcRequest {"),
        "the legacy realm-less lease must not be sent by the proxy"
    );
}
