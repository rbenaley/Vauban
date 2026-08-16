//! Contention: `classify_peek` + `evaluate_conformity` stay correct
//! under parallel load (pure, no I/O).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use shared::iacs_protocol::{
    ConformityDecision, ExpectedProfile, WireProtocol, classify_peek, evaluate_conformity,
};

fn enip() -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0..2].copy_from_slice(&0x0065u16.to_le_bytes());
    p[2..4].copy_from_slice(&4u16.to_le_bytes());
    p
}

fn dnp3() -> Vec<u8> {
    vec![0x05, 0x64, 0x05]
}

fn bvll() -> Vec<u8> {
    vec![0x81, 0x0B, 0x00, 0x08]
}

fn s7() -> Vec<u8> {
    vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80, 0x32, 0x01]
}

#[test]
fn battle_classify_peek_under_barrier() {
    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let frames = Arc::new(vec![enip(), dnp3(), bvll(), s7(), b"HEL".to_vec()]);
    let mut joins = Vec::new();
    for i in 0..N {
        let barrier = Arc::clone(&barrier);
        let frames = Arc::clone(&frames);
        joins.push(thread::spawn(move || {
            barrier.wait();
            let f = &frames[i % frames.len()];
            classify_peek(f)
        }));
    }
    let got: Vec<_> = joins
        .into_iter()
        .map(|j| j.join().expect("thread"))
        .collect();
    assert_eq!(got[0], WireProtocol::Enip);
    assert_eq!(got[1], WireProtocol::Dnp3);
    assert_eq!(got[2], WireProtocol::BacnetIp);
    assert_eq!(got[3], WireProtocol::S7);
    assert_eq!(got[4], WireProtocol::OpcUa);
}

#[test]
fn battle_evaluate_conformity_under_barrier() {
    const N: usize = 8;
    let barrier = Arc::new(Barrier::new(N));
    let mut joins = Vec::new();
    for _ in 0..N {
        let barrier = Arc::clone(&barrier);
        joins.push(thread::spawn(move || {
            barrier.wait();
            evaluate_conformity(ExpectedProfile::BacnetSc, WireProtocol::BacnetIp, false)
        }));
    }
    for j in joins {
        assert_eq!(
            j.join().expect("thread"),
            ConformityDecision::ForeignProtocol
        );
    }
}
