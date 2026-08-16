//! Concurrent dissection of the same buffer (ADR 006 profiles).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use shared::iacs_protocol::ExpectedProfile;
use vauban_web_evidence::analyzer::dissectors;
use vauban_web_evidence::analyzer::types::{Direction, PacketKind};

#[test]
fn battle_dissect_same_buffer_across_threads() {
    let enip = {
        let mut p = vec![0u8; 26];
        p[0..2].copy_from_slice(&0x006Fu16.to_le_bytes());
        p[2..4].copy_from_slice(&2u16.to_le_bytes());
        p[24] = 0x10;
        p
    };
    let dnp3 = vec![
        0x05, 0x64, 0x07, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xC0, 0x04, 0x00, 0x00,
    ];
    let mut iec = vec![
        0x03, 0x00, 0x00, 0x00, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5, 0x00,
    ];
    let len = iec.len() as u16;
    iec[2..4].copy_from_slice(&len.to_be_bytes());
    let tls_app = vec![0x17, 0x03, 0x03, 0x00, 0x08, 0xAA, 0xBB];

    let cases: Arc<Vec<(ExpectedProfile, Vec<u8>, PacketKind)>> = Arc::new(vec![
        (ExpectedProfile::Enip, enip, PacketKind::Cmd),
        (ExpectedProfile::Dnp3, dnp3, PacketKind::Cmd),
        (ExpectedProfile::Iec61850, iec, PacketKind::Cmd),
        (ExpectedProfile::BacnetSc, tls_app, PacketKind::Read),
    ]);

    let n = 8;
    let barrier = Arc::new(Barrier::new(n));
    let mut joins = Vec::new();
    for _ in 0..n {
        let barrier = Arc::clone(&barrier);
        let cases = Arc::clone(&cases);
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            for (profile, buf, want) in cases.iter() {
                let d = dissectors::dissect(buf, 40, Direction::EwsToAsset, *profile);
                assert_eq!(d.kind, *want, "{profile:?}");
            }
        }));
    }
    for j in joins {
        j.join().expect("dissect battle thread");
    }
}
