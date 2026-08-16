//! Property tests for bounded TCP reassembly in the IACS packet analyzer.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use proptest::prelude::*;
use shared::iacs_protocol::ExpectedProfile;
use vauban_web::services::iacs_packet_analyzer::dissectors;
use vauban_web::services::iacs_packet_analyzer::reassembly::{
    MAX_REASSEMBLY_BYTES, TcpReassembler,
};
use vauban_web::services::iacs_packet_analyzer::types::{Direction, PacketKind};

fn all_profiles() -> impl Strategy<Value = ExpectedProfile> {
    prop_oneof![
        Just(ExpectedProfile::Modbus),
        Just(ExpectedProfile::OpcUa),
        Just(ExpectedProfile::Iec104),
        Just(ExpectedProfile::Profinet),
        Just(ExpectedProfile::Enip),
        Just(ExpectedProfile::Dnp3),
        Just(ExpectedProfile::Iec61850),
        Just(ExpectedProfile::BacnetSc),
        Just(ExpectedProfile::Passthrough),
    ]
}

proptest! {
    #[test]
    fn push_never_panics_on_arbitrary_bytes(
        profile in all_profiles(),
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..512), 0..32),
    ) {
        let mut reasm = TcpReassembler::new(profile);
        for chunk in &chunks {
            let _ = reasm.push(chunk);
            prop_assert!(reasm.buffered_len() <= MAX_REASSEMBLY_BYTES);
        }
        let _ = reasm.flush_fragment();
    }

    #[test]
    fn buffer_never_exceeds_max_reassembly_bytes(
        profile in all_profiles(),
        data in prop::collection::vec(any::<u8>(), 0..MAX_REASSEMBLY_BYTES + 4096),
    ) {
        let mut reasm = TcpReassembler::new(profile);
        let mut offset = 0;
        while offset < data.len() {
            let end = std::cmp::min(offset + 37, data.len());
            let _ = reasm.push(&data[offset..end]);
            prop_assert!(reasm.buffered_len() <= MAX_REASSEMBLY_BYTES);
            offset = end;
        }
    }

    #[test]
    fn incomplete_pdus_never_classify_as_cmd(
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let d = dissectors::dissect_fragment(&payload, 40, Direction::EwsToAsset);
        prop_assert_ne!(d.kind, PacketKind::Cmd);
        prop_assert!(d.summary.contains("(fragment)"));
    }
}
