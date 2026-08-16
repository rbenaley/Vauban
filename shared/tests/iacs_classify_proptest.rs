//! Property tests for [`shared::iacs_protocol::classify_peek`].

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::iacs_protocol::{ExpectedProfile, WireProtocol, classify_peek, evaluate_conformity};

fn all_wire() -> [WireProtocol; 11] {
    [
        WireProtocol::Modbus,
        WireProtocol::OpcUa,
        WireProtocol::Iec104,
        WireProtocol::Profinet,
        WireProtocol::Enip,
        WireProtocol::BacnetSc,
        WireProtocol::Dnp3,
        WireProtocol::Iec61850,
        WireProtocol::BacnetIp,
        WireProtocol::S7,
        WireProtocol::Unknown,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Classifier is total and deterministic on arbitrary bytes.
    #[test]
    fn classify_peek_never_panics(buf in prop::collection::vec(any::<u8>(), 0..512)) {
        let a = classify_peek(&buf);
        let b = classify_peek(&buf);
        prop_assert_eq!(a, b);
        prop_assert!(!a.as_str().is_empty());
    }

    /// Random bytes must not confirm a typed profile unless they
    /// actually match that family's magic (Unknown / other family).
    #[test]
    fn random_bytes_do_not_confirm_typed_profile(
        buf in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let detected = classify_peek(&buf);
        for expected in [
            ExpectedProfile::Enip,
            ExpectedProfile::Dnp3,
            ExpectedProfile::BacnetSc,
            ExpectedProfile::Iec61850,
        ] {
            let want = expected.expected_wire().expect("typed");
            if detected != want {
                let d = evaluate_conformity(expected, detected, false);
                prop_assert_ne!(d, shared::iacs_protocol::ConformityDecision::Confirmed);
            }
        }
    }

    /// Short prefixes that cannot complete a family header stay Unknown
    /// (or a stable known family when a complete prefix matches).
    #[test]
    fn short_prefix_is_unknown_or_stable(buf in prop::collection::vec(any::<u8>(), 0..7)) {
        let p = classify_peek(&buf);
        prop_assert!(all_wire().contains(&p));
        // DNP3 needs 3 bytes; ENIP 24; TLS 5; TPKT 5. IEC-104 can
        // confirm on a 2-byte `0x68` prefix.
        if buf.len() < 3 && buf.first() != Some(&0x68) {
            prop_assert!(
                p == WireProtocol::Unknown
                    || p == WireProtocol::OpcUa
                    || p == WireProtocol::Iec104
            );
        }
    }

    /// Golden-family frames remain classified deterministically.
    ///
    /// No trailing pad: Modbus is tried first and a Profinet prefix
    /// (`05 00 00 00`) plus arbitrary bytes can look like a valid MBAP.
    #[test]
    fn known_family_frames_are_deterministic(_unit in Just(())) {
        let modbus = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ];
        prop_assert_eq!(classify_peek(&modbus), WireProtocol::Modbus);
        prop_assert_eq!(classify_peek(b"HEL"), WireProtocol::OpcUa);
        prop_assert_eq!(classify_peek(b"OPN"), WireProtocol::OpcUa);
        prop_assert_eq!(classify_peek(&[0x68, 0x04]), WireProtocol::Iec104);
        prop_assert_eq!(
            classify_peek(&[0x05, 0x00, 0x00, 0x00]),
            WireProtocol::Profinet
        );
        prop_assert_eq!(classify_peek(&[0x05, 0x64, 0x05]), WireProtocol::Dnp3);
        let mut hel = b"HEL".to_vec();
        hel.extend_from_slice(&[0xFF; 16]);
        prop_assert_eq!(classify_peek(&hel), WireProtocol::OpcUa);
    }

    /// `as_str` is nonempty for every catalogue variant.
    #[test]
    fn as_str_nonempty_for_all_variants(_unit in Just(())) {
        for p in all_wire() {
            prop_assert!(!p.as_str().is_empty());
        }
    }
}
