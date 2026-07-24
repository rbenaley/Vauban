//! Property tests for [`shared::iacs_protocol::classify_peek`].

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::iacs_protocol::{WireProtocol, classify_peek};

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

    /// Short prefixes that cannot complete a family header stay Unknown
    /// (or a stable known family when a complete prefix matches).
    #[test]
    fn short_prefix_is_unknown_or_stable(buf in prop::collection::vec(any::<u8>(), 0..7)) {
        let p = classify_peek(&buf);
        // With < 3 bytes only Unknown or (len>=1 IEC104 start) possible.
        // Property: calling twice is stable (already covered) and result
        // is one of the five catalogue variants.
        prop_assert!(matches!(
            p,
            WireProtocol::Modbus
                | WireProtocol::OpcUa
                | WireProtocol::Iec104
                | WireProtocol::Profinet
                | WireProtocol::Unknown
        ));
        if buf.len() < 3 && !(buf.first() == Some(&0x68) && buf.len() >= 2) {
            // No OPC UA 3-byte tag, no Profinet 4-byte, no Modbus 8-byte.
            // IEC104 needs 0x68 + length in 4..=253.
            if buf.first() != Some(&0x68) {
                prop_assert_eq!(p, WireProtocol::Unknown);
            }
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
        // Trailing pad after a complete OPC UA tag stays OPC UA (Modbus
        // needs protocol-id zeros at bytes 2-3 which "HEL..." does not).
        let mut hel = b"HEL".to_vec();
        hel.extend_from_slice(&[0xFF; 16]);
        prop_assert_eq!(classify_peek(&hel), WireProtocol::OpcUa);
    }

    /// `as_str` is nonempty for every catalogue variant.
    #[test]
    fn as_str_nonempty_for_all_variants(_unit in Just(())) {
        for p in [
            WireProtocol::Modbus,
            WireProtocol::OpcUa,
            WireProtocol::Iec104,
            WireProtocol::Profinet,
            WireProtocol::Unknown,
        ] {
            prop_assert!(!p.as_str().is_empty());
        }
    }
}
