//! Conformity decisions for expected vs detected wire protocols.

use super::classify::WireProtocol;
use super::expected::ExpectedProfile;

/// Outcome of comparing an expected profile to a peek classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformityDecision {
    /// Passthrough profile -- gate disabled.
    AllowPassthrough,
    /// Detected protocol matches the expected profile.
    Confirmed,
    /// More bytes required before deciding.
    NeedMoreData,
    /// Detected a foreign industrial protocol -- fail closed.
    ForeignProtocol,
    /// Classification deadline or buffer limit hit without confirmation.
    Unconfirmed,
}

/// Evaluate whether `detected` conforms to `expected`.
///
/// Any named [`WireProtocol`] other than the one this profile wants
/// (including detect-only `BacnetIp` / `S7`) is [`ForeignProtocol`].
pub fn evaluate_conformity(
    expected: ExpectedProfile,
    detected: WireProtocol,
    classifying: bool,
) -> ConformityDecision {
    if expected == ExpectedProfile::Passthrough {
        return ConformityDecision::AllowPassthrough;
    }

    let Some(want) = expected.expected_wire() else {
        return ConformityDecision::AllowPassthrough;
    };

    match detected {
        WireProtocol::Unknown if classifying => ConformityDecision::NeedMoreData,
        WireProtocol::Unknown => ConformityDecision::Unconfirmed,
        other if other == want => ConformityDecision::Confirmed,
        _ => ConformityDecision::ForeignProtocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iacs_protocol::classify::classify_peek;

    fn enip_register() -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0..2].copy_from_slice(&0x0065u16.to_le_bytes());
        p[2..4].copy_from_slice(&4u16.to_le_bytes());
        p
    }

    fn dnp3_link() -> Vec<u8> {
        vec![0x05, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x00]
    }

    fn s7_tpkt() -> Vec<u8> {
        vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80, 0x32, 0x01]
    }

    fn bacnet_ip_bvll() -> Vec<u8> {
        vec![0x81, 0x0B, 0x00, 0x08, 0x01, 0x20, 0xFF, 0xFF]
    }

    #[test]
    fn passthrough_always_allows() {
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Passthrough, WireProtocol::Modbus, true),
            ConformityDecision::AllowPassthrough
        );
    }

    #[test]
    fn confirmed_modbus_on_modbus_profile() {
        let frame = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ];
        let detected = classify_peek(&frame);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Modbus, detected, false),
            ConformityDecision::Confirmed
        );
    }

    #[test]
    fn foreign_opc_ua_on_modbus_profile() {
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Modbus, WireProtocol::OpcUa, false),
            ConformityDecision::ForeignProtocol
        );
    }

    #[test]
    fn unknown_while_classifying_needs_more_data() {
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Modbus, WireProtocol::Unknown, true),
            ConformityDecision::NeedMoreData
        );
    }

    #[test]
    fn unknown_after_deadline_is_unconfirmed() {
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Modbus, WireProtocol::Unknown, false),
            ConformityDecision::Unconfirmed
        );
    }

    #[test]
    fn cross_protocol_matrix_foreign_pairs() {
        let profiles = [
            (ExpectedProfile::Modbus, WireProtocol::OpcUa),
            (ExpectedProfile::Modbus, WireProtocol::Iec104),
            (ExpectedProfile::OpcUa, WireProtocol::Modbus),
            (ExpectedProfile::Iec104, WireProtocol::Modbus),
            (ExpectedProfile::Enip, WireProtocol::Dnp3),
            (ExpectedProfile::Dnp3, WireProtocol::Enip),
            (ExpectedProfile::BacnetSc, WireProtocol::BacnetIp),
            (ExpectedProfile::Iec61850, WireProtocol::S7),
        ];
        for (expected, detected) in profiles {
            assert_eq!(
                evaluate_conformity(expected, detected, false),
                ConformityDecision::ForeignProtocol,
                "expected {:?} vs detected {:?}",
                expected,
                detected
            );
        }
    }

    #[test]
    fn attack_enip_on_dnp3_profile_is_rejected() {
        let detected = classify_peek(&enip_register());
        assert_eq!(detected, WireProtocol::Enip);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Dnp3, detected, false),
            ConformityDecision::ForeignProtocol
        );
    }

    #[test]
    fn attack_bacnet_ip_bvll_on_bacnet_sc_is_rejected() {
        let detected = classify_peek(&bacnet_ip_bvll());
        assert_eq!(detected, WireProtocol::BacnetIp);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::BacnetSc, detected, false),
            ConformityDecision::ForeignProtocol
        );
    }

    #[test]
    fn attack_s7_on_iec61850_is_rejected() {
        let detected = classify_peek(&s7_tpkt());
        assert_eq!(detected, WireProtocol::S7);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Iec61850, detected, false),
            ConformityDecision::ForeignProtocol
        );
    }

    #[test]
    fn attack_s7_prefix_on_iec61850_is_rejected() {
        let prefix = vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80];
        let detected = classify_peek(&prefix);
        assert_eq!(detected, WireProtocol::Unknown);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Iec61850, detected, true),
            ConformityDecision::NeedMoreData
        );
        let mut full = prefix;
        full.extend_from_slice(&[0x32, 0x01]);
        let detected = classify_peek(&full);
        assert_eq!(detected, WireProtocol::S7);
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Iec61850, detected, true),
            ConformityDecision::ForeignProtocol
        );
    }

    #[test]
    fn dnp3_confirms_on_dnp3_profile() {
        let detected = classify_peek(&dnp3_link());
        assert_eq!(
            evaluate_conformity(ExpectedProfile::Dnp3, detected, false),
            ConformityDecision::Confirmed
        );
    }
}
