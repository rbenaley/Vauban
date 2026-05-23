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
        WireProtocol::Modbus
        | WireProtocol::OpcUa
        | WireProtocol::Iec104
        | WireProtocol::Profinet
            if detected == want =>
        {
            ConformityDecision::Confirmed
        }
        WireProtocol::Modbus
        | WireProtocol::OpcUa
        | WireProtocol::Iec104
        | WireProtocol::Profinet => ConformityDecision::ForeignProtocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iacs_protocol::classify::classify_peek;

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
}
