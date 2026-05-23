//! Map `proxy_sessions.industrial_protocol` labels to gate profiles.

/// Expected industrial protocol profile for a tunnel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedProfile {
    Modbus,
    OpcUa,
    Iec104,
    Profinet,
    /// Generic TCP catch-all (`iacs_tcp` / `tcp` label) -- no gate.
    Passthrough,
}

impl ExpectedProfile {
    /// Parse the `industrial_protocol` column / IPC label.
    pub fn from_industrial_label(label: &str) -> Self {
        match label {
            "modbus" => Self::Modbus,
            "opcua" => Self::OpcUa,
            "iec104" => Self::Iec104,
            "profinet" => Self::Profinet,
            // `tcp` and any unknown label degrade to passthrough so a
            // mislabeled row does not brick connectivity.
            _ => Self::Passthrough,
        }
    }

    /// Wire protocol this profile expects once classification completes.
    pub fn expected_wire(self) -> Option<super::classify::WireProtocol> {
        match self {
            Self::Modbus => Some(super::classify::WireProtocol::Modbus),
            Self::OpcUa => Some(super::classify::WireProtocol::OpcUa),
            Self::Iec104 => Some(super::classify::WireProtocol::Iec104),
            Self::Profinet => Some(super::classify::WireProtocol::Profinet),
            Self::Passthrough => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_industrial_label_maps_known_profiles() {
        assert_eq!(
            ExpectedProfile::from_industrial_label("modbus"),
            ExpectedProfile::Modbus
        );
        assert_eq!(
            ExpectedProfile::from_industrial_label("opcua"),
            ExpectedProfile::OpcUa
        );
        assert_eq!(
            ExpectedProfile::from_industrial_label("iec104"),
            ExpectedProfile::Iec104
        );
        assert_eq!(
            ExpectedProfile::from_industrial_label("profinet"),
            ExpectedProfile::Profinet
        );
        assert_eq!(
            ExpectedProfile::from_industrial_label("tcp"),
            ExpectedProfile::Passthrough
        );
    }
}
