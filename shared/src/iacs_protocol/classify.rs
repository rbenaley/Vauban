//! Peek-based wire protocol classification (no command parsing).

/// Detected industrial wire protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProtocol {
    Modbus,
    OpcUa,
    Iec104,
    Profinet,
    Unknown,
}

impl WireProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modbus => "modbus",
            Self::OpcUa => "opcua",
            Self::Iec104 => "iec104",
            Self::Profinet => "profinet",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify a TCP payload prefix. Returns `Unknown` when more bytes
/// are needed or the prefix is ambiguous.
pub fn classify_peek(buf: &[u8]) -> WireProtocol {
    if let Some(p) = try_modbus(buf) {
        return p;
    }
    if let Some(p) = try_opc_ua(buf) {
        return p;
    }
    if let Some(p) = try_iec104(buf) {
        return p;
    }
    if let Some(p) = try_profinet(buf) {
        return p;
    }
    WireProtocol::Unknown
}

fn try_modbus(buf: &[u8]) -> Option<WireProtocol> {
    // Modbus/TCP MBAP header is 7 bytes minimum before PDU.
    if buf.len() < 8 {
        return None;
    }
    // Protocol identifier MUST be 0.
    if buf[2] != 0 || buf[3] != 0 {
        return None;
    }
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    // Length field covers unit id + PDU (1 + pdu_len).
    if length < 2 || length > 260 {
        return None;
    }
    if buf.len() < 6 + length {
        // Might still be Modbus once more bytes arrive; treat as
        // unknown rather than foreign so fragmented frames work.
        return None;
    }
    Some(WireProtocol::Modbus)
}

fn try_opc_ua(buf: &[u8]) -> Option<WireProtocol> {
    if buf.len() < 3 {
        return None;
    }
    let tag = std::str::from_utf8(&buf[..3]).ok()?;
    if matches!(tag, "HEL" | "ACK" | "OPN" | "MSG" | "CLO" | "ERR") {
        return Some(WireProtocol::OpcUa);
    }
    None
}

fn try_iec104(buf: &[u8]) -> Option<WireProtocol> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] != 0x68 {
        return None;
    }
    if buf.len() < 2 {
        return None;
    }
    let len = buf[1] as usize;
    // APCI length byte covers control field + optional ASDU; 4 is the
    // minimum U/S-frame size.
    if !(4..=253).contains(&len) {
        return None;
    }
    Some(WireProtocol::Iec104)
}

fn try_profinet(buf: &[u8]) -> Option<WireProtocol> {
    // DCE/RPC connection-oriented PDU: version 5.0 is the common case
    // for PROFINET configuration / RPC over TCP.
    if buf.len() < 4 {
        return None;
    }
    if buf[0] == 0x05 && buf[1] == 0x00 && buf[2] <= 0x03 {
        return Some(WireProtocol::Profinet);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Modbus/TCP read-holding-registers request (FC 3).
    fn sample_modbus_frame() -> Vec<u8> {
        vec![
            0x00, 0x01, // transaction id
            0x00, 0x00, // protocol id
            0x00, 0x06, // length
            0x01, // unit id
            0x03, // function code
            0x00, 0x00, 0x00, 0x0A,
        ]
    }

    #[test]
    fn classify_modbus_mbap() {
        let frame = sample_modbus_frame();
        assert_eq!(classify_peek(&frame), WireProtocol::Modbus);
    }

    #[test]
    fn classify_modbus_fragment_returns_unknown() {
        let frame = sample_modbus_frame();
        assert_eq!(classify_peek(&frame[..4]), WireProtocol::Unknown);
    }

    #[test]
    fn classify_opc_ua_hel() {
        assert_eq!(classify_peek(b"HEL"), WireProtocol::OpcUa);
        assert_eq!(classify_peek(b"OPN"), WireProtocol::OpcUa);
    }

    #[test]
    fn classify_iec104_start_byte() {
        // U-frame STARTDT act (minimal).
        assert_eq!(classify_peek(&[0x68, 0x04]), WireProtocol::Iec104);
    }

    #[test]
    fn classify_profinet_dce_rpc() {
        assert_eq!(
            classify_peek(&[0x05, 0x00, 0x00, 0x00]),
            WireProtocol::Profinet
        );
    }

    #[test]
    fn modbus_prefix_rejects_opc_ua_hel() {
        assert_eq!(classify_peek(b"HEL"), WireProtocol::OpcUa);
        assert_ne!(classify_peek(b"HEL"), WireProtocol::Modbus);
    }

    #[test]
    fn wire_protocol_catalogue_is_exhaustive() {
        let all = [
            WireProtocol::Modbus,
            WireProtocol::OpcUa,
            WireProtocol::Iec104,
            WireProtocol::Profinet,
            WireProtocol::Unknown,
        ];
        assert_eq!(all.len(), 5);
        for p in all {
            assert!(!p.as_str().is_empty());
        }
    }
}
