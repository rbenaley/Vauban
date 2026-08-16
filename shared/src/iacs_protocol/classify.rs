//! Peek-based wire protocol classification (no command parsing).

/// Detected industrial wire protocol family.
///
/// `BacnetIp` and `S7` are **detect-only**: they have no
/// [`super::ExpectedProfile`] so a typed tunnel always treats them as
/// [`super::ConformityDecision::ForeignProtocol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProtocol {
    Modbus,
    OpcUa,
    Iec104,
    Profinet,
    Enip,
    BacnetSc,
    Dnp3,
    Iec61850,
    /// BACnet/IP BVLL (`0x81`) -- detect-only, no expected profile.
    BacnetIp,
    /// S7comm over TPKT -- detect-only (port-102 collision with MMS).
    S7,
    Unknown,
}

impl WireProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Modbus => "modbus",
            Self::OpcUa => "opcua",
            Self::Iec104 => "iec104",
            Self::Profinet => "profinet",
            Self::Enip => "enip",
            Self::BacnetSc => "bacnet_sc",
            Self::Dnp3 => "dnp3",
            Self::Iec61850 => "iec61850",
            Self::BacnetIp => "bacnet_ip",
            Self::S7 => "s7",
            Self::Unknown => "unknown",
        }
    }

    /// Every catalogue variant including detect-only and Unknown.
    pub const ALL: &'static [Self] = &[
        Self::Modbus,
        Self::OpcUa,
        Self::Iec104,
        Self::Profinet,
        Self::Enip,
        Self::BacnetSc,
        Self::Dnp3,
        Self::Iec61850,
        Self::BacnetIp,
        Self::S7,
        Self::Unknown,
    ];
}

/// CIP encapsulation commands accepted as EtherNet/IP explicit (TCP).
const ENIP_COMMANDS: &[u16] = &[
    0x0001, // NOP
    0x0004, // ListServices
    0x0063, // ListIdentity
    0x0064, // ListInterfaces
    0x0065, // RegisterSession
    0x0066, // UnregisterSession
    0x006F, // SendRRData
    0x0070, // SendUnitData
    0x0072, // IndicateStatus
    0x0073, // Cancel
];

/// Classify a TCP payload prefix. Returns `Unknown` when more bytes
/// are needed or the prefix is ambiguous.
///
/// Order (ADR 006): Modbus → OPC-UA → IEC-104 → DNP3 → ENIP →
/// IEC 61850 → BACnet/SC → BACnet/IP → PROFINET → S7 → Unknown.
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
    if let Some(p) = try_dnp3(buf) {
        return p;
    }
    if let Some(p) = try_enip(buf) {
        return p;
    }
    if let Some(p) = try_iec61850(buf) {
        return p;
    }
    if let Some(p) = try_bacnet_sc(buf) {
        return p;
    }
    if let Some(p) = try_bacnet_ip(buf) {
        return p;
    }
    if let Some(p) = try_profinet(buf) {
        return p;
    }
    if let Some(p) = try_s7(buf) {
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
    if !(2..=260).contains(&length) {
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

fn try_dnp3(buf: &[u8]) -> Option<WireProtocol> {
    // IEEE 1815 link-layer start octets + LENGTH (minimum 5).
    if buf.len() < 3 {
        return None;
    }
    if buf[0] != 0x05 || buf[1] != 0x64 {
        return None;
    }
    let length = buf[2] as usize;
    if !(5..=255).contains(&length) {
        return None;
    }
    Some(WireProtocol::Dnp3)
}

fn try_enip(buf: &[u8]) -> Option<WireProtocol> {
    // EtherNet/IP explicit: 24-byte CIP encapsulation header.
    if buf.len() < 24 {
        return None;
    }
    let command = u16::from_le_bytes([buf[0], buf[1]]);
    if !ENIP_COMMANDS.contains(&command) {
        return None;
    }
    let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    // Data after the 24-byte header; keep a conservative ceiling.
    if length > 65_535 {
        return None;
    }
    Some(WireProtocol::Enip)
}

fn is_tpkt(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] == 0x03 && buf[1] == 0x00
}

fn s7comm_offset(buf: &[u8]) -> Option<usize> {
    if !is_tpkt(buf) || buf.len() < 5 {
        return None;
    }
    let li = buf[4] as usize;
    Some(5 + li)
}

fn try_iec61850(buf: &[u8]) -> Option<WireProtocol> {
    // TPKT version 3 + reserved 0. Do not confirm MMS until the first
    // post-COTP octet is visible -- a 7-byte S7 prefix (TPKT+COTP
    // without 0x32) must stay Unknown so the gate cannot lock in
    // Iec61850 and then passthrough the rest of S7comm.
    if !is_tpkt(buf) || buf.len() < 5 {
        return None;
    }
    let tpkt_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !(7..=65_535).contains(&tpkt_len) {
        return None;
    }
    let off = s7comm_offset(buf)?;
    let first = *buf.get(off)?;
    if first == 0x32 {
        return None;
    }
    Some(WireProtocol::Iec61850)
}

fn try_bacnet_sc(buf: &[u8]) -> Option<WireProtocol> {
    // TLS record: content type handshake (0x16) + version 0x03 0x01..0x04.
    if buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 && (0x01..=0x04).contains(&buf[2]) {
        return Some(WireProtocol::BacnetSc);
    }
    // HTTP/1.1 WebSocket upgrade (BACnet/SC over WSS terminator).
    if buf.len() >= 4 && (buf.starts_with(b"GET ") || buf.starts_with(b"HTTP")) {
        return Some(WireProtocol::BacnetSc);
    }
    None
}

fn try_bacnet_ip(buf: &[u8]) -> Option<WireProtocol> {
    // BVLL: type 0x81, function, length (u16 BE).
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0x81 {
        return None;
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if !(4..=1497).contains(&length) {
        return None;
    }
    Some(WireProtocol::BacnetIp)
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

fn try_s7(buf: &[u8]) -> Option<WireProtocol> {
    let off = s7comm_offset(buf)?;
    if buf.get(off) == Some(&0x32) {
        return Some(WireProtocol::S7);
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

    pub(crate) fn sample_enip_register_session() -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0..2].copy_from_slice(&0x0065u16.to_le_bytes());
        p[2..4].copy_from_slice(&4u16.to_le_bytes());
        p
    }

    pub(crate) fn sample_dnp3_link() -> Vec<u8> {
        vec![0x05, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x00]
    }

    pub(crate) fn sample_tpkt_mms() -> Vec<u8> {
        // TPKT + COTP CR (LI=6, type 0xE0) + MMS Initiate -- not S7comm.
        // The trailing tag is required: a COTP-only prefix must stay
        // Unknown so S7 cannot confirm as IEC 61850 then passthrough.
        vec![
            0x03, 0x00, 0x00, 0x0C, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8,
        ]
    }

    pub(crate) fn sample_s7() -> Vec<u8> {
        // TPKT + COTP DT (LI=2) + S7comm 0x32.
        vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80, 0x32, 0x01]
    }

    pub(crate) fn sample_tls_client_hello_prefix() -> Vec<u8> {
        vec![0x16, 0x03, 0x03, 0x00, 0x20]
    }

    pub(crate) fn sample_bacnet_ip_whois() -> Vec<u8> {
        vec![0x81, 0x0B, 0x00, 0x08, 0x01, 0x20, 0xFF, 0xFF]
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
    fn classify_dnp3_before_profinet() {
        assert_eq!(classify_peek(&sample_dnp3_link()), WireProtocol::Dnp3);
        assert_ne!(classify_peek(&sample_dnp3_link()), WireProtocol::Profinet);
    }

    #[test]
    fn classify_enip_register_session() {
        assert_eq!(
            classify_peek(&sample_enip_register_session()),
            WireProtocol::Enip
        );
    }

    #[test]
    fn classify_enip_short_header_is_unknown() {
        assert_eq!(
            classify_peek(&[0x65, 0x00, 0x04, 0x00]),
            WireProtocol::Unknown
        );
    }

    #[test]
    fn classify_iec61850_tpkt_cotp() {
        assert_eq!(classify_peek(&sample_tpkt_mms()), WireProtocol::Iec61850);
    }

    #[test]
    fn classify_s7_not_iec61850() {
        assert_eq!(classify_peek(&sample_s7()), WireProtocol::S7);
    }

    #[test]
    fn attack_s7_prefix_on_iec61850_stays_unknown() {
        // TPKT+COTP without the S7comm magic: must not confirm 61850.
        let prefix = vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80];
        assert_eq!(classify_peek(&prefix), WireProtocol::Unknown);
    }

    #[test]
    fn classify_bacnet_sc_tls() {
        assert_eq!(
            classify_peek(&sample_tls_client_hello_prefix()),
            WireProtocol::BacnetSc
        );
    }

    #[test]
    fn classify_bacnet_ip_bvll() {
        assert_eq!(
            classify_peek(&sample_bacnet_ip_whois()),
            WireProtocol::BacnetIp
        );
    }

    #[test]
    fn modbus_prefix_rejects_opc_ua_hel() {
        assert_eq!(classify_peek(b"HEL"), WireProtocol::OpcUa);
        assert_ne!(classify_peek(b"HEL"), WireProtocol::Modbus);
    }

    #[test]
    fn wire_protocol_catalogue_is_exhaustive() {
        assert_eq!(WireProtocol::ALL.len(), 11);
        for p in WireProtocol::ALL {
            assert!(!p.as_str().is_empty());
        }
    }
}
