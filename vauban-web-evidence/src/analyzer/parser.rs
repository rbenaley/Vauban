//! Inverse of [`vauban_audit::iacs_pcap_synth`]: parse a gzipped
//! `.pcap.gz` file into a flat `Vec<RawPacket>` we can then
//! dissect.
//!
//! The on-disk layout is:
//!
//! ```text
//! gzip:
//!   24-byte libpcap classic global header
//!   for each frame:
//!       16-byte record header (ts_sec, ts_usec, incl_len, orig_len)
//!       incl_len bytes starting at the IPv4/IPv6 header
//!         (LINKTYPE_RAW, DLT 12)
//! ```
//!
//! The parser is deliberately tolerant: a truncated gzip / pcap
//! body must surface the records read so far, never panic. The
//! audit module guarantees at least the global header is on disk
//! even if the writer was killed mid-stream
//! (`crash_resilience_partial_pcap_still_starts_with_global_header`).

use std::io::Read;

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use flate2::read::GzDecoder;

use super::types::Direction;

/// Hard limit on the size of a single PCAP record we will accept.
/// Forensic frames cap at ~64 KiB by L3 design (IPv4 `total_length`
/// is `u16`); anything larger means a corrupt header and we refuse
/// to allocate.
pub const MAX_RECORD_LEN: u32 = 65_535;

/// Hard limit on the number of records we keep in memory for one
/// channel. Beyond this we stop parsing; the IACS recording layer
/// already enforces a per-session retention so we should never
/// see anywhere close to this in practice.
pub const MAX_RECORDS_PER_CHANNEL: usize = 250_000;

/// Hard limit on the decompressed PCAP size. Defends against zip
/// bombs (a tiny gzip file expanding to gigabytes); 256 MiB is
/// generous enough for a multi-hour Modbus session yet small
/// enough to fit comfortably in memory.
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Magic value of a libpcap classic global header in little-endian.
const PCAP_GLOBAL_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

/// One raw frame parsed out of the PCAP file.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// 1-based index inside the channel.
    pub frame_idx: usize,
    /// libpcap microsecond timestamp (ts_sec * 1_000_000 + ts_usec).
    pub timestamp_us: u64,
    /// Source IP from the synthetic L3 header.
    pub src_ip: std::net::IpAddr,
    /// Destination IP.
    pub dst_ip: std::net::IpAddr,
    /// Source TCP port.
    pub src_port: u16,
    /// Destination TCP port.
    pub dst_port: u16,
    /// TCP flags (FIN/SYN/PSH/ACK from etherparse).
    pub tcp_flags: TcpFlags,
    /// Sequence number from the synthetic TCP header.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Application payload bytes (slice of the captured frame
    /// after the IPv4/IPv6 + TCP headers).
    pub payload: Vec<u8>,
    /// Full captured frame (IP header + TCP header + payload).
    /// Surfaced for the hex pane.
    pub frame_bytes: Vec<u8>,
    /// Byte offset inside `frame_bytes` where the TCP payload
    /// starts (= IP header length + TCP header length). Surfaced
    /// so the dissector field offsets can be re-anchored to the
    /// frame coordinate system without re-parsing.
    pub payload_offset: usize,
}

/// Mirror of the etherparse TCP flag fields, kept simple and
/// owned (etherparse types borrow the underlying buffer).
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    pub fn is_control_only(self, payload_empty: bool) -> bool {
        payload_empty
    }

    pub fn label(self) -> &'static str {
        if self.syn && self.ack {
            "[SYN, ACK]"
        } else if self.syn {
            "[SYN]"
        } else if self.fin && self.ack {
            "[FIN, ACK]"
        } else if self.fin {
            "[FIN]"
        } else if self.rst {
            "[RST]"
        } else if self.psh && self.ack {
            "[PSH, ACK]"
        } else if self.ack {
            "[ACK]"
        } else {
            "[?]"
        }
    }
}

/// Parser-level error. Surfaced to the handler layer so a corrupt
/// PCAP can be reported to the operator without leaking the raw
/// flate2/etherparse error wording.
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error("invalid gzip stream: {0}")]
    Gzip(String),
    #[error("invalid PCAP global header (got magic {0:#010x}, expected {1:#010x})")]
    BadGlobalHeader(u32, u32),
    #[error("PCAP file truncated below the global header (got {0} bytes)")]
    TooShort(usize),
    #[error("decompressed PCAP exceeds limit ({0} bytes > {1})")]
    TooLarge(u64, u64),
}

/// Decompress an `.pcap.gz` reader and parse all records that
/// fit cleanly. Tolerates a truncated trailer: the records read
/// so far are returned, no error.
pub fn parse_pcap_gz<R: Read>(reader: R) -> Result<Vec<RawPacket>, ParserError> {
    let mut decoder = GzDecoder::new(reader);
    let mut decompressed = Vec::new();
    // Cap the decompressed size to defend against zip bombs.
    let mut take = (&mut decoder).take(MAX_DECOMPRESSED_BYTES + 1);
    take.read_to_end(&mut decompressed)
        .map_err(|e| ParserError::Gzip(e.to_string()))?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(ParserError::TooLarge(
            decompressed.len() as u64,
            MAX_DECOMPRESSED_BYTES,
        ));
    }

    parse_pcap_bytes(&decompressed)
}

/// Parse a complete (already decompressed) PCAP buffer. Public so
/// tests can drive it without going through gzip.
pub fn parse_pcap_bytes(buf: &[u8]) -> Result<Vec<RawPacket>, ParserError> {
    if buf.len() < PCAP_GLOBAL_HEADER_LEN {
        return Err(ParserError::TooShort(buf.len()));
    }

    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != PCAP_GLOBAL_MAGIC_LE {
        return Err(ParserError::BadGlobalHeader(magic, PCAP_GLOBAL_MAGIC_LE));
    }

    let mut out: Vec<RawPacket> = Vec::new();
    let mut cursor = PCAP_GLOBAL_HEADER_LEN;
    let mut frame_idx: usize = 0;

    while cursor + PCAP_RECORD_HEADER_LEN <= buf.len() && out.len() < MAX_RECORDS_PER_CHANNEL {
        let hdr = &buf[cursor..cursor + PCAP_RECORD_HEADER_LEN];
        let ts_sec = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let ts_usec = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
        let incl_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        // orig_len ignored: dissection is based on incl_len.

        if incl_len == 0 || incl_len > MAX_RECORD_LEN {
            // Defensive stop: a corrupted record header would otherwise
            // make us run wild on the buffer.
            break;
        }

        let payload_start = cursor + PCAP_RECORD_HEADER_LEN;
        let payload_end = payload_start.saturating_add(incl_len as usize);
        if payload_end > buf.len() {
            // Truncated frame at end of file: stop, do not error.
            break;
        }

        let frame_bytes = buf[payload_start..payload_end].to_vec();
        match decode_frame(&frame_bytes) {
            Ok(decoded) => {
                frame_idx += 1;
                out.push(RawPacket {
                    frame_idx,
                    timestamp_us: ts_sec * 1_000_000 + ts_usec,
                    src_ip: decoded.src_ip,
                    dst_ip: decoded.dst_ip,
                    src_port: decoded.src_port,
                    dst_port: decoded.dst_port,
                    tcp_flags: decoded.flags,
                    seq: decoded.seq,
                    ack: decoded.ack,
                    payload: decoded.payload,
                    frame_bytes,
                    payload_offset: decoded.payload_offset,
                });
            }
            Err(_) => {
                // Skip records we cannot decode (malformed L3/L4):
                // the audit synth layer always emits well-formed
                // frames so this can only happen on a corrupt PCAP.
                // We keep the global parse going.
            }
        }

        cursor = payload_end;
    }

    Ok(out)
}

struct DecodedFrame {
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
    payload_offset: usize,
}

fn decode_frame(frame: &[u8]) -> Result<DecodedFrame, ()> {
    let parsed = PacketHeaders::from_ip_slice(frame).map_err(|_| ())?;
    let (src_ip, dst_ip, ip_header_len) = match parsed.net.as_ref() {
        Some(NetHeaders::Ipv4(h, _)) => {
            let src = std::net::IpAddr::V4(std::net::Ipv4Addr::from(h.source));
            let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::from(h.destination));
            (src, dst, h.header_len())
        }
        Some(NetHeaders::Ipv6(h, _)) => {
            let src = std::net::IpAddr::V6(std::net::Ipv6Addr::from(h.source));
            let dst = std::net::IpAddr::V6(std::net::Ipv6Addr::from(h.destination));
            (src, dst, h.header_len())
        }
        _ => return Err(()),
    };

    let (src_port, dst_port, flags, seq, ack, tcp_header_len) = match parsed.transport.as_ref() {
        Some(TransportHeader::Tcp(t)) => (
            t.source_port,
            t.destination_port,
            TcpFlags {
                fin: t.fin,
                syn: t.syn,
                rst: t.rst,
                psh: t.psh,
                ack: t.ack,
            },
            t.sequence_number,
            t.acknowledgment_number,
            t.header_len(),
        ),
        _ => return Err(()),
    };

    let payload = parsed.payload.slice().to_vec();
    let payload_offset = ip_header_len + tcp_header_len;

    Ok(DecodedFrame {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        flags,
        seq,
        ack,
        payload,
        payload_offset,
    })
}

/// Convenience helper: TCP control frames vs application data.
/// Used by the dissector registry to skip the protocol parsers
/// when the segment carries no application payload.
pub fn classify_control(p: &RawPacket) -> bool {
    p.payload.is_empty()
}

/// Direction inferred from the frame's source endpoint matching
/// the EWS (client) or asset (server) endpoint. The caller is
/// expected to provide the canonical client/server tuple from
/// `meta.json` (see `flow.rs`); on mismatch we fall back to a
/// port heuristic (`> 1024 -> EWS`).
pub fn infer_direction(
    p: &RawPacket,
    client_ip: std::net::IpAddr,
    client_port: u16,
    server_ip: std::net::IpAddr,
    server_port: u16,
) -> Direction {
    if p.src_ip == client_ip
        && p.src_port == client_port
        && p.dst_ip == server_ip
        && p.dst_port == server_port
    {
        return Direction::EwsToAsset;
    }
    if p.src_ip == server_ip
        && p.src_port == server_port
        && p.dst_ip == client_ip
        && p.dst_port == client_port
    {
        return Direction::AssetToEws;
    }
    if p.src_port == server_port || (p.dst_port >= 1024 && p.src_port < 1024) {
        return Direction::AssetToEws;
    }
    Direction::EwsToAsset
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
    use vauban_audit::iacs_pcap_synth as synth;

    fn build_full_pcap_modbus_request() -> Vec<u8> {
        let mut flow = synth::TcpFlow::new(
            "session-test",
            1,
            synth::Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502),
        );
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        for r in synth::build_handshake(&flow, 1_000) {
            buf.extend_from_slice(&r);
        }
        let modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";
        for r in
            synth::build_data_records(&mut flow, synth::Direction::ClientToServer, modbus, 2_000)
        {
            buf.extend_from_slice(&r);
        }
        for r in synth::build_close(&flow, 3_000) {
            buf.extend_from_slice(&r);
        }
        buf
    }

    fn gzip(buf: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(buf).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn parse_full_modbus_pcap_round_trips() {
        let buf = build_full_pcap_modbus_request();
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        // 3 handshake + 2 data + 4 close = 9 records.
        assert_eq!(parsed.len(), 9);
        // First record must be SYN.
        assert!(parsed[0].tcp_flags.syn);
        // PSH+ACK record carries our Modbus payload.
        let data = parsed
            .iter()
            .find(|p| !p.payload.is_empty())
            .expect("data record");
        assert_eq!(data.payload[0..2], [0x00, 0x01]); // tx_id
        assert_eq!(data.payload[7], 0x03); // function code
    }

    #[test]
    fn parse_pcap_gz_round_trips_through_gzip() {
        let buf = build_full_pcap_modbus_request();
        let gz = gzip(&buf);
        let parsed = parse_pcap_gz(&gz[..]).expect("parse gz");
        assert_eq!(parsed.len(), 9);
    }

    #[test]
    fn parse_truncated_after_header_returns_empty() {
        let buf = synth::build_global_header().to_vec();
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_too_short_returns_error() {
        let err = parse_pcap_bytes(&[0u8; 10]);
        assert!(matches!(err, Err(ParserError::TooShort(10))));
    }

    #[test]
    fn parse_bad_magic_returns_error() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        let err = parse_pcap_bytes(&buf);
        assert!(matches!(err, Err(ParserError::BadGlobalHeader(_, _))));
    }

    #[test]
    fn parse_truncated_record_in_middle_returns_what_was_read() {
        let mut buf = build_full_pcap_modbus_request();
        buf.truncate(buf.len() - 5);
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        // We lost the last record but earlier ones must be intact.
        assert!(!parsed.is_empty());
    }

    #[test]
    fn parse_ipv6_pcap_records() {
        let mut flow = synth::TcpFlow::new(
            "s",
            1,
            synth::Endpoints::parse("2001:db8::1", 49_152, "2001:db8::2", 4840),
        );
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        for r in synth::build_handshake(&flow, 0) {
            buf.extend_from_slice(&r);
        }
        for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, b"hi", 1) {
            buf.extend_from_slice(&r);
        }
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        assert!(
            parsed
                .iter()
                .all(|p| matches!(p.src_ip, std::net::IpAddr::V6(_)))
        );
    }

    #[test]
    fn parse_segmented_payload_yields_multiple_records() {
        let mut flow = synth::TcpFlow::new(
            "s",
            1,
            synth::Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502),
        );
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        // Payload bigger than IPv4 max segment.
        let payload = vec![0xAB; synth::MAX_IPV4_PAYLOAD + 100];
        for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &payload, 0)
        {
            buf.extend_from_slice(&r);
        }
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        // 2 PSH+ACK + 2 cumulative ACK = 4.
        assert_eq!(parsed.len(), 4);
    }

    #[test]
    fn tcp_flags_label_maps_known_combinations() {
        let f = TcpFlags {
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: false,
        };
        assert_eq!(f.label(), "[SYN]");
        let f = TcpFlags {
            fin: false,
            syn: true,
            rst: false,
            psh: false,
            ack: true,
        };
        assert_eq!(f.label(), "[SYN, ACK]");
        let f = TcpFlags {
            fin: true,
            syn: false,
            rst: false,
            psh: false,
            ack: true,
        };
        assert_eq!(f.label(), "[FIN, ACK]");
        let f = TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: true,
            ack: true,
        };
        assert_eq!(f.label(), "[PSH, ACK]");
        let f = TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: true,
        };
        assert_eq!(f.label(), "[ACK]");
    }

    #[test]
    fn payload_offset_matches_ip_plus_tcp_header_lengths() {
        let buf = build_full_pcap_modbus_request();
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        for p in &parsed {
            // Without IP options or TCP options synth always emits
            // 20-byte IPv4 + 20-byte TCP. payload_offset must agree.
            assert_eq!(p.payload_offset, 40);
        }
    }

    #[test]
    fn infer_direction_matches_canonical_tuple() {
        let buf = build_full_pcap_modbus_request();
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        let client_ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let server_ip: std::net::IpAddr = "198.51.100.20".parse().unwrap();
        // PSH+ACK from client to server.
        let data = parsed.iter().find(|p| !p.payload.is_empty()).expect("data");
        let dir = infer_direction(data, client_ip, 49_152, server_ip, 502);
        assert_eq!(dir, Direction::EwsToAsset);
    }

    #[test]
    fn classify_control_returns_true_for_empty_payload() {
        let buf = build_full_pcap_modbus_request();
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        let syn = &parsed[0];
        assert!(classify_control(syn));
    }

    #[test]
    fn parse_handles_zero_record_lengths_gracefully() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        // Bogus record header with incl_len = 0.
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        buf.extend_from_slice(&0u32.to_le_bytes()); // incl_len = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // orig_len = 0
        let parsed = parse_pcap_bytes(&buf).expect("parse");
        assert!(parsed.is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Arbitrary / truncated buffers never panic.
        #[test]
        fn parse_pcap_bytes_never_panics(
            buf in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let _ = parse_pcap_bytes(&buf);
        }

        /// Below the global header length → TooShort.
        #[test]
        fn too_short_is_err(len in 0usize..PCAP_GLOBAL_HEADER_LEN) {
            let buf = vec![0u8; len];
            let err = parse_pcap_bytes(&buf).unwrap_err();
            prop_assert!(matches!(err, ParserError::TooShort(_)));
        }

        /// Wrong magic → BadGlobalHeader (when long enough).
        #[test]
        fn bad_magic_is_err(
            magic in any::<u32>().prop_filter("not pcap magic", |m| *m != PCAP_GLOBAL_MAGIC_LE),
            rest in prop::collection::vec(any::<u8>(), 20..64),
        ) {
            let mut buf = magic.to_le_bytes().to_vec();
            buf.extend_from_slice(&rest);
            let err = parse_pcap_bytes(&buf).unwrap_err();
            prop_assert!(matches!(err, ParserError::BadGlobalHeader(_, _)));
        }

        /// incl_len == 0 or > MAX_RECORD_LEN stops without panic (empty ok).
        #[test]
        fn bogus_incl_len_stops_safely(
            incl_len in prop_oneof![Just(0u32), (MAX_RECORD_LEN + 1)..=u32::MAX],
        ) {
            let mut buf = Vec::new();
            buf.extend_from_slice(&PCAP_GLOBAL_MAGIC_LE.to_le_bytes());
            buf.extend_from_slice(&[0u8; PCAP_GLOBAL_HEADER_LEN - 4]);
            buf.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
            buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            buf.extend_from_slice(&incl_len.to_le_bytes());
            buf.extend_from_slice(&incl_len.to_le_bytes()); // orig_len
            let parsed = parse_pcap_bytes(&buf).expect("structural ok");
            prop_assert!(parsed.is_empty());
        }

        /// Non-gzip bytes into parse_pcap_gz yield Gzip (or TooShort after empty).
        #[test]
        fn gzip_garbage_is_err(
            buf in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            // Valid gzip magic is 1f 8b; skip accidental well-formed streams.
            prop_assume!(!(buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b));
            let err = parse_pcap_gz(&buf[..]).unwrap_err();
            prop_assert!(matches!(
                err,
                ParserError::Gzip(_) | ParserError::TooShort(_) | ParserError::BadGlobalHeader(_, _)
            ));
        }
    }
}
