//! Synthetic L3/L4 PCAP layer for IACS recordings.
//!
//! Each `direct-tcpip` channel is reconstructed as a real-looking
//! TCP/IP conversation:
//!
//! - SYN / SYN-ACK / ACK three-way handshake at channel start,
//! - PSH+ACK with monotonically increasing sequence number on every
//!   relay batch, plus a cumulative ACK record on the opposite leg,
//! - FIN+ACK / ACK / FIN+ACK / ACK 4-way close at channel end.
//!
//! The resulting `.pcap` files dissect natively in tcpdump,
//! Wireshark and Zeek: industrial protocols (Modbus/TCP, OPC-UA,
//! S7, EtherNet/IP, ...) are recognised by the application
//! dissectors with zero post-processing. The TCP layer is purely
//! forensic -- the segments would NOT replay against a live asset
//! because the seq/ack space is detached from the real TCP
//! conversation that vauban-proxy-iacs proxied through SCM_RIGHTS.
//!
//! ## Linktype
//!
//! `LINKTYPE_RAW` (DLT 12). The PCAP record payload starts directly
//! at the IP header; Wireshark and tcpdump detect IPv4 vs IPv6 from
//! the first nibble (`4` -> IPv4, `6` -> IPv6).
//!
//! ## Checksums
//!
//! IPv4 header checksum and TCP checksum are emitted as zero. Both
//! tcpdump and Wireshark accept the "checksum offload" pattern (a
//! warning may be displayed, dissection is not affected). The
//! cryptographic integrity of the recording is anchored by the
//! per-channel BLAKE3 (and the session-level aggregate), not by
//! per-segment TCP checksums.
//!
//! ## Determinism
//!
//! Initial sequence numbers (ISN) are derived from a stable hash of
//! `(session_id, channel_id, direction)` so test fixtures are
//! reproducible. The hash is BLAKE3 (not a CSPRNG, but the ISN
//! space is forensic, not security-relevant: an attacker who can
//! observe the recording can also observe the meta.json that lists
//! every channel id).

use blake3::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `LINKTYPE_RAW` (libpcap). Wireshark's "Raw IP" linktype.
pub const LINKTYPE_RAW: u32 = 12;

/// libpcap classic global header magic, microsecond timestamp resolution.
pub const PCAP_GLOBAL_MAGIC: u32 = 0xa1b2_c3d4;

/// libpcap classic global header length.
pub const PCAP_GLOBAL_HEADER_LEN: usize = 24;

/// libpcap per-record header length.
pub const PCAP_RECORD_HEADER_LEN: usize = 16;

/// Maximum payload bytes we put in a single IPv4 PSH+ACK segment.
/// `total_length` of the IPv4 header is a `u16`, so the absolute
/// ceiling is `65535 - 20 (IPv4 header) - 20 (TCP header)`.
pub const MAX_IPV4_PAYLOAD: usize = 65_535 - 20 - 20;

/// Same constraint, IPv6 fixed header is also 40 bytes.
/// `payload_length` is a `u16`, so the ceiling is
/// `65535 (payload_length) - 20 (TCP header)`.
pub const MAX_IPV6_PAYLOAD: usize = 65_535 - 20;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

/// Direction of a captured chunk relative to the synthetic flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// EWS application -> industrial asset.
    ClientToServer,
    /// Industrial asset -> EWS application.
    ServerToClient,
}

/// Resolved endpoints for one synthetic flow.
#[derive(Debug, Clone)]
pub enum Endpoints {
    V4 {
        client_ip: Ipv4Addr,
        client_port: u16,
        server_ip: Ipv4Addr,
        server_port: u16,
    },
    V6 {
        client_ip: Ipv6Addr,
        client_port: u16,
        server_ip: Ipv6Addr,
        server_port: u16,
    },
}

impl Endpoints {
    /// Parse a `(client_ip, server_ip)` string pair into a coherent
    /// `Endpoints`. Loopback fallback (`127.0.0.1`) is applied when
    /// the input is not a valid IP literal (typical case: `target_host`
    /// arrived as an FQDN -- vauban-audit is in Capsicum and cannot
    /// resolve DNS). When one side is IPv4 and the other IPv6, the
    /// IPv4 endpoint is mapped through `::ffff:a.b.c.d` so the flow
    /// stays in a single address family.
    pub fn parse(client_ip: &str, client_port: u16, server_ip: &str, server_port: u16) -> Self {
        let c = parse_ip_with_loopback_fallback(client_ip);
        let s = parse_ip_with_loopback_fallback(server_ip);
        match (c, s) {
            (IpAddr::V4(c4), IpAddr::V4(s4)) => Endpoints::V4 {
                client_ip: c4,
                client_port,
                server_ip: s4,
                server_port,
            },
            (IpAddr::V6(c6), IpAddr::V6(s6)) => Endpoints::V6 {
                client_ip: c6,
                client_port,
                server_ip: s6,
                server_port,
            },
            (IpAddr::V4(c4), IpAddr::V6(s6)) => Endpoints::V6 {
                client_ip: c4.to_ipv6_mapped(),
                client_port,
                server_ip: s6,
                server_port,
            },
            (IpAddr::V6(c6), IpAddr::V4(s4)) => Endpoints::V6 {
                client_ip: c6,
                client_port,
                server_ip: s4.to_ipv6_mapped(),
                server_port,
            },
        }
    }

    fn is_v4(&self) -> bool {
        matches!(self, Endpoints::V4 { .. })
    }

    fn max_segment_payload(&self) -> usize {
        if self.is_v4() {
            MAX_IPV4_PAYLOAD
        } else {
            MAX_IPV6_PAYLOAD
        }
    }
}

fn parse_ip_with_loopback_fallback(s: &str) -> IpAddr {
    s.parse::<IpAddr>()
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Per-channel TCP state. The audit module owns one of these per
/// active `direct-tcpip` channel; both directions share the struct
/// because every emitted segment carries a cumulative ACK over the
/// peer leg.
#[derive(Debug, Clone)]
pub struct TcpFlow {
    pub endpoints: Endpoints,
    /// Initial sequence number on the client -> server leg. The
    /// next byte the client would send carries seq = `isn_client + 1`
    /// post-handshake.
    pub isn_client: u32,
    /// Initial sequence number on the server -> client leg.
    pub isn_server: u32,
    /// Bytes of application payload already emitted on the client ->
    /// server leg (exclusive of the SYN/FIN sequence-number bumps).
    pub bytes_c2s: u32,
    /// Bytes of application payload already emitted on the server ->
    /// client leg.
    pub bytes_s2c: u32,
}

impl TcpFlow {
    /// Build a deterministic flow from `(session_id, channel_id,
    /// endpoints)`. ISNs are 32-bit truncations of a BLAKE3 keyed
    /// hash so test fixtures are stable while collisions across
    /// concurrent flows are negligible.
    pub fn new(session_id: &str, channel_id: u32, endpoints: Endpoints) -> Self {
        let isn_client = derive_isn(session_id, channel_id, b"client");
        let mut isn_server = derive_isn(session_id, channel_id, b"server");
        // Make sure the two ISNs differ; equality would still be a
        // valid TCP conversation but it confuses some dissectors.
        if isn_server == isn_client {
            isn_server = isn_server.wrapping_add(0x9E37_79B9);
        }
        Self {
            endpoints,
            isn_client,
            isn_server,
            bytes_c2s: 0,
            bytes_s2c: 0,
        }
    }

    /// Sequence number the next client-to-server segment should
    /// carry (post-handshake, so `isn_client + 1 + bytes_c2s`).
    fn next_seq_c2s(&self) -> u32 {
        self.isn_client.wrapping_add(1).wrapping_add(self.bytes_c2s)
    }

    fn next_seq_s2c(&self) -> u32 {
        self.isn_server.wrapping_add(1).wrapping_add(self.bytes_s2c)
    }

    /// Cumulative ack the client should send (= seq the server has
    /// produced so far + 1).
    fn ack_to_server(&self) -> u32 {
        self.next_seq_s2c()
    }

    fn ack_to_client(&self) -> u32 {
        self.next_seq_c2s()
    }
}

fn derive_isn(session_id: &str, channel_id: u32, leg: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(session_id.as_bytes());
    h.update(&channel_id.to_be_bytes());
    h.update(leg);
    let bytes = *h.finalize().as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Build the libpcap classic global header (24 bytes).
pub fn build_global_header() -> [u8; PCAP_GLOBAL_HEADER_LEN] {
    let mut buf = [0u8; PCAP_GLOBAL_HEADER_LEN];
    buf[0..4].copy_from_slice(&PCAP_GLOBAL_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
    buf[6..8].copy_from_slice(&4u16.to_le_bytes()); // minor
    // bytes 8..16 are timezone offset and sigfigs (always zero).
    buf[16..20].copy_from_slice(&65_535u32.to_le_bytes()); // snaplen
    buf[20..24].copy_from_slice(&LINKTYPE_RAW.to_le_bytes());
    buf
}

/// Build the three SYN / SYN-ACK / ACK PCAP records that open a
/// synthetic flow at `timestamp_us`. Returns three already-framed
/// `(record_header + payload)` buffers ready to be appended to the
/// PCAP file. Mutates `flow` to advance bytes counters by zero
/// (handshake consumes 1 sequence number per direction but no
/// payload; the SYN/FIN sequence bump is encoded by the
/// `+1`/`-1` in `next_seq_*`).
pub fn build_handshake(flow: &TcpFlow, timestamp_us: u64) -> Vec<Vec<u8>> {
    let syn = ip_tcp_segment(
        flow,
        Direction::ClientToServer,
        flow.isn_client,
        0, // ack ignored when ACK flag is unset
        TCP_FLAG_SYN,
        &[],
    );
    let syn_ack = ip_tcp_segment(
        flow,
        Direction::ServerToClient,
        flow.isn_server,
        flow.isn_client.wrapping_add(1),
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        &[],
    );
    let ack = ip_tcp_segment(
        flow,
        Direction::ClientToServer,
        flow.isn_client.wrapping_add(1),
        flow.isn_server.wrapping_add(1),
        TCP_FLAG_ACK,
        &[],
    );
    vec![
        wrap_pcap_record(timestamp_us, &syn),
        wrap_pcap_record(timestamp_us, &syn_ack),
        wrap_pcap_record(timestamp_us, &ack),
    ]
}

/// Build the PCAP record(s) for one application data batch. The
/// payload is segmented if it exceeds `endpoints.max_segment_payload()`
/// (16-bit IPv4/IPv6 length cap). `flow` is mutated to reflect the
/// new bytes-emitted counters; an opposite-direction ACK record is
/// also emitted so dissectors see proper TCP acking.
pub fn build_data_records(
    flow: &mut TcpFlow,
    direction: Direction,
    payload: &[u8],
    timestamp_us: u64,
) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mss = flow.endpoints.max_segment_payload();
    let mut offset = 0;
    while offset < payload.len() {
        let end = std::cmp::min(offset + mss, payload.len());
        let chunk = &payload[offset..end];
        let (seq, ack, ack_seq, ack_ack) = match direction {
            Direction::ClientToServer => {
                let s = flow.next_seq_c2s();
                let a = flow.ack_to_server();
                // After this segment the client has produced
                // `bytes_c2s + chunk.len()` bytes.
                let new_bytes = flow.bytes_c2s.wrapping_add(chunk.len() as u32);
                let ack_seq = flow.next_seq_s2c();
                let ack_ack = flow.isn_client.wrapping_add(1).wrapping_add(new_bytes);
                (s, a, ack_seq, ack_ack)
            }
            Direction::ServerToClient => {
                let s = flow.next_seq_s2c();
                let a = flow.ack_to_client();
                let new_bytes = flow.bytes_s2c.wrapping_add(chunk.len() as u32);
                let ack_seq = flow.next_seq_c2s();
                let ack_ack = flow.isn_server.wrapping_add(1).wrapping_add(new_bytes);
                (s, a, ack_seq, ack_ack)
            }
        };

        let data_seg = ip_tcp_segment(
            flow,
            direction,
            seq,
            ack,
            TCP_FLAG_PSH | TCP_FLAG_ACK,
            chunk,
        );
        out.push(wrap_pcap_record(timestamp_us, &data_seg));

        // Advance byte counters BEFORE the cumulative ACK record so
        // the ACK number reflects the just-sent segment.
        match direction {
            Direction::ClientToServer => {
                flow.bytes_c2s = flow.bytes_c2s.wrapping_add(chunk.len() as u32);
            }
            Direction::ServerToClient => {
                flow.bytes_s2c = flow.bytes_s2c.wrapping_add(chunk.len() as u32);
            }
        }

        let opposite = match direction {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        };
        let ack_seg = ip_tcp_segment(flow, opposite, ack_seq, ack_ack, TCP_FLAG_ACK, &[]);
        out.push(wrap_pcap_record(timestamp_us, &ack_seg));

        offset = end;
    }
    out
}

/// Build the FIN-FIN 4-way close (initiated by the client) starting
/// at `timestamp_us`. The flow is left in a final state where any
/// further `build_data_records` would still encode well-formed
/// (but post-FIN, dissector-flagged) segments; production callers
/// should not emit data after `build_close`.
pub fn build_close(flow: &TcpFlow, timestamp_us: u64) -> Vec<Vec<u8>> {
    let fin1 = ip_tcp_segment(
        flow,
        Direction::ClientToServer,
        flow.next_seq_c2s(),
        flow.ack_to_server(),
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        &[],
    );
    let ack1 = ip_tcp_segment(
        flow,
        Direction::ServerToClient,
        flow.next_seq_s2c(),
        flow.next_seq_c2s().wrapping_add(1),
        TCP_FLAG_ACK,
        &[],
    );
    let fin2 = ip_tcp_segment(
        flow,
        Direction::ServerToClient,
        flow.next_seq_s2c(),
        flow.next_seq_c2s().wrapping_add(1),
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        &[],
    );
    let ack2 = ip_tcp_segment(
        flow,
        Direction::ClientToServer,
        flow.next_seq_c2s().wrapping_add(1),
        flow.next_seq_s2c().wrapping_add(1),
        TCP_FLAG_ACK,
        &[],
    );
    vec![
        wrap_pcap_record(timestamp_us, &fin1),
        wrap_pcap_record(timestamp_us, &ack1),
        wrap_pcap_record(timestamp_us, &fin2),
        wrap_pcap_record(timestamp_us, &ack2),
    ]
}

fn ip_tcp_segment(
    flow: &TcpFlow,
    direction: Direction,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (src_port, dst_port) = match (&flow.endpoints, direction) {
        (
            Endpoints::V4 {
                client_port,
                server_port,
                ..
            },
            Direction::ClientToServer,
        )
        | (
            Endpoints::V6 {
                client_port,
                server_port,
                ..
            },
            Direction::ClientToServer,
        ) => (*client_port, *server_port),
        (
            Endpoints::V4 {
                client_port,
                server_port,
                ..
            },
            Direction::ServerToClient,
        )
        | (
            Endpoints::V6 {
                client_port,
                server_port,
                ..
            },
            Direction::ServerToClient,
        ) => (*server_port, *client_port),
    };
    let tcp = tcp_header_with_payload(src_port, dst_port, seq, ack, flags, payload);
    match &flow.endpoints {
        Endpoints::V4 {
            client_ip,
            server_ip,
            ..
        } => {
            let (src_ip, dst_ip) = match direction {
                Direction::ClientToServer => (*client_ip, *server_ip),
                Direction::ServerToClient => (*server_ip, *client_ip),
            };
            let mut out = ipv4_header(src_ip, dst_ip, tcp.len());
            out.extend_from_slice(&tcp);
            out
        }
        Endpoints::V6 {
            client_ip,
            server_ip,
            ..
        } => {
            let (src_ip, dst_ip) = match direction {
                Direction::ClientToServer => (*client_ip, *server_ip),
                Direction::ServerToClient => (*server_ip, *client_ip),
            };
            let mut out = ipv6_header(src_ip, dst_ip, tcp.len());
            out.extend_from_slice(&tcp);
            out
        }
    }
}

fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, l4_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    let total_len = (20 + l4_len) as u16;
    h.push(0x45); // version=4, IHL=5 (5*4=20 bytes, no options)
    h.push(0x00); // DSCP/ECN
    h.extend_from_slice(&total_len.to_be_bytes()); // total length
    h.extend_from_slice(&[0x00, 0x00]); // identification
    h.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset (DF set)
    h.push(64); // TTL
    h.push(6); // protocol = TCP
    h.extend_from_slice(&[0x00, 0x00]); // header checksum (zeroed)
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

fn ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, l4_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(40);
    // version=6, TC=0, FL=0
    h.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    h.extend_from_slice(&(l4_len as u16).to_be_bytes()); // payload length
    h.push(6); // next header = TCP
    h.push(64); // hop limit
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

fn tcp_header_with_payload(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&src_port.to_be_bytes());
    t.extend_from_slice(&dst_port.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    // data offset = 5 (5*4=20, no options); reserved=0
    t.push(0x50);
    t.push(flags);
    t.extend_from_slice(&65_535u16.to_be_bytes()); // window
    t.extend_from_slice(&[0x00, 0x00]); // checksum (zeroed)
    t.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    t.extend_from_slice(payload);
    t
}

/// Wrap a raw L3+L4+payload buffer in a libpcap classic record
/// header (16 bytes).
pub fn wrap_pcap_record(timestamp_us: u64, payload: &[u8]) -> Vec<u8> {
    let ts_sec = (timestamp_us / 1_000_000) as u32;
    let ts_usec = (timestamp_us % 1_000_000) as u32;
    let len = payload.len() as u32;
    let mut record = Vec::with_capacity(PCAP_RECORD_HEADER_LEN + payload.len());
    record.extend_from_slice(&ts_sec.to_le_bytes());
    record.extend_from_slice(&ts_usec.to_le_bytes());
    record.extend_from_slice(&len.to_le_bytes()); // incl_len
    record.extend_from_slice(&len.to_le_bytes()); // orig_len
    record.extend_from_slice(payload);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketHeaders;
    use std::net::Ipv4Addr;

    fn v4_endpoints() -> Endpoints {
        Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502)
    }

    fn v6_endpoints() -> Endpoints {
        Endpoints::parse("2001:db8::1", 49_152, "2001:db8::2", 4840)
    }

    fn parse_payload(rec: &[u8]) -> PacketHeaders<'_> {
        let ip_payload = &rec[PCAP_RECORD_HEADER_LEN..];
        PacketHeaders::from_ip_slice(ip_payload).expect("ip slice parse")
    }

    #[test]
    fn endpoints_parse_ipv4_pair() {
        let e = Endpoints::parse("10.0.0.1", 1234, "10.0.0.2", 502);
        assert!(e.is_v4());
    }

    #[test]
    fn endpoints_parse_ipv6_pair() {
        let e = Endpoints::parse("::1", 1234, "::2", 502);
        assert!(!e.is_v4());
    }

    #[test]
    fn endpoints_parse_mixed_promotes_to_ipv6_mapped() {
        let e = Endpoints::parse("10.0.0.1", 1234, "::2", 502);
        assert!(!e.is_v4());
        if let Endpoints::V6 { client_ip, .. } = e {
            assert!(
                client_ip.to_string().starts_with("::ffff:"),
                "expected IPv4-mapped, got {}",
                client_ip
            );
        } else {
            panic!("expected V6 endpoints");
        }
    }

    #[test]
    fn endpoints_parse_fallbacks_to_loopback_on_invalid() {
        let e = Endpoints::parse("not-an-ip", 1234, "still-not", 502);
        if let Endpoints::V4 {
            client_ip,
            server_ip,
            ..
        } = e
        {
            assert_eq!(client_ip, Ipv4Addr::LOCALHOST);
            assert_eq!(server_ip, Ipv4Addr::LOCALHOST);
        } else {
            panic!("expected V4 fallback");
        }
    }

    #[test]
    fn tcp_flow_isn_is_deterministic_per_session_channel() {
        let e = v4_endpoints();
        let f1 = TcpFlow::new("session-A", 1, e.clone());
        let f2 = TcpFlow::new("session-A", 1, e.clone());
        assert_eq!(f1.isn_client, f2.isn_client);
        assert_eq!(f1.isn_server, f2.isn_server);
        assert_ne!(f1.isn_client, f1.isn_server);
    }

    #[test]
    fn tcp_flow_isn_differs_across_channels() {
        let e = v4_endpoints();
        let f1 = TcpFlow::new("session-A", 1, e.clone());
        let f2 = TcpFlow::new("session-A", 2, e);
        assert_ne!(f1.isn_client, f2.isn_client);
    }

    #[test]
    fn handshake_three_records_have_correct_flags_v4() {
        let flow = TcpFlow::new("s", 1, v4_endpoints());
        let recs = build_handshake(&flow, 1_000_000);
        assert_eq!(recs.len(), 3);

        let p0 = parse_payload(&recs[0]);
        let p1 = parse_payload(&recs[1]);
        let p2 = parse_payload(&recs[2]);

        match (
            p0.transport.as_ref().unwrap(),
            p1.transport.as_ref().unwrap(),
            p2.transport.as_ref().unwrap(),
        ) {
            (
                etherparse::TransportHeader::Tcp(t0),
                etherparse::TransportHeader::Tcp(t1),
                etherparse::TransportHeader::Tcp(t2),
            ) => {
                assert!(t0.syn && !t0.ack, "rec0 must be pure SYN");
                assert!(t1.syn && t1.ack, "rec1 must be SYN-ACK");
                assert!(!t2.syn && t2.ack, "rec2 must be pure ACK");
                assert_eq!(t1.acknowledgment_number, flow.isn_client.wrapping_add(1));
                assert_eq!(t2.acknowledgment_number, flow.isn_server.wrapping_add(1));
            }
            _ => panic!("non-TCP transport in handshake"),
        }
    }

    #[test]
    fn handshake_three_records_v6() {
        let flow = TcpFlow::new("s", 1, v6_endpoints());
        let recs = build_handshake(&flow, 0);
        assert_eq!(recs.len(), 3);
        for r in &recs {
            let p = parse_payload(r);
            assert!(matches!(p.net, Some(etherparse::NetHeaders::Ipv6(_, _))));
        }
    }

    #[test]
    fn data_record_is_psh_ack_with_payload() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"; // Modbus
        let recs = build_data_records(&mut flow, Direction::ClientToServer, payload, 1_000_000);
        assert_eq!(recs.len(), 2, "data record + cumulative ACK");

        let data = parse_payload(&recs[0]);
        if let Some(etherparse::TransportHeader::Tcp(t)) = data.transport {
            assert!(t.psh && t.ack, "data segment must be PSH+ACK");
        } else {
            panic!("not TCP");
        }
        assert_eq!(data.payload.slice(), payload);

        let ack = parse_payload(&recs[1]);
        if let Some(etherparse::TransportHeader::Tcp(t)) = ack.transport {
            assert!(!t.psh && t.ack, "ack segment must be pure ACK");
        } else {
            panic!("not TCP");
        }
    }

    #[test]
    fn empty_payload_emits_no_records() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let recs = build_data_records(&mut flow, Direction::ClientToServer, b"", 0);
        assert!(recs.is_empty());
    }

    #[test]
    fn sequence_numbers_advance_monotonically_c2s() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let initial = flow.next_seq_c2s();
        let _ = build_data_records(&mut flow, Direction::ClientToServer, b"abc", 0);
        let after_first = flow.next_seq_c2s();
        let _ = build_data_records(&mut flow, Direction::ClientToServer, b"defgh", 0);
        let after_second = flow.next_seq_c2s();
        assert_eq!(after_first, initial.wrapping_add(3));
        assert_eq!(after_second, initial.wrapping_add(8));
    }

    #[test]
    fn sequence_numbers_independent_per_direction() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let _ = build_data_records(&mut flow, Direction::ClientToServer, b"abc", 0);
        let s2c_initial = flow.next_seq_s2c();
        let _ = build_data_records(&mut flow, Direction::ServerToClient, b"DE", 0);
        assert_eq!(flow.next_seq_s2c(), s2c_initial.wrapping_add(2));
    }

    #[test]
    fn segmentation_for_oversized_payload() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let payload = vec![0xAB; MAX_IPV4_PAYLOAD + 100];
        let recs = build_data_records(&mut flow, Direction::ClientToServer, &payload, 0);
        // 2 segments * (data + ack) = 4 records.
        assert_eq!(recs.len(), 4, "expected 4 records for >MSS payload");
    }

    #[test]
    fn close_sequence_is_four_records_with_correct_flags() {
        let flow = TcpFlow::new("s", 1, v4_endpoints());
        let recs = build_close(&flow, 0);
        assert_eq!(recs.len(), 4);

        let p0 = parse_payload(&recs[0]);
        let p1 = parse_payload(&recs[1]);
        let p2 = parse_payload(&recs[2]);
        let p3 = parse_payload(&recs[3]);

        let f = |p: PacketHeaders| {
            if let Some(etherparse::TransportHeader::Tcp(t)) = p.transport {
                (t.fin, t.ack)
            } else {
                panic!("not TCP")
            }
        };
        assert_eq!(f(p0), (true, true), "FIN+ACK from client");
        assert_eq!(f(p1), (false, true), "ACK from server");
        assert_eq!(f(p2), (true, true), "FIN+ACK from server");
        assert_eq!(f(p3), (false, true), "ACK from client");
    }

    #[test]
    fn modbus_payload_is_dissectable_after_handshake() {
        // Modbus/TCP "Read Holding Registers" frame.
        let payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";
        let mut flow = TcpFlow::new("modbus-test", 1, v4_endpoints());

        let mut all = Vec::new();
        all.extend_from_slice(&build_global_header());
        for r in build_handshake(&flow, 0) {
            all.extend_from_slice(&r);
        }
        for r in build_data_records(&mut flow, Direction::ClientToServer, payload, 1_000) {
            all.extend_from_slice(&r);
        }
        for r in build_close(&flow, 2_000) {
            all.extend_from_slice(&r);
        }

        // First record after global header should be SYN.
        let first_rec_offset = PCAP_GLOBAL_HEADER_LEN + PCAP_RECORD_HEADER_LEN;
        // Strip libpcap headers and parse the first IP packet.
        let p = PacketHeaders::from_ip_slice(&all[first_rec_offset..]).expect("parse first record");
        if let Some(etherparse::TransportHeader::Tcp(t)) = p.transport {
            assert!(t.syn, "first record must be SYN");
            assert_eq!(t.destination_port, 502);
        } else {
            panic!("not TCP");
        }
    }

    #[test]
    fn ipv6_data_segment_dissects() {
        let mut flow = TcpFlow::new("s6", 1, v6_endpoints());
        let recs = build_data_records(&mut flow, Direction::ServerToClient, b"hello", 0);
        let p = parse_payload(&recs[0]);
        assert!(matches!(p.net, Some(etherparse::NetHeaders::Ipv6(_, _))));
    }

    #[test]
    fn ipv4_mapped_pair_emits_ipv6_records() {
        let mut flow = TcpFlow::new("s", 1, Endpoints::parse("10.0.0.1", 1234, "::2", 502));
        let recs = build_data_records(&mut flow, Direction::ClientToServer, b"x", 0);
        let p = parse_payload(&recs[0]);
        assert!(matches!(p.net, Some(etherparse::NetHeaders::Ipv6(_, _))));
    }

    #[test]
    fn pcap_record_header_carries_microsecond_timestamp() {
        let payload = b"abc";
        let rec = wrap_pcap_record(2_500_000, payload);
        let ts_sec = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
        let ts_usec = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
        let incl = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
        let orig = u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]);
        assert_eq!(ts_sec, 2);
        assert_eq!(ts_usec, 500_000);
        assert_eq!(incl, 3);
        assert_eq!(orig, 3);
        assert_eq!(&rec[16..], payload);
    }

    #[test]
    fn global_header_has_correct_magic_and_linktype() {
        let h = build_global_header();
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let linktype = u32::from_le_bytes([h[20], h[21], h[22], h[23]]);
        assert_eq!(magic, PCAP_GLOBAL_MAGIC);
        assert_eq!(linktype, LINKTYPE_RAW);
    }

    #[test]
    fn ipv4_header_total_length_matches() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let payload = b"abcdef";
        let recs = build_data_records(&mut flow, Direction::ClientToServer, payload, 0);
        // skip libpcap record header
        let ip = &recs[0][PCAP_RECORD_HEADER_LEN..];
        let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        assert_eq!(total_len, 20 + 20 + payload.len());
    }

    #[test]
    fn ipv6_payload_length_matches() {
        let mut flow = TcpFlow::new("s", 1, v6_endpoints());
        let payload = b"hello";
        let recs = build_data_records(&mut flow, Direction::ClientToServer, payload, 0);
        let ip = &recs[0][PCAP_RECORD_HEADER_LEN..];
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        assert_eq!(payload_len, 20 + payload.len());
    }

    #[test]
    fn ack_segment_has_expected_acknowledgment_number() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let initial_isn_client = flow.isn_client;
        let payload = b"hello";
        let recs = build_data_records(&mut flow, Direction::ClientToServer, payload, 0);
        let ack = parse_payload(&recs[1]);
        if let Some(etherparse::TransportHeader::Tcp(t)) = ack.transport {
            // The server's cumulative ACK back to the client should be
            // ISN_client + 1 (SYN) + payload.len()
            assert_eq!(
                t.acknowledgment_number,
                initial_isn_client
                    .wrapping_add(1)
                    .wrapping_add(payload.len() as u32)
            );
        } else {
            panic!("not TCP");
        }
    }

    #[test]
    fn three_concurrent_flows_have_disjoint_isns() {
        let e = v4_endpoints();
        let a = TcpFlow::new("session-1", 1, e.clone());
        let b = TcpFlow::new("session-1", 2, e.clone());
        let c = TcpFlow::new("session-2", 1, e);
        let isns = [a.isn_client, b.isn_client, c.isn_client];
        let mut sorted: Vec<u32> = isns.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "ISNs must be distinct across flows");
    }

    #[test]
    fn loopback_to_loopback_pair_dissects() {
        let mut flow = TcpFlow::new(
            "s",
            1,
            Endpoints::parse("127.0.0.1", 49_152, "127.0.0.1", 502),
        );
        let recs = build_data_records(&mut flow, Direction::ClientToServer, b"x", 0);
        let p = parse_payload(&recs[0]);
        assert!(matches!(p.net, Some(etherparse::NetHeaders::Ipv4(_, _))));
    }

    #[test]
    fn checksums_are_zeroed() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let recs = build_data_records(&mut flow, Direction::ClientToServer, b"xy", 0);
        let ip = &recs[0][PCAP_RECORD_HEADER_LEN..];
        // IPv4 checksum: bytes 10-11 of the IPv4 header.
        assert_eq!(&ip[10..12], &[0, 0]);
        // TCP checksum: bytes 16-17 of the TCP header = bytes 36-37
        // of the L3+L4 buffer (20-byte IPv4 header).
        assert_eq!(&ip[20 + 16..20 + 18], &[0, 0]);
    }

    #[test]
    fn psh_data_carries_correct_seq() {
        let mut flow = TcpFlow::new("s", 1, v4_endpoints());
        let isn = flow.isn_client;
        let recs = build_data_records(&mut flow, Direction::ClientToServer, b"abc", 0);
        let p = parse_payload(&recs[0]);
        if let Some(etherparse::TransportHeader::Tcp(t)) = p.transport {
            assert_eq!(t.sequence_number, isn.wrapping_add(1));
        } else {
            panic!("not TCP");
        }
    }
}
