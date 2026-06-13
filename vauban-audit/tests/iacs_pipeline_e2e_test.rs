// Integration tests legitimately use unwrap/expect/panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end PCAP pipeline tests for the IACS recording layer.
//!
//! These tests drive `IacsRecordingManager` with realistic
//! industrial-protocol payloads (Modbus/TCP, OPC-UA, S7), gzip the
//! resulting `.pcap` (simulating the supervisor broker), then
//! reparse the bytes to confirm:
//!
//! - the libpcap classic global header is correct,
//! - the synthetic L3/L4 layer produces well-formed IPv4 + TCP
//!   packets that `etherparse` can dissect,
//! - the application payload bytes are present verbatim inside
//!   PSH+ACK segments (Wireshark / tcpdump can therefore offer the
//!   industrial dissectors),
//! - timestamps are monotonic across the whole capture,
//! - the BLAKE3 aggregate of the meta.json mirrors the RDP rule
//!   (concat-of-channel-digests, ASCII hex bytes hashed).

use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use shared::messages::IacsRecordingDirection;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use vauban_audit::iacs_pcap_synth::{
    LINKTYPE_RAW, PCAP_GLOBAL_HEADER_LEN, PCAP_GLOBAL_MAGIC, PCAP_RECORD_HEADER_LEN,
};
use vauban_audit::iacs_recording_manager::{
    IacsChannelEndpoints, IacsChannelMeta, IacsRecordingManager, aggregate_channel_blake3,
};

/// Modbus/TCP "Read Holding Registers" PDU (function code 0x03).
/// 7-byte MBAP header (txid/protoid/len/uid) + 5-byte PDU.
const MODBUS_READ_HOLDING: &[u8] = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";

/// OPC-UA "Hello" message (HELF + length + protocol fields).
/// First 4 bytes "HELF" identify the OPC-UA Binary protocol.
const OPCUA_HELLO: &[u8] = b"HELF\x36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40";

/// S7 ROSCTR "Job" header skeleton (TPKT + COTP + S7 header).
const S7_JOB: &[u8] =
    b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02";

fn endpoints() -> IacsChannelEndpoints {
    IacsChannelEndpoints {
        client_ip: "10.10.10.10".into(),
        client_port: 49_152,
        server_ip: "10.10.10.20".into(),
        server_port: 502,
    }
}

fn read_handle(mut f: File) -> Vec<u8> {
    f.seek(SeekFrom::Start(0)).expect("seek");
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).expect("read");
    buf
}

/// Walk a PCAP buffer: yield `(timestamp_us, ip_payload)` for every
/// record. Returns `None` on a truncated buffer rather than
/// panicking, so partial-write tests can use the same helper.
fn iter_pcap_records(buf: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    if buf.len() < PCAP_GLOBAL_HEADER_LEN {
        return out;
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    assert_eq!(magic, PCAP_GLOBAL_MAGIC, "pcap magic");
    let linktype = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    assert_eq!(linktype, LINKTYPE_RAW, "linktype");

    let mut offset = PCAP_GLOBAL_HEADER_LEN;
    while offset + PCAP_RECORD_HEADER_LEN <= buf.len() {
        let ts_sec = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as u64;
        let ts_usec = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as u64;
        let incl_len = u32::from_le_bytes([
            buf[offset + 8],
            buf[offset + 9],
            buf[offset + 10],
            buf[offset + 11],
        ]) as usize;
        offset += PCAP_RECORD_HEADER_LEN;
        if offset + incl_len > buf.len() {
            break;
        }
        let payload = buf[offset..offset + incl_len].to_vec();
        out.push((ts_sec * 1_000_000 + ts_usec, payload));
        offset += incl_len;
    }
    out
}

fn run_modbus_session() -> (Vec<u8>, IacsChannelMeta) {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    let reader = f.try_clone().unwrap();
    let connected_at_us: u64 = 1_700_000_000_000_000;

    mgr.start_channel(
        "modbus-session",
        1,
        f,
        "plc.local".into(),
        502,
        connected_at_us,
        connected_at_us,
        endpoints(),
    );
    for i in 0..3u64 {
        mgr.handle_data(
            "modbus-session",
            1,
            i,
            IacsRecordingDirection::EwsToAsset,
            connected_at_us + i * 10_000,
            MODBUS_READ_HOLDING,
        )
        .unwrap();
    }
    mgr.end_channel("modbus-session", 1, connected_at_us + 1_000_000);
    mgr.finalize_channel_gzip("modbus-session", 1, "ab".repeat(32), 1234);
    let result = mgr.end_session("modbus-session").unwrap();
    let meta = result.channels[0].clone();
    (read_handle(reader), meta)
}

#[test]
fn modbus_session_pcap_reparses_with_etherparse() {
    let (bytes, _meta) = run_modbus_session();
    let recs = iter_pcap_records(&bytes);
    assert!(recs.len() >= 3 + 3 * 2 + 4, "expected handshake+data+close");

    // First record is the SYN.
    let first = PacketHeaders::from_ip_slice(&recs[0].1).expect("parse SYN");
    if let Some(TransportHeader::Tcp(t)) = first.transport {
        assert!(t.syn && !t.ack, "first record must be SYN");
        assert_eq!(t.destination_port, 502);
    } else {
        panic!("not TCP");
    }

    // The 4th record (after handshake) is the first data PSH+ACK
    // and MUST carry the Modbus PDU verbatim.
    let psh = PacketHeaders::from_ip_slice(&recs[3].1).expect("parse PSH");
    if let Some(TransportHeader::Tcp(t)) = psh.transport {
        assert!(t.psh && t.ack);
    } else {
        panic!("not TCP");
    }
    assert_eq!(
        psh.payload.slice(),
        MODBUS_READ_HOLDING,
        "Modbus payload missing from PSH+ACK"
    );

    // Last record is a pure ACK (the post-FIN ACK from the client).
    let last = PacketHeaders::from_ip_slice(&recs.last().unwrap().1).expect("parse last");
    if let Some(TransportHeader::Tcp(t)) = last.transport {
        assert!(t.ack && !t.fin && !t.psh);
    } else {
        panic!("not TCP");
    }
}

#[test]
fn timestamps_are_monotonic_across_capture() {
    let (bytes, _meta) = run_modbus_session();
    let recs = iter_pcap_records(&bytes);
    let mut prev = 0u64;
    for (ts, _payload) in &recs {
        assert!(
            *ts >= prev,
            "timestamps must be monotonically non-decreasing"
        );
        prev = *ts;
    }
}

#[test]
fn ip_layer_is_ipv4_for_ipv4_endpoints() {
    let (bytes, _meta) = run_modbus_session();
    let recs = iter_pcap_records(&bytes);
    for (_ts, payload) in recs.iter().take(8) {
        let p = PacketHeaders::from_ip_slice(payload).expect("parse");
        assert!(matches!(p.net, Some(NetHeaders::Ipv4(_, _))));
    }
}

#[test]
fn opcua_hello_payload_survives_through_synthetic_layer() {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    let reader = f.try_clone().unwrap();
    mgr.start_channel(
        "opcua",
        1,
        f,
        "asset".into(),
        4840,
        0,
        0,
        IacsChannelEndpoints {
            client_ip: "10.0.0.1".into(),
            client_port: 49_152,
            server_ip: "10.0.0.2".into(),
            server_port: 4840,
        },
    );
    mgr.handle_data(
        "opcua",
        1,
        0,
        IacsRecordingDirection::EwsToAsset,
        1000,
        OPCUA_HELLO,
    )
    .unwrap();
    mgr.end_channel("opcua", 1, 2_000_000);
    let result = mgr.end_session("opcua").unwrap();
    assert_eq!(result.channels.len(), 1);

    let bytes = read_handle(reader);
    let recs = iter_pcap_records(&bytes);
    // record index 3 = first data segment (after 3 handshake records).
    let psh = PacketHeaders::from_ip_slice(&recs[3].1).unwrap();
    assert_eq!(psh.payload.slice(), OPCUA_HELLO);
}

#[test]
fn s7_payload_dissectable() {
    let mut mgr = IacsRecordingManager::new();
    let f = tempfile::tempfile().unwrap();
    let reader = f.try_clone().unwrap();
    mgr.start_channel("s7", 1, f, "h".into(), 102, 0, 0, endpoints());
    mgr.handle_data("s7", 1, 0, IacsRecordingDirection::EwsToAsset, 100, S7_JOB)
        .unwrap();
    mgr.end_channel("s7", 1, 1_000);
    mgr.end_session("s7");

    let bytes = read_handle(reader);
    let recs = iter_pcap_records(&bytes);
    let psh = PacketHeaders::from_ip_slice(&recs[3].1).unwrap();
    assert_eq!(psh.payload.slice(), S7_JOB);
}

#[test]
fn gzip_roundtrip_preserves_pcap_bytes_and_dissection() {
    let (raw, _meta) = run_modbus_session();
    let mut compressed = Vec::new();
    {
        let mut enc = GzEncoder::new(&mut compressed, Compression::default());
        enc.write_all(&raw).unwrap();
    }
    let mut decompressed = Vec::new();
    GzDecoder::new(&compressed[..])
        .read_to_end(&mut decompressed)
        .unwrap();
    assert_eq!(decompressed, raw);
    let recs_pre = iter_pcap_records(&raw);
    let recs_post = iter_pcap_records(&decompressed);
    assert_eq!(recs_pre.len(), recs_post.len());
    for (a, b) in recs_pre.iter().zip(recs_post.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn blake3_aggregate_matches_rdp_concat_rule() {
    // Cross-validation: the documentation v1.5 promises "BLAKE3
    // over the concatenated ASCII hex digests of every channel".
    // We hand-implement the rule and assert
    // `aggregate_channel_blake3` returns the same value.
    let channels: Vec<IacsChannelMeta> = (0..3)
        .map(|i| IacsChannelMeta {
            index: i,
            target_host: "h".into(),
            target_port: 502,
            file: format!("channels/{:03}.pcap.gz", i),
            blake3_hex: format!("{:02x}", i).repeat(32),
            file_size: 100,
            packet_count: 10,
            bytes_ews_to_asset: 50,
            bytes_asset_to_ews: 50,
            opened_at_us: 0,
            closed_at_us: 0,
        })
        .collect();
    let actual = aggregate_channel_blake3(&channels);

    let mut hasher = blake3::Hasher::new();
    for ch in &channels {
        hasher.update(ch.blake3_hex.as_bytes());
    }
    let expected = hasher.finalize().to_hex().to_string();
    assert_eq!(actual, expected);
}

#[test]
fn ip_total_length_field_matches_actual_payload_for_every_record() {
    let (bytes, _meta) = run_modbus_session();
    let recs = iter_pcap_records(&bytes);
    for (_, payload) in &recs {
        // IPv4 total_length is bytes 2..4 of the L3 header.
        let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        assert_eq!(
            total_len,
            payload.len(),
            "IPv4 total_length must match the actual record payload length"
        );
    }
}
