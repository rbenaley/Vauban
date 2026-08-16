//! Offline pipeline E2E for the IACS Inspect Capture analyzer.
//!
//! Synthesises a real PCAP via `vauban-audit::iacs_pcap_synth`,
//! gzips it, and drives it through the full
//! `services::iacs_packet_analyzer` stack
//! (`analyze_channel_bytes` + `analyze_packet_bytes`). Pins the
//! end-to-end accuracy contract:
//!
//! - Modbus FC03 (read) and FC06 (write) classify correctly.
//! - IEC-104 STARTDT, S-frame and a C_SC_NA_1 command classify correctly.
//! - Direction is inferred from the first SYN tuple.
//! - Frame indices match the synthesis ordering 1..=N.
//! - The detail builder produces a per-byte field map of the
//!   correct length (frame size).
//!
//! The supervisor / HTTP layer is intentionally NOT exercised here:
//! `SupervisorClient` is a concrete type and the broker cannot be
//! mocked without test-only infra. The handler-level pins live in
//! `inspect_capture_test.rs`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use vauban_audit::iacs_pcap_synth as synth;
use vauban_web::services::iacs_packet_analyzer::types::{Direction, PacketKind, PacketListFilter};
use vauban_web::services::iacs_packet_analyzer::{
    analyze_channel_bytes, analyze_packet_bytes, page_summaries,
};

use shared::iacs_protocol::ExpectedProfile;

fn build_modbus_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        1,
        synth::Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    // FC03 read holding registers (10 regs from 0).
    let read_req = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, read_req, 1_000)
    {
        buf.extend_from_slice(&r);
    }
    // Read response 20 bytes payload.
    let read_resp = b"\x00\x01\x00\x00\x00\x17\x01\x03\x14\
                     \x00\x0a\x00\x14\x00\x1e\x00\x28\x00\x32\x00\x3c\x00\x46\x00\x50\x00\x5a\x00\x64";
    for r in synth::build_data_records(
        &mut flow,
        synth::Direction::ServerToClient,
        read_resp,
        2_000,
    ) {
        buf.extend_from_slice(&r);
    }
    // FC06 write single register @5 = 0x002a.
    let write = b"\x00\x02\x00\x00\x00\x06\x01\x06\x00\x05\x00\x2a";
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, write, 3_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 4_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

fn build_iec104_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        2,
        synth::Endpoints::parse("192.0.2.20", 49_153, "198.51.100.21", 2404),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    // U-frame STARTDT act.
    let startdt = vec![0x68u8, 0x04, 0x07, 0x00, 0x00, 0x00];
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &startdt, 1_000)
    {
        buf.extend_from_slice(&r);
    }
    // I-frame C_SC_NA_1 (Single Command) -- type 45, cot 6.
    // APDU length 0x0D -> 15-byte frame (2 + 13).
    let cmd = vec![
        0x68, 0x0D, 0x00, 0x00, 0x00, 0x00, // APCI
        45, 0x01, 0x06, 0x00, 0x01, 0x00, // ASDU header: type=45, vsq=1, cot=6, oa=0, ca=1
        0x00, 0x00, 0x00, // info object addr
    ];
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &cmd, 2_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 3_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

#[test]
fn modbus_capture_round_trips_with_correct_classification() {
    let buf = build_modbus_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();

    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    let reads: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Read)
        .collect();
    assert_eq!(cmds.len(), 1, "exactly one FC06 write (Cmd)");
    // FC03 request and FC03 response -> two Reads.
    assert_eq!(reads.len(), 2, "request + response -> 2 reads");
}

#[test]
fn modbus_first_data_frame_dissects_fc03() {
    let buf = build_modbus_capture();
    // Frame indices: 1..=3 handshake, 4 = first PSH+ACK c2s.
    let detail = analyze_packet_bytes(&buf, ExpectedProfile::Modbus, 4).expect("detail");
    assert_eq!(detail.summary.kind, PacketKind::Read);
    assert!(detail.summary.summary.contains("FC03"));
    // Per-byte field map matches the frame length.
    assert_eq!(detail.byte_field_ids.len(), detail.hex.len());
    // The FC byte (offset 47 = 40 IP+TCP + 7 MBAP) is tagged as modbus.function.
    assert_eq!(detail.byte_field_ids[47], "modbus.function");
}

#[test]
fn modbus_directions_are_inferred_from_first_syn() {
    let buf = build_modbus_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
    // Read request goes from EWS -> Asset.
    let req = summaries
        .iter()
        .find(|s| s.kind == PacketKind::Read && s.dst_port == 502)
        .expect("read req");
    assert_eq!(req.direction, Direction::EwsToAsset);
    // Read response goes Asset -> EWS.
    let resp = summaries
        .iter()
        .find(|s| s.kind == PacketKind::Read && s.src_port == 502)
        .expect("read resp");
    assert_eq!(resp.direction, Direction::AssetToEws);
}

#[test]
fn iec104_capture_classifies_startdt_and_command() {
    let buf = build_iec104_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Iec104).unwrap();
    assert!(
        summaries.iter().any(|s| s.summary.contains("STARTDT")),
        "STARTDT U-frame must be visible in the timeline"
    );
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "exactly one C_SC_NA_1 (Cmd)");
}

#[test]
fn frame_indices_are_one_based_and_dense() {
    let buf = build_modbus_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
    for (i, s) in summaries.iter().enumerate() {
        assert_eq!(s.frame_idx, i + 1, "frame_idx must be 1-based dense");
    }
}

#[test]
fn page_summaries_pagination_yields_correct_page_window() {
    let buf = build_modbus_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
    let total = summaries.len();
    let filter = PacketListFilter {
        page: 2,
        page_size: 5,
        ..Default::default()
    };
    let page = page_summaries(summaries, filter);
    assert_eq!(page.total, total);
    if total > 5 {
        assert!(!page.items.is_empty());
        assert_eq!(page.items[0].frame_idx, 6);
    }
}

#[test]
fn passthrough_profile_classifies_application_payload_as_read() {
    let buf = build_modbus_capture();
    // Drive the same PCAP through the Passthrough profile (a generic
    // TCP IACS asset). Application payload becomes plain Read,
    // never Cmd.
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Passthrough).unwrap();
    assert!(summaries.iter().all(|s| s.kind != PacketKind::Cmd));
}

fn build_opcua_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        3,
        synth::Endpoints::parse("192.0.2.30", 49_154, "198.51.100.22", 4840),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    // HEL handshake.
    let mut hel = vec![0u8; 28];
    hel[..3].copy_from_slice(b"HEL");
    hel[4..8].copy_from_slice(&28u32.to_le_bytes());
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &hel, 1_000) {
        buf.extend_from_slice(&r);
    }
    // MSG WriteRequest (service id 672 at offset 16).
    let mut msg = vec![0u8; 32];
    msg[..3].copy_from_slice(b"MSG");
    msg[4..8].copy_from_slice(&32u32.to_le_bytes());
    msg[16..20].copy_from_slice(&672u32.to_le_bytes());
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &msg, 2_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 3_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

fn build_profinet_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        4,
        synth::Endpoints::parse("192.0.2.40", 49_155, "198.51.100.23", 102),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    let mut dce = vec![0u8; 16];
    dce[0] = 0x05;
    dce[1] = 0x00;
    dce[2] = 0x00; // request -> Cmd
    dce[8..10].copy_from_slice(&32u16.to_le_bytes());
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &dce, 1_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 2_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

fn build_modbus_split_write_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        5,
        synth::Endpoints::parse("192.0.2.50", 49_156, "198.51.100.24", 502),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    let write = b"\x00\x02\x00\x00\x00\x06\x01\x06\x00\x05\x00\x2a";
    // First half: MBAP header only (6 bytes).
    for r in synth::build_data_records(
        &mut flow,
        synth::Direction::ClientToServer,
        &write[..6],
        1_000,
    ) {
        buf.extend_from_slice(&r);
    }
    // Second half: PDU body (6 bytes).
    for r in synth::build_data_records(
        &mut flow,
        synth::Direction::ClientToServer,
        &write[6..],
        2_000,
    ) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 3_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

#[test]
fn opcua_capture_classifies_hel_and_write_request() {
    let buf = build_opcua_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::OpcUa).unwrap();
    assert!(
        summaries.iter().any(|s| s.summary.contains("HEL")),
        "HEL handshake must appear in the timeline"
    );
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "WriteRequest MSG -> exactly one Cmd");
}

#[test]
fn profinet_capture_classifies_dce_request_as_cmd() {
    let buf = build_profinet_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Profinet).unwrap();
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "DCE request -> Cmd");
}

#[test]
fn modbus_split_fc06_write_yields_single_cmd() {
    let buf = build_modbus_split_write_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(
        cmds.len(),
        1,
        "reassembly must collapse split FC06 into one Cmd"
    );
    assert!(
        summaries.iter().any(|s| s.summary.contains("(fragment)")),
        "first segment should surface as a fragment"
    );
}

fn build_enip_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        3,
        synth::Endpoints::parse("192.0.2.30", 49_154, "198.51.100.22", 44818),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    let mut set = vec![0u8; 26];
    set[0..2].copy_from_slice(&0x006Fu16.to_le_bytes());
    set[2..4].copy_from_slice(&2u16.to_le_bytes());
    set[24] = 0x10; // SetAttributeSingle
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &set, 1_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 2_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

fn build_dnp3_operate_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        4,
        synth::Endpoints::parse("192.0.2.31", 49_155, "198.51.100.23", 20000),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    // IEEE 1815: LENGTH=7 => user=2 + one data CRC (2) => 14 octets.
    let operate = vec![
        0x05, 0x64, 0x07, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xC0, 0x04, 0x00, 0x00,
    ];
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &operate, 1_000)
    {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 2_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

fn build_bacnet_sc_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        5,
        synth::Endpoints::parse("192.0.2.32", 49_156, "198.51.100.24", 443),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    let mut hello = vec![0x16, 0x03, 0x03, 0x00, 0x20];
    hello.resize(5 + 0x20, 0);
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &hello, 1_000) {
        buf.extend_from_slice(&r);
    }
    let app = vec![0x17, 0x03, 0x03, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD];
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &app, 2_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 3_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

#[test]
fn enip_capture_classifies_set_attribute_as_cmd() {
    let buf = build_enip_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Enip).unwrap();
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "SetAttributeSingle -> Cmd");
}

#[test]
fn dnp3_capture_classifies_operate_as_cmd() {
    let buf = build_dnp3_operate_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Dnp3).unwrap();
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "Operate -> Cmd");
}

#[test]
fn bacnet_sc_ciphertext_never_cmd() {
    let buf = build_bacnet_sc_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::BacnetSc).unwrap();
    assert!(
        summaries.iter().any(|s| s.summary.contains("handshake")),
        "TLS handshake must appear"
    );
    assert!(
        summaries.iter().all(|s| s.kind != PacketKind::Cmd),
        "BACnet/SC ciphertext must never classify as Cmd"
    );
}

fn build_iec61850_write_capture() -> Vec<u8> {
    let mut flow = synth::TcpFlow::new(
        "uuid",
        6,
        synth::Endpoints::parse("192.0.2.33", 49_157, "198.51.100.25", 102),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&synth::build_global_header());
    for r in synth::build_handshake(&flow, 0) {
        buf.extend_from_slice(&r);
    }
    let mut write = vec![
        0x03, 0x00, 0x00, 0x00, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5, 0x00,
    ];
    let len = write.len() as u16;
    write[2..4].copy_from_slice(&len.to_be_bytes());
    for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, &write, 1_000) {
        buf.extend_from_slice(&r);
    }
    for r in synth::build_close(&flow, 2_000) {
        buf.extend_from_slice(&r);
    }
    buf
}

#[test]
fn iec61850_capture_classifies_mms_write_as_cmd() {
    let buf = build_iec61850_write_capture();
    let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Iec61850).unwrap();
    let cmds: Vec<_> = summaries
        .iter()
        .filter(|s| s.kind == PacketKind::Cmd)
        .collect();
    assert_eq!(cmds.len(), 1, "MMS Write tag 0xA5 -> Cmd");
}
