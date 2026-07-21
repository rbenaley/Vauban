//! PROFINET DCE/RPC CO PDU dissector (MVP scope).
//!
//! Wire format (connection-oriented PDU header, minimum 16 bytes):
//!
//! ```text
//! +-- version --+ minor | ptype | ... | frag length (u16 LE @8) |
//! | 0x05        | 0x00  | u8    |     | optional               |
//! +-------------+-------+-------+-----+------------------------+
//! ```
//!
//! `ptype` values (byte 2):
//!
//! | Value | Meaning   | PacketKind |
//! |-------|-----------|------------|
//! | 0     | request   | Cmd        |
//! | 2     | response  | Read       |
//! | 3     | fault     | Cmd        |
//! | other | —         | Read       |
//!
//! Payloads that do not start with `05 00` or are shorter than 16
//! bytes fall back to [`super::passthrough`] (never `Cmd`).

use crate::services::iacs_packet_analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const MIN_HEADER_LEN: usize = 16;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < MIN_HEADER_LEN || payload[0] != 0x05 || payload[1] != 0x00 {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let ptype = payload[2];
    let frag_len = u16::from_le_bytes([payload[8], payload[9]]);

    let kind = match ptype {
        0 | 3 => PacketKind::Cmd,
        2 => PacketKind::Read,
        _ => PacketKind::Read,
    };

    let ptype_label = ptype_label(ptype);

    let children = vec![
        FieldNode::leaf(
            "Version",
            format!("0x{:02x}", payload[0]),
            "profinet.version",
            payload_offset,
            1,
        ),
        FieldNode::leaf(
            "Minor",
            format!("0x{:02x}", payload[1]),
            "profinet.minor",
            payload_offset + 1,
            1,
        ),
        FieldNode::leaf(
            "Packet Type",
            format!("{} ({})", ptype_label, ptype),
            "profinet.ptype",
            payload_offset + 2,
            1,
        ),
        FieldNode::leaf(
            "Frag Length",
            format!("{} bytes", frag_len),
            "profinet.frag_len",
            payload_offset + 8,
            2,
        ),
    ];

    let summary = format!(
        "{} PROFINET DCE {} ({})",
        direction.arrow(),
        ptype_label,
        frag_len
    );

    let tree = vec![FieldNode::parent(
        "PROFINET",
        "profinet",
        payload_offset,
        payload.len(),
        children,
    )];

    Dissection {
        kind,
        summary,
        tree,
    }
}

fn ptype_label(ptype: u8) -> &'static str {
    match ptype {
        0 => "request",
        2 => "response",
        3 => "fault",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dce_request() -> Vec<u8> {
        let mut p = vec![0u8; 16];
        p[0] = 0x05;
        p[1] = 0x00;
        p[2] = 0x00; // request
        p[8..10].copy_from_slice(&32u16.to_le_bytes());
        p
    }

    fn dce_response() -> Vec<u8> {
        let mut p = dce_request();
        p[2] = 0x02;
        p
    }

    #[test]
    fn request_classifies_as_cmd() {
        let d = dissect(&dce_request(), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
        assert!(d.summary.contains("request"));
    }

    #[test]
    fn response_classifies_as_read() {
        let d = dissect(&dce_response(), 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn bad_magic_falls_back_without_cmd() {
        let p = b"\x04\x00\x00";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn short_payload_falls_back_without_cmd() {
        let p = b"\x05\x00\x00";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn dissect_is_panic_free_on_arbitrary_bytes() {
        for len in [0, 1, 15, 16, 64] {
            let buf = vec![0xAA; len];
            let _ = dissect(&buf, 40, Direction::EwsToAsset);
        }
    }
}
