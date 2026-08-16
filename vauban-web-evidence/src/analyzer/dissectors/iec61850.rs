//! IEC 61850 MMS/TCP dissector (MVP).
//!
//! TPKT + COTP. MMS Initiate / Read → `Read`; a confirmed Write
//! (BER context tag 0xA5 heuristic) → `Cmd`; confirmed-error →
//! `Exception`. S7-shaped TPKT falls back to passthrough (`Read`).

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < 5 || payload[0] != 0x03 || payload[1] != 0x00 {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let tpkt_len = u16::from_be_bytes([payload[2], payload[3]]);
    let li = payload[4] as usize;
    let s7_off = 5 + li;
    if payload.get(s7_off) == Some(&0x32) {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let cotp_type = payload.get(5).copied().unwrap_or(0);
    let mut children = vec![
        FieldNode::leaf(
            "TPKT Length",
            format!("{}", tpkt_len),
            "iec61850.tpkt_len",
            payload_offset + 2,
            2,
        ),
        FieldNode::leaf(
            "COTP LI",
            format!("{}", li),
            "iec61850.cotp_li",
            payload_offset + 4,
            1,
        ),
        FieldNode::leaf(
            "COTP Type",
            format!("0x{:02x}", cotp_type),
            "iec61850.cotp_type",
            payload_offset + 5,
            1,
        ),
    ];

    let mms = payload.get(s7_off..).unwrap_or(&[]);
    let kind = if mms.contains(&0xA2) {
        PacketKind::Exception
    } else if mms.contains(&0xA5) {
        PacketKind::Cmd
    } else {
        PacketKind::Read
    };

    if let Some(tag) = mms.first() {
        children.push(FieldNode::leaf(
            "MMS Tag",
            format!("0x{:02x}", tag),
            "iec61850.mms_tag",
            payload_offset + s7_off,
            1,
        ));
    }

    let summary = format!(
        "{} IEC 61850 MMS {} ({} bytes)",
        direction.arrow(),
        match kind {
            PacketKind::Cmd => "Write",
            PacketKind::Exception => "Error",
            _ => "Read/Initiate",
        },
        payload.len()
    );

    Dissection {
        kind,
        summary,
        tree: vec![FieldNode::parent(
            "IEC 61850",
            "iec61850",
            payload_offset,
            payload.len(),
            children,
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpkt_cotp(rest: &[u8]) -> Vec<u8> {
        // COTP CR: LI=6 so the MMS PDU starts after the COTP header.
        let mut p = vec![
            0x03, 0x00, 0x00, 0x00, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        p.extend_from_slice(rest);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    #[test]
    fn initiate_is_read() {
        let d = dissect(&tpkt_cotp(&[0xA8, 0x00]), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn write_tag_is_cmd() {
        let d = dissect(&tpkt_cotp(&[0xA5, 0x00]), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn s7_falls_back_without_cmd() {
        let p = vec![0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x80, 0x32, 0x01];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }
}
