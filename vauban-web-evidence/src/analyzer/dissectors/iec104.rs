//! IEC 60870-5-104 dissector (MVP scope).
//!
//! Wire format:
//!
//! ```text
//! +---- APCI (6 bytes) ----+--- ASDU (variable) ---+
//! | start (0x68)           |
//! | length (u8)            |
//! | ctrl[0..3] (u32)       |
//! +------------------------+
//! ```
//!
//! Frame format is encoded in the lowest two bits of `ctrl[0]`:
//!
//! - `00` -> I-frame (information transfer, has ASDU).
//! - `01` -> S-frame (supervisory, ack-only).
//! - `11` -> U-frame (unnumbered control: STARTDT/STOPDT/TESTFR).
//!
//! For I-frames we extract the ASDU type id + cause of transmission.
//! Single Command (`C_SC_NA_1`, type 45) is the canonical Cmd; any
//! `M_*` (monitoring direction) is Read; cause `0x2D-0x2F` (negative
//! acks / unknown / unknown common addr) is Exception.

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const APCI_LEN: usize = 6;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < APCI_LEN || payload[0] != 0x68 {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let length = payload[1];
    let c0 = payload[2];
    let c1 = payload[3];
    let c2 = payload[4];
    let c3 = payload[5];

    let mut tree_children = vec![
        FieldNode::leaf(
            "Start",
            format!("0x{:02x}", payload[0]),
            "iec104.start",
            payload_offset,
            1,
        ),
        FieldNode::leaf(
            "APDU Length",
            format!("{} bytes", length),
            "iec104.length",
            payload_offset + 1,
            1,
        ),
    ];

    let frame_format = c0 & 0x03;
    let format_label = match frame_format {
        0x00 => "I-frame",
        0x01 => "S-frame",
        0x03 => "U-frame",
        _ => "I-frame",
    };
    let mut summary;

    let mut kind = PacketKind::Tcp;

    match frame_format {
        0x01 | 0x00 => {
            // I-frame or S-frame: 16-bit send/recv sequence numbers.
            let send_seq = if frame_format == 0x00 {
                ((c1 as u16) << 7) | ((c0 as u16) >> 1)
            } else {
                0
            };
            let recv_seq = ((c3 as u16) << 7) | ((c2 as u16) >> 1);
            tree_children.push(FieldNode::leaf(
                "Format",
                format_label.into(),
                "iec104.format",
                payload_offset + 2,
                1,
            ));
            if frame_format == 0x00 {
                tree_children.push(FieldNode::leaf(
                    "Send Seq (Ns)",
                    format!("{}", send_seq),
                    "iec104.ns",
                    payload_offset + 2,
                    2,
                ));
            }
            tree_children.push(FieldNode::leaf(
                "Recv Seq (Nr)",
                format!("{}", recv_seq),
                "iec104.nr",
                payload_offset + 4,
                2,
            ));
            summary = format!("{} {}", direction.arrow(), format_label);
        }
        0x03 => {
            let u_label = match c0 & 0xFC {
                0x04 => "STARTDT act",
                0x08 => "STARTDT con",
                0x10 => "STOPDT act",
                0x20 => "STOPDT con",
                0x40 => "TESTFR act",
                0x80 => "TESTFR con",
                _ => "U-frame",
            };
            tree_children.push(FieldNode::leaf(
                "Format",
                format!("U-frame ({})", u_label),
                "iec104.format",
                payload_offset + 2,
                1,
            ));
            summary = format!("{} {} {}", direction.arrow(), format_label, u_label);
        }
        _ => {
            summary = format!("{} {}", direction.arrow(), format_label);
        }
    }

    let apci = FieldNode::parent(
        "APCI",
        "iec104.apci",
        payload_offset,
        APCI_LEN,
        tree_children,
    );

    let mut nodes = vec![apci];

    if frame_format == 0x00 && payload.len() > APCI_LEN {
        let asdu_off = APCI_LEN;
        let type_id = payload[asdu_off];
        let vsq = payload.get(asdu_off + 1).copied().unwrap_or(0);
        let cot = payload.get(asdu_off + 2).copied().unwrap_or(0);
        let common_addr = if payload.len() >= asdu_off + 6 {
            u16::from_le_bytes([payload[asdu_off + 4], payload[asdu_off + 5]])
        } else {
            0
        };

        let type_label = type_id_label(type_id);
        let asdu_kind = classify_asdu(type_id, cot);
        kind = asdu_kind;

        let asdu_children = vec![
            FieldNode::leaf(
                "Type ID",
                format!("{} ({})", type_id, type_label),
                "iec104.type_id",
                payload_offset + asdu_off,
                1,
            ),
            FieldNode::leaf(
                "VSQ",
                format!("0x{:02x} (count={})", vsq, vsq & 0x7F),
                "iec104.vsq",
                payload_offset + asdu_off + 1,
                1,
            ),
            FieldNode::leaf(
                "Cause of Transmission",
                format!("0x{:02x} ({})", cot, cause_label(cot)),
                "iec104.cot",
                payload_offset + asdu_off + 2,
                1,
            ),
            FieldNode::leaf(
                "Common Address",
                format!("{}", common_addr),
                "iec104.common_addr",
                payload_offset + asdu_off + 4,
                2,
            ),
        ];

        nodes.push(FieldNode::parent(
            "ASDU",
            "iec104.asdu",
            payload_offset + asdu_off,
            payload.len() - asdu_off,
            asdu_children,
        ));

        summary = format!(
            "{} I-frame  T{:03} {} ({})",
            direction.arrow(),
            type_id,
            type_label,
            cause_label(cot)
        );
    } else if frame_format == 0x03 || frame_format == 0x01 {
        kind = PacketKind::Tcp;
    }

    Dissection {
        kind,
        summary,
        tree: nodes,
    }
}

fn type_id_label(id: u8) -> &'static str {
    match id {
        1 => "M_SP_NA_1 Single Point",
        3 => "M_DP_NA_1 Double Point",
        5 => "M_ST_NA_1 Step Position",
        9 => "M_ME_NA_1 Measured Normalised",
        13 => "M_ME_NC_1 Measured Float",
        30 => "M_SP_TB_1 Single Point CP56",
        45 => "C_SC_NA_1 Single Command",
        46 => "C_DC_NA_1 Double Command",
        49 => "C_SE_NA_1 Set Point Normalised",
        50 => "C_SE_NB_1 Set Point Scaled",
        51 => "C_SE_NC_1 Set Point Float",
        100 => "C_IC_NA_1 General Interrogation",
        103 => "C_CS_NA_1 Clock Sync",
        _ => "(unknown)",
    }
}

fn cause_label(cot: u8) -> &'static str {
    match cot & 0x3F {
        1 => "periodic/cyclic",
        2 => "background",
        3 => "spontaneous",
        4 => "initialised",
        5 => "request/requested",
        6 => "act",
        7 => "actcon",
        8 => "deact",
        9 => "deactcon",
        10 => "actterm",
        20 => "interrogated by station",
        44 => "unknown type",
        45 => "unknown cause",
        46 => "unknown common address",
        47 => "unknown info object addr",
        _ => "?",
    }
}

fn classify_asdu(type_id: u8, cot: u8) -> PacketKind {
    let cause = cot & 0x3F;
    if (44..=47).contains(&cause) {
        return PacketKind::Exception;
    }
    match type_id {
        45..=51 | 58..=64 | 100..=107 => PacketKind::Cmd,
        1..=40 => PacketKind::Read,
        _ => PacketKind::Read,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i_frame(type_id: u8, cot: u8) -> Vec<u8> {
        let mut p = vec![0x68, 0x0E, 0x00, 0x00, 0x00, 0x00];
        p.push(type_id);
        p.push(0x01);
        p.push(cot);
        p.push(0x00);
        p.push(0x01);
        p.push(0x00);
        p.push(0x00);
        p.push(0x00);
        p.push(0x00);
        p
    }

    #[test]
    fn i_frame_c_sc_na_1_classifies_as_cmd() {
        let p = i_frame(45, 6);
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
        assert!(d.summary.contains("T045"));
    }

    #[test]
    fn i_frame_m_sp_na_1_classifies_as_read() {
        let p = i_frame(1, 3);
        let d = dissect(&p, 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn unknown_cot_classifies_as_exception() {
        let p = i_frame(45, 45);
        let d = dissect(&p, 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Exception);
    }

    #[test]
    fn u_frame_startdt_act_recognised() {
        let p = vec![0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert!(d.summary.contains("STARTDT"));
    }

    #[test]
    fn s_frame_recognised() {
        let p = vec![0x68, 0x04, 0x01, 0x00, 0x00, 0x00];
        let d = dissect(&p, 40, Direction::AssetToEws);
        assert!(d.summary.contains("S-frame"));
    }

    #[test]
    fn truncated_falls_back_to_passthrough() {
        let p = vec![0x68, 0x02];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn invalid_start_byte_falls_back_to_passthrough() {
        let p = vec![0x99, 0x04, 0x00, 0x00, 0x00, 0x00];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }
}
