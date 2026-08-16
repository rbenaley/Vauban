//! EtherNet/IP explicit (CIP encapsulation over TCP) dissector (MVP).
//!
//! 24-byte encapsulation header, then optional CPF / CIP service.
//! SetAttribute / Forward Open → `Cmd`; GetAttribute → `Read`;
//! nonzero status → `Exception`. Unknown services stay `Read`.

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const HEADER_LEN: usize = 24;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < HEADER_LEN {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let command = u16::from_le_bytes([payload[0], payload[1]]);
    let length = u16::from_le_bytes([payload[2], payload[3]]);
    let status = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

    let mut children = vec![
        FieldNode::leaf(
            "Command",
            format!("0x{:04x} ({})", command, command_label(command)),
            "enip.command",
            payload_offset,
            2,
        ),
        FieldNode::leaf(
            "Length",
            format!("{} bytes", length),
            "enip.length",
            payload_offset + 2,
            2,
        ),
        FieldNode::leaf(
            "Status",
            format!("0x{:08x}", status),
            "enip.status",
            payload_offset + 8,
            4,
        ),
    ];

    let cip = payload.get(HEADER_LEN..).and_then(find_cip_service);
    if let Some((svc, rel)) = cip {
        children.push(FieldNode::leaf(
            "CIP Service",
            format!("0x{:02x} ({})", svc, cip_label(svc)),
            "enip.cip_service",
            payload_offset + HEADER_LEN + rel,
            1,
        ));
    }

    let kind = if status != 0 {
        PacketKind::Exception
    } else if cip.is_some_and(|(s, _)| matches!(s, 0x10 | 0x54 | 0x4E | 0x16)) {
        PacketKind::Cmd
    } else {
        PacketKind::Read
    };

    let summary = format!(
        "{} ENIP {} ({})",
        direction.arrow(),
        command_label(command),
        length
    );

    Dissection {
        kind,
        summary,
        tree: vec![FieldNode::parent(
            "EtherNet/IP",
            "enip",
            payload_offset,
            payload.len(),
            children,
        )],
    }
}

fn command_label(command: u16) -> &'static str {
    match command {
        0x0001 => "NOP",
        0x0004 => "ListServices",
        0x0063 => "ListIdentity",
        0x0065 => "RegisterSession",
        0x0066 => "UnregisterSession",
        0x006F => "SendRRData",
        0x0070 => "SendUnitData",
        _ => "other",
    }
}

fn cip_label(svc: u8) -> &'static str {
    match svc {
        0x0E => "GetAttributeSingle",
        0x10 => "SetAttributeSingle",
        0x16 => "SetAttributeList",
        0x4E => "ForwardClose",
        0x54 => "ForwardOpen",
        _ => "other",
    }
}

/// Scan the CPF body for a CIP service octet (MVP heuristic).
fn find_cip_service(data: &[u8]) -> Option<(u8, usize)> {
    for (i, b) in data.iter().enumerate() {
        if matches!(b, 0x0E | 0x10 | 0x16 | 0x4E | 0x54) {
            return Some((*b, i));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u16, extra: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; HEADER_LEN];
        p[0..2].copy_from_slice(&command.to_le_bytes());
        p[2..4].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        p.extend_from_slice(extra);
        p
    }

    #[test]
    fn register_session_is_read() {
        let d = dissect(&header(0x0065, &[0, 0, 0, 0]), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
        assert!(d.summary.contains("RegisterSession"));
    }

    #[test]
    fn set_attribute_is_cmd() {
        let d = dissect(&header(0x006F, &[0x10, 0x00]), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn nonzero_status_is_exception() {
        let mut p = header(0x0065, &[]);
        p[8] = 1;
        let d = dissect(&p, 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Exception);
    }

    #[test]
    fn short_payload_never_cmd() {
        let d = dissect(&[0x65, 0x00], 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }
}
