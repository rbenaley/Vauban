//! IEEE 1815 (DNP3) TCP dissector (MVP).
//!
//! Link start `05 64`, then control / dest / src. Application function
//! codes: Read → `Read`; Write / Select / Operate / Direct Operate →
//! `Cmd`; IIN-bearing responses → `Exception`.

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const MIN_LINK: usize = 10;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < MIN_LINK || payload[0] != 0x05 || payload[1] != 0x64 {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let length = payload[2];
    let control = payload[3];
    let dest = u16::from_le_bytes([payload[4], payload[5]]);
    let src = u16::from_le_bytes([payload[6], payload[7]]);

    let mut children = vec![
        FieldNode::leaf("Start", "0x0564".into(), "dnp3.start", payload_offset, 2),
        FieldNode::leaf(
            "Length",
            format!("{}", length),
            "dnp3.length",
            payload_offset + 2,
            1,
        ),
        FieldNode::leaf(
            "Control",
            format!("0x{:02x}", control),
            "dnp3.control",
            payload_offset + 3,
            1,
        ),
        FieldNode::leaf(
            "Dest",
            format!("{}", dest),
            "dnp3.dest",
            payload_offset + 4,
            2,
        ),
        FieldNode::leaf("Src", format!("{}", src), "dnp3.src", payload_offset + 6, 2),
    ];

    // User data starts after the 10-byte link header. Transport FIR/FIN
    // occupies the first userdata octet when present; app FC follows.
    let app_fc = payload
        .get(11)
        .copied()
        .or_else(|| payload.get(10).copied());
    let kind = match app_fc {
        Some(0x02..=0x06) => PacketKind::Cmd,
        Some(fc) if fc >= 0x81 => PacketKind::Exception,
        Some(_) => PacketKind::Read,
        None => PacketKind::Tcp,
    };

    if let Some(fc) = app_fc {
        children.push(FieldNode::leaf(
            "App Function",
            format!("0x{:02x} ({})", fc, fc_label(fc)),
            "dnp3.app_fc",
            payload_offset + if payload.len() > 11 { 11 } else { 10 },
            1,
        ));
    }

    let summary = format!(
        "{} DNP3 {} dest={} src={}",
        direction.arrow(),
        app_fc.map(fc_label).unwrap_or("link"),
        dest,
        src
    );

    Dissection {
        kind,
        summary,
        tree: vec![FieldNode::parent(
            "DNP3",
            "dnp3",
            payload_offset,
            payload.len(),
            children,
        )],
    }
}

fn fc_label(fc: u8) -> &'static str {
    match fc {
        0x01 => "Read",
        0x02 => "Write",
        0x03 => "Select",
        0x04 => "Operate",
        0x05 => "Direct Operate",
        0x06 => "Direct Operate NR",
        0x81 => "Response",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link_with_app(fc: u8) -> Vec<u8> {
        // 10-byte link + transport + app FC.
        let mut p = vec![0x05, 0x64, 0x07, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
        p.push(0xC0); // transport FIR+FIN
        p.push(fc);
        p
    }

    #[test]
    fn operate_is_cmd() {
        let d = dissect(&link_with_app(0x04), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
        assert!(d.summary.contains("Operate"));
    }

    #[test]
    fn read_is_read() {
        let d = dissect(&link_with_app(0x01), 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn response_81_is_exception() {
        let d = dissect(&link_with_app(0x81), 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Exception);
    }

    #[test]
    fn short_never_cmd() {
        let d = dissect(&[0x05, 0x64], 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }
}
