//! BACnet/SC (TLS / WebSocket) dissector (MVP).
//!
//! Handshake (TLS ClientHello / HTTP upgrade) → `Read`. Encrypted
//! application records stay passthrough and **never** `Cmd` -- the
//! APDU is not visible without the session keys (same honesty as
//! OPC-UA Sign&Encrypt).

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
        let rec_len = u16::from_be_bytes([payload[3], payload[4]]);
        let children = vec![
            FieldNode::leaf(
                "TLS Content Type",
                "handshake (0x16)".into(),
                "bacnet_sc.content_type",
                payload_offset,
                1,
            ),
            FieldNode::leaf(
                "TLS Record Length",
                format!("{}", rec_len),
                "bacnet_sc.rec_len",
                payload_offset + 3,
                2,
            ),
        ];
        return Dissection {
            kind: PacketKind::Read,
            summary: format!(
                "{} BACnet/SC TLS handshake ({})",
                direction.arrow(),
                rec_len
            ),
            tree: vec![FieldNode::parent(
                "BACnet/SC",
                "bacnet_sc",
                payload_offset,
                payload.len(),
                children,
            )],
        };
    }

    if payload.starts_with(b"GET ") || payload.starts_with(b"HTTP") {
        return Dissection {
            kind: PacketKind::Read,
            summary: format!("{} BACnet/SC WebSocket upgrade", direction.arrow()),
            tree: vec![FieldNode::leaf(
                "HTTP",
                "upgrade".into(),
                "bacnet_sc.http",
                payload_offset,
                payload.len().min(16),
            )],
        };
    }

    // Ciphertext / application data: never Cmd.
    let mut d = super::passthrough::dissect(payload, payload_offset, direction);
    d.summary = format!("{} BACnet/SC TLS application (opaque)", direction.arrow());
    d.kind = PacketKind::Read;
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_read() {
        let p = vec![0x16, 0x03, 0x03, 0x00, 0x20];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
        assert!(d.summary.contains("handshake"));
    }

    #[test]
    fn cmd_not_emitted_on_bacnet_sc_ciphertext() {
        // TLS application_data (0x17) -- encrypted BACnet APDU.
        let p = vec![0x17, 0x03, 0x03, 0x00, 0x10, 0xAA, 0xBB, 0xCC];
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn http_upgrade_is_read() {
        let d = dissect(b"GET / HTTP/1.1\r\n", 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
    }
}
