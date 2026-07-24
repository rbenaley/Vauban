//! OPC-UA Binary (UA TCP) dissector (MVP scope).
//!
//! Wire format (message header, 8 bytes):
//!
//! ```text
//! +-- 3-byte ASCII type --+ reserved | message size (u32 LE) |
//! | HEL / ACK / OPN / ... |   u8     | includes header       |
//! +-----------------------+----------+-----------------------+
//! ```
//!
//! ## Classification heuristic (MVP)
//!
//! Handshake / control message types (`HEL`, `ACK`, `OPN`, `CLO`, `ERR`)
//! are always classified as [`PacketKind::Read`] — they denote channel
//! setup or teardown, not asset state mutation.
//!
//! For `MSG` payloads the secure-channel and sequence headers vary with
//! security policy; a full parser would walk the NodeId encoding. The
//! MVP instead peeks a **u32 LE service identifier at byte offset 16**
//! (relative to the TCP payload start). This offset matches the common
//! layout of unencrypted / minimal-security `MSG` frames observed in
//! industrial captures and in Wireshark's default UA dissector heuristics.
//!
//! | Service ID | Name                  | Kind |
//! |------------|-----------------------|------|
//! | 498        | DeleteNodesRequest    | Cmd  |
//! | 672        | WriteRequest          | Cmd  |
//! | 675        | WriteResponse         | Cmd  |
//! | 698        | HistoryUpdateRequest  | Cmd  |
//! | 710        | CallRequest           | Cmd  |
//! | 713        | CallResponse          | Cmd  |
//! | 525        | BrowseRequest         | Read |
//! | 631        | ReadRequest           | Read |
//! | 634        | ReadResponse          | Read |
//! | 826        | PublishRequest        | Read |
//! | 829        | PublishResponse       | Read |
//! | other      | —                     | Read (fail-closed for Cmd) |
//!
//! Payloads shorter than 8 bytes or with an unknown message type fall
//! back to [`super::passthrough`] (never `Cmd`).

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const HEADER_LEN: usize = 8;
/// Heuristic offset for the service type id inside unsecure `MSG` bodies.
const MSG_SERVICE_ID_OFFSET: usize = 16;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < HEADER_LEN {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }

    let msg_type = match parse_message_type(payload) {
        Some(t) => t,
        None => return super::passthrough::dissect(payload, payload_offset, direction),
    };

    let msg_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;

    let mut children = vec![
        FieldNode::leaf(
            "Message Type",
            msg_type.to_string(),
            "opcua.msg_type",
            payload_offset,
            3,
        ),
        FieldNode::leaf(
            "Reserved",
            format!("0x{:02x}", payload[3]),
            "opcua.reserved",
            payload_offset + 3,
            1,
        ),
        FieldNode::leaf(
            "Message Size",
            format!("{} bytes", msg_size),
            "opcua.msg_size",
            payload_offset + 4,
            4,
        ),
    ];

    let (kind, service_label) = match msg_type {
        MessageType::Hel
        | MessageType::Ack
        | MessageType::Opn
        | MessageType::Clo
        | MessageType::Err => (PacketKind::Read, None),
        MessageType::Msg => {
            if payload.len() >= MSG_SERVICE_ID_OFFSET + 4 {
                let service_id = u32::from_le_bytes([
                    payload[MSG_SERVICE_ID_OFFSET],
                    payload[MSG_SERVICE_ID_OFFSET + 1],
                    payload[MSG_SERVICE_ID_OFFSET + 2],
                    payload[MSG_SERVICE_ID_OFFSET + 3],
                ]);
                let label = service_name(service_id);
                children.push(FieldNode::leaf(
                    "Service",
                    format!("{} ({})", label, service_id),
                    "opcua.service",
                    payload_offset + MSG_SERVICE_ID_OFFSET,
                    4,
                ));
                (classify_service(service_id), Some(label))
            } else {
                (PacketKind::Read, None)
            }
        }
    };

    let summary = match (msg_type, service_label) {
        (MessageType::Msg, Some(svc)) => {
            format!("{} OPC-UA MSG {} ({})", direction.arrow(), svc, msg_type)
        }
        _ => format!("{} OPC-UA {} ({})", direction.arrow(), msg_type, msg_size),
    };

    let tree = vec![FieldNode::parent(
        "OPC-UA",
        "opcua",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageType {
    Hel,
    Ack,
    Opn,
    Msg,
    Clo,
    Err,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MessageType::Hel => "HEL",
            MessageType::Ack => "ACK",
            MessageType::Opn => "OPN",
            MessageType::Msg => "MSG",
            MessageType::Clo => "CLO",
            MessageType::Err => "ERR",
        })
    }
}

fn parse_message_type(payload: &[u8]) -> Option<MessageType> {
    match &payload[..3] {
        b"HEL" => Some(MessageType::Hel),
        b"ACK" => Some(MessageType::Ack),
        b"OPN" => Some(MessageType::Opn),
        b"MSG" => Some(MessageType::Msg),
        b"CLO" => Some(MessageType::Clo),
        b"ERR" => Some(MessageType::Err),
        _ => None,
    }
}

fn classify_service(service_id: u32) -> PacketKind {
    match service_id {
        498 | 672 | 675 | 698 | 710 | 713 => PacketKind::Cmd,
        525 | 631 | 634 | 826 | 829 => PacketKind::Read,
        _ => PacketKind::Read,
    }
}

fn service_name(service_id: u32) -> &'static str {
    match service_id {
        498 => "DeleteNodesRequest",
        525 => "BrowseRequest",
        631 => "ReadRequest",
        634 => "ReadResponse",
        672 => "WriteRequest",
        675 => "WriteResponse",
        698 => "HistoryUpdateRequest",
        710 => "CallRequest",
        713 => "CallResponse",
        826 => "PublishRequest",
        829 => "PublishResponse",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hel_payload() -> Vec<u8> {
        let mut p = b"HEL\x00\x1c\x00\x00\x00".to_vec();
        p.extend_from_slice(&[0u8; 20]);
        p
    }

    #[test]
    fn hel_classifies_as_read() {
        let p = hel_payload();
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
        assert!(d.summary.contains("HEL"));
    }

    #[test]
    fn msg_write_request_at_offset_16_classifies_as_cmd() {
        let mut p = vec![0u8; 24];
        p[..3].copy_from_slice(b"MSG");
        p[3] = 0;
        // Message size (includes 8-byte header).
        let size = 24u32.to_le_bytes();
        p[4..8].copy_from_slice(&size);
        // Service id WriteRequest (672) at offset 16.
        p[16..20].copy_from_slice(&672u32.to_le_bytes());
        let d = dissect(&p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
        assert!(d.summary.contains("WriteRequest"));
    }

    #[test]
    fn truncated_payload_falls_back_without_cmd() {
        let p = b"MSG\x00";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn unknown_type_never_cmd() {
        let p = b"FOO\x00\x10\x00\x00\x00";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn dissect_is_panic_free_on_arbitrary_bytes() {
        for len in [0, 1, 7, 8, 16, 64] {
            let buf = vec![0xAA; len];
            let _ = dissect(&buf, 40, Direction::EwsToAsset);
        }
    }

    #[test]
    fn msg_tree_offsets_are_frame_relative() {
        let mut p = vec![0u8; 24];
        p[..3].copy_from_slice(b"MSG");
        p[4..8].copy_from_slice(&24u32.to_le_bytes());
        p[16..20].copy_from_slice(&631u32.to_le_bytes());
        let d = dissect(&p, 40, Direction::EwsToAsset);
        fn find<'a>(nodes: &'a [FieldNode], id: &str) -> Option<&'a FieldNode> {
            for n in nodes {
                if n.field_id == id {
                    return Some(n);
                }
                if let Some(found) = find(&n.children, id) {
                    return Some(found);
                }
            }
            None
        }
        let svc = find(&d.tree, "opcua.service").expect("service node");
        assert_eq!(svc.offset, 40 + MSG_SERVICE_ID_OFFSET);
    }
}
