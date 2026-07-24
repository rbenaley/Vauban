//! Raw-TCP fallback. Used when the channel does not match a
//! supported industrial profile (OPC-UA, PROFINET, generic TCP)
//! or when a Modbus/IEC-104 packet is too short to dissect.
//!
//! The fallback never returns `PacketKind::Cmd` -- the safe default
//! is `PacketKind::Read` so an operator visually distinguishes raw
//! data flow from positively-classified commands.

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    let preview = ascii_preview(payload);
    let summary = format!(
        "{} TCP payload  ({} bytes)  {}",
        direction.arrow(),
        payload.len(),
        preview
    );
    let tree = vec![FieldNode::leaf(
        "TCP Payload",
        format!("{} bytes", payload.len()),
        "tcp.payload",
        payload_offset,
        payload.len(),
    )];
    Dissection {
        kind: PacketKind::Read,
        summary,
        tree,
    }
}

fn ascii_preview(buf: &[u8]) -> String {
    let cap = std::cmp::min(buf.len(), 24);
    let mut s = String::with_capacity(cap);
    for b in &buf[..cap] {
        if (0x20..=0x7E).contains(b) {
            s.push(*b as char);
        } else {
            s.push('.');
        }
    }
    if buf.len() > cap {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_never_returns_cmd() {
        let d = dissect(b"\x00\x01\x02\x03", 40, Direction::EwsToAsset);
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn passthrough_is_panic_free_on_arbitrary_bytes() {
        for len in [0usize, 1, 7, 64, 1024] {
            let buf = vec![0xAA; len];
            let _ = dissect(&buf, 40, Direction::EwsToAsset);
        }
    }

    #[test]
    fn passthrough_classifies_as_read() {
        let d = dissect(b"hello", 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn passthrough_summary_includes_byte_count() {
        let d = dissect(&[0u8; 12], 40, Direction::EwsToAsset);
        assert!(d.summary.contains("12 bytes"));
    }

    #[test]
    fn passthrough_tree_node_carries_full_payload_offset() {
        let d = dissect(&[0u8; 8], 40, Direction::EwsToAsset);
        assert_eq!(d.tree.len(), 1);
        assert_eq!(d.tree[0].offset, 40);
        assert_eq!(d.tree[0].len, 8);
    }
}
