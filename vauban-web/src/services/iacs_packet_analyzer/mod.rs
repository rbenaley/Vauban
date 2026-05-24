//! IACS Inspect Capture - in-browser packet analyzer.
//!
//! This module is the inverse of [`vauban_audit::iacs_pcap_synth`]:
//! given a (gzipped) `.pcap.gz` produced by the audit service it
//! reconstructs the application timeline + per-frame dissection
//! that drive the Inspect Capture UI.
//!
//! Architectural invariants (cf. plan section 2):
//!
//! - **No replay**: the analyzer is read-only. The audit service is
//!   the only writer; vauban-web can only `read()` PCAPs through
//!   the supervisor's SCM_RIGHTS broker.
//! - **No JS in templates**: filtering / pagination / detail
//!   navigation are all server-side HTMX. Only the tree<->hex
//!   highlight uses an inline Alpine `x-data` (~10 lines).
//! - **Tree<->hex contract**: every leaf [`FieldNode`] carries a
//!   `field_id` + frame-relative `(offset, len)`. The hex pane
//!   stamps the same `data-field` on each covered byte so the
//!   bidirectional highlight works without any JS computation.

pub mod dissectors;
pub mod flow;
pub mod parser;
pub mod types;

use std::io::Read;

use shared::iacs_protocol::ExpectedProfile;

use self::dissectors::Dissection;
use self::flow::ChannelEndpoints;
use self::parser::{ParserError, RawPacket};
use self::types::{
    Direction, FieldNode, PacketDetail, PacketKind, PacketListFilter, PacketListPage,
    PacketSummary,
};

pub use self::parser::parse_pcap_bytes;
pub use self::parser::parse_pcap_gz;

/// Format a timestamp as a short HH:MM:SS.fff string for the list
/// row. The full UTC timestamp is rendered in the detail panel
/// using the user's `BrowserTz`.
fn format_short_timestamp(ts_us: u64) -> String {
    let secs = ts_us / 1_000_000;
    let micros = ts_us % 1_000_000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3_600) % 24;
    format!("{:02}:{:02}:{:02}.{:06}", h, m, s, micros)
}

/// Build the full per-channel summary timeline. Returns one entry
/// per PCAP record. Errors propagate from the parser only; once the
/// parser succeeds the summary build is infallible (control frames
/// surface as `PacketKind::Tcp` with no dissection tree).
pub fn analyze_channel<R: Read>(
    reader: R,
    profile: ExpectedProfile,
) -> Result<Vec<PacketSummary>, ParserError> {
    let raw = parse_pcap_gz(reader)?;
    Ok(summaries_from_raw(&raw, profile))
}

/// Variant for tests / pipeline E2E that already hold the
/// decompressed PCAP buffer.
pub fn analyze_channel_bytes(
    buf: &[u8],
    profile: ExpectedProfile,
) -> Result<Vec<PacketSummary>, ParserError> {
    let raw = parse_pcap_bytes(buf)?;
    Ok(summaries_from_raw(&raw, profile))
}

fn summaries_from_raw(raw: &[RawPacket], profile: ExpectedProfile) -> Vec<PacketSummary> {
    let endpoints = ChannelEndpoints::infer_from_first_packets(raw);

    raw.iter()
        .map(|p| {
            let direction = endpoints
                .as_ref()
                .map(|e| e.direction_of(p))
                .unwrap_or(Direction::EwsToAsset);

            let summary_text;
            let kind;
            if p.payload.is_empty() {
                kind = PacketKind::Tcp;
                summary_text = format!("{} {}", direction.arrow(), p.tcp_flags.label());
            } else {
                let d = dissectors::dissect(&p.payload, p.payload_offset, direction, profile);
                kind = d.kind;
                summary_text = d.summary;
            }
            PacketSummary {
                frame_idx: p.frame_idx,
                timestamp_us: p.timestamp_us,
                timestamp_human: format_short_timestamp(p.timestamp_us),
                direction,
                kind,
                summary: summary_text,
                payload_len: p.payload.len(),
                src_port: p.src_port,
                dst_port: p.dst_port,
            }
        })
        .collect()
}

/// Apply the filter to a pre-built summary timeline and return the
/// requested page. Pagination is 1-based; out-of-range pages
/// surface as an empty page (with the unchanged total count).
pub fn page_summaries(items: Vec<PacketSummary>, filter: PacketListFilter) -> PacketListPage {
    let filter = filter.normalised();
    let filtered: Vec<PacketSummary> = items
        .into_iter()
        .filter(|s| {
            if let Some(d) = filter.direction
                && s.direction != d
            {
                return false;
            }
            if let Some(k) = filter.kind
                && s.kind != k
            {
                return false;
            }
            if let Some(q) = filter.search.as_deref() {
                let q = q.trim();
                if !q.is_empty() {
                    let needle = q.to_lowercase();
                    let hay = s.summary.to_lowercase();
                    if !hay.contains(&needle) {
                        return false;
                    }
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    let start = (filter.page - 1) * filter.page_size;
    let end = std::cmp::min(start + filter.page_size, total);
    let items = if start >= total {
        Vec::new()
    } else {
        filtered[start..end].to_vec()
    };

    PacketListPage {
        items,
        total,
        page: filter.page,
        page_size: filter.page_size,
    }
}

/// Build the full detail (tree + hex + per-byte field map) for one
/// frame. `frame_idx` is 1-based (matches the URL path segment).
pub fn analyze_packet<R: Read>(
    reader: R,
    profile: ExpectedProfile,
    frame_idx: usize,
) -> Result<Option<PacketDetail>, ParserError> {
    let raw = parse_pcap_gz(reader)?;
    Ok(detail_from_raw(&raw, profile, frame_idx))
}

/// Variant for tests / pipeline E2E.
pub fn analyze_packet_bytes(
    buf: &[u8],
    profile: ExpectedProfile,
    frame_idx: usize,
) -> Option<PacketDetail> {
    let raw = parse_pcap_bytes(buf).ok()?;
    detail_from_raw(&raw, profile, frame_idx)
}

fn detail_from_raw(
    raw: &[RawPacket],
    profile: ExpectedProfile,
    frame_idx: usize,
) -> Option<PacketDetail> {
    let endpoints = ChannelEndpoints::infer_from_first_packets(raw);
    let p = raw.iter().find(|r| r.frame_idx == frame_idx)?;
    let direction = endpoints
        .as_ref()
        .map(|e| e.direction_of(p))
        .unwrap_or(Direction::EwsToAsset);

    let (kind, summary_text, mut tree) = if p.payload.is_empty() {
        (
            PacketKind::Tcp,
            format!("{} {}", direction.arrow(), p.tcp_flags.label()),
            Vec::new(),
        )
    } else {
        let Dissection {
            kind,
            summary,
            tree,
        } = dissectors::dissect(&p.payload, p.payload_offset, direction, profile);
        (kind, summary, tree)
    };

    // Always prepend a synthetic "Frame" parent listing IP + TCP
    // for the operator's context. We do not duplicate the byte
    // ranges -- those are surfaced by the dissector tree.
    let frame_parent = FieldNode::parent(
        "Frame",
        "frame",
        0,
        p.frame_bytes.len(),
        vec![
            FieldNode::leaf(
                "Source",
                format!("{}:{}", p.src_ip, p.src_port),
                "frame.src",
                0,
                0,
            ),
            FieldNode::leaf(
                "Destination",
                format!("{}:{}", p.dst_ip, p.dst_port),
                "frame.dst",
                0,
                0,
            ),
            FieldNode::leaf(
                "TCP Flags",
                p.tcp_flags.label().to_string(),
                "frame.flags",
                0,
                0,
            ),
            FieldNode::leaf(
                "Sequence",
                format!("{}", p.seq),
                "frame.seq",
                0,
                0,
            ),
            FieldNode::leaf("Acknowledgment", format!("{}", p.ack), "frame.ack", 0, 0),
        ],
    );
    let mut full_tree = vec![frame_parent];
    full_tree.append(&mut tree);

    let byte_field_ids = build_byte_field_map(&full_tree, p.frame_bytes.len());

    let summary = PacketSummary {
        frame_idx: p.frame_idx,
        timestamp_us: p.timestamp_us,
        timestamp_human: format_short_timestamp(p.timestamp_us),
        direction,
        kind,
        summary: summary_text,
        payload_len: p.payload.len(),
        src_port: p.src_port,
        dst_port: p.dst_port,
    };

    Some(PacketDetail {
        summary,
        tree: full_tree,
        hex: p.frame_bytes.clone(),
        byte_field_ids,
    })
}

fn build_byte_field_map(tree: &[FieldNode], frame_len: usize) -> Vec<String> {
    let mut map = vec![String::new(); frame_len];
    fn recurse(nodes: &[FieldNode], map: &mut [String]) {
        for n in nodes {
            if !n.children.is_empty() {
                recurse(&n.children, map);
            } else if n.len > 0 && n.offset < map.len() {
                let end = std::cmp::min(n.offset + n.len, map.len());
                for cell in &mut map[n.offset..end] {
                    *cell = n.field_id.clone();
                }
            }
        }
    }
    recurse(tree, &mut map);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use vauban_audit::iacs_pcap_synth as synth;

    fn build_modbus_pcap() -> Vec<u8> {
        let mut flow = synth::TcpFlow::new(
            "s",
            1,
            synth::Endpoints::parse("192.0.2.10", 49_152, "198.51.100.20", 502),
        );
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        for r in synth::build_handshake(&flow, 1_000) {
            buf.extend_from_slice(&r);
        }
        // FC06 Write Single Register -> Cmd.
        let modbus = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x05\x00\x2a";
        for r in synth::build_data_records(&mut flow, synth::Direction::ClientToServer, modbus, 2_000) {
            buf.extend_from_slice(&r);
        }
        // Response (echo).
        for r in synth::build_data_records(&mut flow, synth::Direction::ServerToClient, modbus, 3_000) {
            buf.extend_from_slice(&r);
        }
        for r in synth::build_close(&flow, 4_000) {
            buf.extend_from_slice(&r);
        }
        buf
    }

    #[test]
    fn analyze_channel_bytes_returns_one_summary_per_record() {
        let buf = build_modbus_pcap();
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
        // 3 handshake + (PSH+ACK + cumulative ACK) c2s + (PSH+ACK + cumulative ACK) s2c
        // + 4 close = 11 records.
        let cmds: Vec<_> = summaries.iter().filter(|s| s.kind == PacketKind::Cmd).collect();
        assert_eq!(cmds.len(), 2, "two PSH+ACK frames carry the FC06 payload");
        assert_eq!(summaries.len(), 11);
    }

    #[test]
    fn page_summaries_filters_by_kind() {
        let buf = build_modbus_pcap();
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
        let filter = PacketListFilter {
            kind: Some(PacketKind::Cmd),
            ..Default::default()
        };
        let page = page_summaries(summaries, filter);
        assert_eq!(page.total, 2);
        assert!(page.items.iter().all(|s| s.kind == PacketKind::Cmd));
    }

    #[test]
    fn page_summaries_filters_by_direction() {
        let buf = build_modbus_pcap();
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
        let filter = PacketListFilter {
            direction: Some(Direction::AssetToEws),
            ..Default::default()
        };
        let page = page_summaries(summaries, filter);
        assert!(page.items.iter().all(|s| s.direction == Direction::AssetToEws));
    }

    #[test]
    fn page_summaries_search_matches_summary_text() {
        let buf = build_modbus_pcap();
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
        let filter = PacketListFilter {
            search: Some("FC06".into()),
            ..Default::default()
        };
        let page = page_summaries(summaries, filter);
        assert!(page.total > 0);
        for s in &page.items {
            assert!(s.summary.contains("FC06"));
        }
    }

    #[test]
    fn page_summaries_pagination_returns_correct_window() {
        let buf = build_modbus_pcap();
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Modbus).unwrap();
        let total = summaries.len();
        let filter = PacketListFilter {
            page: 1,
            page_size: 5,
            ..Default::default()
        };
        let page = page_summaries(summaries.clone(), filter);
        assert_eq!(page.items.len(), std::cmp::min(5, total));
        assert_eq!(page.total, total);
        let filter2 = PacketListFilter {
            page: 100,
            page_size: 5,
            ..Default::default()
        };
        let page2 = page_summaries(summaries, filter2);
        assert!(page2.items.is_empty());
    }

    #[test]
    fn analyze_packet_bytes_returns_detail_for_data_frame() {
        let buf = build_modbus_pcap();
        // Frame 4 is the first PSH+ACK data segment (after 3 handshake records).
        let detail = analyze_packet_bytes(&buf, ExpectedProfile::Modbus, 4).expect("detail");
        assert_eq!(detail.summary.kind, PacketKind::Cmd);
        assert!(!detail.tree.is_empty());
        // byte_field_ids must match frame size.
        assert_eq!(detail.byte_field_ids.len(), detail.hex.len());
        // The FC byte (offset 47 = 40 IP+TCP + 7 MBAP) should be tagged.
        let tag = &detail.byte_field_ids[47];
        assert_eq!(tag, "modbus.function");
    }

    #[test]
    fn analyze_packet_bytes_returns_none_for_unknown_index() {
        let buf = build_modbus_pcap();
        assert!(analyze_packet_bytes(&buf, ExpectedProfile::Modbus, 9_999).is_none());
    }

    #[test]
    fn build_byte_field_map_handles_overlapping_parents() {
        let leaf_a = FieldNode::leaf("A", "x".into(), "a", 0, 2);
        let leaf_b = FieldNode::leaf("B", "y".into(), "b", 2, 1);
        let map = build_byte_field_map(&[leaf_a, leaf_b], 4);
        assert_eq!(map[0], "a");
        assert_eq!(map[1], "a");
        assert_eq!(map[2], "b");
        assert_eq!(map[3], ""); // uncovered
    }

    #[test]
    fn analyze_channel_handles_empty_capture() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&synth::build_global_header());
        let summaries = analyze_channel_bytes(&buf, ExpectedProfile::Passthrough).unwrap();
        assert!(summaries.is_empty());
    }
}
