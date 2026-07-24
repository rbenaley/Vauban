//! Shared types for the IACS Inspect Capture analyzer.
//!
//! These types are produced by `parser.rs` + `dissectors/*.rs` and
//! consumed by both the HTTP handlers (`handlers/web/sessions.rs`)
//! and the Askama partials (`templates/sessions/inspect/*.html`).

use serde::{Deserialize, Serialize};

/// Direction inferred from the synthetic L3/L4 headers vs the
/// per-channel endpoints recorded in `meta.json`.
///
/// The audit module always emits `ClientToServer` / `ServerToClient`
/// from the EWS perspective: the client is the EWS application that
/// initiated the `direct-tcpip` channel, the server is the
/// industrial asset on the far side of the IACS proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// EWS application -> industrial asset (commands, reads, writes).
    EwsToAsset,
    /// Industrial asset -> EWS application (responses, exceptions).
    AssetToEws,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::EwsToAsset => "ews_to_asset",
            Direction::AssetToEws => "asset_to_ews",
        }
    }

    pub fn arrow(self) -> &'static str {
        match self {
            Direction::EwsToAsset => "EWS -> Asset",
            Direction::AssetToEws => "Asset -> EWS",
        }
    }

    /// Parse a query-string value back into a Direction.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ews_to_asset" => Some(Direction::EwsToAsset),
            "asset_to_ews" => Some(Direction::AssetToEws),
            _ => None,
        }
    }
}

/// High-level classification of a captured packet.
///
/// `Tcp` is reserved for control segments (SYN / FIN / pure ACK)
/// that carry no application payload; `Read` / `Cmd` / `Exception`
/// are produced by the protocol dissectors and drive the row tint
/// in the packet list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketKind {
    /// TCP control plane (SYN / FIN / pure ACK / no payload).
    Tcp,
    /// Read / monitor request or response.
    Read,
    /// State-changing command (modification of asset state).
    Cmd,
    /// Negative response, exception, busy, unsupported, ...
    Exception,
}

impl PacketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PacketKind::Tcp => "tcp",
            PacketKind::Read => "read",
            PacketKind::Cmd => "cmd",
            PacketKind::Exception => "excp",
        }
    }

    /// Parse a query-string value back into a PacketKind.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(PacketKind::Tcp),
            "read" => Some(PacketKind::Read),
            "cmd" => Some(PacketKind::Cmd),
            "excp" => Some(PacketKind::Exception),
            _ => None,
        }
    }
}

/// Compact summary used to populate the packet list row.
///
/// One per PCAP record. The list partial renders these directly --
/// `frame_idx` is the 1-based index inside the channel and is the
/// stable URL key for the detail fragment.
#[derive(Debug, Clone, Serialize)]
pub struct PacketSummary {
    pub frame_idx: usize,
    pub timestamp_us: u64,
    /// Wall-clock timestamp formatted in the user's tz (browser_tz).
    pub timestamp_human: String,
    pub direction: Direction,
    pub kind: PacketKind,
    /// One-line glyph + summary (e.g. `[SYN]`, `FC03 Read 10x@0`).
    pub summary: String,
    /// Bytes of application payload (zero for SYN/FIN/pure-ACK).
    pub payload_len: usize,
    /// Source TCP port from the synthetic header.
    pub src_port: u16,
    /// Destination TCP port from the synthetic header.
    pub dst_port: u16,
}

/// One node of the dissection tree shown in the detail panel.
///
/// `field_id` is the stable handle (e.g. `modbus.function`) used
/// by both the tree partial and the hex partial to drive the
/// bidirectional Alpine highlight. `offset`/`len` are absolute
/// byte positions inside the captured frame so the hex view can
/// localise them with `field_id` matched on hover.
#[derive(Debug, Clone, Serialize)]
pub struct FieldNode {
    pub label: String,
    pub value: String,
    pub field_id: String,
    pub offset: usize,
    pub len: usize,
    pub children: Vec<FieldNode>,
}

impl FieldNode {
    pub fn leaf(label: &str, value: String, field_id: &str, offset: usize, len: usize) -> Self {
        FieldNode {
            label: label.to_string(),
            value,
            field_id: field_id.to_string(),
            offset,
            len,
            children: Vec::new(),
        }
    }

    pub fn parent(
        label: &str,
        field_id: &str,
        offset: usize,
        len: usize,
        children: Vec<FieldNode>,
    ) -> Self {
        FieldNode {
            label: label.to_string(),
            value: String::new(),
            field_id: field_id.to_string(),
            offset,
            len,
            children,
        }
    }
}

/// Full detail produced by `analyze_packet` for one frame.
///
/// `tree` is rendered top-down in the dissection panel; `hex` is
/// the raw frame bytes (capture from libpcap, i.e. starting at the
/// IPv4/IPv6 header). The hex view is a flat byte array so the
/// template can pair each byte with the matching `field_id` from
/// the tree.
#[derive(Debug, Clone, Serialize)]
pub struct PacketDetail {
    pub summary: PacketSummary,
    pub tree: Vec<FieldNode>,
    pub hex: Vec<u8>,
    /// Mapping `byte_offset -> field_id` for every byte covered by
    /// a leaf field. Bytes not covered by the dissection map to
    /// the empty string.
    pub byte_field_ids: Vec<String>,
}

/// Filter / pagination request shared by the list and detail
/// fragments.
#[derive(Debug, Clone, Default)]
pub struct PacketListFilter {
    pub direction: Option<Direction>,
    pub kind: Option<PacketKind>,
    /// Free-text search (matched against summary text, ASCII
    /// payload, hex string).
    pub search: Option<String>,
    /// 1-based page index (default 1).
    pub page: usize,
    /// Page size (capped server-side to `MAX_PAGE_SIZE`).
    pub page_size: usize,
}

pub const DEFAULT_PAGE_SIZE: usize = 100;
pub const MAX_PAGE_SIZE: usize = 500;

impl PacketListFilter {
    pub fn normalised(mut self) -> Self {
        if self.page == 0 {
            self.page = 1;
        }
        if self.page_size == 0 {
            self.page_size = DEFAULT_PAGE_SIZE;
        }
        if self.page_size > MAX_PAGE_SIZE {
            self.page_size = MAX_PAGE_SIZE;
        }
        self
    }
}

/// Result of a paginated list query.
#[derive(Debug, Clone, Serialize)]
pub struct PacketListPage {
    pub items: Vec<PacketSummary>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_round_trip() {
        for d in [Direction::EwsToAsset, Direction::AssetToEws] {
            assert_eq!(Direction::parse(d.as_str()), Some(d));
        }
        assert_eq!(Direction::parse("garbage"), None);
    }

    #[test]
    fn packet_kind_round_trip() {
        for k in [
            PacketKind::Tcp,
            PacketKind::Read,
            PacketKind::Cmd,
            PacketKind::Exception,
        ] {
            assert_eq!(PacketKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(PacketKind::parse(""), None);
    }

    #[test]
    fn packet_list_filter_normalises_zero_page_to_one() {
        let f = PacketListFilter::default().normalised();
        assert_eq!(f.page, 1);
        assert_eq!(f.page_size, DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn packet_list_filter_caps_page_size() {
        let f = PacketListFilter {
            page_size: MAX_PAGE_SIZE + 1_000,
            ..Default::default()
        };
        let f = f.normalised();
        assert_eq!(f.page_size, MAX_PAGE_SIZE);
    }

    #[test]
    fn field_node_leaf_has_no_children() {
        let n = FieldNode::leaf("Function", "06".into(), "modbus.function", 7, 1);
        assert!(n.children.is_empty());
        assert_eq!(n.field_id, "modbus.function");
    }
}
