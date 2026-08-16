//! Askama view-models for the IACS Inspect Capture analyzer.
//!
//! Three top-level templates back the three HTTP routes registered
//! in `main.rs`:
//!
//! 1. [`InspectCaptureTemplate`] -- full HTML shell, rendered on
//!    initial GET.
//! 2. [`PacketListPartial`] -- HTMX swap target on filter / search /
//!    pagination / channel change.
//! 3. [`PacketDetailPartial`] -- HTMX swap target on row click.
//!
//! All three derive from the parser/dissector services. The
//! template structs stay logic-free: every conditional class is
//! resolved at the handler/view-model layer.

use askama::Template;

use crate::auth::PermissionContext;
use crate::services::iacs_packet_analyzer::types::{
    Direction, FieldNode, PacketDetail, PacketKind, PacketSummary,
};
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// One channel entry in the channel selector dropdown.
#[derive(Debug, Clone)]
pub struct ChannelOption {
    pub index: u32,
    pub label: String,
    pub target: String,
    pub packets: u64,
}

/// Top-level view-model for the Inspect Capture page.
#[derive(Debug, Clone)]
pub struct InspectCaptureViewModel {
    pub session_uuid: String,
    pub asset_name: String,
    pub asset_hostname: String,
    /// Wire protocol surfaced in the header pill (`modbus`, `iec104`,
    /// `tcp`, ...). Comes from the `industrial_protocol` column.
    pub industrial_protocol: String,
    pub industrial_protocol_label: String,
    pub channels: Vec<ChannelOption>,
    /// Currently selected channel index (1-based; matches meta.json).
    pub selected_channel: u32,
    pub back_url: String,
    pub list_url: String,
    pub recording_detail_url: String,
    /// Packet list partial pre-rendered into the shell on first paint.
    pub initial_list: PacketListViewModel,
}

/// Filter state surfaced in the chip row + propagated via
/// `hx-include` on every fragment request.
#[derive(Debug, Clone, Default)]
pub struct InspectFilterViewModel {
    pub direction: Option<String>,
    pub kind: Option<String>,
    pub search: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

/// Packet list partial. Carries enough context to render the
/// pagination footer and re-render itself with the same filter
/// when HTMX swaps it.
#[derive(Debug, Clone)]
pub struct PacketListViewModel {
    pub session_uuid: String,
    pub channel: u32,
    pub items: Vec<PacketRowViewModel>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    /// Pre-computed `ceil(total / page_size)`, exposed to the template
    /// so the Askama side stays free of arithmetic.
    pub total_pages: usize,
    pub has_prev: bool,
    pub has_next: bool,
    pub filter: InspectFilterViewModel,
    /// First frame index visible on this page; used to seed the
    /// detail panel when the shell renders for the first time.
    pub first_frame_idx: Option<usize>,
}

/// One row rendered in the packet list.
#[derive(Debug, Clone)]
pub struct PacketRowViewModel {
    pub frame_idx: usize,
    pub timestamp: String,
    pub direction: Direction,
    pub direction_label: &'static str,
    pub direction_border_class: &'static str,
    pub kind: PacketKind,
    pub kind_row_class: &'static str,
    pub kind_glyph: &'static str,
    pub summary: String,
    pub payload_len: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub detail_url: String,
}

impl PacketRowViewModel {
    pub fn from_summary(s: &PacketSummary, session_uuid: &str, channel: u32) -> Self {
        let direction_label = match s.direction {
            Direction::EwsToAsset => "EWS -> Asset",
            Direction::AssetToEws => "Asset -> EWS",
        };
        let direction_border_class = match s.direction {
            Direction::EwsToAsset => "border-l-4 border-amber-400",
            Direction::AssetToEws => "border-l-4 border-emerald-400",
        };
        let (kind_row_class, kind_glyph) = match s.kind {
            PacketKind::Tcp => ("text-gray-500 italic", "[TCP]"),
            PacketKind::Read => ("", "[R]"),
            PacketKind::Cmd => (
                "bg-amber-50 dark:bg-amber-900/30 text-amber-800 dark:text-amber-200",
                "[CMD]",
            ),
            PacketKind::Exception => (
                "bg-rose-50 dark:bg-rose-900/30 text-rose-700 dark:text-rose-200",
                "[EXC]",
            ),
        };
        Self {
            frame_idx: s.frame_idx,
            timestamp: s.timestamp_human.clone(),
            direction: s.direction,
            direction_label,
            direction_border_class,
            kind: s.kind,
            kind_row_class,
            kind_glyph,
            summary: s.summary.clone(),
            payload_len: s.payload_len,
            src_port: s.src_port,
            dst_port: s.dst_port,
            detail_url: format!(
                "/sessions/recordings/{}/inspect/channels/{}/packets/{}",
                session_uuid, channel, s.frame_idx
            ),
        }
    }
}

/// Packet detail partial: tree + hex + replay-safety banner.
#[derive(Debug, Clone)]
pub struct PacketDetailViewModel {
    pub session_uuid: String,
    pub channel: u32,
    pub frame_idx: usize,
    pub direction_label: String,
    pub kind_label: String,
    pub kind_pill_class: &'static str,
    pub timestamp: String,
    pub summary: String,
    pub src: String,
    pub dst: String,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: usize,
    /// Flattened tree (depth-first) for the template. Askama's
    /// `{% include %}` is static, so a recursive include of the
    /// node template would loop at expansion time -- we flatten
    /// once at the view-model layer and surface a `depth` per
    /// node instead.
    pub tree: Vec<TreeRowViewModel>,
    pub hex_rows: Vec<HexRowViewModel>,
}

/// One flattened row in the dissection tree.
#[derive(Debug, Clone)]
pub struct TreeRowViewModel {
    pub depth: usize,
    /// Pre-computed left padding in pixels (depth * 12).
    pub indent_px: usize,
    pub label: String,
    pub value: String,
    pub field_id: String,
    pub is_parent: bool,
}

/// One row of the hex pane (offset + 16 bytes).
#[derive(Debug, Clone)]
pub struct HexRowViewModel {
    pub offset: String,
    pub bytes: Vec<HexByteViewModel>,
    pub ascii: Vec<HexByteViewModel>,
}

/// One byte cell in the hex pane.
#[derive(Debug, Clone)]
pub struct HexByteViewModel {
    pub hex: String,
    pub printable: String,
    pub field_id: String,
}

impl PacketDetailViewModel {
    pub fn from_detail(d: PacketDetail, session_uuid: &str, channel: u32) -> Self {
        let direction_label = d.summary.direction.arrow().to_string();
        let (kind_label, kind_pill_class) = match d.summary.kind {
            PacketKind::Tcp => (
                "TCP",
                "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200",
            ),
            PacketKind::Read => (
                "Read",
                "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
            ),
            PacketKind::Cmd => (
                "Cmd",
                "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200",
            ),
            PacketKind::Exception => (
                "Exception",
                "bg-rose-100 text-rose-700 dark:bg-rose-900/50 dark:text-rose-200",
            ),
        };

        let mut hex_rows = Vec::new();
        for (chunk_idx, chunk) in d.hex.chunks(16).enumerate() {
            let base = chunk_idx * 16;
            let mut bytes = Vec::with_capacity(chunk.len());
            let mut ascii = Vec::with_capacity(chunk.len());
            for (i, b) in chunk.iter().enumerate() {
                let off = base + i;
                let field_id = d.byte_field_ids.get(off).cloned().unwrap_or_default();
                bytes.push(HexByteViewModel {
                    hex: format!("{:02x}", b),
                    printable: String::new(),
                    field_id: field_id.clone(),
                });
                let ch = if (0x20..=0x7E).contains(b) {
                    (*b as char).to_string()
                } else {
                    ".".to_string()
                };
                ascii.push(HexByteViewModel {
                    hex: String::new(),
                    printable: ch,
                    field_id,
                });
            }
            hex_rows.push(HexRowViewModel {
                offset: format!("{:04x}", base),
                bytes,
                ascii,
            });
        }

        let mut tree = Vec::new();
        flatten_tree(&d.tree, 0, &mut tree);

        Self {
            session_uuid: session_uuid.to_string(),
            channel,
            frame_idx: d.summary.frame_idx,
            direction_label,
            kind_label: kind_label.to_string(),
            kind_pill_class,
            timestamp: d.summary.timestamp_human.clone(),
            summary: d.summary.summary.clone(),
            src: format!("port {}", d.summary.src_port),
            dst: format!("port {}", d.summary.dst_port),
            seq: 0,
            ack: 0,
            payload_len: d.summary.payload_len,
            tree,
            hex_rows,
        }
    }
}

fn flatten_tree(nodes: &[FieldNode], depth: usize, out: &mut Vec<TreeRowViewModel>) {
    for n in nodes {
        let is_parent = !n.children.is_empty();
        out.push(TreeRowViewModel {
            depth,
            indent_px: depth * 12,
            label: n.label.clone(),
            value: n.value.clone(),
            field_id: n.field_id.clone(),
            is_parent,
        });
        if is_parent {
            flatten_tree(&n.children, depth + 1, out);
        }
    }
}

/// Full Inspect Capture page (initial paint).
#[derive(Template)]
#[template(path = "sessions/inspect/shell.html")]
pub struct InspectCaptureTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub perms: PermissionContext,
    pub view: InspectCaptureViewModel,
}

/// Packet list HTMX fragment.
#[derive(Template)]
#[template(path = "sessions/inspect/_packet_list.html")]
pub struct PacketListPartial {
    pub list: PacketListViewModel,
}

/// Packet detail HTMX fragment.
#[derive(Template)]
#[template(path = "sessions/inspect/_packet_detail.html")]
pub struct PacketDetailPartial {
    pub detail: PacketDetailViewModel,
}

/// Map an `industrial_protocol` enum value to a human label.
pub fn industrial_protocol_label(p: &str) -> &'static str {
    match p {
        "modbus" => "Modbus/TCP",
        "iec104" => "IEC 60870-5-104",
        "opcua" => "OPC-UA Binary",
        "profinet" => "PROFINET",
        "enip" => "EtherNet/IP",
        "bacnet_sc" => "BACnet/SC",
        "dnp3" => "DNP3",
        "iec61850" => "IEC 61850 MMS",
        "tcp" | "" => "Generic TCP",
        _ => "Generic TCP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn industrial_protocol_label_known_values() {
        assert_eq!(industrial_protocol_label("modbus"), "Modbus/TCP");
        assert_eq!(industrial_protocol_label("iec104"), "IEC 60870-5-104");
        assert_eq!(industrial_protocol_label("enip"), "EtherNet/IP");
        assert_eq!(industrial_protocol_label("bacnet_sc"), "BACnet/SC");
        assert_eq!(industrial_protocol_label("dnp3"), "DNP3");
        assert_eq!(industrial_protocol_label("iec61850"), "IEC 61850 MMS");
        assert_eq!(industrial_protocol_label("tcp"), "Generic TCP");
        assert_eq!(industrial_protocol_label(""), "Generic TCP");
        assert_eq!(industrial_protocol_label("garbage"), "Generic TCP");
    }

    #[test]
    fn packet_row_view_model_classifies_cmd_with_amber_classes() {
        let s = PacketSummary {
            frame_idx: 1,
            timestamp_us: 0,
            timestamp_human: "00:00:00.000000".into(),
            direction: Direction::EwsToAsset,
            kind: PacketKind::Cmd,
            summary: "FC06".into(),
            payload_len: 12,
            src_port: 49_152,
            dst_port: 502,
        };
        let row = PacketRowViewModel::from_summary(&s, "uuid", 1);
        assert!(row.kind_row_class.contains("amber"));
        assert_eq!(row.kind_glyph, "[CMD]");
        assert_eq!(row.direction_border_class, "border-l-4 border-amber-400");
    }

    #[test]
    fn packet_row_view_model_classifies_exception_with_rose_classes() {
        let s = PacketSummary {
            frame_idx: 2,
            timestamp_us: 0,
            timestamp_human: "00:00:00.001000".into(),
            direction: Direction::AssetToEws,
            kind: PacketKind::Exception,
            summary: "exception".into(),
            payload_len: 9,
            src_port: 502,
            dst_port: 49_152,
        };
        let row = PacketRowViewModel::from_summary(&s, "uuid", 1);
        assert!(row.kind_row_class.contains("rose"));
        assert_eq!(row.kind_glyph, "[EXC]");
        assert_eq!(row.direction_border_class, "border-l-4 border-emerald-400");
    }

    #[test]
    fn packet_detail_view_model_chunks_hex_into_16_byte_rows() {
        let detail = PacketDetail {
            summary: PacketSummary {
                frame_idx: 1,
                timestamp_us: 0,
                timestamp_human: "00:00:00.000000".into(),
                direction: Direction::EwsToAsset,
                kind: PacketKind::Cmd,
                summary: "FC06".into(),
                payload_len: 12,
                src_port: 49_152,
                dst_port: 502,
            },
            tree: Vec::new(),
            hex: vec![0u8; 33],
            byte_field_ids: vec![String::new(); 33],
        };
        let vm = PacketDetailViewModel::from_detail(detail, "uuid", 1);
        assert_eq!(vm.hex_rows.len(), 3);
        assert_eq!(vm.hex_rows[0].bytes.len(), 16);
        assert_eq!(vm.hex_rows[1].bytes.len(), 16);
        assert_eq!(vm.hex_rows[2].bytes.len(), 1);
    }
}
