//! Protocol dissectors for the IACS Inspect Capture analyzer.
//!
//! Each dissector takes the application payload (post TCP), the
//! direction (EWS -> Asset / Asset -> EWS), and produces a
//! [`PacketKind`] classification + a tree of [`FieldNode`]s with
//! absolute byte offsets relative to the captured **frame**.
//!
//! Dissectors operate on a single segment: TCP cross-segment
//! reassembly is explicitly out of scope (see plan section 2).
//! Industrial protocols are mono-segment in 99%+ of recordings;
//! the rare fragmented PDU is rendered with a "(fragment)" hint
//! in the summary.

pub mod iec104;
pub mod modbus;
pub mod passthrough;

use crate::services::iacs_packet_analyzer::types::{Direction, FieldNode, PacketKind};

use shared::iacs_protocol::ExpectedProfile;

/// Output of one dissector pass.
pub struct Dissection {
    pub kind: PacketKind,
    /// One-line summary surfaced in the packet list row
    /// (e.g. `FC03 Read Holding Registers @0 x10`).
    pub summary: String,
    /// Tree of field nodes with `offset`/`len` absolute to the
    /// captured frame.
    pub tree: Vec<FieldNode>,
}

/// Dispatch dissection to the appropriate per-protocol module.
///
/// `payload_offset` is where the TCP payload starts inside the
/// captured frame; it is added to every offset returned by the
/// per-protocol dissector so the tree<->hex contract is
/// frame-relative end-to-end.
pub fn dissect(
    payload: &[u8],
    payload_offset: usize,
    direction: Direction,
    profile: ExpectedProfile,
) -> Dissection {
    if payload.is_empty() {
        return Dissection {
            kind: PacketKind::Tcp,
            summary: String::new(),
            tree: Vec::new(),
        };
    }
    match profile {
        ExpectedProfile::Modbus => modbus::dissect(payload, payload_offset, direction),
        ExpectedProfile::Iec104 => iec104::dissect(payload, payload_offset, direction),
        // OPC-UA Binary and PROFINET dissectors land in v1 (post-MVP).
        // Until then we render them through the raw TCP fallback so
        // the timeline + hex view is still usable.
        ExpectedProfile::OpcUa | ExpectedProfile::Profinet | ExpectedProfile::Passthrough => {
            passthrough::dissect(payload, payload_offset, direction)
        }
    }
}

/// Re-export so handler/template code can pattern-match on it
/// without reaching into the inner module path.
pub use shared::iacs_protocol::ExpectedProfile as Profile;
