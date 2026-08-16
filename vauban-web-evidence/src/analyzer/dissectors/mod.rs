//! Protocol dissectors for the IACS Inspect Capture analyzer.
//!
//! Each dissector takes the application payload (post TCP), the
//! direction (EWS -> Asset / Asset -> EWS), and produces a
//! [`PacketKind`] classification + a tree of [`FieldNode`]s with
//! absolute byte offsets relative to the captured **frame**.
//!
//! TCP cross-segment reassembly is handled upstream in
//! [`crate::analyzer::reassembly`]; dissectors
//! always receive a complete application PDU when `complete == true`.
//! Incomplete fragments are routed through [`dissect_fragment`] so
//! they never classify as `Cmd`.

pub mod bacnet_sc;
pub mod dnp3;
pub mod enip;
pub mod iec104;
pub mod iec61850;
pub mod modbus;
pub mod opcua;
pub mod passthrough;
pub mod profinet;

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

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
        ExpectedProfile::OpcUa => opcua::dissect(payload, payload_offset, direction),
        ExpectedProfile::Profinet => profinet::dissect(payload, payload_offset, direction),
        ExpectedProfile::Enip => enip::dissect(payload, payload_offset, direction),
        ExpectedProfile::Dnp3 => dnp3::dissect(payload, payload_offset, direction),
        ExpectedProfile::Iec61850 => iec61850::dissect(payload, payload_offset, direction),
        ExpectedProfile::BacnetSc => bacnet_sc::dissect(payload, payload_offset, direction),
        ExpectedProfile::Passthrough => passthrough::dissect(payload, payload_offset, direction),
    }
}

/// Dissect an incomplete TCP reassembly fragment. Never returns `Cmd`.
pub fn dissect_fragment(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    let mut d = passthrough::dissect(payload, payload_offset, direction);
    if !d.summary.contains("(fragment)") {
        d.summary = format!("{} (fragment)", d.summary);
    }
    d.kind = PacketKind::Read;
    d
}

/// Re-export so handler/template code can pattern-match on it
/// without reaching into the inner module path.
pub use shared::iacs_protocol::ExpectedProfile as Profile;
