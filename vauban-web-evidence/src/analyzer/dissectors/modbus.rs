//! Modbus/TCP dissector (MVP scope).
//!
//! Wire format:
//!
//! ```text
//! +------- MBAP header (7 bytes) -------+--- PDU ---+
//! | tx_id (u16 BE) | proto_id (u16 BE)  |  fc (u8)  | data ...
//! | length (u16 BE) | unit_id (u8)      |
//! +-------------------------------------+-----------+
//! ```
//!
//! Function code semantics:
//!
//! | FC | Name                       | PacketKind |
//! |----|----------------------------|------------|
//! | 01 | Read Coils                 | Read       |
//! | 02 | Read Discrete Inputs       | Read       |
//! | 03 | Read Holding Registers     | Read       |
//! | 04 | Read Input Registers       | Read       |
//! | 05 | Write Single Coil          | Cmd        |
//! | 06 | Write Single Register      | Cmd        |
//! | 07 | Read Exception Status      | Read       |
//! | 15 | Write Multiple Coils       | Cmd        |
//! | 16 | Write Multiple Registers   | Cmd        |
//! | 22 | Mask Write Register        | Cmd        |
//! | 23 | R/W Multiple Registers     | Cmd        |
//! | FC | 0x80 -> Exception              | Exception |
//!
//! The dissector is request-shaped: response framing differs (the
//! fields after `fc` are byte-count + payload instead of address +
//! qty), and we surface the byte-count + first-byte preview to keep
//! the tree useful for both legs.

use crate::analyzer::types::{Direction, FieldNode, PacketKind};

use super::Dissection;

const MBAP_LEN: usize = 7;

pub fn dissect(payload: &[u8], payload_offset: usize, direction: Direction) -> Dissection {
    if payload.len() < MBAP_LEN + 1 {
        return super::passthrough::dissect(payload, payload_offset, direction);
    }
    let tx_id = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]);
    let unit_id = payload[6];
    let raw_fc = payload[7];

    let is_exception = (raw_fc & 0x80) != 0;
    let fc = raw_fc & 0x7F;

    let kind = if is_exception {
        PacketKind::Exception
    } else if matches!(fc, 0x05 | 0x06 | 0x0F | 0x10 | 0x16 | 0x17) {
        PacketKind::Cmd
    } else {
        PacketKind::Read
    };

    let mut children = Vec::new();
    children.push(FieldNode::leaf(
        "Transaction ID",
        format!("0x{:04x}", tx_id),
        "modbus.tx_id",
        payload_offset,
        2,
    ));
    children.push(FieldNode::leaf(
        "Protocol ID",
        format!("0x{:04x}", proto_id),
        "modbus.proto_id",
        payload_offset + 2,
        2,
    ));
    children.push(FieldNode::leaf(
        "Length",
        format!("{} bytes", length),
        "modbus.length",
        payload_offset + 4,
        2,
    ));
    children.push(FieldNode::leaf(
        "Unit ID",
        format!("{}", unit_id),
        "modbus.unit_id",
        payload_offset + 6,
        1,
    ));
    children.push(FieldNode::leaf(
        "Function Code",
        format!("0x{:02x} ({})", raw_fc, fc_label(raw_fc)),
        "modbus.function",
        payload_offset + 7,
        1,
    ));

    let summary = if is_exception {
        let exc_code = payload.get(8).copied().unwrap_or(0);
        children.push(FieldNode::leaf(
            "Exception Code",
            format!("0x{:02x} ({})", exc_code, exception_label(exc_code)),
            "modbus.exception",
            payload_offset + 8,
            1,
        ));
        format!(
            "{} Exception FC{:02} -> {}",
            direction.arrow(),
            fc,
            exception_label(exc_code)
        )
    } else {
        match fc {
            0x01..=0x04 => match direction {
                Direction::EwsToAsset => {
                    render_read_request(&mut children, payload, payload_offset, fc)
                }
                Direction::AssetToEws => {
                    render_read_response(&mut children, payload, payload_offset, fc)
                }
            },
            0x05 | 0x06 => {
                render_write_single(&mut children, payload, payload_offset, fc, direction)
            }
            0x0F | 0x10 => {
                render_write_multiple(&mut children, payload, payload_offset, fc, direction)
            }
            _ => format!("{} FC{:02x} {}", direction.arrow(), fc, fc_label(raw_fc)),
        }
    };

    let mbap = FieldNode::parent(
        "MBAP Header",
        "modbus.mbap",
        payload_offset,
        MBAP_LEN,
        children.drain(..4).collect(),
    );
    let pdu = FieldNode::parent(
        "PDU",
        "modbus.pdu",
        payload_offset + MBAP_LEN,
        payload.len() - MBAP_LEN,
        children,
    );

    Dissection {
        kind,
        summary,
        tree: vec![mbap, pdu],
    }
}

fn render_read_request(
    children: &mut Vec<FieldNode>,
    payload: &[u8],
    offset: usize,
    fc: u8,
) -> String {
    if payload.len() < MBAP_LEN + 5 {
        return format!("FC{:02x} Read (truncated)", fc);
    }
    let address = u16::from_be_bytes([payload[8], payload[9]]);
    let quantity = u16::from_be_bytes([payload[10], payload[11]]);
    children.push(FieldNode::leaf(
        "Reference Address",
        format!("0x{:04x} ({})", address, address),
        "modbus.address",
        offset + 8,
        2,
    ));
    children.push(FieldNode::leaf(
        "Quantity",
        format!("{}", quantity),
        "modbus.quantity",
        offset + 10,
        2,
    ));
    format!(
        "EWS -> Asset  FC{:02} {}  @{}  x{}",
        fc,
        fc_short(fc),
        address,
        quantity
    )
}

fn render_read_response(
    children: &mut Vec<FieldNode>,
    payload: &[u8],
    offset: usize,
    fc: u8,
) -> String {
    if payload.len() < MBAP_LEN + 2 {
        return format!("FC{:02x} Read response (truncated)", fc);
    }
    let byte_count = payload[8];
    children.push(FieldNode::leaf(
        "Byte Count",
        format!("{}", byte_count),
        "modbus.byte_count",
        offset + 8,
        1,
    ));
    let data_start = MBAP_LEN + 2;
    if payload.len() > data_start {
        let preview_end = std::cmp::min(payload.len(), data_start + byte_count as usize);
        children.push(FieldNode::leaf(
            "Data",
            hex_preview(&payload[data_start..preview_end]),
            "modbus.data",
            offset + data_start,
            preview_end - data_start,
        ));
    }
    format!(
        "Asset -> EWS  FC{:02} {} response  ({} bytes)",
        fc,
        fc_short(fc),
        byte_count
    )
}

fn render_write_single(
    children: &mut Vec<FieldNode>,
    payload: &[u8],
    offset: usize,
    fc: u8,
    direction: Direction,
) -> String {
    if payload.len() < MBAP_LEN + 5 {
        return format!("FC{:02x} Write (truncated)", fc);
    }
    let address = u16::from_be_bytes([payload[8], payload[9]]);
    let value = u16::from_be_bytes([payload[10], payload[11]]);
    children.push(FieldNode::leaf(
        "Reference Address",
        format!("0x{:04x} ({})", address, address),
        "modbus.address",
        offset + 8,
        2,
    ));
    children.push(FieldNode::leaf(
        "Value",
        format!("0x{:04x} ({})", value, value),
        "modbus.value",
        offset + 10,
        2,
    ));
    format!(
        "{}  FC{:02} {}  @{}  = 0x{:04x}",
        direction.arrow(),
        fc,
        fc_short(fc),
        address,
        value
    )
}

fn render_write_multiple(
    children: &mut Vec<FieldNode>,
    payload: &[u8],
    offset: usize,
    fc: u8,
    direction: Direction,
) -> String {
    if payload.len() < MBAP_LEN + 6 {
        return format!("FC{:02x} Write multiple (truncated)", fc);
    }
    let address = u16::from_be_bytes([payload[8], payload[9]]);
    let quantity = u16::from_be_bytes([payload[10], payload[11]]);
    let byte_count = payload[12];
    children.push(FieldNode::leaf(
        "Reference Address",
        format!("0x{:04x} ({})", address, address),
        "modbus.address",
        offset + 8,
        2,
    ));
    children.push(FieldNode::leaf(
        "Quantity",
        format!("{}", quantity),
        "modbus.quantity",
        offset + 10,
        2,
    ));
    children.push(FieldNode::leaf(
        "Byte Count",
        format!("{}", byte_count),
        "modbus.byte_count",
        offset + 12,
        1,
    ));
    let data_start = MBAP_LEN + 6;
    if payload.len() > data_start {
        let preview_end = std::cmp::min(payload.len(), data_start + byte_count as usize);
        children.push(FieldNode::leaf(
            "Data",
            hex_preview(&payload[data_start..preview_end]),
            "modbus.data",
            offset + data_start,
            preview_end - data_start,
        ));
    }
    format!(
        "{}  FC{:02} {}  @{}  x{}  ({} bytes)",
        direction.arrow(),
        fc,
        fc_short(fc),
        address,
        quantity,
        byte_count
    )
}

fn fc_label(raw: u8) -> &'static str {
    if (raw & 0x80) != 0 {
        return "Exception";
    }
    match raw & 0x7F {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding Registers",
        0x04 => "Read Input Registers",
        0x05 => "Write Single Coil",
        0x06 => "Write Single Register",
        0x07 => "Read Exception Status",
        0x0F => "Write Multiple Coils",
        0x10 => "Write Multiple Registers",
        0x14 => "Read File Record",
        0x15 => "Write File Record",
        0x16 => "Mask Write Register",
        0x17 => "Read/Write Multiple Registers",
        0x18 => "Read FIFO Queue",
        _ => "Unknown",
    }
}

fn fc_short(fc: u8) -> &'static str {
    match fc {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding",
        0x04 => "Read Input",
        0x05 => "Write Coil",
        0x06 => "Write Register",
        0x0F => "Write Coils",
        0x10 => "Write Registers",
        _ => "",
    }
}

fn exception_label(code: u8) -> &'static str {
    match code {
        0x01 => "Illegal Function",
        0x02 => "Illegal Data Address",
        0x03 => "Illegal Data Value",
        0x04 => "Slave Device Failure",
        0x05 => "Acknowledge",
        0x06 => "Slave Device Busy",
        0x08 => "Memory Parity Error",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Failed to Respond",
        _ => "Unknown",
    }
}

fn hex_preview(buf: &[u8]) -> String {
    let cap = std::cmp::min(buf.len(), 32);
    let mut s = String::with_capacity(cap * 3);
    for (i, b) in buf[..cap].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02x}", b));
    }
    if buf.len() > cap {
        s.push_str(" ...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fc03_read_holding_registers_classifies_as_read() {
        let p = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
        assert!(d.summary.contains("FC03"));
    }

    #[test]
    fn fc06_write_single_register_classifies_as_cmd() {
        let p = b"\x00\x02\x00\x00\x00\x06\x01\x06\x00\x05\x00\x2a";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
        assert!(d.summary.contains("FC06"));
    }

    #[test]
    fn fc16_write_multiple_registers_classifies_as_cmd() {
        let p = b"\x00\x03\x00\x00\x00\x09\x01\x10\x00\x10\x00\x01\x02\x00\xff";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn exception_response_classifies_as_exception() {
        let p = b"\x00\x04\x00\x00\x00\x03\x01\x83\x02";
        let d = dissect(p, 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Exception);
        assert!(d.summary.contains("Exception"));
    }

    #[test]
    fn truncated_payload_falls_back_to_passthrough() {
        let p = b"\x00\x01"; // shorter than MBAP
        let d = dissect(p, 40, Direction::EwsToAsset);
        // Passthrough never returns Cmd.
        assert_ne!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn fc03_field_offsets_are_frame_relative() {
        let p = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a";
        let d = dissect(p, 40, Direction::EwsToAsset);
        // Walk the tree to find modbus.function.
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
        let func = find(&d.tree, "modbus.function").expect("function");
        // payload_offset 40 + MBAP offset 7 = 47 for the FC byte.
        assert_eq!(func.offset, 47);
        assert_eq!(func.len, 1);
    }

    #[test]
    fn fc05_write_single_coil_classifies_as_cmd() {
        let p = b"\x00\x05\x00\x00\x00\x06\x01\x05\x00\x00\xff\x00";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Cmd);
    }

    #[test]
    fn fc01_read_coils_classifies_as_read() {
        let p = b"\x00\x06\x00\x00\x00\x06\x01\x01\x00\x00\x00\x10";
        let d = dissect(p, 40, Direction::EwsToAsset);
        assert_eq!(d.kind, PacketKind::Read);
    }

    #[test]
    fn read_response_extracts_byte_count() {
        // FC03 response: byte_count=4, two registers
        let p = b"\x00\x01\x00\x00\x00\x07\x01\x03\x04\x00\x0a\x00\x14";
        let d = dissect(p, 40, Direction::AssetToEws);
        assert_eq!(d.kind, PacketKind::Read);
        assert!(d.summary.contains("response"));
    }
}
