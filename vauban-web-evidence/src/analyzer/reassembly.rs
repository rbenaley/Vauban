//! Bounded TCP payload reassembly for length-framed industrial protocols.
//!
//! Modbus/TCP, OPC-UA Binary, and IEC-60870-5-104 carry explicit length
//! fields that may span multiple TCP segments. This module buffers
//! per-direction byte streams and emits complete application PDUs for
//! dissection. PROFINET and passthrough profiles treat each TCP segment
//! as an atomic PDU unless a partial DCE header is detected.

use shared::iacs_protocol::ExpectedProfile;

pub const MAX_REASSEMBLY_BYTES: usize = 64 * 1024;
pub const MAX_SEGMENTS: usize = 64;

/// One reassembled application PDU ready for dissection.
#[derive(Debug, Clone)]
pub struct ReassembledPdu {
    pub data: Vec<u8>,
    /// When `false`, callers must not classify the payload as `Cmd`.
    pub complete: bool,
}

/// Per-direction TCP stream reassembler keyed by industrial profile.
#[derive(Debug)]
pub struct TcpReassembler {
    profile: ExpectedProfile,
    buffer: Vec<u8>,
    segment_count: usize,
}

impl TcpReassembler {
    pub fn new(profile: ExpectedProfile) -> Self {
        Self {
            profile,
            buffer: Vec::new(),
            segment_count: 0,
        }
    }

    /// Returns `true` when bytes are buffered awaiting a complete PDU.
    pub fn has_buffered(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Number of bytes currently buffered (test / invariant helper).
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Push a TCP payload segment. Returns zero or more complete (or
    /// overflow-flushed incomplete) application PDUs ready for dissection.
    pub fn push(&mut self, payload: &[u8]) -> Vec<ReassembledPdu> {
        if payload.is_empty() {
            return Vec::new();
        }

        match self.profile {
            ExpectedProfile::Passthrough => {
                vec![ReassembledPdu {
                    data: payload.to_vec(),
                    complete: true,
                }]
            }
            ExpectedProfile::Profinet => self.push_profinet(payload),
            ExpectedProfile::Modbus
            | ExpectedProfile::OpcUa
            | ExpectedProfile::Iec104
            | ExpectedProfile::Enip
            | ExpectedProfile::Dnp3
            | ExpectedProfile::Iec61850
            | ExpectedProfile::BacnetSc => self.push_length_framed(payload),
        }
    }

    /// Emit any bytes still buffered as an incomplete fragment.
    pub fn flush_fragment(&mut self) -> Option<ReassembledPdu> {
        if self.buffer.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.buffer);
        self.segment_count = 0;
        Some(ReassembledPdu {
            data,
            complete: false,
        })
    }

    fn push_profinet(&mut self, payload: &[u8]) -> Vec<ReassembledPdu> {
        // Partial DCE magic: buffer until header complete or overflow.
        if self.buffer.is_empty()
            && payload.len() < MIN_PROFINET_HEADER
            && payload.starts_with(&[0x05])
        {
            self.buffer.extend_from_slice(payload);
            self.segment_count = 1;
            if self.buffer.len() >= MIN_PROFINET_HEADER {
                let data = std::mem::take(&mut self.buffer);
                self.segment_count = 0;
                return vec![ReassembledPdu {
                    data,
                    complete: true,
                }];
            }
            return Vec::new();
        }

        if !self.buffer.is_empty() {
            return self.push_length_framed(payload);
        }

        vec![ReassembledPdu {
            data: payload.to_vec(),
            complete: true,
        }]
    }

    fn push_length_framed(&mut self, payload: &[u8]) -> Vec<ReassembledPdu> {
        self.buffer.extend_from_slice(payload);
        self.segment_count += 1;

        if self.buffer.len() > MAX_REASSEMBLY_BYTES || self.segment_count > MAX_SEGMENTS {
            let data = std::mem::take(&mut self.buffer);
            self.segment_count = 0;
            return vec![ReassembledPdu {
                data,
                complete: false,
            }];
        }

        let mut out = Vec::new();
        while let Some(pdu_len) = expected_pdu_len(&self.buffer, self.profile) {
            if self.buffer.len() < pdu_len {
                break;
            }
            let data = self.buffer.drain(..pdu_len).collect();
            self.segment_count = 0;
            out.push(ReassembledPdu {
                data,
                complete: true,
            });
        }
        out
    }
}

const MIN_PROFINET_HEADER: usize = 16;

/// Returns the total byte length of the next PDU when enough header
/// bytes are present.
fn expected_pdu_len(buf: &[u8], profile: ExpectedProfile) -> Option<usize> {
    match profile {
        ExpectedProfile::Modbus => {
            if buf.len() < 6 {
                return None;
            }
            let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            Some(6 + length)
        }
        ExpectedProfile::OpcUa => {
            if buf.len() < 8 {
                return None;
            }
            let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
            if size < 8 {
                return None;
            }
            Some(size)
        }
        ExpectedProfile::Iec104 => {
            if buf.len() < 2 || buf[0] != 0x68 {
                return None;
            }
            let length = buf[1] as usize;
            Some(2 + length)
        }
        ExpectedProfile::Profinet => {
            if buf.len() < MIN_PROFINET_HEADER || buf[0] != 0x05 || buf[1] != 0x00 {
                return None;
            }
            Some(buf.len())
        }
        ExpectedProfile::Enip => {
            if buf.len() < 24 {
                return None;
            }
            let length = u16::from_le_bytes([buf[2], buf[3]]) as usize;
            Some(24 + length)
        }
        ExpectedProfile::Dnp3 => dnp3_link_frame_len(buf),
        ExpectedProfile::Iec61850 => {
            if buf.len() < 4 || buf[0] != 0x03 || buf[1] != 0x00 {
                return None;
            }
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            if len < 4 {
                return None;
            }
            Some(len)
        }
        ExpectedProfile::BacnetSc => {
            // TLS record: type (1) + version (2) + length (2).
            if buf.len() < 5 || buf[0] != 0x16 {
                return None;
            }
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            Some(5 + len)
        }
        ExpectedProfile::Passthrough => Some(buf.len()),
    }
}

/// IEEE 1815 link-layer size from START + LENGTH.
/// LENGTH counts CONTROL+DEST+SRC+userdata (min 5), excluding CRCs.
/// Header CRC is 2 octets; userdata is CRC'd in 16-octet blocks.
fn dnp3_link_frame_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 3 || buf[0] != 0x05 || buf[1] != 0x64 {
        return None;
    }
    let length = buf[2] as usize;
    if length < 5 {
        return None;
    }
    let user = length - 5;
    let data_crcs = if user == 0 { 0 } else { user.div_ceil(16) * 2 };
    Some(10 + user + data_crcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_split_across_two_segments_yields_one_complete_pdu() {
        let pdu = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x05\x00\x2a";
        let mut reasm = TcpReassembler::new(ExpectedProfile::Modbus);

        let first = reasm.push(&pdu[..6]);
        assert!(first.is_empty());
        assert!(reasm.has_buffered());

        let second = reasm.push(&pdu[6..]);
        assert_eq!(second.len(), 1);
        assert!(second[0].complete);
        assert_eq!(second[0].data, pdu);
    }

    #[test]
    fn overflow_flushes_incomplete_fragment() {
        let mut reasm = TcpReassembler::new(ExpectedProfile::Modbus);
        let chunk = vec![0u8; MAX_REASSEMBLY_BYTES + 1];
        let out = reasm.push(&chunk);
        assert_eq!(out.len(), 1);
        assert!(!out[0].complete);
        assert!(reasm.buffer.is_empty());
    }

    #[test]
    fn passthrough_emits_each_segment_immediately() {
        let mut reasm = TcpReassembler::new(ExpectedProfile::Passthrough);
        let out = reasm.push(b"hello");
        assert_eq!(out.len(), 1);
        assert!(out[0].complete);
        assert_eq!(out[0].data, b"hello");
    }

    #[test]
    fn flush_fragment_returns_remaining_bytes() {
        let mut reasm = TcpReassembler::new(ExpectedProfile::Modbus);
        reasm.push(b"\x00\x01\x00\x00");
        let frag = reasm.flush_fragment().expect("fragment");
        assert!(!frag.complete);
        assert_eq!(frag.data.len(), 4);
    }

    #[test]
    fn opcua_length_framing_extracts_complete_message() {
        let mut msg = [0u8; 32];
        msg[..3].copy_from_slice(b"MSG");
        msg[4..8].copy_from_slice(&32u32.to_le_bytes());
        let mut reasm = TcpReassembler::new(ExpectedProfile::OpcUa);
        let a = reasm.push(&msg[..10]);
        assert!(a.is_empty());
        let b = reasm.push(&msg[10..]);
        assert_eq!(b.len(), 1);
        assert!(b[0].complete);
        assert_eq!(b[0].data.len(), 32);
    }

    #[test]
    fn dnp3_empty_userdata_frame_is_ten_bytes() {
        let frame = [0x05u8, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(dnp3_link_frame_len(&frame), Some(10));
        let mut reasm = TcpReassembler::new(ExpectedProfile::Dnp3);
        let out = reasm.push(&frame);
        assert_eq!(out.len(), 1);
        assert!(out[0].complete);
        assert_eq!(out[0].data.len(), 10);
    }

    #[test]
    fn enip_length_includes_24_byte_header() {
        let mut p = vec![0u8; 28];
        p[0..2].copy_from_slice(&0x0065u16.to_le_bytes());
        p[2..4].copy_from_slice(&4u16.to_le_bytes());
        let mut reasm = TcpReassembler::new(ExpectedProfile::Enip);
        let out = reasm.push(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data.len(), 28);
    }
}
