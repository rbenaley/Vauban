//! Fragmented MP4 (fMP4) writer for a single H.264 Baseline track.
//!
//! Produces ISO BMFF files with the structure:
//!   ftyp | moov (mvhd, trak/tkhd/mdia/..., mvex/trex) | [moof + mdat]*
//!
//! Each fragment is flushed immediately for crash resilience: a truncated file
//! remains playable up to the last complete fragment.

use std::io::{self, Write};

const TIMESCALE: u32 = 90_000; // 90 kHz (standard for H.264 in MP4)

/// Parse H.264 Annex B NAL units, returning (nal_type, payload_start, payload_end) for each.
pub fn parse_annex_b_nals(data: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut nals = Vec::new();
    let mut i = 0;
    let len = data.len();

    while i < len {
        // Look for start code: 0x000001 or 0x00000001
        if i + 2 < len && data[i] == 0 && data[i + 1] == 0 {
            let (sc_len, found) = if i + 3 < len && data[i + 2] == 0 && data[i + 3] == 1 {
                (4, true)
            } else if data[i + 2] == 1 {
                (3, true)
            } else {
                (0, false)
            };

            if found {
                let nal_start = i + sc_len;
                if nal_start < len {
                    let nal_type = data[nal_start] & 0x1F;
                    // Find the end: next start code or EOF
                    let mut end = nal_start + 1;
                    while end < len {
                        if end + 2 < len
                            && data[end] == 0
                            && data[end + 1] == 0
                            && (data[end + 2] == 1
                                || (end + 3 < len && data[end + 2] == 0 && data[end + 3] == 1))
                        {
                            break;
                        }
                        end += 1;
                    }
                    nals.push((nal_type, nal_start, end));
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    nals
}

/// Convert Annex B NAL units to AVCC format (4-byte length prefix, big-endian).
/// Strips SPS (7) and PPS (8) NAL units (they go in avcC, not in samples).
pub fn annex_b_to_avcc(data: &[u8]) -> Vec<u8> {
    let nals = parse_annex_b_nals(data);
    let mut avcc = Vec::with_capacity(data.len());
    for (nal_type, start, end) in &nals {
        if *nal_type == 7 || *nal_type == 8 {
            continue; // SPS/PPS go in moov, not in mdat
        }
        let nal_data = &data[*start..*end];
        let len = nal_data.len() as u32;
        avcc.extend_from_slice(&len.to_be_bytes());
        avcc.extend_from_slice(nal_data);
    }
    avcc
}

/// Extract SPS and PPS NAL units from Annex B data.
pub fn extract_sps_pps(data: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let nals = parse_annex_b_nals(data);
    let mut sps = None;
    let mut pps = None;
    for (nal_type, start, end) in &nals {
        match nal_type {
            7 if sps.is_none() => sps = Some(data[*start..*end].to_vec()),
            8 if pps.is_none() => pps = Some(data[*start..*end].to_vec()),
            _ => {}
        }
    }
    (sps, pps)
}

/// A single sample (frame) in a fragment.
pub struct Sample {
    pub data: Vec<u8>,
    pub duration_ticks: u32,
    pub is_keyframe: bool,
}

/// Build the AVC codec string from SPS NAL unit bytes (e.g. `avc1.42c01e`).
///
/// The SPS must include the NAL header byte (0x67). Bytes 1-3 after the
/// header are profile_idc, constraint_flags, and level_idc.
pub fn codec_string_from_sps(sps: &[u8]) -> String {
    let profile_idc = if sps.len() > 1 { sps[1] } else { 66 };
    let profile_compat = if sps.len() > 2 { sps[2] } else { 0xC0 };
    let level_idc = if sps.len() > 3 { sps[3] } else { 30 };
    format!("avc1.{profile_idc:02x}{profile_compat:02x}{level_idc:02x}")
}

/// State for writing a fragmented MP4 file.
pub struct Fmp4Writer<W: Write> {
    writer: W,
    sequence_number: u32,
    base_decode_time: u64,
    track_id: u32,
    bytes_written: u64,
    init_size: u64,
}

impl<W: Write> Fmp4Writer<W> {
    /// Initialize the writer, writing `ftyp` and `moov` boxes.
    ///
    /// `sps` and `pps` are full NAL unit bytes including the NAL header byte
    /// (e.g. 0x67 for SPS, 0x68 for PPS), without Annex B start codes.
    /// `width` and `height` are the video dimensions.
    pub fn new(
        mut writer: W,
        sps: &[u8],
        pps: &[u8],
        width: u16,
        height: u16,
    ) -> io::Result<Self> {
        let ftyp = build_ftyp();
        let moov = build_moov(sps, pps, width, height);

        writer.write_all(&ftyp)?;
        writer.write_all(&moov)?;
        writer.flush()?;

        let bytes_written = (ftyp.len() + moov.len()) as u64;

        Ok(Self {
            writer,
            sequence_number: 0,
            base_decode_time: 0,
            track_id: 1,
            bytes_written,
            init_size: bytes_written,
        })
    }

    /// Write a fragment (one GOP: keyframe + following P-frames).
    pub fn write_fragment(&mut self, samples: &[Sample]) -> io::Result<()> {
        if samples.is_empty() {
            return Ok(());
        }

        self.sequence_number += 1;

        let moof = build_moof(
            self.sequence_number,
            self.track_id,
            self.base_decode_time,
            samples,
        );
        let mdat = build_mdat(samples);

        self.writer.write_all(&moof)?;
        self.writer.write_all(&mdat)?;
        self.writer.flush()?;

        self.bytes_written += (moof.len() + mdat.len()) as u64;

        let total_duration: u64 = samples.iter().map(|s| u64::from(s.duration_ticks)).sum();
        self.base_decode_time += total_duration;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Size of the initialization segment (ftyp + moov) in bytes.
    /// Used by DASH MPD generation to set the `Initialization range` attribute.
    pub fn init_size(&self) -> u64 {
        self.init_size
    }

    /// Total media duration in timescale ticks (90 kHz).
    pub fn duration_ticks(&self) -> u64 {
        self.base_decode_time
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

// ── Box builders ───────────────────────────────────────────────

fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Wrap content in an MP4 box with the given 4-char type.
fn mp4_box(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let size = 8 + content.len() as u32;
    let mut buf = Vec::with_capacity(size as usize);
    write_u32(&mut buf, size);
    buf.extend_from_slice(box_type);
    buf.extend_from_slice(content);
    buf
}

/// Wrap content in a fullbox (box + version + flags).
fn full_box(box_type: &[u8; 4], version: u8, flags: u32, content: &[u8]) -> Vec<u8> {
    let size = 12 + content.len() as u32;
    let mut buf = Vec::with_capacity(size as usize);
    write_u32(&mut buf, size);
    buf.extend_from_slice(box_type);
    write_u8(&mut buf, version);
    // flags: 3 bytes
    buf.push((flags >> 16) as u8);
    buf.push((flags >> 8) as u8);
    buf.push(flags as u8);
    buf.extend_from_slice(content);
    buf
}

fn build_ftyp() -> Vec<u8> {
    let mut content = Vec::with_capacity(16);
    content.extend_from_slice(b"isom"); // major brand
    write_u32(&mut content, 0x200); // minor version
    content.extend_from_slice(b"isom"); // compatible brands
    content.extend_from_slice(b"iso5");
    content.extend_from_slice(b"iso6");
    content.extend_from_slice(b"mp41");
    mp4_box(b"ftyp", &content)
}

fn build_moov(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mvhd = build_mvhd();
    let trak = build_trak(sps, pps, width, height);
    let mvex = build_mvex();

    let mut content = Vec::new();
    content.extend_from_slice(&mvhd);
    content.extend_from_slice(&trak);
    content.extend_from_slice(&mvex);
    mp4_box(b"moov", &content)
}

fn build_mvhd() -> Vec<u8> {
    let mut content = Vec::with_capacity(96);
    write_u32(&mut content, 0); // creation_time
    write_u32(&mut content, 0); // modification_time
    write_u32(&mut content, TIMESCALE); // timescale
    write_u32(&mut content, 0); // duration (unknown for fragmented)
    write_u32(&mut content, 0x0001_0000); // rate (1.0 fixed-point)
    write_u16(&mut content, 0x0100); // volume (1.0 fixed-point)
    content.extend_from_slice(&[0u8; 10]); // reserved
    // Matrix (identity: 3x3 fixed-point)
    write_u32(&mut content, 0x0001_0000);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0x0001_0000);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0x4000_0000);
    content.extend_from_slice(&[0u8; 24]); // pre-defined
    write_u32(&mut content, 2); // next_track_ID
    full_box(b"mvhd", 0, 0, &content)
}

fn build_trak(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let tkhd = build_tkhd(width, height);
    let mdia = build_mdia(sps, pps, width, height);

    let mut content = Vec::new();
    content.extend_from_slice(&tkhd);
    content.extend_from_slice(&mdia);
    mp4_box(b"trak", &content)
}

fn build_tkhd(width: u16, height: u16) -> Vec<u8> {
    // flags = 3 (track_enabled | track_in_movie)
    let mut content = Vec::with_capacity(80);
    write_u32(&mut content, 0); // creation_time
    write_u32(&mut content, 0); // modification_time
    write_u32(&mut content, 1); // track_ID
    write_u32(&mut content, 0); // reserved
    write_u32(&mut content, 0); // duration
    content.extend_from_slice(&[0u8; 8]); // reserved
    write_u16(&mut content, 0); // layer
    write_u16(&mut content, 0); // alternate_group
    write_u16(&mut content, 0); // volume (0 for video)
    write_u16(&mut content, 0); // reserved
    // Matrix (identity)
    write_u32(&mut content, 0x0001_0000);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0x0001_0000);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0);
    write_u32(&mut content, 0x4000_0000);
    // Width and height in 16.16 fixed point
    write_u32(&mut content, u32::from(width) << 16);
    write_u32(&mut content, u32::from(height) << 16);
    full_box(b"tkhd", 0, 3, &content)
}

fn build_mdia(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mdhd = build_mdhd();
    let hdlr = build_hdlr();
    let minf = build_minf(sps, pps, width, height);

    let mut content = Vec::new();
    content.extend_from_slice(&mdhd);
    content.extend_from_slice(&hdlr);
    content.extend_from_slice(&minf);
    mp4_box(b"mdia", &content)
}

fn build_mdhd() -> Vec<u8> {
    let mut content = Vec::with_capacity(20);
    write_u32(&mut content, 0); // creation_time
    write_u32(&mut content, 0); // modification_time
    write_u32(&mut content, TIMESCALE); // timescale
    write_u32(&mut content, 0); // duration (unknown)
    write_u16(&mut content, 0x55C4); // language (und)
    write_u16(&mut content, 0); // pre-defined
    full_box(b"mdhd", 0, 0, &content)
}

fn build_hdlr() -> Vec<u8> {
    let mut content = Vec::with_capacity(33);
    write_u32(&mut content, 0); // pre-defined
    content.extend_from_slice(b"vide"); // handler_type
    content.extend_from_slice(&[0u8; 12]); // reserved
    content.extend_from_slice(b"Vauban Video\0"); // name
    full_box(b"hdlr", 0, 0, &content)
}

fn build_minf(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let vmhd = build_vmhd();
    let dinf = build_dinf();
    let stbl = build_stbl(sps, pps, width, height);

    let mut content = Vec::new();
    content.extend_from_slice(&vmhd);
    content.extend_from_slice(&dinf);
    content.extend_from_slice(&stbl);
    mp4_box(b"minf", &content)
}

fn build_vmhd() -> Vec<u8> {
    let mut content = Vec::with_capacity(8);
    write_u16(&mut content, 0); // graphicsmode
    content.extend_from_slice(&[0u8; 6]); // opcolor
    full_box(b"vmhd", 0, 1, &content)
}

fn build_dinf() -> Vec<u8> {
    // dref with a single self-contained data reference
    let mut dref_content = Vec::with_capacity(4);
    write_u32(&mut dref_content, 1); // entry_count
    let url = full_box(b"url ", 0, 1, &[]); // flags=1 means self-contained
    dref_content.extend_from_slice(&url);
    let dref = full_box(b"dref", 0, 0, &dref_content);
    mp4_box(b"dinf", &dref)
}

fn build_stbl(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let stsd = build_stsd(sps, pps, width, height);
    let stts = full_box(b"stts", 0, 0, &[0, 0, 0, 0]); // empty (fragmented)
    let stsc = full_box(b"stsc", 0, 0, &[0, 0, 0, 0]); // empty
    let stsz = {
        let mut c = Vec::with_capacity(8);
        write_u32(&mut c, 0); // sample_size
        write_u32(&mut c, 0); // sample_count
        full_box(b"stsz", 0, 0, &c)
    };
    let stco = full_box(b"stco", 0, 0, &[0, 0, 0, 0]); // empty

    let mut content = Vec::new();
    content.extend_from_slice(&stsd);
    content.extend_from_slice(&stts);
    content.extend_from_slice(&stsc);
    content.extend_from_slice(&stsz);
    content.extend_from_slice(&stco);
    mp4_box(b"stbl", &content)
}

fn build_stsd(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let avc1 = build_avc1(sps, pps, width, height);
    let mut content = Vec::with_capacity(4 + avc1.len());
    write_u32(&mut content, 1); // entry_count
    content.extend_from_slice(&avc1);
    full_box(b"stsd", 0, 0, &content)
}

fn build_avc1(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let avcc = build_avcc(sps, pps);
    let mut content = Vec::with_capacity(78 + avcc.len());
    content.extend_from_slice(&[0u8; 6]); // reserved
    write_u16(&mut content, 1); // data_reference_index
    content.extend_from_slice(&[0u8; 16]); // pre-defined + reserved
    write_u16(&mut content, width);
    write_u16(&mut content, height);
    write_u32(&mut content, 0x0048_0000); // horizresolution (72 dpi)
    write_u32(&mut content, 0x0048_0000); // vertresolution
    write_u32(&mut content, 0); // reserved
    write_u16(&mut content, 1); // frame_count
    content.extend_from_slice(&[0u8; 32]); // compressorname
    write_u16(&mut content, 0x0018); // depth (24-bit)
    write_u16(&mut content, 0xFFFF); // pre_defined = -1 (int16 per ISO 14496-12 §12.1.3)
    content.extend_from_slice(&avcc);
    mp4_box(b"avc1", &content)
}

fn build_avcc(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    // SPS is a full NAL unit: [nal_header, profile_idc, profile_compat, level_idc, ...]
    let profile_idc = if sps.len() > 1 { sps[1] } else { 66 }; // Baseline
    let profile_compat = if sps.len() > 2 { sps[2] } else { 0xC0 };
    let level_idc = if sps.len() > 3 { sps[3] } else { 30 };

    let mut content = Vec::with_capacity(11 + sps.len() + pps.len());
    write_u8(&mut content, 1); // configurationVersion
    write_u8(&mut content, profile_idc);
    write_u8(&mut content, profile_compat);
    write_u8(&mut content, level_idc);
    write_u8(&mut content, 0xFF); // lengthSizeMinusOne = 3 (4-byte lengths)
    write_u8(&mut content, 0xE1); // numOfSequenceParameterSets = 1
    write_u16(&mut content, sps.len() as u16);
    content.extend_from_slice(sps);
    write_u8(&mut content, 1); // numOfPictureParameterSets
    write_u16(&mut content, pps.len() as u16);
    content.extend_from_slice(pps);
    mp4_box(b"avcC", &content)
}

fn build_mvex() -> Vec<u8> {
    let mut trex_content = Vec::with_capacity(20);
    write_u32(&mut trex_content, 1); // track_ID
    write_u32(&mut trex_content, 1); // default_sample_description_index
    write_u32(&mut trex_content, 0); // default_sample_duration
    write_u32(&mut trex_content, 0); // default_sample_size
    write_u32(&mut trex_content, 0); // default_sample_flags
    let trex = full_box(b"trex", 0, 0, &trex_content);
    mp4_box(b"mvex", &trex)
}

fn build_moof(
    sequence_number: u32,
    track_id: u32,
    base_decode_time: u64,
    samples: &[Sample],
) -> Vec<u8> {
    let mfhd = build_mfhd(sequence_number);

    // Build traf contents: tfhd + tfdt + trun (with placeholder data_offset)
    let mut tfhd_content = Vec::with_capacity(4);
    write_u32(&mut tfhd_content, track_id);
    let tfhd = full_box(b"tfhd", 0, 0x02_0000, &tfhd_content);

    let mut tfdt_content = Vec::with_capacity(8);
    write_u64(&mut tfdt_content, base_decode_time);
    let tfdt = full_box(b"tfdt", 1, 0, &tfdt_content);

    let trun_flags: u32 = 0x001 | 0x100 | 0x200 | 0x400;
    let mut trun_content = Vec::with_capacity(4 + 4 + samples.len() * 12);
    write_u32(&mut trun_content, samples.len() as u32);
    write_i32(&mut trun_content, 0); // data_offset placeholder

    for sample in samples {
        write_u32(&mut trun_content, sample.duration_ticks);
        write_u32(&mut trun_content, sample.data.len() as u32);
        let flags: u32 = if sample.is_keyframe {
            0x0200_0000
        } else {
            0x0101_0000
        };
        write_u32(&mut trun_content, flags);
    }
    let trun = full_box(b"trun", 0, trun_flags, &trun_content);

    let mut traf_inner = Vec::new();
    traf_inner.extend_from_slice(&tfhd);
    traf_inner.extend_from_slice(&tfdt);
    traf_inner.extend_from_slice(&trun);
    let traf = mp4_box(b"traf", &traf_inner);

    // Compute moof size to patch data_offset
    let moof_size = 8u32 + mfhd.len() as u32 + traf.len() as u32;
    let data_offset = moof_size as i32 + 8; // +8 for mdat header

    // Patch data_offset in the trun within the traf bytes.
    // trun starts at: 8 (traf header) + tfhd.len() + tfdt.len()
    // data_offset field is at byte 16 within the trun fullbox
    let trun_offset_in_traf = 8 + tfhd.len() + tfdt.len();
    let data_offset_pos = trun_offset_in_traf + 16;

    let mut patched_traf = traf;
    patched_traf[data_offset_pos..data_offset_pos + 4]
        .copy_from_slice(&data_offset.to_be_bytes());

    let mut content = Vec::new();
    content.extend_from_slice(&mfhd);
    content.extend_from_slice(&patched_traf);
    mp4_box(b"moof", &content)
}

fn build_mfhd(sequence_number: u32) -> Vec<u8> {
    let mut content = Vec::with_capacity(4);
    write_u32(&mut content, sequence_number);
    full_box(b"mfhd", 0, 0, &content)
}

fn build_mdat(samples: &[Sample]) -> Vec<u8> {
    let total_data: usize = samples.iter().map(|s| s.data.len()).sum();
    let mut buf = Vec::with_capacity(8 + total_data);
    write_u32(&mut buf, (8 + total_data) as u32);
    buf.extend_from_slice(b"mdat");
    for sample in samples {
        buf.extend_from_slice(&sample.data);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_box(data: &[u8], box_type: &[u8; 4]) -> Option<(usize, usize)> {
        let mut offset = 0;
        while offset + 8 <= data.len() {
            let size =
                u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
                    as usize;
            if size < 8 || offset + size > data.len() {
                break;
            }
            if &data[offset + 4..offset + 8] == box_type {
                return Some((offset, size));
            }
            offset += size;
        }
        None
    }

    fn find_box_nested(data: &[u8], path: &[&[u8; 4]]) -> Option<(usize, usize)> {
        let mut offset = 0;
        let mut len = data.len();
        let mut abs_offset = 0;
        for (i, box_type) in path.iter().enumerate() {
            let found = find_box(&data[offset..offset + len], box_type)?;
            abs_offset = offset + found.0;
            if i < path.len() - 1 {
                let header_size = if &data[abs_offset + 4..abs_offset + 8] == b"moof"
                    || &data[abs_offset + 4..abs_offset + 8] == b"moov"
                    || &data[abs_offset + 4..abs_offset + 8] == b"trak"
                    || &data[abs_offset + 4..abs_offset + 8] == b"mdia"
                    || &data[abs_offset + 4..abs_offset + 8] == b"minf"
                    || &data[abs_offset + 4..abs_offset + 8] == b"stbl"
                    || &data[abs_offset + 4..abs_offset + 8] == b"dinf"
                    || &data[abs_offset + 4..abs_offset + 8] == b"mvex"
                    || &data[abs_offset + 4..abs_offset + 8] == b"traf"
                {
                    8 // container box
                } else {
                    12 // fullbox
                };
                offset = abs_offset + header_size;
                len = found.1 - header_size;
            }
        }
        Some((abs_offset, path.last().map(|_| {
            u32::from_be_bytes([
                data[abs_offset],
                data[abs_offset + 1],
                data[abs_offset + 2],
                data[abs_offset + 3],
            ]) as usize
        }).unwrap_or(0)))
    }

    // Minimal SPS for H.264 Baseline Level 3.0, 1920x1080
    fn test_sps() -> Vec<u8> {
        vec![0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0x88]
    }

    fn test_pps() -> Vec<u8> {
        vec![0x68, 0xCE, 0x38, 0x80]
    }

    #[test]
    fn test_parse_annex_b_nals_4byte_start_code() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E];
        let nals = parse_annex_b_nals(&data);
        assert_eq!(nals.len(), 1);
        assert_eq!(nals[0].0, 7); // SPS
        assert_eq!(&data[nals[0].1..nals[0].2], &[0x67, 0x42, 0xC0, 0x1E]);
    }

    #[test]
    fn test_parse_annex_b_nals_3byte_start_code() {
        let data = [0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80];
        let nals = parse_annex_b_nals(&data);
        assert_eq!(nals.len(), 1);
        assert_eq!(nals[0].0, 8); // PPS
    }

    #[test]
    fn test_parse_annex_b_multiple_nals() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // start code
        data.extend_from_slice(&[0x67, 0x42, 0xC0, 0x1E]); // SPS
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // start code
        data.extend_from_slice(&[0x68, 0xCE, 0x38, 0x80]); // PPS
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // start code
        data.extend_from_slice(&[0x65, 0x88, 0x80]); // IDR slice

        let nals = parse_annex_b_nals(&data);
        assert_eq!(nals.len(), 3);
        assert_eq!(nals[0].0, 7); // SPS
        assert_eq!(nals[1].0, 8); // PPS
        assert_eq!(nals[2].0, 5); // IDR
    }

    #[test]
    fn test_extract_sps_pps() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x80]);

        let (sps, pps) = extract_sps_pps(&data);
        assert!(sps.is_some());
        assert!(pps.is_some());
        assert_eq!(sps.unwrap()[0] & 0x1F, 7);
        assert_eq!(pps.unwrap()[0] & 0x1F, 8);
    }

    #[test]
    fn test_annex_b_to_avcc_strips_sps_pps() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x80]);

        let avcc = annex_b_to_avcc(&data);
        // Only the IDR slice should remain, with a 4-byte length prefix
        assert_eq!(avcc.len(), 4 + 3); // 4 bytes length + 3 bytes IDR data
        let nal_len = u32::from_be_bytes([avcc[0], avcc[1], avcc[2], avcc[3]]);
        assert_eq!(nal_len, 3);
        assert_eq!(avcc[4] & 0x1F, 5); // IDR
    }

    #[test]
    fn test_ftyp_structure() {
        let ftyp = build_ftyp();
        assert_eq!(&ftyp[4..8], b"ftyp");
        assert_eq!(&ftyp[8..12], b"isom");
    }

    #[test]
    fn test_fmp4_writer_creates_valid_header() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();
        let writer = Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
        drop(writer);

        assert!(output.len() > 16);
        // ftyp at the start
        assert_eq!(&output[4..8], b"ftyp");
        // moov after ftyp
        let ftyp_size = u32::from_be_bytes([output[0], output[1], output[2], output[3]]) as usize;
        assert_eq!(&output[ftyp_size + 4..ftyp_size + 8], b"moov");
    }

    #[test]
    fn test_fmp4_writer_single_fragment() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

            let samples = vec![Sample {
                data: vec![0x00, 0x00, 0x00, 0x05, 0x65, 0x88, 0x80, 0x40, 0x00],
                duration_ticks: 3000,
                is_keyframe: true,
            }];
            writer.write_fragment(&samples).unwrap();
        }

        // Should have ftyp + moov + moof + mdat
        assert!(find_box(&output, b"ftyp").is_some());
        assert!(find_box(&output, b"moov").is_some());
        assert!(find_box(&output, b"moof").is_some());
        assert!(find_box(&output, b"mdat").is_some());
    }

    #[test]
    fn test_fmp4_writer_multiple_fragments() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

            for i in 0..3 {
                let samples = vec![
                    Sample {
                        data: vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80],
                        duration_ticks: 3000,
                        is_keyframe: i == 0,
                    },
                    Sample {
                        data: vec![0x00, 0x00, 0x00, 0x02, 0x41, 0x9A],
                        duration_ticks: 3000,
                        is_keyframe: false,
                    },
                ];
                writer.write_fragment(&samples).unwrap();
            }
        }

        // Count moof boxes
        let mut count = 0;
        let mut offset = 0;
        while offset + 8 <= output.len() {
            let size = u32::from_be_bytes([
                output[offset],
                output[offset + 1],
                output[offset + 2],
                output[offset + 3],
            ]) as usize;
            if size < 8 || offset + size > output.len() {
                break;
            }
            if &output[offset + 4..offset + 8] == b"moof" {
                count += 1;
            }
            offset += size;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_fmp4_writer_bytes_written() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();

        let mut writer =
            Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
        let header_bytes = writer.bytes_written();
        assert!(header_bytes > 0);

        let samples = vec![Sample {
            data: vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80],
            duration_ticks: 3000,
            is_keyframe: true,
        }];
        writer.write_fragment(&samples).unwrap();
        assert!(writer.bytes_written() > header_bytes);
        assert_eq!(writer.bytes_written(), output.len() as u64);
    }

    #[test]
    fn test_avcc_box_structure() {
        let sps = test_sps();
        let pps = test_pps();
        let avcc = build_avcc(&sps, &pps);
        assert_eq!(&avcc[4..8], b"avcC");
        // version
        assert_eq!(avcc[8], 1);
        // profile_idc (byte after NAL header in SPS)
        assert_eq!(avcc[9], sps[1]); // 0x42 = Baseline
        // SPS NAL data in avcC must start with NAL header byte 0x67
        let sps_len_offset = 14; // after version + profile + compat + level + flags + numSPS
        let sps_len = u16::from_be_bytes([avcc[sps_len_offset], avcc[sps_len_offset + 1]]);
        assert_eq!(sps_len as usize, sps.len());
        assert_eq!(avcc[sps_len_offset + 2], 0x67); // SPS NAL header byte present
    }

    #[test]
    fn test_avc1_visual_sample_entry_layout() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();
        let _ = Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

        let avc1_pos = output.windows(4).position(|w| w == b"avc1").unwrap();
        let avc1_start = avc1_pos - 4;
        let avc1_size =
            u32::from_be_bytes([output[avc1_start], output[avc1_start+1], output[avc1_start+2], output[avc1_start+3]]) as usize;
        let content = &output[avc1_start + 8..avc1_start + avc1_size];

        // VisualSampleEntry fixed fields: 6+2+16+2+2+4+4+4+2+32+2+2 = 78 bytes
        assert!(content.len() >= 78, "avc1 content must be at least 78 bytes");

        // pre_defined at offset 76 must be exactly 2 bytes (0xFFFF), NOT 4
        assert_eq!(content[76], 0xFF);
        assert_eq!(content[77], 0xFF);

        // Child box (avcC) must start at offset 78
        let child_size = u32::from_be_bytes([content[78], content[79], content[80], content[81]]) as usize;
        assert_eq!(&content[82..86], b"avcC", "avcC must be the first child box at offset 78");
        assert!(child_size > 8 && child_size < avc1_size, "avcC size must be reasonable");
    }

    #[test]
    fn test_moov_contains_required_boxes() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();
        let _ = Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

        let moov = find_box(&output, b"moov");
        assert!(moov.is_some(), "moov box must exist");

        // Check nested structure
        assert!(find_box_nested(&output, &[b"moov", b"mvhd"]).is_some(), "mvhd must exist");
        assert!(find_box_nested(&output, &[b"moov", b"trak"]).is_some(), "trak must exist");
        assert!(find_box_nested(&output, &[b"moov", b"mvex"]).is_some(), "mvex must exist");
    }

    #[test]
    fn test_empty_fragment_is_noop() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();
        let mut writer =
            Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
        let before = writer.bytes_written();
        writer.write_fragment(&[]).unwrap();
        assert_eq!(writer.bytes_written(), before);
    }

    #[test]
    fn test_mdat_contains_sample_data() {
        let sps = test_sps();
        let pps = test_pps();
        let sample_data = vec![0x00, 0x00, 0x00, 0x05, 0x65, 0x88, 0x80, 0x40, 0x00];
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
            writer
                .write_fragment(&[Sample {
                    data: sample_data.clone(),
                    duration_ticks: 3000,
                    is_keyframe: true,
                }])
                .unwrap();
        }

        let (mdat_offset, mdat_size) = find_box(&output, b"mdat").unwrap();
        let mdat_payload = &output[mdat_offset + 8..mdat_offset + mdat_size];
        assert_eq!(mdat_payload, &sample_data);
    }

    #[test]
    fn test_data_offset_points_to_mdat_payload() {
        let sps = test_sps();
        let pps = test_pps();
        let sample_data = vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80];
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
            writer
                .write_fragment(&[Sample {
                    data: sample_data.clone(),
                    duration_ticks: 3000,
                    is_keyframe: true,
                }])
                .unwrap();
        }

        let (moof_offset, moof_size) = find_box(&output, b"moof").unwrap();
        let (mdat_offset, _) = find_box(&output, b"mdat").unwrap();
        // data_offset in trun is relative to moof start and should point to mdat payload (mdat_offset + 8)
        let expected_data_offset = (mdat_offset + 8 - moof_offset) as i32;
        // data_offset = moof_size + 8 (mdat header)
        assert_eq!(expected_data_offset, moof_size as i32 + 8);
    }

    #[test]
    fn test_truncated_file_has_valid_prefix() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();
            for _ in 0..5 {
                writer
                    .write_fragment(&[
                        Sample {
                            data: vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80],
                            duration_ticks: 3000,
                            is_keyframe: true,
                        },
                        Sample {
                            data: vec![0x00, 0x00, 0x00, 0x02, 0x41, 0x9A],
                            duration_ticks: 3000,
                            is_keyframe: false,
                        },
                    ])
                    .unwrap();
            }
        }

        // Simulate crash: truncate after the 3rd fragment pair (moof+mdat)
        // Walk through boxes to find the end of the 3rd mdat
        let mut offset = 0;
        let mut mdat_count = 0;
        let mut truncation_point = 0;
        while offset + 8 <= output.len() {
            let size = u32::from_be_bytes([
                output[offset],
                output[offset + 1],
                output[offset + 2],
                output[offset + 3],
            ]) as usize;
            if size < 8 || offset + size > output.len() {
                break;
            }
            if &output[offset + 4..offset + 8] == b"mdat" {
                mdat_count += 1;
                if mdat_count == 3 {
                    truncation_point = offset + size;
                    break;
                }
            }
            offset += size;
        }
        assert!(truncation_point > 0);

        let truncated = &output[..truncation_point];
        // Truncated file should still have valid ftyp, moov, and 3 moof+mdat pairs
        assert!(find_box(truncated, b"ftyp").is_some());
        assert!(find_box(truncated, b"moov").is_some());

        let mut moof_count = 0;
        let mut off = 0;
        while off + 8 <= truncated.len() {
            let sz = u32::from_be_bytes([
                truncated[off],
                truncated[off + 1],
                truncated[off + 2],
                truncated[off + 3],
            ]) as usize;
            if sz < 8 || off + sz > truncated.len() {
                break;
            }
            if &truncated[off + 4..off + 8] == b"moof" {
                moof_count += 1;
            }
            off += sz;
        }
        assert_eq!(moof_count, 3);
    }

    #[test]
    fn test_sequential_fragment_base_decode_time() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();

        {
            let mut writer =
                Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

            writer
                .write_fragment(&[Sample {
                    data: vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80],
                    duration_ticks: 3000,
                    is_keyframe: true,
                }])
                .unwrap();

            writer
                .write_fragment(&[Sample {
                    data: vec![0x00, 0x00, 0x00, 0x03, 0x65, 0x88, 0x80],
                    duration_ticks: 3000,
                    is_keyframe: true,
                }])
                .unwrap();
        }

        // Find both moof boxes and check tfdt base_decode_time
        let mut moof_offsets = Vec::new();
        let mut off = 0;
        while off + 8 <= output.len() {
            let sz = u32::from_be_bytes([
                output[off],
                output[off + 1],
                output[off + 2],
                output[off + 3],
            ]) as usize;
            if sz < 8 || off + sz > output.len() {
                break;
            }
            if &output[off + 4..off + 8] == b"moof" {
                moof_offsets.push(off);
            }
            off += sz;
        }
        assert_eq!(moof_offsets.len(), 2);
    }

    #[test]
    fn test_annex_b_to_avcc_preserves_idr_and_non_idr() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E]); // SPS
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80]); // PPS
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x80]);       // IDR
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x9A]);                   // non-IDR (3-byte start code)

        let avcc = annex_b_to_avcc(&data);
        // Should have two NAL units: IDR (3 bytes) + non-IDR (2 bytes)
        assert_eq!(avcc.len(), 4 + 3 + 4 + 2); // two 4-byte length prefixes + data
        let idr_len = u32::from_be_bytes([avcc[0], avcc[1], avcc[2], avcc[3]]);
        assert_eq!(idr_len, 3);
        assert_eq!(avcc[4] & 0x1F, 5); // IDR
        let non_idr_len = u32::from_be_bytes([avcc[7], avcc[8], avcc[9], avcc[10]]);
        assert_eq!(non_idr_len, 2);
        assert_eq!(avcc[11] & 0x1F, 1); // non-IDR slice
    }

    #[test]
    fn test_parse_annex_b_empty_data() {
        let nals = parse_annex_b_nals(&[]);
        assert!(nals.is_empty());
    }

    #[test]
    fn test_extract_sps_pps_no_sps() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0x01];
        let (sps, pps) = extract_sps_pps(&data);
        assert!(sps.is_none());
        assert!(pps.is_none());
    }

    #[test]
    fn test_init_size_matches_ftyp_moov() {
        let sps = test_sps();
        let pps = test_pps();
        let mut output = Vec::new();
        let writer = Fmp4Writer::new(&mut output, &sps, &pps, 1920, 1080).unwrap();

        let init_size = writer.init_size();
        assert!(init_size > 0);
        assert_eq!(init_size, writer.bytes_written());

        // ftyp starts at 0, moov follows; init_size should cover both
        let ftyp_size = u32::from_be_bytes([output[0], output[1], output[2], output[3]]) as u64;
        let moov_offset = ftyp_size as usize;
        let moov_size = u32::from_be_bytes([
            output[moov_offset],
            output[moov_offset + 1],
            output[moov_offset + 2],
            output[moov_offset + 3],
        ]) as u64;
        assert_eq!(init_size, ftyp_size + moov_size);
    }

    #[test]
    fn test_codec_string_baseline() {
        // SPS: NAL header 0x67, profile_idc=0x42 (Baseline), compat=0xC0, level=0x1E (3.0)
        let sps = vec![0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0];
        assert_eq!(codec_string_from_sps(&sps), "avc1.42c01e");
    }

    #[test]
    fn test_codec_string_extraction() {
        // High profile, level 4.0
        let sps_high = vec![0x67, 0x64, 0x00, 0x28];
        assert_eq!(codec_string_from_sps(&sps_high), "avc1.640028");

        // Main profile, level 3.1
        let sps_main = vec![0x67, 0x4D, 0x40, 0x1F];
        assert_eq!(codec_string_from_sps(&sps_main), "avc1.4d401f");

        // Short SPS (fallback values)
        let sps_short: Vec<u8> = vec![0x67];
        assert_eq!(codec_string_from_sps(&sps_short), "avc1.42c01e");
    }
}
