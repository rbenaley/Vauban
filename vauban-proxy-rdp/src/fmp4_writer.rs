//! Fragmented MP4 writer used by the proxy-owned RDP recorder.

use std::io::{self, Write};

const TIMESCALE: u32 = 90_000;

pub fn parse_annex_b_nals(data: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut nals = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 2 < data.len() && data[i] == 0 && data[i + 1] == 0 {
            let start_code_len = if i + 3 < data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                Some(4)
            } else if data[i + 2] == 1 {
                Some(3)
            } else {
                None
            };
            if let Some(start_code_len) = start_code_len {
                let start = i + start_code_len;
                if start < data.len() {
                    let mut end = start + 1;
                    while end < data.len() {
                        if end + 2 < data.len()
                            && data[end] == 0
                            && data[end + 1] == 0
                            && (data[end + 2] == 1
                                || (end + 3 < data.len()
                                    && data[end + 2] == 0
                                    && data[end + 3] == 1))
                        {
                            break;
                        }
                        end += 1;
                    }
                    nals.push((data[start] & 0x1f, start, end));
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    nals
}

pub fn annex_b_to_avcc(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for (nal_type, start, end) in parse_annex_b_nals(data) {
        if nal_type == 7 || nal_type == 8 {
            continue;
        }
        let nal = &data[start..end];
        output.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        output.extend_from_slice(nal);
    }
    output
}

pub fn extract_sps_pps(data: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut sps = None;
    let mut pps = None;
    for (nal_type, start, end) in parse_annex_b_nals(data) {
        match nal_type {
            7 if sps.is_none() => sps = Some(data[start..end].to_vec()),
            8 if pps.is_none() => pps = Some(data[start..end].to_vec()),
            _ => {}
        }
    }
    (sps, pps)
}

pub fn codec_string_from_sps(sps: &[u8]) -> String {
    let profile = sps.get(1).copied().unwrap_or(66);
    let compatibility = sps.get(2).copied().unwrap_or(0xc0);
    let level = sps.get(3).copied().unwrap_or(30);
    format!("avc1.{profile:02x}{compatibility:02x}{level:02x}")
}

pub struct Sample {
    pub data: Vec<u8>,
    pub duration_ticks: u32,
    pub is_keyframe: bool,
}

pub struct Fmp4Writer<W: Write> {
    writer: W,
    sequence_number: u32,
    base_decode_time: u64,
    bytes_written: u64,
    init_size: u64,
}

impl<W: Write> Fmp4Writer<W> {
    pub fn new(mut writer: W, sps: &[u8], pps: &[u8], width: u16, height: u16) -> io::Result<Self> {
        let ftyp = build_ftyp();
        let moov = build_moov(sps, pps, width, height);
        writer.write_all(&ftyp)?;
        writer.write_all(&moov)?;
        writer.flush()?;
        let init_size = (ftyp.len() + moov.len()) as u64;
        Ok(Self {
            writer,
            sequence_number: 0,
            base_decode_time: 0,
            bytes_written: init_size,
            init_size,
        })
    }

    pub fn write_fragment(&mut self, samples: &[Sample]) -> io::Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        self.sequence_number = self.sequence_number.wrapping_add(1);
        let moof = build_moof(self.sequence_number, self.base_decode_time, samples);
        let mdat = build_mdat(samples);
        self.writer.write_all(&moof)?;
        self.writer.write_all(&mdat)?;
        self.writer.flush()?;
        self.bytes_written += (moof.len() + mdat.len()) as u64;
        self.base_decode_time += samples
            .iter()
            .map(|sample| u64::from(sample.duration_ticks))
            .sum::<u64>();
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn init_size(&self) -> u64 {
        self.init_size
    }

    pub fn duration_ticks(&self) -> u64 {
        self.base_decode_time
    }
}

impl Fmp4Writer<std::io::BufWriter<std::fs::File>> {
    pub fn sync(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()
    }
}

fn push_u16(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn mp4_box(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + content.len());
    push_u32(&mut output, (8 + content.len()) as u32);
    output.extend_from_slice(kind);
    output.extend_from_slice(content);
    output
}

fn full_box(kind: &[u8; 4], version: u8, flags: u32, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(12 + content.len());
    push_u32(&mut output, (12 + content.len()) as u32);
    output.extend_from_slice(kind);
    output.push(version);
    output.extend_from_slice(&flags.to_be_bytes()[1..]);
    output.extend_from_slice(content);
    output
}

fn build_ftyp() -> Vec<u8> {
    let mut content = b"isom".to_vec();
    push_u32(&mut content, 0x200);
    content.extend_from_slice(b"isomiso5iso6mp41");
    mp4_box(b"ftyp", &content)
}

fn build_moov(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut content = build_mvhd();
    content.extend_from_slice(&build_trak(sps, pps, width, height));
    content.extend_from_slice(&build_mvex());
    mp4_box(b"moov", &content)
}

fn build_mvhd() -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&[0; 8]);
    push_u32(&mut content, TIMESCALE);
    push_u32(&mut content, 0);
    push_u32(&mut content, 0x0001_0000);
    push_u16(&mut content, 0x0100);
    content.extend_from_slice(&[0; 10]);
    for value in [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
        push_u32(&mut content, value);
    }
    content.extend_from_slice(&[0; 24]);
    push_u32(&mut content, 2);
    full_box(b"mvhd", 0, 0, &content)
}

fn build_trak(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut content = build_tkhd(width, height);
    content.extend_from_slice(&build_mdia(sps, pps, width, height));
    mp4_box(b"trak", &content)
}

fn build_tkhd(width: u16, height: u16) -> Vec<u8> {
    let mut content = vec![0; 8];
    push_u32(&mut content, 1);
    content.extend_from_slice(&[0; 16]);
    content.extend_from_slice(&[0; 8]);
    for value in [0x0001_0000, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000] {
        push_u32(&mut content, value);
    }
    push_u32(&mut content, u32::from(width) << 16);
    push_u32(&mut content, u32::from(height) << 16);
    full_box(b"tkhd", 0, 3, &content)
}

fn build_mdia(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut mdhd = vec![0; 8];
    push_u32(&mut mdhd, TIMESCALE);
    push_u32(&mut mdhd, 0);
    push_u16(&mut mdhd, 0x55c4);
    push_u16(&mut mdhd, 0);
    let mut content = full_box(b"mdhd", 0, 0, &mdhd);
    let mut hdlr = vec![0; 4];
    hdlr.extend_from_slice(b"vide");
    hdlr.extend_from_slice(&[0; 12]);
    hdlr.extend_from_slice(b"Vauban Video\0");
    content.extend_from_slice(&full_box(b"hdlr", 0, 0, &hdlr));
    content.extend_from_slice(&build_minf(sps, pps, width, height));
    mp4_box(b"mdia", &content)
}

fn build_minf(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut content = full_box(b"vmhd", 0, 1, &[0; 8]);
    let url = full_box(b"url ", 0, 1, &[]);
    let mut dref = Vec::new();
    push_u32(&mut dref, 1);
    dref.extend_from_slice(&url);
    content.extend_from_slice(&mp4_box(b"dinf", &full_box(b"dref", 0, 0, &dref)));
    content.extend_from_slice(&build_stbl(sps, pps, width, height));
    mp4_box(b"minf", &content)
}

fn build_stbl(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let avc1 = build_avc1(sps, pps, width, height);
    let mut stsd = Vec::new();
    push_u32(&mut stsd, 1);
    stsd.extend_from_slice(&avc1);
    let mut content = full_box(b"stsd", 0, 0, &stsd);
    content.extend_from_slice(&full_box(b"stts", 0, 0, &[0; 4]));
    content.extend_from_slice(&full_box(b"stsc", 0, 0, &[0; 4]));
    content.extend_from_slice(&full_box(b"stsz", 0, 0, &[0; 8]));
    content.extend_from_slice(&full_box(b"stco", 0, 0, &[0; 4]));
    mp4_box(b"stbl", &content)
}

fn build_avc1(sps: &[u8], pps: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut content = vec![0; 6];
    push_u16(&mut content, 1);
    content.extend_from_slice(&[0; 16]);
    push_u16(&mut content, width);
    push_u16(&mut content, height);
    push_u32(&mut content, 0x0048_0000);
    push_u32(&mut content, 0x0048_0000);
    push_u32(&mut content, 0);
    push_u16(&mut content, 1);
    content.extend_from_slice(&[0; 32]);
    push_u16(&mut content, 24);
    push_u16(&mut content, 0xffff);
    content.extend_from_slice(&build_avcc(sps, pps));
    mp4_box(b"avc1", &content)
}

fn build_avcc(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut content = vec![
        1,
        sps.get(1).copied().unwrap_or(66),
        sps.get(2).copied().unwrap_or(0xc0),
        sps.get(3).copied().unwrap_or(30),
        0xff,
        0xe1,
    ];
    push_u16(&mut content, sps.len() as u16);
    content.extend_from_slice(sps);
    content.push(1);
    push_u16(&mut content, pps.len() as u16);
    content.extend_from_slice(pps);
    mp4_box(b"avcC", &content)
}

fn build_mvex() -> Vec<u8> {
    let mut trex = Vec::new();
    for value in [1, 1, 0, 0, 0] {
        push_u32(&mut trex, value);
    }
    mp4_box(b"mvex", &full_box(b"trex", 0, 0, &trex))
}

fn build_moof(sequence: u32, base_decode_time: u64, samples: &[Sample]) -> Vec<u8> {
    let mut mfhd = Vec::new();
    push_u32(&mut mfhd, sequence);
    let mfhd = full_box(b"mfhd", 0, 0, &mfhd);
    let mut tfhd = Vec::new();
    push_u32(&mut tfhd, 1);
    let tfhd = full_box(b"tfhd", 0, 0x02_0000, &tfhd);
    let mut tfdt = Vec::new();
    push_u64(&mut tfdt, base_decode_time);
    let tfdt = full_box(b"tfdt", 1, 0, &tfdt);
    let mut trun = Vec::new();
    push_u32(&mut trun, samples.len() as u32);
    push_u32(&mut trun, 0);
    for sample in samples {
        push_u32(&mut trun, sample.duration_ticks);
        push_u32(&mut trun, sample.data.len() as u32);
        push_u32(
            &mut trun,
            if sample.is_keyframe {
                0x0200_0000
            } else {
                0x0101_0000
            },
        );
    }
    let trun = full_box(b"trun", 0, 0x701, &trun);
    let mut traf_content = tfhd.clone();
    traf_content.extend_from_slice(&tfdt);
    traf_content.extend_from_slice(&trun);
    let mut traf = mp4_box(b"traf", &traf_content);
    let moof_size = 8 + mfhd.len() + traf.len();
    let data_offset = (moof_size + 8) as u32;
    let offset = 8 + tfhd.len() + tfdt.len() + 16;
    traf[offset..offset + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mut content = mfhd;
    content.extend_from_slice(&traf);
    mp4_box(b"moof", &content)
}

fn build_mdat(samples: &[Sample]) -> Vec<u8> {
    let mut content = Vec::new();
    for sample in samples {
        content.extend_from_slice(&sample.data);
    }
    mp4_box(b"mdat", &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_fragmented_mp4_prefix_and_fragment() {
        let mut bytes = Vec::new();
        let mut writer = Fmp4Writer::new(
            &mut bytes,
            &[0x67, 0x42, 0xc0, 0x1e],
            &[0x68, 0xce, 0x38, 0x80],
            1280,
            720,
        )
        .unwrap();
        writer
            .write_fragment(&[Sample {
                data: vec![0, 0, 0, 2, 0x65, 0x88],
                duration_ticks: 3000,
                is_keyframe: true,
            }])
            .unwrap();
        assert_eq!(&bytes[4..8], b"ftyp");
        assert!(bytes.windows(4).any(|window| window == b"moov"));
        assert!(bytes.windows(4).any(|window| window == b"moof"));
        assert!(bytes.windows(4).any(|window| window == b"mdat"));
    }
}
