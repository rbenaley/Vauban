//! Proxy-owned segmented RDP recording writer.

use crate::fmp4_writer::{self, Fmp4Writer, Sample};
use shared::messages::RdpRecordingSegment;
use std::fs::File;
use std::io::{self, BufWriter};

const TIMESCALE: u32 = 90_000;
const US_PER_TICK: f64 = 1_000_000.0 / TIMESCALE as f64;

pub struct PendingSegment {
    pub relative_path: String,
}

struct PendingFrame {
    timestamp_us: u64,
    width: u16,
    height: u16,
    data: Vec<u8>,
}

pub struct RdpRecordingSeal {
    pub segments: Vec<RdpRecordingSegment>,
    pub meta_json_relative_path: String,
    pub total_frames: u64,
    pub total_bytes: u64,
}

pub struct RdpRecordingWriter {
    writer: Option<Fmp4Writer<BufWriter<File>>>,
    initial_file: Option<File>,
    base_dir: String,
    segment_index: u32,
    current_width: u16,
    current_height: u16,
    current_sps: Vec<u8>,
    segment_hasher: blake3::Hasher,
    fragment: Vec<Sample>,
    previous_timestamp_us: Option<u64>,
    pending_frame: Option<PendingFrame>,
    segments: Vec<RdpRecordingSegment>,
    total_frames: u64,
    dirty: bool,
}

impl RdpRecordingWriter {
    pub fn compute_base_dir(session_id: &str) -> String {
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86_400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    pub fn first_segment_path(session_id: &str) -> String {
        format!("{}/001.mp4", Self::compute_base_dir(session_id))
    }

    pub fn new(file: File, first_segment_path: String) -> Self {
        let base_dir = first_segment_path
            .rsplit_once('/')
            .map(|(directory, _)| directory.to_string())
            .unwrap_or_default();
        Self {
            writer: None,
            initial_file: Some(file),
            base_dir,
            segment_index: 1,
            current_width: 0,
            current_height: 0,
            current_sps: Vec::new(),
            segment_hasher: blake3::Hasher::new(),
            fragment: Vec::new(),
            previous_timestamp_us: None,
            pending_frame: None,
            segments: Vec::new(),
            total_frames: 0,
            dirty: false,
        }
    }

    pub fn handle_frame(
        &mut self,
        timestamp_us: u64,
        is_keyframe: bool,
        width: u16,
        height: u16,
        data: &[u8],
    ) -> io::Result<Option<PendingSegment>> {
        if self.pending_frame.is_some() {
            return Ok(None);
        }

        if self.writer.is_none() {
            if !is_keyframe {
                return Ok(None);
            }
            let file = self.initial_file.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "initial recording FD missing")
            })?;
            self.initialize_segment(file, data, width, height)?;
            self.append_frame(timestamp_us, true, data)?;
            return Ok(None);
        }

        if is_keyframe
            && self.current_width != 0
            && (width != self.current_width || height != self.current_height)
        {
            self.finalize_segment()?;
            self.segment_index = self.segment_index.saturating_add(1);
            let relative_path = format!("{}/{:03}.mp4", self.base_dir, self.segment_index);
            self.pending_frame = Some(PendingFrame {
                timestamp_us,
                width,
                height,
                data: data.to_vec(),
            });
            return Ok(Some(PendingSegment { relative_path }));
        }

        if !is_keyframe && (width != self.current_width || height != self.current_height) {
            return Ok(None);
        }

        self.segment_hasher.update(data);
        self.total_frames = self.total_frames.saturating_add(1);
        self.append_frame(timestamp_us, is_keyframe, data)?;
        Ok(None)
    }

    pub fn provide_segment_file(&mut self, file: File) -> io::Result<()> {
        let pending = self
            .pending_frame
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no pending RDP segment"))?;
        self.segment_hasher = blake3::Hasher::new();
        self.initialize_segment(file, &pending.data, pending.width, pending.height)?;
        self.append_frame(pending.timestamp_us, true, &pending.data)
    }

    pub fn sync_if_dirty(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(writer) = self.writer.as_mut() {
            writer.sync()?;
        }
        self.dirty = false;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<Option<RdpRecordingSeal>> {
        if self.writer.is_some() {
            self.finalize_segment()?;
        }
        if self.segments.is_empty() {
            return Ok(None);
        }
        let total_bytes = self.segments.iter().map(|segment| segment.file_size).sum();
        Ok(Some(RdpRecordingSeal {
            meta_json_relative_path: format!("{}/meta.json", self.base_dir),
            segments: self.segments,
            total_frames: self.total_frames,
            total_bytes,
        }))
    }

    fn initialize_segment(
        &mut self,
        file: File,
        keyframe: &[u8],
        width: u16,
        height: u16,
    ) -> io::Result<()> {
        let (sps, pps) = fmp4_writer::extract_sps_pps(keyframe);
        let sps = sps
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RDP keyframe has no SPS"))?;
        let pps = pps.unwrap_or_else(|| vec![0x68, 0xce, 0x38, 0x80]);
        let buffered = BufWriter::with_capacity(64 * 1024, file);
        self.writer = Some(Fmp4Writer::new(buffered, &sps, &pps, width, height)?);
        self.current_width = width;
        self.current_height = height;
        self.current_sps = sps;
        self.previous_timestamp_us = None;
        self.segment_hasher.update(keyframe);
        self.total_frames = self.total_frames.saturating_add(1);
        self.dirty = true;
        Ok(())
    }

    fn append_frame(
        &mut self,
        timestamp_us: u64,
        is_keyframe: bool,
        data: &[u8],
    ) -> io::Result<()> {
        let duration_us =
            timestamp_us.saturating_sub(self.previous_timestamp_us.unwrap_or(timestamp_us));
        let duration_ticks = if duration_us == 0 {
            3000
        } else {
            (duration_us as f64 / US_PER_TICK).round() as u32
        };
        self.previous_timestamp_us = Some(timestamp_us);
        let avcc = fmp4_writer::annex_b_to_avcc(data);
        if avcc.is_empty() {
            return Ok(());
        }
        if is_keyframe && !self.fragment.is_empty() {
            if let Some(writer) = self.writer.as_mut() {
                writer.write_fragment(&self.fragment)?;
            }
            self.fragment.clear();
            self.dirty = true;
        }
        self.fragment.push(Sample {
            data: avcc,
            duration_ticks,
            is_keyframe,
        });
        Ok(())
    }

    fn finalize_segment(&mut self) -> io::Result<()> {
        let Some(writer) = self.writer.as_mut() else {
            return Ok(());
        };
        if !self.fragment.is_empty() {
            writer.write_fragment(&self.fragment)?;
            self.fragment.clear();
        }
        writer.sync()?;
        self.segments.push(RdpRecordingSegment {
            index: self.segment_index,
            width: self.current_width,
            height: self.current_height,
            duration_ticks: writer.duration_ticks(),
            init_size: writer.init_size(),
            file_size: writer.bytes_written(),
            blake3_hex: self.segment_hasher.finalize().to_hex().to_string(),
            codec_string: fmp4_writer::codec_string_from_sps(&self.current_sps),
        });
        self.writer = None;
        self.dirty = false;
        Ok(())
    }
}

fn unix_days_to_year_month(days: u64) -> (u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (
        (if month <= 2 { year + 1 } else { year }) as u32,
        month as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyframe() -> Vec<u8> {
        vec![
            0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1e, 0xd9, 0, 0xa0, 0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80,
            0, 0, 0, 1, 0x65, 0x88, 0x80,
        ]
    }

    #[test]
    fn seals_local_segment_with_wire_metadata() {
        let path = std::env::temp_dir().join(format!(
            "vauban-rdp-recording-{}-{}.mp4",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let file = File::create(&path).unwrap();
        let mut writer = RdpRecordingWriter::new(file, "2026/07/session/001.mp4".to_string());
        writer
            .handle_frame(0, true, 1280, 720, &keyframe())
            .unwrap();
        let seal = writer.finish().unwrap().unwrap();
        assert_eq!(seal.segments.len(), 1);
        assert_eq!(seal.segments[0].width, 1280);
        assert_eq!(seal.meta_json_relative_path, "2026/07/session/meta.json");
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[4..8], b"ftyp");
        let _ = std::fs::remove_file(path);
    }
}
