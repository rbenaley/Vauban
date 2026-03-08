//! Manages active RDP recording sessions with segmentation support.
//!
//! Receives `RdpRecordingStart`, `RdpVideoFrame`, and `RdpRecordingEnd` messages
//! from the proxy-rdp IPC channel, and writes fragmented MP4 files with BLAKE3
//! integrity hashing.
//!
//! When the desktop resolution changes mid-session (e.g. windowed -> fullscreen),
//! the current segment is finalized and a new segment is started at the new
//! resolution. Each segment is a self-contained fMP4 file with its own `moov`.
//!
//! File creation is delegated to the caller (typically the supervisor via
//! SCM_RIGHTS). This module only receives pre-opened `File` handles, following
//! the principle of least privilege in Capsicum sandbox mode.

use crate::fmp4_writer::{self, Fmp4Writer, Sample};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter};
use tracing::{debug, error, info, warn};

const TIMESCALE: u32 = 90_000;

/// Microseconds per tick at 90 kHz timescale.
const US_PER_TICK: f64 = 1_000_000.0 / TIMESCALE as f64;

/// Metadata for a finalized recording segment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SegmentInfo {
    pub index: u32,
    pub width: u16,
    pub height: u16,
    pub duration_ticks: u64,
    pub init_size: u64,
    pub file_size: u64,
    pub blake3_hex: String,
    pub codec_string: String,
}

/// Result of processing a frame.
pub enum FrameResult {
    /// Frame was processed normally.
    Processed,
    /// A resolution change was detected. The caller must request a new file
    /// from the supervisor at the given `relative_path`, then call
    /// `provide_segment_file()` to continue recording.
    NewSegmentNeeded { relative_path: String },
}

/// Buffered keyframe data waiting for a new segment file.
struct PendingFrame {
    timestamp_us: u64,
    width: u16,
    height: u16,
    data: Vec<u8>,
}

/// State for a single active recording.
struct ActiveRecording {
    /// Pre-opened file, consumed when the first keyframe arrives.
    file: Option<File>,
    /// Created from `file` on the first keyframe (needs SPS/PPS for moov box).
    writer: Option<Fmp4Writer<BufWriter<File>>>,
    /// Per-segment BLAKE3 hasher (reset on each new segment).
    segment_hasher: blake3::Hasher,
    current_fragment: Vec<Sample>,
    prev_timestamp_us: Option<u64>,
    /// Base directory for this session (e.g. "2026/03/uuid").
    base_dir: String,
    /// Current segment index (1-based).
    segment_index: u32,
    /// Current segment dimensions.
    current_width: u16,
    current_height: u16,
    /// Current segment's SPS (needed for codec_string at finalization).
    current_sps: Vec<u8>,
    /// Finalized segments metadata.
    segments: Vec<SegmentInfo>,
    /// Buffered keyframe from a resolution change, waiting for a new file.
    pending_keyframe: Option<PendingFrame>,
    frame_count: u64,
    total_fragment_count: u64,
}

/// Result returned by `end_session` so the caller can write `meta.json`.
#[allow(dead_code)]
pub struct EndSessionResult {
    pub segments: Vec<SegmentInfo>,
    pub meta_json_relative_path: String,
    pub total_frames: u64,
    pub total_bytes: u64,
}

/// Manages all active recording sessions.
///
/// Does not perform any file I/O itself: it receives pre-opened `File` handles
/// from the caller (opened by the supervisor via SCM_RIGHTS in production).
pub struct RecordingManager {
    recordings: HashMap<String, ActiveRecording>,
}

impl RecordingManager {
    pub fn new() -> Self {
        Self {
            recordings: HashMap::new(),
        }
    }

    /// Start recording a new session with a pre-opened file for the first segment.
    ///
    /// The fMP4 header (ftyp + moov) is written lazily when the first keyframe
    /// arrives, since SPS/PPS are needed and only present in keyframes.
    pub fn start_session(&mut self, session_id: &str, file: File, relative_path: String) {
        if self.recordings.contains_key(session_id) {
            warn!(session_id, "Recording already active, ignoring duplicate start");
            return;
        }

        let base_dir = relative_path
            .strip_suffix(".mp4")
            .and_then(|s| s.rsplit_once('/'))
            .map(|(dir, _file)| dir.to_string())
            .unwrap_or_else(|| {
                relative_path
                    .rsplit_once('/')
                    .map(|(dir, _)| dir.to_string())
                    .unwrap_or_default()
            });

        info!(session_id, path = %relative_path, "Recording session started (pending first keyframe)");

        self.recordings.insert(session_id.to_string(), ActiveRecording {
            file: Some(file),
            writer: None,
            segment_hasher: blake3::Hasher::new(),
            current_fragment: Vec::new(),
            prev_timestamp_us: None,
            base_dir,
            segment_index: 1,
            current_width: 0,
            current_height: 0,
            current_sps: Vec::new(),
            segments: Vec::new(),
            pending_keyframe: None,
            frame_count: 0,
            total_fragment_count: 0,
        });
    }

    /// Compute the base directory for a session (e.g. "2026/03/uuid").
    pub fn compute_base_dir(session_id: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() / 86400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    /// Compute the relative recording path for the first segment.
    pub fn compute_relative_path(session_id: &str) -> String {
        let base = Self::compute_base_dir(session_id);
        format!("{base}/001.mp4")
    }

    /// Process an H.264 video frame.
    ///
    /// Returns `FrameResult::NewSegmentNeeded` when a resolution change is
    /// detected, signaling the caller to request a new file from the supervisor
    /// and then call `provide_segment_file()`.
    pub fn handle_frame(
        &mut self,
        session_id: &str,
        timestamp_us: u64,
        is_keyframe: bool,
        width: u16,
        height: u16,
        data: &[u8],
    ) -> FrameResult {
        let Some(rec) = self.recordings.get_mut(session_id) else {
            debug!(session_id, "Frame for unknown recording session, ignoring");
            return FrameResult::Processed;
        };

        // If we're waiting for a new segment file, drop frames
        if rec.pending_keyframe.is_some() {
            debug!(session_id, "Dropping frame while waiting for new segment file");
            return FrameResult::Processed;
        }

        // Initialize writer on first keyframe using the pre-opened file
        if rec.writer.is_none() {
            if !is_keyframe {
                debug!(session_id, "Waiting for first keyframe, skipping P-frame");
                return FrameResult::Processed;
            }

            let Some(file) = rec.file.take() else {
                error!(session_id, "No pre-opened file available for recording");
                return FrameResult::Processed;
            };

            rec.segment_hasher.update(data);
            rec.frame_count += 1;

            if !init_writer(rec, session_id, file, data, width, height) {
                return FrameResult::Processed;
            }

            append_frame(rec, session_id, timestamp_us, is_keyframe, data);
            return FrameResult::Processed;
        }

        // Detect resolution change on keyframe -> trigger segment split
        // (before hashing, since this frame belongs to the next segment)
        if is_keyframe
            && rec.current_width != 0
            && (width != rec.current_width || height != rec.current_height)
        {
            info!(
                session_id,
                old_w = rec.current_width, old_h = rec.current_height,
                new_w = width, new_h = height,
                "Resolution change detected, splitting segment"
            );

            finalize_current_segment(rec, session_id);

            rec.segment_index += 1;
            let relative_path = format!(
                "{}/{:03}.mp4",
                rec.base_dir, rec.segment_index
            );

            rec.pending_keyframe = Some(PendingFrame {
                timestamp_us,
                width,
                height,
                data: data.to_vec(),
            });

            return FrameResult::NewSegmentNeeded { relative_path };
        }

        // Drop P-frames with mismatched dimensions (defensive)
        if !is_keyframe && rec.current_width != 0
            && (width != rec.current_width || height != rec.current_height)
        {
            debug!(
                session_id,
                frame_w = width, frame_h = height,
                seg_w = rec.current_width, seg_h = rec.current_height,
                "Dropping P-frame with mismatched dimensions"
            );
            return FrameResult::Processed;
        }

        rec.segment_hasher.update(data);
        rec.frame_count += 1;

        append_frame(rec, session_id, timestamp_us, is_keyframe, data);
        FrameResult::Processed
    }

    /// Provide a new pre-opened file for the next segment after a resolution change.
    ///
    /// Must be called after `handle_frame` returns `FrameResult::NewSegmentNeeded`.
    pub fn provide_segment_file(&mut self, session_id: &str, file: File) {
        let Some(rec) = self.recordings.get_mut(session_id) else {
            warn!(session_id, "provide_segment_file for unknown session");
            return;
        };

        let Some(pending) = rec.pending_keyframe.take() else {
            warn!(session_id, "provide_segment_file called without pending keyframe");
            return;
        };

        rec.segment_hasher = blake3::Hasher::new();
        rec.segment_hasher.update(&pending.data);

        if !init_writer(rec, session_id, file, &pending.data, pending.width, pending.height) {
            return;
        }

        append_frame(
            rec,
            session_id,
            pending.timestamp_us,
            true,
            &pending.data,
        );
    }

    /// End a recording session. Flushes the last fragment and returns metadata.
    ///
    /// The caller is responsible for writing `meta.json` (by requesting a file
    /// from the supervisor and serializing the returned `EndSessionResult`).
    pub fn end_session(&mut self, session_id: &str) -> Option<EndSessionResult> {
        let Some(mut rec) = self.recordings.remove(session_id) else {
            debug!(session_id, "End for unknown recording session, ignoring");
            return None;
        };

        if rec.writer.is_none() && rec.segments.is_empty() {
            info!(session_id, "Recording ended before any keyframe was received");
            return None;
        }

        // Finalize the current (last) segment if a writer is active
        if rec.writer.is_some() {
            finalize_current_segment(&mut rec, session_id);
        }

        let total_bytes: u64 = rec.segments.iter().map(|s| s.init_size).sum();
        let meta_json_relative_path = format!("{}/meta.json", rec.base_dir);

        info!(
            session_id,
            segments = rec.segments.len(),
            total_frames = rec.frame_count,
            "Recording session finalized"
        );

        Some(EndSessionResult {
            segments: rec.segments,
            meta_json_relative_path,
            total_frames: rec.frame_count,
            total_bytes,
        })
    }

    /// Serialize segment metadata to JSON for writing to `meta.json`.
    pub fn serialize_meta_json(segments: &[SegmentInfo]) -> String {
        #[derive(serde::Serialize)]
        struct Meta<'a> {
            segments: &'a [SegmentInfo],
        }
        serde_json::to_string_pretty(&Meta { segments }).unwrap_or_else(|_| "{}".to_string())
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.recordings.len()
    }
}

/// Initialize the Fmp4Writer from a keyframe's SPS/PPS.
fn init_writer(
    rec: &mut ActiveRecording,
    session_id: &str,
    file: File,
    data: &[u8],
    width: u16,
    height: u16,
) -> bool {
    let (sps, pps) = fmp4_writer::extract_sps_pps(data);
    let Some(sps) = sps else {
        warn!(session_id, "Keyframe missing SPS, cannot initialize segment");
        return false;
    };
    let pps = pps.unwrap_or_else(|| {
        warn!(session_id, "Keyframe missing PPS, using minimal default");
        vec![0x68, 0xCE, 0x38, 0x80]
    });

    let buf_writer = BufWriter::with_capacity(64 * 1024, file);
    match Fmp4Writer::new(buf_writer, &sps, &pps, width, height) {
        Ok(writer) => {
            rec.writer = Some(writer);
            rec.current_width = width;
            rec.current_height = height;
            rec.current_sps = sps;
            info!(
                session_id, width, height,
                segment = rec.segment_index,
                "fMP4 writer initialized for segment"
            );
            true
        }
        Err(e) => {
            error!(session_id, error = %e, "Failed to initialize fMP4 writer");
            false
        }
    }
}

/// Append a frame to the current segment.
fn append_frame(
    rec: &mut ActiveRecording,
    session_id: &str,
    timestamp_us: u64,
    is_keyframe: bool,
    data: &[u8],
) {
    let duration_us = timestamp_us.saturating_sub(rec.prev_timestamp_us.unwrap_or(timestamp_us));
    let duration_ticks = if duration_us == 0 {
        3000
    } else {
        (duration_us as f64 / US_PER_TICK).round() as u32
    };
    rec.prev_timestamp_us = Some(timestamp_us);

    let avcc_data = fmp4_writer::annex_b_to_avcc(data);
    if avcc_data.is_empty() {
        return;
    }

    if is_keyframe && !rec.current_fragment.is_empty() {
        if let Some(ref mut writer) = rec.writer
            && let Err(e) = writer.write_fragment(&rec.current_fragment)
        {
            error!(session_id, error = %e, "Failed to write fragment");
            return;
        }
        rec.total_fragment_count += 1;
        rec.current_fragment.clear();
    }

    rec.current_fragment.push(Sample {
        data: avcc_data,
        duration_ticks,
        is_keyframe,
    });
}

/// Finalize the current segment: flush remaining samples, record SegmentInfo.
fn finalize_current_segment(rec: &mut ActiveRecording, session_id: &str) {
    let Some(ref mut writer) = rec.writer else {
        return;
    };

    if !rec.current_fragment.is_empty() {
        if let Err(e) = writer.write_fragment(&rec.current_fragment) {
            error!(session_id, error = %e, "Failed to write final fragment for segment");
        }
        rec.total_fragment_count += 1;
        rec.current_fragment.clear();
    }

    let hash = rec.segment_hasher.finalize();

    let info = SegmentInfo {
        index: rec.segment_index,
        width: rec.current_width,
        height: rec.current_height,
        duration_ticks: writer.duration_ticks(),
        init_size: writer.init_size(),
        file_size: writer.bytes_written(),
        blake3_hex: hash.to_hex().to_string(),
        codec_string: fmp4_writer::codec_string_from_sps(&rec.current_sps),
    };

    info!(
        session_id,
        segment = info.index,
        width = info.width, height = info.height,
        duration_ticks = info.duration_ticks,
        blake3 = %info.blake3_hex,
        "Segment finalized"
    );

    rec.segments.push(info);
    rec.writer = None;
}

/// Convert Unix days (since 1970-01-01) to (year, month).
fn unix_days_to_year_month(days: u64) -> (u32, u32) {
    // Civil calendar algorithm (Howard Hinnant)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as u32, m as u32)
}

/// Write BLAKE3 hash to a pre-opened sidecar file (legacy format).
#[allow(dead_code)]
pub fn write_blake3_sidecar(mut file: File, hash_hex: &str, filename: &str) -> io::Result<()> {
    use std::io::Write;
    writeln!(file, "{hash_hex}  {filename}")?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn create_test_file(dir: &TempDir, name: &str) -> (File, std::path::PathBuf) {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let file = File::create(&path).unwrap();
        (file, path)
    }

    fn sample_keyframe_annex_b() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x67, 0x42, 0xC0, 0x1E, 0xD9, 0x00, 0xA0, 0x47, 0xFE, 0x88]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x68, 0xCE, 0x38, 0x80]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x65, 0x88, 0x80, 0x40, 0x00]);
        data
    }

    /// Keyframe with different SPS (High profile, different level) for resolution change tests.
    fn sample_keyframe_alt_sps() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x67, 0x64, 0x00, 0x28, 0xAC, 0xD1, 0x00, 0x50, 0x1E, 0xD0]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x68, 0xCE, 0x06, 0xE2]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x65, 0x88, 0x80, 0x40, 0x00]);
        data
    }

    fn sample_pframe_annex_b() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x41, 0x9A, 0x01, 0x23]);
        data
    }

    fn count_mp4_boxes(data: &[u8], box_type: &[u8; 4]) -> usize {
        let mut count = 0;
        let mut off = 0;
        while off + 8 <= data.len() {
            let sz = u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) as usize;
            if sz < 8 || off + sz > data.len() { break; }
            if &data[off+4..off+8] == box_type { count += 1; }
            off += sz;
        }
        count
    }

    // ──────────────────────────────────────────────────────────────
    // Existing tests (adapted for segmented API)
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_recording_manager_full_lifecycle() {
        let dir = temp_dir();
        let (mp4_file, mp4_path) = create_test_file(&dir, "uuid1/001.mp4");
        let mut mgr = RecordingManager::new();
        let session_id = "test-session-001";

        mgr.start_session(session_id, mp4_file, "2026/03/uuid1/001.mp4".to_string());
        assert_eq!(mgr.active_count(), 1);

        mgr.handle_frame(session_id, 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &sample_pframe_annex_b());

        let result = mgr.end_session(session_id).expect("should return EndSessionResult");
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.segments[0].width, 1920);
        assert_eq!(result.segments[0].height, 1080);

        let mp4_data = std::fs::read(&mp4_path).unwrap();
        assert!(mp4_data.len() > 8);
        assert_eq!(&mp4_data[4..8], b"ftyp");
    }

    #[test]
    fn test_recording_manager_ignores_pframes_before_keyframe() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "sess/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("sess", file, "2026/03/sess/001.mp4".to_string());
        mgr.handle_frame("sess", 0, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("sess", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("sess", 66666, true, 1920, 1080, &sample_keyframe_annex_b());
        let result = mgr.end_session("sess");
        assert!(result.is_some());

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
    }

    #[test]
    fn test_recording_manager_unknown_session() {
        let mut mgr = RecordingManager::new();
        mgr.handle_frame("ghost", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        assert!(mgr.end_session("ghost").is_none());
    }

    #[test]
    fn test_recording_manager_duplicate_start() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "dup/001.mp4");
        let (file2, _) = create_test_file(&dir, "dup2/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("dup", file1, "2026/03/dup/001.mp4".to_string());
        mgr.start_session("dup", file2, "2026/03/dup2/001.mp4".to_string());
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_recording_end_without_keyframe() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "nokey/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("nokey", file, "2026/03/nokey/001.mp4".to_string());
        assert!(mgr.end_session("nokey").is_none());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_blake3_hash_matches_frame_data() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "b3/001.mp4");
        let mut mgr = RecordingManager::new();
        let session_id = "blake3-verify";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(&keyframe);
        expected_hasher.update(&pframe);
        let expected_hash = expected_hasher.finalize().to_hex().to_string();

        mgr.start_session(session_id, file, "2026/03/b3/001.mp4".to_string());
        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        let result = mgr.end_session(session_id).unwrap();
        assert_eq!(result.segments[0].blake3_hex, expected_hash);
    }

    #[test]
    fn test_multiple_concurrent_sessions() {
        let dir = temp_dir();
        let (file_a, path_a) = create_test_file(&dir, "sa/001.mp4");
        let (file_b, path_b) = create_test_file(&dir, "sb/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("sess-a", file_a, "2026/03/sa/001.mp4".to_string());
        mgr.start_session("sess-b", file_b, "2026/03/sb/001.mp4".to_string());
        assert_eq!(mgr.active_count(), 2);

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        mgr.handle_frame("sess-a", 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame("sess-b", 0, true, 1280, 720, &keyframe);
        mgr.handle_frame("sess-a", 33333, false, 1920, 1080, &pframe);
        mgr.handle_frame("sess-b", 33333, false, 1280, 720, &pframe);

        assert!(mgr.end_session("sess-a").is_some());
        assert_eq!(mgr.active_count(), 1);
        assert!(std::fs::read(&path_a).unwrap().len() > 8);

        assert!(mgr.end_session("sess-b").is_some());
        assert_eq!(mgr.active_count(), 0);
        assert!(std::fs::read(&path_b).unwrap().len() > 8);
    }

    #[test]
    fn test_crash_resilience_partial_recording() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "crash/001.mp4");
        let mut mgr = RecordingManager::new();
        let session_id = "crash-test";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        mgr.start_session(session_id, file, "2026/03/crash/001.mp4".to_string());

        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &pframe);
        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &pframe);
        mgr.handle_frame(session_id, 200000, true, 1920, 1080, &keyframe);

        drop(mgr);

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
        assert_eq!(count_mp4_boxes(&data, b"moof"), 2, "Two fragments should survive a crash");
    }

    #[test]
    fn test_single_keyframe_recording() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "single/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("single", file, "2026/03/single/001.mp4".to_string());
        mgr.handle_frame("single", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        let result = mgr.end_session("single");
        assert!(result.is_some());

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
    }

    #[test]
    fn test_only_pframes_produces_no_output() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "ponly/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("ponly", file, "2026/03/ponly/001.mp4".to_string());
        mgr.handle_frame("ponly", 0, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("ponly", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        assert!(mgr.end_session("ponly").is_none());

        let data = std::fs::read(&mp4_path).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_compute_relative_path_format() {
        let path = RecordingManager::compute_relative_path("abc-123");
        assert!(path.ends_with("/abc-123/001.mp4"));
        let parts: Vec<&str> = path.split('/').collect();
        assert_eq!(parts.len(), 4); // YYYY/MM/uuid/001.mp4
        assert_eq!(parts[0].len(), 4); // year
        assert_eq!(parts[1].len(), 2); // month
    }

    // ──────────────────────────────────────────────────────────────
    // New segmentation tests
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_single_segment_no_resize() {
        let dir = temp_dir();
        let (file, path) = create_test_file(&dir, "nosplit/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("nosplit", file, "2026/03/nosplit/001.mp4".to_string());
        mgr.handle_frame("nosplit", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("nosplit", 33333, false, 1280, 720, &sample_pframe_annex_b());
        mgr.handle_frame("nosplit", 66666, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("nosplit", 100000, false, 1280, 720, &sample_pframe_annex_b());

        let result = mgr.end_session("nosplit").unwrap();
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.segments[0].index, 1);
        assert_eq!(result.segments[0].width, 1280);
        assert_eq!(result.segments[0].height, 720);
        assert!(result.segments[0].duration_ticks > 0);
        assert!(result.segments[0].init_size > 0);
        assert!(!result.segments[0].blake3_hex.is_empty());
        assert!(result.segments[0].codec_string.starts_with("avc1."));

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");

        let meta = RecordingManager::serialize_meta_json(&result.segments);
        let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
        assert_eq!(parsed["segments"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_segment_split_on_resolution_change() {
        let dir = temp_dir();
        let (file1, path1) = create_test_file(&dir, "split/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("split", file1, "2026/03/split/001.mp4".to_string());
        mgr.handle_frame("split", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("split", 33333, false, 1280, 720, &sample_pframe_annex_b());

        // Keyframe at new resolution triggers split
        let result = mgr.handle_frame(
            "split", 66666, true, 1920, 1080, &sample_keyframe_alt_sps(),
        );
        assert!(matches!(result, FrameResult::NewSegmentNeeded { .. }));

        // Provide the new segment file
        let (file2, path2) = create_test_file(&dir, "split/002.mp4");
        mgr.provide_segment_file("split", file2);

        mgr.handle_frame("split", 100000, false, 1920, 1080, &sample_pframe_annex_b());

        let result = mgr.end_session("split").unwrap();
        assert_eq!(result.segments.len(), 2);
        assert_eq!(result.segments[0].index, 1);
        assert_eq!(result.segments[0].width, 1280);
        assert_eq!(result.segments[1].index, 2);
        assert_eq!(result.segments[1].width, 1920);

        // Both files should be valid fMP4
        let d1 = std::fs::read(&path1).unwrap();
        assert_eq!(&d1[4..8], b"ftyp");
        let d2 = std::fs::read(&path2).unwrap();
        assert_eq!(&d2[4..8], b"ftyp");
    }

    #[test]
    fn test_multiple_resolution_changes() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "multi/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("multi", file1, "2026/03/multi/001.mp4".to_string());
        mgr.handle_frame("multi", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("multi", 33333, false, 1280, 720, &sample_pframe_annex_b());

        // First resize: 720 -> 1080
        let r = mgr.handle_frame("multi", 66666, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file2, _) = create_test_file(&dir, "multi/002.mp4");
        mgr.provide_segment_file("multi", file2);

        mgr.handle_frame("multi", 100000, false, 1920, 1080, &sample_pframe_annex_b());

        // Second resize: 1080 -> 800x600
        let r = mgr.handle_frame("multi", 133333, true, 800, 600, &sample_keyframe_annex_b());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file3, _) = create_test_file(&dir, "multi/003.mp4");
        mgr.provide_segment_file("multi", file3);

        mgr.handle_frame("multi", 166666, false, 800, 600, &sample_pframe_annex_b());

        let result = mgr.end_session("multi").unwrap();
        assert_eq!(result.segments.len(), 3);
        assert_eq!(result.segments[0].width, 1280);
        assert_eq!(result.segments[1].width, 1920);
        assert_eq!(result.segments[2].width, 800);
        assert_eq!(result.segments[2].index, 3);
    }

    #[test]
    fn test_resolution_change_back_to_original() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "bounce/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("bounce", file1, "2026/03/bounce/001.mp4".to_string());
        mgr.handle_frame("bounce", 0, true, 1280, 720, &sample_keyframe_annex_b());

        // 720 -> 1080
        let r = mgr.handle_frame("bounce", 33333, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file2, _) = create_test_file(&dir, "bounce/002.mp4");
        mgr.provide_segment_file("bounce", file2);

        // 1080 -> 720 (back)
        let r = mgr.handle_frame("bounce", 66666, true, 1280, 720, &sample_keyframe_annex_b());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file3, _) = create_test_file(&dir, "bounce/003.mp4");
        mgr.provide_segment_file("bounce", file3);

        let result = mgr.end_session("bounce").unwrap();
        assert_eq!(result.segments.len(), 3);
        assert_eq!(result.segments[0].width, 1280);
        assert_eq!(result.segments[1].width, 1920);
        assert_eq!(result.segments[2].width, 1280);
    }

    #[test]
    fn test_pframe_before_new_keyframe_stays_in_current_segment() {
        let dir = temp_dir();
        let (file, path) = create_test_file(&dir, "pstay/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("pstay", file, "2026/03/pstay/001.mp4".to_string());
        mgr.handle_frame("pstay", 0, true, 1280, 720, &sample_keyframe_annex_b());
        // P-frames at old resolution
        mgr.handle_frame("pstay", 33333, false, 1280, 720, &sample_pframe_annex_b());
        mgr.handle_frame("pstay", 66666, false, 1280, 720, &sample_pframe_annex_b());

        let result = mgr.end_session("pstay").unwrap();
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.total_frames, 3);

        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
    }

    #[test]
    fn test_segment_blake3_independent() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "b3ind/001.mp4");
        let mut mgr = RecordingManager::new();

        let kf1 = sample_keyframe_annex_b();
        let kf2 = sample_keyframe_alt_sps();

        mgr.start_session("b3ind", file1, "2026/03/b3ind/001.mp4".to_string());
        mgr.handle_frame("b3ind", 0, true, 1280, 720, &kf1);

        let r = mgr.handle_frame("b3ind", 33333, true, 1920, 1080, &kf2);
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file2, _) = create_test_file(&dir, "b3ind/002.mp4");
        mgr.provide_segment_file("b3ind", file2);

        let result = mgr.end_session("b3ind").unwrap();

        // Each segment should have a different hash (different frame data)
        assert_ne!(result.segments[0].blake3_hex, result.segments[1].blake3_hex);

        // Verify hashes independently
        let mut h1 = blake3::Hasher::new();
        h1.update(&kf1);
        assert_eq!(result.segments[0].blake3_hex, h1.finalize().to_hex().to_string());

        let mut h2 = blake3::Hasher::new();
        h2.update(&kf2);
        assert_eq!(result.segments[1].blake3_hex, h2.finalize().to_hex().to_string());
    }

    #[test]
    fn test_segment_init_size_recorded() {
        let dir = temp_dir();
        let (file, path) = create_test_file(&dir, "init/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("init", file, "2026/03/init/001.mp4".to_string());
        mgr.handle_frame("init", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame("init", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        let result = mgr.end_session("init").unwrap();

        let init_size = result.segments[0].init_size;
        assert!(init_size > 0);

        // init_size should be ftyp + moov
        let data = std::fs::read(&path).unwrap();
        let ftyp_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let moov_off = ftyp_size as usize;
        let moov_size = u32::from_be_bytes([data[moov_off], data[moov_off+1], data[moov_off+2], data[moov_off+3]]) as u64;
        assert_eq!(init_size, ftyp_size + moov_size);
    }

    #[test]
    fn test_segment_codec_string() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "codec/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("codec", file, "2026/03/codec/001.mp4".to_string());
        mgr.handle_frame("codec", 0, true, 1280, 720, &sample_keyframe_annex_b());

        let result = mgr.end_session("codec").unwrap();
        assert_eq!(result.segments[0].codec_string, "avc1.42c01e");
    }

    #[test]
    fn test_segment_duration_computed() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "dur/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("dur", file, "2026/03/dur/001.mp4".to_string());
        mgr.handle_frame("dur", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("dur", 33333, false, 1280, 720, &sample_pframe_annex_b());
        mgr.handle_frame("dur", 66666, false, 1280, 720, &sample_pframe_annex_b());

        let result = mgr.end_session("dur").unwrap();
        assert!(result.segments[0].duration_ticks > 0);
    }

    #[test]
    fn test_meta_json_structure() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "meta/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("meta", file1, "2026/03/meta/001.mp4".to_string());
        mgr.handle_frame("meta", 0, true, 1280, 720, &sample_keyframe_annex_b());

        let r = mgr.handle_frame("meta", 33333, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file2, _) = create_test_file(&dir, "meta/002.mp4");
        mgr.provide_segment_file("meta", file2);

        let result = mgr.end_session("meta").unwrap();
        let json_str = RecordingManager::serialize_meta_json(&result.segments);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let segs = parsed["segments"].as_array().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0]["index"], 1);
        assert_eq!(segs[0]["width"], 1280);
        assert_eq!(segs[0]["height"], 720);
        assert!(segs[0]["init_size"].as_u64().unwrap() > 0);
        assert!(segs[0]["blake3_hex"].as_str().unwrap().len() == 64);
        assert!(segs[0]["codec_string"].as_str().unwrap().starts_with("avc1."));
        assert_eq!(segs[1]["index"], 2);
        assert_eq!(segs[1]["width"], 1920);
    }

    #[test]
    fn test_provide_segment_file_processes_buffered_keyframe() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "buf/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("buf", file1, "2026/03/buf/001.mp4".to_string());
        mgr.handle_frame("buf", 0, true, 1280, 720, &sample_keyframe_annex_b());

        let r = mgr.handle_frame("buf", 33333, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));

        let (file2, path2) = create_test_file(&dir, "buf/002.mp4");
        mgr.provide_segment_file("buf", file2);

        // The buffered keyframe should have been processed -> segment 2 has data
        let result = mgr.end_session("buf").unwrap();
        assert_eq!(result.segments.len(), 2);

        let d2 = std::fs::read(&path2).unwrap();
        assert_eq!(&d2[4..8], b"ftyp");
    }

    #[test]
    fn test_end_session_returns_all_segments() {
        let dir = temp_dir();
        let (file1, _) = create_test_file(&dir, "all/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("all", file1, "2026/03/all/001.mp4".to_string());
        mgr.handle_frame("all", 0, true, 1280, 720, &sample_keyframe_annex_b());

        let r = mgr.handle_frame("all", 33333, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file2, _) = create_test_file(&dir, "all/002.mp4");
        mgr.provide_segment_file("all", file2);

        let r = mgr.handle_frame("all", 66666, true, 800, 600, &sample_keyframe_annex_b());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));
        let (file3, _) = create_test_file(&dir, "all/003.mp4");
        mgr.provide_segment_file("all", file3);

        let result = mgr.end_session("all").unwrap();
        assert_eq!(result.segments.len(), 3);
        assert_eq!(result.meta_json_relative_path, "2026/03/all/meta.json");

        for (i, seg) in result.segments.iter().enumerate() {
            assert_eq!(seg.index, (i + 1) as u32);
            assert!(seg.init_size > 0);
            assert!(!seg.blake3_hex.is_empty());
        }
    }

    #[test]
    fn test_crash_resilience_mid_segment_split() {
        let dir = temp_dir();
        let (file1, path1) = create_test_file(&dir, "csplit/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("csplit", file1, "2026/03/csplit/001.mp4".to_string());
        mgr.handle_frame("csplit", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("csplit", 33333, false, 1280, 720, &sample_pframe_annex_b());

        // Second GOP triggers flush of first fragment
        mgr.handle_frame("csplit", 66666, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("csplit", 100000, false, 1280, 720, &sample_pframe_annex_b());

        // Resolution change -> split (flushes current fragment)
        let r = mgr.handle_frame("csplit", 133333, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));

        // Simulate crash: drop without providing new file or calling end_session
        drop(mgr);

        // First segment should have survived with its flushed fragments
        let data = std::fs::read(&path1).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
        assert!(count_mp4_boxes(&data, b"moof") >= 1);
    }

    #[test]
    fn test_compute_relative_path_segmented() {
        let path = RecordingManager::compute_relative_path("my-uuid");
        assert!(path.ends_with("/my-uuid/001.mp4"), "got: {path}");

        let base = RecordingManager::compute_base_dir("my-uuid");
        assert!(base.ends_with("/my-uuid"), "got: {base}");
    }

    // ──────────────────────────────────────────────────────────────
    // Integration tests: full lifecycle round-trips
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle_with_resize_meta_roundtrip() {
        let dir = temp_dir();
        let (file1, path1) = create_test_file(&dir, "integ-resize/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("integ-resize", file1, "2026/03/integ-resize/001.mp4".to_string());

        // Segment 1: 1280x720
        mgr.handle_frame("integ-resize", 0, true, 1280, 720, &sample_keyframe_annex_b());
        mgr.handle_frame("integ-resize", 33333, false, 1280, 720, &sample_pframe_annex_b());
        mgr.handle_frame("integ-resize", 66666, false, 1280, 720, &sample_pframe_annex_b());

        // Resolution change to 1920x1080
        let r = mgr.handle_frame("integ-resize", 100000, true, 1920, 1080, &sample_keyframe_alt_sps());
        assert!(matches!(r, FrameResult::NewSegmentNeeded { .. }));

        let (file2, path2) = create_test_file(&dir, "integ-resize/002.mp4");
        mgr.provide_segment_file("integ-resize", file2);

        // Segment 2: 1920x1080
        mgr.handle_frame("integ-resize", 133333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("integ-resize", 166666, false, 1920, 1080, &sample_pframe_annex_b());

        let result = mgr.end_session("integ-resize").unwrap();

        // Verify 2 valid fMP4 segments
        let d1 = std::fs::read(&path1).unwrap();
        let d2 = std::fs::read(&path2).unwrap();
        assert_eq!(&d1[4..8], b"ftyp");
        assert_eq!(&d2[4..8], b"ftyp");

        // Verify meta.json round-trip
        let json_str = RecordingManager::serialize_meta_json(&result.segments);
        let meta_path = dir.path().join("integ-resize/meta.json");
        std::fs::write(&meta_path, &json_str).unwrap();
        let read_back = std::fs::read_to_string(&meta_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&read_back).unwrap();
        let segs = parsed["segments"].as_array().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0]["width"], 1280);
        assert_eq!(segs[0]["height"], 720);
        assert_eq!(segs[1]["width"], 1920);
        assert_eq!(segs[1]["height"], 1080);
    }

    #[test]
    fn test_full_lifecycle_without_resize_meta_roundtrip() {
        let dir = temp_dir();
        let (file, path) = create_test_file(&dir, "integ-noresize/001.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("integ-nr", file, "2026/03/integ-noresize/001.mp4".to_string());
        mgr.handle_frame("integ-nr", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame("integ-nr", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("integ-nr", 66666, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame("integ-nr", 100000, false, 1920, 1080, &sample_pframe_annex_b());

        let result = mgr.end_session("integ-nr").unwrap();
        assert_eq!(result.segments.len(), 1);

        // Valid fMP4
        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
        assert!(count_mp4_boxes(&data, b"moof") >= 1);

        // Valid meta.json
        let json_str = RecordingManager::serialize_meta_json(&result.segments);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let segs = parsed["segments"].as_array().unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0]["width"], 1920);
        assert_eq!(segs[0]["height"], 1080);
        assert!(segs[0]["duration_ticks"].as_u64().unwrap() > 0);
    }
}
