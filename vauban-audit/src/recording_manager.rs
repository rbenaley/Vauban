//! Manages active RDP recording sessions.
//!
//! Receives `RdpRecordingStart`, `RdpVideoFrame`, and `RdpRecordingEnd` messages
//! from the proxy-rdp IPC channel, and writes fragmented MP4 files with BLAKE3
//! integrity hashing.
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

/// State for a single active recording.
struct ActiveRecording {
    /// Pre-opened file, consumed when the first keyframe arrives.
    file: Option<File>,
    /// Created from `file` on the first keyframe (needs SPS/PPS for moov box).
    writer: Option<Fmp4Writer<BufWriter<File>>>,
    hasher: blake3::Hasher,
    current_fragment: Vec<Sample>,
    prev_timestamp_us: Option<u64>,
    /// Relative path (e.g. "2026/02/session.mp4") for logging and blake3 sidecar.
    relative_path: String,
    frame_count: u64,
    fragment_count: u64,
}

/// Result returned by `end_session` so the caller can write the BLAKE3 sidecar.
#[allow(dead_code)]
pub struct EndSessionResult {
    pub hash_hex: String,
    pub mp4_filename: String,
    pub blake3_relative_path: String,
    pub frames: u64,
    pub fragments: u64,
    pub bytes: u64,
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

    /// Start recording a new session with a pre-opened file.
    ///
    /// The fMP4 header (ftyp + moov) is written lazily when the first keyframe
    /// arrives, since SPS/PPS are needed and only present in keyframes.
    pub fn start_session(&mut self, session_id: &str, file: File, relative_path: String) {
        if self.recordings.contains_key(session_id) {
            warn!(session_id, "Recording already active, ignoring duplicate start");
            return;
        }

        info!(session_id, path = %relative_path, "Recording session started (pending first keyframe)");

        self.recordings.insert(session_id.to_string(), ActiveRecording {
            file: Some(file),
            writer: None,
            hasher: blake3::Hasher::new(),
            current_fragment: Vec::new(),
            prev_timestamp_us: None,
            relative_path,
            frame_count: 0,
            fragment_count: 0,
        });
    }

    /// Compute the relative recording path for a session based on the current date.
    pub fn compute_relative_path(session_id: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() / 86400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}.mp4")
    }

    /// Process an H.264 video frame.
    pub fn handle_frame(
        &mut self,
        session_id: &str,
        timestamp_us: u64,
        is_keyframe: bool,
        width: u16,
        height: u16,
        data: &[u8],
    ) {
        let Some(rec) = self.recordings.get_mut(session_id) else {
            debug!(session_id, "Frame for unknown recording session, ignoring");
            return;
        };

        rec.hasher.update(data);
        rec.frame_count += 1;

        // Initialize writer on first keyframe using the pre-opened file
        if rec.writer.is_none() {
            if !is_keyframe {
                debug!(session_id, "Waiting for first keyframe, skipping P-frame");
                return;
            }

            let Some(file) = rec.file.take() else {
                error!(session_id, "No pre-opened file available for recording");
                return;
            };

            let (sps, pps) = fmp4_writer::extract_sps_pps(data);
            let Some(sps) = sps else {
                warn!(session_id, "First keyframe missing SPS, cannot initialize recording");
                return;
            };
            let pps = pps.unwrap_or_else(|| {
                warn!(session_id, "First keyframe missing PPS, using minimal default");
                vec![0x68, 0xCE, 0x38, 0x80]
            });

            let buf_writer = BufWriter::with_capacity(64 * 1024, file);
            match Fmp4Writer::new(buf_writer, &sps, &pps, width, height) {
                Ok(writer) => {
                    rec.writer = Some(writer);
                    rec.prev_timestamp_us = Some(timestamp_us);
                    info!(session_id, width, height, "fMP4 writer initialized with SPS/PPS");
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to initialize fMP4 writer");
                    return;
                }
            }
        }

        let duration_us = timestamp_us.saturating_sub(rec.prev_timestamp_us.unwrap_or(timestamp_us));
        let duration_ticks = if duration_us == 0 {
            3000 // ~33ms at 90kHz (30fps fallback)
        } else {
            (duration_us as f64 / US_PER_TICK).round() as u32
        };
        rec.prev_timestamp_us = Some(timestamp_us);

        let avcc_data = fmp4_writer::annex_b_to_avcc(data);
        if avcc_data.is_empty() {
            return;
        }

        // On new keyframe, flush the accumulated fragment
        if is_keyframe && !rec.current_fragment.is_empty() {
            if let Some(ref mut writer) = rec.writer
                && let Err(e) = writer.write_fragment(&rec.current_fragment)
            {
                error!(session_id, error = %e, "Failed to write fragment");
                return;
            }
            rec.fragment_count += 1;
            rec.current_fragment.clear();
        }

        rec.current_fragment.push(Sample {
            data: avcc_data,
            duration_ticks,
            is_keyframe,
        });
    }

    /// End a recording session. Flushes the last fragment and returns hash info.
    ///
    /// The caller is responsible for writing the BLAKE3 sidecar file (by requesting
    /// another file from the supervisor).
    pub fn end_session(&mut self, session_id: &str) -> Option<EndSessionResult> {
        let Some(mut rec) = self.recordings.remove(session_id) else {
            debug!(session_id, "End for unknown recording session, ignoring");
            return None;
        };

        let Some(ref mut writer) = rec.writer else {
            info!(session_id, "Recording ended before any keyframe was received");
            return None;
        };

        // Flush remaining samples
        if !rec.current_fragment.is_empty() {
            if let Err(e) = writer.write_fragment(&rec.current_fragment) {
                error!(session_id, error = %e, "Failed to write final fragment");
            }
            rec.fragment_count += 1;
        }

        let bytes = writer.bytes_written();
        let hash = rec.hasher.finalize();
        let hash_hex = hash.to_hex().to_string();
        let mp4_filename = rec.relative_path.rsplit('/').next().unwrap_or(&rec.relative_path).to_string();
        let blake3_relative_path = format!("{}.blake3", rec.relative_path);

        info!(
            session_id,
            frames = rec.frame_count,
            fragments = rec.fragment_count,
            bytes,
            blake3 = %hash_hex,
            "Recording session finalized"
        );

        Some(EndSessionResult {
            hash_hex,
            mp4_filename,
            blake3_relative_path,
            frames: rec.frame_count,
            fragments: rec.fragment_count,
            bytes,
        })
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.recordings.len()
    }
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

/// Write BLAKE3 hash to a pre-opened sidecar file.
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

    /// Create a temp file for a recording test. Returns (File, path on disk).
    fn create_test_file(dir: &TempDir, name: &str) -> (File, std::path::PathBuf) {
        let path = dir.path().join(name);
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

    fn sample_pframe_annex_b() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x41, 0x9A, 0x01, 0x23]);
        data
    }

    #[test]
    fn test_recording_manager_full_lifecycle() {
        let dir = temp_dir();
        let (mp4_file, mp4_path) = create_test_file(&dir, "test-session-001.mp4");
        let (blake3_file, blake3_path) = create_test_file(&dir, "test-session-001.mp4.blake3");
        let mut mgr = RecordingManager::new();

        let session_id = "test-session-001";

        mgr.start_session(session_id, mp4_file, "test-session-001.mp4".to_string());
        assert_eq!(mgr.active_count(), 1);

        mgr.handle_frame(session_id, 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &sample_pframe_annex_b());

        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &sample_pframe_annex_b());

        let result = mgr.end_session(session_id).expect("should return EndSessionResult");
        assert_eq!(mgr.active_count(), 0);

        // Write blake3 sidecar (normally done by the caller)
        write_blake3_sidecar(blake3_file, &result.hash_hex, &result.mp4_filename).unwrap();

        let mp4_data = std::fs::read(&mp4_path).unwrap();
        assert!(mp4_data.len() > 8);
        assert_eq!(&mp4_data[4..8], b"ftyp");

        let blake3_content = std::fs::read_to_string(&blake3_path).unwrap();
        assert!(blake3_content.contains("test-session-001.mp4"));
        assert_eq!(blake3_content.split_whitespace().count(), 2);
    }

    #[test]
    fn test_recording_manager_ignores_pframes_before_keyframe() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "sess.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("sess", file, "sess.mp4".to_string());
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
        let (file1, _) = create_test_file(&dir, "dup1.mp4");
        let (file2, _) = create_test_file(&dir, "dup2.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("dup", file1, "dup.mp4".to_string());
        mgr.start_session("dup", file2, "dup.mp4".to_string());
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_recording_end_without_keyframe() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "nokey.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("nokey", file, "nokey.mp4".to_string());
        assert!(mgr.end_session("nokey").is_none());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_blake3_hash_matches_frame_data() {
        let dir = temp_dir();
        let (file, _) = create_test_file(&dir, "blake3-verify.mp4");
        let mut mgr = RecordingManager::new();
        let session_id = "blake3-verify";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(&keyframe);
        expected_hasher.update(&pframe);
        let expected_hash = expected_hasher.finalize().to_hex().to_string();

        mgr.start_session(session_id, file, "blake3-verify.mp4".to_string());
        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        let result = mgr.end_session(session_id).unwrap();
        assert_eq!(result.hash_hex, expected_hash);
    }

    #[test]
    fn test_multiple_concurrent_sessions() {
        let dir = temp_dir();
        let (file_a, path_a) = create_test_file(&dir, "sess-a.mp4");
        let (file_b, path_b) = create_test_file(&dir, "sess-b.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("sess-a", file_a, "sess-a.mp4".to_string());
        mgr.start_session("sess-b", file_b, "sess-b.mp4".to_string());
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
        let (file, mp4_path) = create_test_file(&dir, "crash-test.mp4");
        let mut mgr = RecordingManager::new();
        let session_id = "crash-test";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        mgr.start_session(session_id, file, "crash-test.mp4".to_string());

        // First GOP
        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &pframe);

        // Second GOP (this flushes the first fragment)
        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &pframe);

        // Third GOP (this flushes the second fragment)
        mgr.handle_frame(session_id, 200000, true, 1920, 1080, &keyframe);

        // Simulate crash: drop the manager without calling end_session
        drop(mgr);

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");

        let mut moof_count = 0;
        let mut off = 0;
        while off + 8 <= data.len() {
            let sz = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            if sz < 8 || off + sz > data.len() {
                break;
            }
            if &data[off + 4..off + 8] == b"moof" {
                moof_count += 1;
            }
            off += sz;
        }
        assert_eq!(moof_count, 2, "Two fragments should survive a crash");
    }

    #[test]
    fn test_single_keyframe_recording() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "single.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("single", file, "single.mp4".to_string());
        mgr.handle_frame("single", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        let result = mgr.end_session("single");
        assert!(result.is_some());

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
    }

    #[test]
    fn test_only_pframes_produces_no_output() {
        let dir = temp_dir();
        let (file, mp4_path) = create_test_file(&dir, "ponly.mp4");
        let mut mgr = RecordingManager::new();

        mgr.start_session("ponly", file, "ponly.mp4".to_string());
        mgr.handle_frame("ponly", 0, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("ponly", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        // end_session returns None when no keyframe was received
        assert!(mgr.end_session("ponly").is_none());

        // File exists but is empty (opened but never written to)
        let data = std::fs::read(&mp4_path).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_compute_relative_path_format() {
        let path = RecordingManager::compute_relative_path("abc-123");
        assert!(path.ends_with("/abc-123.mp4"));
        // Should match YYYY/MM/session.mp4 format
        let parts: Vec<&str> = path.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 4); // year
        assert_eq!(parts[1].len(), 2); // month
    }
}
