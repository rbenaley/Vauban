//! Manages active RDP recording sessions.
//!
//! Receives `RdpRecordingStart`, `RdpVideoFrame`, and `RdpRecordingEnd` messages
//! from the proxy-rdp IPC channel, and writes fragmented MP4 files with BLAKE3
//! integrity hashing.

use crate::fmp4_writer::{self, Fmp4Writer, Sample};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

const TIMESCALE: u32 = 90_000;

/// Microseconds per tick at 90 kHz timescale.
const US_PER_TICK: f64 = 1_000_000.0 / TIMESCALE as f64;

/// State for a single active recording.
struct ActiveRecording {
    /// None until the first keyframe with SPS/PPS is received.
    writer: Option<Fmp4Writer<BufWriter<File>>>,
    hasher: blake3::Hasher,
    current_fragment: Vec<Sample>,
    prev_timestamp_us: Option<u64>,
    mp4_path: PathBuf,
    frame_count: u64,
    fragment_count: u64,
}

/// Manages all active recording sessions.
pub struct RecordingManager {
    recordings: HashMap<String, ActiveRecording>,
    storage_path: PathBuf,
}

impl RecordingManager {
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            recordings: HashMap::new(),
            storage_path,
        }
    }

    /// Start recording a new session.
    ///
    /// The fMP4 header (ftyp + moov) is written lazily when the first keyframe
    /// arrives, since SPS/PPS are needed and only present in keyframes.
    pub fn start_session(&mut self, session_id: &str, _width: u16, _height: u16) {
        if self.recordings.contains_key(session_id) {
            warn!(session_id, "Recording already active, ignoring duplicate start");
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        // Extract year/month from Unix timestamp (approximate, sufficient for directory naming)
        let days = secs / 86400;
        let (year, month) = unix_days_to_year_month(days);
        let mp4_path = self.storage_path.join(format!("{year}/{month:02}/{session_id}.mp4"));
        info!(session_id, path = %mp4_path.display(), "Recording session started (pending first keyframe)");

        self.recordings.insert(session_id.to_string(), ActiveRecording {
            writer: None,
            hasher: blake3::Hasher::new(),
            current_fragment: Vec::new(),
            prev_timestamp_us: None,
            mp4_path,
            frame_count: 0,
            fragment_count: 0,
        });
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

        // Initialize writer on first keyframe
        if rec.writer.is_none() {
            if !is_keyframe {
                debug!(session_id, "Waiting for first keyframe, skipping P-frame");
                return;
            }

            let (sps, pps) = fmp4_writer::extract_sps_pps(data);
            let Some(sps) = sps else {
                warn!(session_id, "First keyframe missing SPS, cannot initialize recording");
                return;
            };
            let pps = pps.unwrap_or_else(|| {
                warn!(session_id, "First keyframe missing PPS, using minimal default");
                vec![0x68, 0xCE, 0x38, 0x80]
            });

            match create_recording_file(&rec.mp4_path, &sps, &pps, width, height) {
                Ok(writer) => {
                    rec.writer = Some(writer);
                    rec.prev_timestamp_us = Some(timestamp_us);
                    info!(session_id, width, height, "fMP4 writer initialized with SPS/PPS");
                }
                Err(e) => {
                    error!(session_id, error = %e, "Failed to create recording file");
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

    /// End a recording session. Flushes the last fragment and writes the BLAKE3 hash.
    pub fn end_session(&mut self, session_id: &str) {
        let Some(mut rec) = self.recordings.remove(session_id) else {
            debug!(session_id, "End for unknown recording session, ignoring");
            return;
        };

        let Some(ref mut writer) = rec.writer else {
            info!(session_id, "Recording ended before any keyframe was received");
            return;
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
        let hash_hex = hash.to_hex();

        let blake3_path = rec.mp4_path.with_extension("mp4.blake3");
        let filename = rec.mp4_path.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Err(e) = write_blake3_file(&blake3_path, &hash_hex, &filename) {
            error!(session_id, error = %e, "Failed to write BLAKE3 sidecar");
        }

        info!(
            session_id,
            frames = rec.frame_count,
            fragments = rec.fragment_count,
            bytes,
            blake3 = %hash_hex,
            "Recording session finalized"
        );
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

fn create_recording_file(
    path: &Path,
    sps: &[u8],
    pps: &[u8],
    width: u16,
    height: u16,
) -> io::Result<Fmp4Writer<BufWriter<File>>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let buf_writer = BufWriter::with_capacity(64 * 1024, file);
    Fmp4Writer::new(buf_writer, sps, pps, width, height)
}

fn write_blake3_file(path: &Path, hash_hex: &str, filename: &str) -> io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "{hash_hex}  {filename}")?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Find a recording file by session ID within the YYYY/MM/ directory structure.
    fn find_recording(base: &Path, session_id: &str) -> Option<PathBuf> {
        find_file_recursive(base, &format!("{session_id}.mp4"))
    }

    /// Find a BLAKE3 sidecar file by session ID.
    fn find_blake3(base: &Path, session_id: &str) -> Option<PathBuf> {
        find_file_recursive(base, &format!("{session_id}.mp4.blake3"))
    }

    fn find_file_recursive(base: &Path, filename: &str) -> Option<PathBuf> {
        for entry in std::fs::read_dir(base).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find_file_recursive(&path, filename) {
                    return Some(found);
                }
            } else if path.file_name().map(|f| f == filename).unwrap_or(false) {
                return Some(path);
            }
        }
        None
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
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());

        let session_id = "test-session-001";

        mgr.start_session(session_id, 1920, 1080);
        assert_eq!(mgr.active_count(), 1);

        mgr.handle_frame(session_id, 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &sample_pframe_annex_b());

        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &sample_pframe_annex_b());

        mgr.end_session(session_id);
        assert_eq!(mgr.active_count(), 0);

        let mp4_path = find_recording(&storage_path, session_id)
            .expect("MP4 file should exist");
        let blake3_path = find_blake3(&storage_path, session_id)
            .expect("BLAKE3 sidecar should exist");

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
        let mut mgr = RecordingManager::new(dir.path().to_path_buf());

        mgr.start_session("sess", 1920, 1080);
        mgr.handle_frame("sess", 0, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("sess", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("sess", 66666, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.end_session("sess");

        assert!(find_recording(dir.path(), "sess").is_some());
    }

    #[test]
    fn test_recording_manager_unknown_session() {
        let dir = temp_dir();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf());

        mgr.handle_frame("ghost", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.end_session("ghost");
    }

    #[test]
    fn test_recording_manager_duplicate_start() {
        let dir = temp_dir();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf());

        mgr.start_session("dup", 1920, 1080);
        mgr.start_session("dup", 1920, 1080);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_recording_end_without_keyframe() {
        let dir = temp_dir();
        let mut mgr = RecordingManager::new(dir.path().to_path_buf());

        mgr.start_session("nokey", 1920, 1080);
        mgr.end_session("nokey");
        assert_eq!(mgr.active_count(), 0);
        assert!(find_recording(dir.path(), "nokey").is_none());
    }

    #[test]
    fn test_blake3_hash_matches_frame_data() {
        let dir = temp_dir();
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());
        let session_id = "blake3-verify";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        // Compute expected hash from the same raw frame data
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(&keyframe);
        expected_hasher.update(&pframe);
        let expected_hash = expected_hasher.finalize().to_hex().to_string();

        mgr.start_session(session_id, 1920, 1080);
        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        mgr.end_session(session_id);

        let blake3_path = find_blake3(&storage_path, session_id)
            .expect("BLAKE3 sidecar should exist");
        let blake3_content = std::fs::read_to_string(&blake3_path).unwrap();
        let stored_hash = blake3_content.split_whitespace().next().unwrap();
        assert_eq!(stored_hash, expected_hash);
    }

    #[test]
    fn test_multiple_concurrent_sessions() {
        let dir = temp_dir();
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());

        mgr.start_session("sess-a", 1920, 1080);
        mgr.start_session("sess-b", 1280, 720);
        assert_eq!(mgr.active_count(), 2);

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        mgr.handle_frame("sess-a", 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame("sess-b", 0, true, 1280, 720, &keyframe);
        mgr.handle_frame("sess-a", 33333, false, 1920, 1080, &pframe);
        mgr.handle_frame("sess-b", 33333, false, 1280, 720, &pframe);

        mgr.end_session("sess-a");
        assert_eq!(mgr.active_count(), 1);
        assert!(find_recording(&storage_path, "sess-a").is_some());
        assert!(find_blake3(&storage_path, "sess-a").is_some());

        mgr.end_session("sess-b");
        assert_eq!(mgr.active_count(), 0);
        assert!(find_recording(&storage_path, "sess-b").is_some());
        assert!(find_blake3(&storage_path, "sess-b").is_some());
    }

    #[test]
    fn test_crash_resilience_partial_recording() {
        let dir = temp_dir();
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());
        let session_id = "crash-test";

        let keyframe = sample_keyframe_annex_b();
        let pframe = sample_pframe_annex_b();

        mgr.start_session(session_id, 1920, 1080);

        // First GOP
        mgr.handle_frame(session_id, 0, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 33333, false, 1920, 1080, &pframe);
        mgr.handle_frame(session_id, 66666, false, 1920, 1080, &pframe);

        // Second GOP (this flushes the first fragment)
        mgr.handle_frame(session_id, 100000, true, 1920, 1080, &keyframe);
        mgr.handle_frame(session_id, 133333, false, 1920, 1080, &pframe);

        // Third GOP (this flushes the second fragment)
        mgr.handle_frame(session_id, 200000, true, 1920, 1080, &keyframe);

        // Simulate crash: drop the manager without calling end_session.
        // The file on disk should have ftyp + moov + 2 complete moof+mdat pairs.
        drop(mgr);

        let mp4_path = find_recording(&storage_path, session_id)
            .expect("MP4 file must exist after partial write");

        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");

        // Count moof boxes in the surviving file
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
        // Two complete fragments should have been flushed before the "crash"
        assert_eq!(moof_count, 2, "Two fragments should survive a crash");
    }

    #[test]
    fn test_single_keyframe_recording() {
        let dir = temp_dir();
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());

        mgr.start_session("single", 1920, 1080);
        mgr.handle_frame("single", 0, true, 1920, 1080, &sample_keyframe_annex_b());
        mgr.end_session("single");

        let mp4_path = find_recording(&storage_path, "single")
            .expect("MP4 file should exist");
        let data = std::fs::read(&mp4_path).unwrap();
        assert_eq!(&data[4..8], b"ftyp");
    }

    #[test]
    fn test_only_pframes_produces_no_output() {
        let dir = temp_dir();
        let storage_path = dir.path().to_path_buf();
        let mut mgr = RecordingManager::new(storage_path.clone());

        mgr.start_session("ponly", 1920, 1080);
        mgr.handle_frame("ponly", 0, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.handle_frame("ponly", 33333, false, 1920, 1080, &sample_pframe_annex_b());
        mgr.end_session("ponly");

        assert!(find_recording(&storage_path, "ponly").is_none());
    }
}
