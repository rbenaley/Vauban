//! SSH session recording manager using asciicast v2 format.
//!
//! Writes terminal session recordings as asciicast v2 files (.cast) with
//! BLAKE3 integrity hashing and meta.json metadata for each session.

use shared::messages::SshRecordingEvent;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use tracing::{debug, warn};

/// Metadata returned when an SSH recording session ends.
pub struct SshEndSessionResult {
    #[allow(dead_code)]
    pub relative_path: String,
    pub meta_json_relative_path: String,
    pub blake3_hex: String,
    pub total_bytes: u64,
    pub total_events: u64,
    pub duration_secs: f64,
    pub width: u16,
    pub height: u16,
}

struct SshRecordingSession {
    writer: BufWriter<File>,
    hasher: blake3::Hasher,
    first_timestamp_us: Option<u64>,
    last_timestamp_us: u64,
    total_bytes: u64,
    total_events: u64,
    width: u16,
    height: u16,
    #[allow(dead_code)]
    asset_name: String,
    #[allow(dead_code)]
    username: String,
    relative_path: String,
}

/// Parameters for starting a new SSH recording session.
pub struct SshSessionStartParams {
    pub file: File,
    pub relative_path: String,
    pub width: u16,
    pub height: u16,
    pub asset_name: String,
    pub username: String,
}

/// Manages multiple concurrent SSH recording sessions.
pub struct SshRecordingManager {
    sessions: HashMap<String, SshRecordingSession>,
}

impl SshRecordingManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Compute the base directory for a session's recording files.
    pub fn compute_base_dir(session_id: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() / 86400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    /// Compute the relative path for the asciicast file.
    pub fn compute_relative_path(session_id: &str) -> String {
        format!("{}/session.cast", Self::compute_base_dir(session_id))
    }

    /// Start recording an SSH session. Writes the asciicast v2 header.
    pub fn start_session(&mut self, session_id: &str, params: SshSessionStartParams) {
        if self.sessions.contains_key(session_id) {
            warn!(session_id = %session_id, "Duplicate SSH recording start, ignoring");
            return;
        }

        let SshSessionStartParams {
            file,
            relative_path,
            width,
            height,
            asset_name,
            username,
        } = params;

        let mut writer = BufWriter::new(file);
        let mut hasher = blake3::Hasher::new();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let title = format!("SSH: {}@{}", username, asset_name);
        let header = format!(
            "{{\"version\":2,\"width\":{},\"height\":{},\"timestamp\":{},\"title\":{}}}\n",
            width,
            height,
            timestamp,
            serde_json::to_string(&title).unwrap_or_else(|_| format!("\"{}\"", title)),
        );

        let header_bytes = header.as_bytes();
        hasher.update(header_bytes);
        if let Err(e) = writer.write_all(header_bytes) {
            warn!(session_id = %session_id, error = %e, "Failed to write asciicast header");
            return;
        }

        self.sessions.insert(
            session_id.to_string(),
            SshRecordingSession {
                writer,
                hasher,
                first_timestamp_us: None,
                last_timestamp_us: 0,
                total_bytes: header_bytes.len() as u64,
                total_events: 0,
                width,
                height,
                asset_name,
                username,
                relative_path,
            },
        );

        debug!(session_id = %session_id, "SSH recording started");
    }

    /// Record a single event (output, input, or resize).
    pub fn handle_data(
        &mut self,
        session_id: &str,
        timestamp_us: u64,
        event_type: SshRecordingEvent,
        data: &[u8],
    ) {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return;
        };

        if data.is_empty() {
            return;
        }

        if session.first_timestamp_us.is_none() {
            session.first_timestamp_us = Some(timestamp_us);
        }
        session.last_timestamp_us = timestamp_us;

        let relative_ts = timestamp_us.saturating_sub(session.first_timestamp_us.unwrap_or(0));
        let ts_secs = relative_ts as f64 / 1_000_000.0;

        let event_code = match event_type {
            SshRecordingEvent::Output => "o",
            SshRecordingEvent::Input => "i",
            SshRecordingEvent::Resize => "r",
        };

        let data_str = String::from_utf8_lossy(data);
        let escaped = serde_json::to_string(data_str.as_ref())
            .unwrap_or_else(|_| format!("\"{}\"", data_str));

        let line = format!("[{:.6},\"{}\",{}]\n", ts_secs, event_code, escaped);

        let line_bytes = line.as_bytes();
        session.hasher.update(line_bytes);
        if let Err(e) = session.writer.write_all(line_bytes) {
            warn!(session_id = %session_id, error = %e, "Failed to write asciicast event");
            return;
        }

        session.total_bytes += line_bytes.len() as u64;
        session.total_events += 1;
    }

    /// End a recording session, flush the file, and return metadata.
    pub fn end_session(&mut self, session_id: &str) -> Option<SshEndSessionResult> {
        let mut session = self.sessions.remove(session_id)?;

        if let Err(e) = session.writer.flush() {
            warn!(session_id = %session_id, error = %e, "Failed to flush asciicast file");
        }

        let blake3_hex = session.hasher.finalize().to_hex().to_string();

        let duration_us = if let Some(first) = session.first_timestamp_us {
            session.last_timestamp_us.saturating_sub(first)
        } else {
            0
        };

        let base_dir = session
            .relative_path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_default();

        debug!(
            session_id = %session_id,
            events = session.total_events,
            bytes = session.total_bytes,
            duration_secs = duration_us as f64 / 1_000_000.0,
            "SSH recording ended"
        );

        Some(SshEndSessionResult {
            relative_path: session.relative_path,
            meta_json_relative_path: format!("{}/meta.json", base_dir),
            blake3_hex,
            total_bytes: session.total_bytes,
            total_events: session.total_events,
            duration_secs: duration_us as f64 / 1_000_000.0,
            width: session.width,
            height: session.height,
        })
    }

    /// Serialize recording metadata to JSON for the meta.json file.
    pub fn serialize_meta_json(result: &SshEndSessionResult) -> String {
        #[derive(serde::Serialize)]
        struct Meta<'a> {
            format: &'a str,
            blake3_hex: &'a str,
            total_bytes: u64,
            total_events: u64,
            duration_secs: f64,
            width: u16,
            height: u16,
        }

        let meta = Meta {
            format: "asciicast-v2",
            blake3_hex: &result.blake3_hex,
            total_bytes: result.total_bytes,
            total_events: result.total_events,
            duration_secs: result.duration_secs,
            width: result.width,
            height: result.height,
        };

        serde_json::to_string_pretty(&meta).unwrap_or_else(|_| "{}".to_string())
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.sessions.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    fn create_temp_file() -> File {
        tempfile::tempfile().unwrap()
    }

    fn read_file_contents(mut file: File) -> String {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents
    }

    fn create_temp_file_pair() -> (File, File) {
        let f = tempfile::tempfile().unwrap();
        let f2 = f.try_clone().unwrap();
        (f, f2)
    }

    fn test_params(file: File, relative_path: &str) -> SshSessionStartParams {
        SshSessionStartParams {
            file,
            relative_path: relative_path.to_string(),
            width: 80,
            height: 24,
            asset_name: "h".to_string(),
            username: "u".to_string(),
        }
    }

    #[test]
    fn test_ssh_recording_full_lifecycle() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session(
            "s1",
            SshSessionStartParams {
                file: f,
                relative_path: "2026/03/s1/session.cast".to_string(),
                width: 120,
                height: 40,
                asset_name: "srv".to_string(),
                username: "admin".to_string(),
            },
        );

        mgr.handle_data("s1", 0, SshRecordingEvent::Output, b"$ ");
        mgr.handle_data("s1", 100_000, SshRecordingEvent::Input, b"ls\r");
        mgr.handle_data(
            "s1",
            200_000,
            SshRecordingEvent::Output,
            b"file1  file2\r\n",
        );

        let result = mgr.end_session("s1").unwrap();
        assert_eq!(result.total_events, 3);
        assert!(result.total_bytes > 0);
        assert!(!result.blake3_hex.is_empty());
        assert_eq!(result.width, 120);
        assert_eq!(result.height, 40);

        let contents = read_file_contents(reader);
        assert!(contents.starts_with("{\"version\":2"));
        assert!(contents.contains("\"o\""));
        assert!(contents.contains("\"i\""));
    }

    #[test]
    fn test_ssh_recording_header_format() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session(
            "s1",
            SshSessionStartParams {
                file: f,
                relative_path: "p".to_string(),
                width: 80,
                height: 24,
                asset_name: "host".to_string(),
                username: "user".to_string(),
            },
        );
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let header: serde_json::Value =
            serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 80);
        assert_eq!(header["height"], 24);
        assert!(header["timestamp"].as_i64().unwrap() > 0);
        assert!(header["title"].as_str().unwrap().contains("user@host"));
    }

    #[test]
    fn test_ssh_recording_output_event_format() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 1_500_000, SshRecordingEvent::Output, b"hello");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(event_line).unwrap();
        assert_eq!(parsed[1], "o");
        assert_eq!(parsed[2], "hello");
    }

    #[test]
    fn test_ssh_recording_input_event_format() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 500_000, SshRecordingEvent::Input, b"cmd");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(event_line).unwrap();
        assert_eq!(parsed[1], "i");
        assert_eq!(parsed[2], "cmd");
    }

    #[test]
    fn test_ssh_recording_resize_event_format() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 1_000_000, SshRecordingEvent::Resize, b"160x50");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(event_line).unwrap();
        assert_eq!(parsed[1], "r");
        assert_eq!(parsed[2], "160x50");
    }

    #[test]
    fn test_ssh_recording_timestamps_increase() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 100_000, SshRecordingEvent::Output, b"a");
        mgr.handle_data("s1", 200_000, SshRecordingEvent::Output, b"b");
        mgr.handle_data("s1", 500_000, SshRecordingEvent::Output, b"c");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let mut prev_ts = -1.0_f64;
        for line in contents.lines().skip(1) {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            let ts = parsed[0].as_f64().unwrap();
            assert!(
                ts >= prev_ts,
                "Timestamps must be monotonically non-decreasing"
            );
            prev_ts = ts;
        }
    }

    #[test]
    fn test_ssh_recording_blake3_matches_data() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 0, SshRecordingEvent::Output, b"data");
        let result = mgr.end_session("s1").unwrap();

        let contents = read_file_contents(reader);
        let expected_hash = blake3::hash(contents.as_bytes()).to_hex().to_string();
        assert_eq!(result.blake3_hex, expected_hash);
    }

    #[test]
    fn test_ssh_recording_unknown_session_ignored() {
        let mut mgr = SshRecordingManager::new();
        mgr.handle_data("unknown", 0, SshRecordingEvent::Output, b"data");
        assert!(mgr.end_session("unknown").is_none());
    }

    #[test]
    fn test_ssh_recording_duplicate_start_idempotent() {
        let mut mgr = SshRecordingManager::new();
        let f1 = create_temp_file();
        let f2 = create_temp_file();

        mgr.start_session("s1", test_params(f1, "p1"));
        mgr.start_session(
            "s1",
            SshSessionStartParams {
                file: f2,
                relative_path: "p2".to_string(),
                width: 120,
                height: 40,
                asset_name: "h2".to_string(),
                username: "u2".to_string(),
            },
        );

        let result = mgr.end_session("s1").unwrap();
        assert_eq!(result.width, 80);
    }

    #[test]
    fn test_ssh_recording_end_without_data() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        let result = mgr.end_session("s1").unwrap();

        assert_eq!(result.total_events, 0);
        assert!(result.total_bytes > 0); // header
        assert_eq!(result.duration_secs, 0.0);

        let contents = read_file_contents(reader);
        assert!(contents.starts_with("{\"version\":2"));
        assert_eq!(contents.lines().count(), 1); // header only
    }

    #[test]
    fn test_ssh_recording_concurrent_sessions() {
        let mut mgr = SshRecordingManager::new();
        let (f1, reader1) = create_temp_file_pair();
        let (f2, reader2) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f1, "p1"));
        mgr.start_session(
            "s2",
            SshSessionStartParams {
                file: f2,
                relative_path: "p2".to_string(),
                width: 120,
                height: 40,
                asset_name: "h2".to_string(),
                username: "u2".to_string(),
            },
        );

        assert_eq!(mgr.active_count(), 2);

        mgr.handle_data("s1", 0, SshRecordingEvent::Output, b"session1");
        mgr.handle_data("s2", 0, SshRecordingEvent::Output, b"session2");

        let r1 = mgr.end_session("s1").unwrap();
        let r2 = mgr.end_session("s2").unwrap();

        assert_eq!(r1.width, 80);
        assert_eq!(r2.width, 120);

        let c1 = read_file_contents(reader1);
        let c2 = read_file_contents(reader2);
        assert!(c1.contains("session1"));
        assert!(c2.contains("session2"));
        assert!(!c1.contains("session2"));
        assert!(!c2.contains("session1"));
    }

    #[test]
    fn test_ssh_recording_large_output() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));

        let large_data = vec![b'X'; 1_000_000];
        mgr.handle_data("s1", 0, SshRecordingEvent::Output, &large_data);
        let result = mgr.end_session("s1").unwrap();

        assert!(result.total_bytes > 1_000_000);

        let contents = read_file_contents(reader);
        assert!(contents.len() > 1_000_000);
    }

    #[test]
    fn test_ssh_recording_binary_data_in_output() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data(
            "s1",
            0,
            SshRecordingEvent::Output,
            &[0xFF, 0xFE, 0x00, 0x01],
        );
        let result = mgr.end_session("s1").unwrap();

        assert_eq!(result.total_events, 1);
        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let _: serde_json::Value = serde_json::from_str(event_line).unwrap();
    }

    #[test]
    fn test_ssh_recording_meta_json_structure() {
        let result = SshEndSessionResult {
            relative_path: "2026/03/s1/session.cast".to_string(),
            meta_json_relative_path: "2026/03/s1/meta.json".to_string(),
            blake3_hex: "abc123".to_string(),
            total_bytes: 5000,
            total_events: 42,
            duration_secs: 12.5,
            width: 120,
            height: 40,
        };

        let json = SshRecordingManager::serialize_meta_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["format"], "asciicast-v2");
        assert_eq!(parsed["blake3_hex"], "abc123");
        assert_eq!(parsed["total_bytes"], 5000);
        assert_eq!(parsed["total_events"], 42);
        assert_eq!(parsed["duration_secs"], 12.5);
        assert_eq!(parsed["width"], 120);
        assert_eq!(parsed["height"], 40);
    }

    #[test]
    fn test_ssh_recording_compute_relative_path() {
        let path = SshRecordingManager::compute_relative_path("test-uuid-123");
        assert!(path.ends_with("/test-uuid-123/session.cast"));
        let parts: Vec<&str> = path.split('/').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[2], "test-uuid-123");
        assert_eq!(parts[3], "session.cast");
        assert!(parts[0].len() == 4); // YYYY
        assert!(parts[1].len() <= 2); // MM
    }

    #[test]
    fn test_ssh_recording_crash_resilience() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 0, SshRecordingEvent::Output, b"partial data");

        drop(mgr);

        let contents = read_file_contents(reader);
        assert!(contents.starts_with("{\"version\":2"));
    }

    #[test]
    fn test_ssh_recording_redacted_input_preserved() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 0, SshRecordingEvent::Input, b"[REDACTED]\r\n");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        assert!(contents.contains("[REDACTED]"));
    }

    #[test]
    fn test_ssh_recording_utf8_output() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data(
            "s1",
            0,
            SshRecordingEvent::Output,
            "Bonjour le monde! \u{1F600}".as_bytes(),
        );
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(event_line).unwrap();
        let text = parsed[2].as_str().unwrap();
        assert!(text.contains("Bonjour"));
        assert!(text.contains("\u{1F600}"));
    }

    #[test]
    fn test_ssh_recording_empty_data_event() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 0, SshRecordingEvent::Output, b"");
        let result = mgr.end_session("s1").unwrap();

        assert_eq!(result.total_events, 0);
        let contents = read_file_contents(reader);
        assert_eq!(contents.lines().count(), 1); // header only
    }

    #[test]
    fn test_ssh_recording_duration_calculation() {
        let mut mgr = SshRecordingManager::new();
        let f = create_temp_file();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 1_000_000, SshRecordingEvent::Output, b"a");
        mgr.handle_data("s1", 6_000_000, SshRecordingEvent::Output, b"b");
        let result = mgr.end_session("s1").unwrap();

        assert!((result.duration_secs - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_ssh_recording_first_event_timestamp_zero() {
        let mut mgr = SshRecordingManager::new();
        let (f, reader) = create_temp_file_pair();

        mgr.start_session("s1", test_params(f, "p"));
        mgr.handle_data("s1", 5_000_000, SshRecordingEvent::Output, b"a");
        mgr.end_session("s1");

        let contents = read_file_contents(reader);
        let event_line = contents.lines().nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(event_line).unwrap();
        let ts = parsed[0].as_f64().unwrap();
        assert!(
            (ts - 0.0).abs() < 0.001,
            "First event timestamp should be relative (0.0)"
        );
    }

    #[test]
    fn test_ssh_recording_compute_base_dir() {
        let base = SshRecordingManager::compute_base_dir("test-uuid");
        assert!(base.ends_with("/test-uuid"));
        assert!(base.len() > 10);
    }

    #[test]
    fn test_ssh_recording_meta_json_relative_path() {
        let mut mgr = SshRecordingManager::new();
        let f = create_temp_file();

        mgr.start_session("s1", test_params(f, "2026/03/s1/session.cast"));
        let result = mgr.end_session("s1").unwrap();

        assert_eq!(result.meta_json_relative_path, "2026/03/s1/meta.json");
    }
}
