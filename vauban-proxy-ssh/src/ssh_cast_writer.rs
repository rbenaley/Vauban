//! Proxy-owned asciicast v2 writer for SSH session recordings.

use shared::messages::SshRecordingEvent;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Final integrity and playback metadata for a sealed asciicast file.
pub struct SshCastStats {
    pub blake3_hex: String,
    pub total_bytes: u64,
    pub total_events: u64,
    pub duration_secs: f64,
    pub width: u16,
    pub height: u16,
    pub meta_json_relative_path: String,
}

/// Writes one SSH session directly to a supervisor-leased file descriptor.
pub struct SshCastWriter {
    writer: BufWriter<File>,
    hasher: blake3::Hasher,
    first_timestamp_us: Option<u64>,
    last_timestamp_us: u64,
    total_bytes: u64,
    total_events: u64,
    width: u16,
    height: u16,
    relative_path: String,
    meta_json_relative_path: String,
    dirty: bool,
}

impl SshCastWriter {
    /// Compute the date-partitioned directory for one session.
    pub fn compute_base_dir(session_id: &str) -> String {
        let days = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86_400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    /// Compute the supervisor-relative asciicast path.
    pub fn compute_relative_path(session_id: &str) -> String {
        format!("{}/session.cast", Self::compute_base_dir(session_id))
    }

    /// Compute the supervisor-relative metadata path.
    pub fn compute_meta_json_relative_path(session_id: &str) -> String {
        let cast_path = Self::compute_relative_path(session_id);
        let base_dir = cast_path
            .strip_suffix("/session.cast")
            .unwrap_or(cast_path.as_str());
        format!("{base_dir}/meta.json")
    }

    /// Start a recording and buffer its asciicast v2 header.
    pub fn start(
        file: File,
        relative_path: String,
        meta_json_relative_path: String,
        width: u16,
        height: u16,
        asset_name: &str,
        username: &str,
    ) -> io::Result<Self> {
        let mut writer = BufWriter::new(file);
        let mut hasher = blake3::Hasher::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let title = format!("SSH: {username}@{asset_name}");
        let title_json = serde_json::to_string(&title).map_err(io::Error::other)?;
        let header = format!(
            "{{\"version\":2,\"width\":{width},\"height\":{height},\
             \"timestamp\":{timestamp},\"title\":{title_json}}}\n"
        );
        let header_bytes = header.as_bytes();
        writer.write_all(header_bytes)?;
        hasher.update(header_bytes);

        Ok(Self {
            writer,
            hasher,
            first_timestamp_us: None,
            last_timestamp_us: 0,
            total_bytes: header_bytes.len() as u64,
            total_events: 0,
            width,
            height,
            relative_path,
            meta_json_relative_path,
            dirty: true,
        })
    }

    /// Append one output, redacted-input, or resize event.
    pub fn append(
        &mut self,
        event_type: SshRecordingEvent,
        timestamp_us: u64,
        data: &[u8],
    ) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let first = *self.first_timestamp_us.get_or_insert(timestamp_us);
        self.last_timestamp_us = timestamp_us;
        let timestamp_secs = timestamp_us.saturating_sub(first) as f64 / 1_000_000.0;
        let event_code = match event_type {
            SshRecordingEvent::Output => "o",
            SshRecordingEvent::Input => "i",
            SshRecordingEvent::Resize => "r",
        };
        let text = String::from_utf8_lossy(data);
        let text_json = serde_json::to_string(text.as_ref()).map_err(io::Error::other)?;
        let line = format!("[{timestamp_secs:.6},\"{event_code}\",{text_json}]\n");
        let line_bytes = line.as_bytes();

        self.writer.write_all(line_bytes)?;
        self.hasher.update(line_bytes);
        self.total_bytes = self.total_bytes.saturating_add(line_bytes.len() as u64);
        self.total_events = self.total_events.saturating_add(1);
        self.dirty = true;
        Ok(())
    }

    /// Flush and fdatasync only when new bytes have been buffered.
    pub fn sync_if_dirty(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        self.dirty = false;
        Ok(())
    }

    /// Seal the recording and return metadata for `SshRecordingEnd`.
    pub fn finish(mut self) -> io::Result<SshCastStats> {
        let cast_dir = self.relative_path.rsplit_once('/').map(|(dir, _)| dir);
        let meta_dir = self
            .meta_json_relative_path
            .rsplit_once('/')
            .map(|(dir, _)| dir);
        if cast_dir.is_none() || cast_dir != meta_dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "asciicast and metadata paths must share a directory",
            ));
        }
        self.sync_if_dirty()?;
        let duration_us = self
            .first_timestamp_us
            .map_or(0, |first| self.last_timestamp_us.saturating_sub(first));

        Ok(SshCastStats {
            blake3_hex: self.hasher.finalize().to_hex().to_string(),
            total_bytes: self.total_bytes,
            total_events: self.total_events,
            duration_secs: duration_us as f64 / 1_000_000.0,
            width: self.width,
            height: self.height,
            meta_json_relative_path: self.meta_json_relative_path,
        })
    }
}

/// Convert Unix days (since 1970-01-01) to a civil year and month.
fn unix_days_to_year_month(days: u64) -> (u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as u32, month as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn temporary_file() -> (File, std::path::PathBuf) {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vauban-ssh-cast-{}-{sequence}.cast",
            std::process::id()
        ));
        let file = File::create(&path).unwrap();
        (file, path)
    }

    #[test]
    fn writer_seals_hash_and_stats_from_disk_bytes() {
        let (file, path) = temporary_file();
        let mut writer = SshCastWriter::start(
            file,
            "2026/07/session/session.cast".to_string(),
            "2026/07/session/meta.json".to_string(),
            120,
            40,
            "asset",
            "alice",
        )
        .unwrap();

        writer
            .append(SshRecordingEvent::Output, 1_000_000, b"hello\r\n")
            .unwrap();
        writer
            .append(SshRecordingEvent::Input, 2_000_000, b"whoami\r")
            .unwrap();
        writer.sync_if_dirty().unwrap();
        writer.sync_if_dirty().unwrap();
        let stats = writer.finish().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(bytes.starts_with(b"{\"version\":2"));
        assert_eq!(stats.blake3_hex, blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(stats.total_bytes, bytes.len() as u64);
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.duration_secs, 1.0);
        assert_eq!(stats.width, 120);
        assert_eq!(stats.height, 40);
        assert_eq!(stats.meta_json_relative_path, "2026/07/session/meta.json");
    }

    #[test]
    fn relative_paths_share_the_session_directory() {
        let session_id = "session-123";
        let cast = SshCastWriter::compute_relative_path(session_id);
        let meta = SshCastWriter::compute_meta_json_relative_path(session_id);
        assert!(cast.ends_with("/session-123/session.cast"));
        assert!(meta.ends_with("/session-123/meta.json"));
        assert_eq!(
            cast.rsplit_once('/').unwrap().0,
            meta.rsplit_once('/').unwrap().0
        );
    }
}
