//! IACS tunnel PCAP recording manager.
//!
//! Writes one PCAP file per `direct-tcpip` channel with batching, `fdatasync`,
//! and session-level `meta.json` for the pcap-bundle format. File creation and
//! gzip are delegated to the supervisor (Capsicum-safe).

use shared::messages::IacsRecordingDirection;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// PCAP magic number (microsecond resolution, native endian).
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// LINKTYPE_RAW (DLT_RAW).
const PCAP_LINKTYPE_RAW: u32 = 12;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

/// Default batch size before an internal buffer flush (bytes).
pub const DEFAULT_BATCH_MAX_BYTES: usize = 8 * 1024;
/// Default maximum time a batch may remain unflushed.
pub const DEFAULT_BATCH_MAX_MS: u64 = 25;

/// Batching / durability configuration for PCAP writes.
#[derive(Debug, Clone, Copy)]
pub struct IacsRecordingConfig {
    pub batch_max_bytes: usize,
    pub batch_max_ms: u64,
}

impl Default for IacsRecordingConfig {
    fn default() -> Self {
        Self {
            batch_max_bytes: DEFAULT_BATCH_MAX_BYTES,
            batch_max_ms: DEFAULT_BATCH_MAX_MS,
        }
    }
}

/// Metadata for a finalized channel after gzip (filled by the supervisor response).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IacsChannelMeta {
    pub index: u32,
    pub target_host: String,
    pub target_port: u16,
    pub file: String,
    pub blake3_hex: String,
    pub file_size: u64,
    pub packet_count: u64,
    pub bytes_ews_to_asset: u64,
    pub bytes_asset_to_ews: u64,
    pub opened_at_us: u64,
    pub closed_at_us: u64,
}

/// Result of finalizing an entire IACS SSH session recording.
pub struct IacsSessionEndResult {
    pub meta_json_relative_path: String,
    pub channels: Vec<IacsChannelMeta>,
    pub blake3_hex: String,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub duration_ms: u64,
}

/// Paths needed to gzip a channel PCAP via the supervisor.
pub struct IacsChannelEndPaths {
    pub src_relative: String,
    pub dst_relative: String,
}

struct ActiveChannel {
    writer: BufWriter<File>,
    batch_buf: Vec<u8>,
    batch_started: Instant,
    expected_batch_seq: u64,
    packet_count: u64,
    bytes_ews_to_asset: u64,
    bytes_asset_to_ews: u64,
    opened_at_us: u64,
    last_timestamp_us: u64,
    target_host: String,
    target_port: u16,
    pcap_relative: String,
    gz_relative: String,
    channel_index: u32,
}

struct IacsRecordingSession {
    /// Captured at first channel open; reused for every PCAP path and
    /// `meta.json` so a long-lived tunnel cannot split artefacts across
    /// two month directories.
    base_dir: String,
    channels: HashMap<u32, ActiveChannel>,
    completed: Vec<IacsChannelMeta>,
    session_opened_at_us: Option<u64>,
}

/// Manages concurrent IACS PCAP recordings keyed by Vauban session UUID.
pub struct IacsRecordingManager {
    sessions: HashMap<String, IacsRecordingSession>,
    config: IacsRecordingConfig,
}

impl IacsRecordingManager {
    pub fn new() -> Self {
        Self::with_config(IacsRecordingConfig::default())
    }

    pub fn with_config(config: IacsRecordingConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            config,
        }
    }

    pub fn compute_base_dir(session_id: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() / 86400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    pub fn compute_channel_pcap_path(session_id: &str, channel_id: u32) -> String {
        format!(
            "{}/channels/{:03}.pcap",
            Self::compute_base_dir(session_id),
            channel_id
        )
    }

    pub fn start_channel(
        &mut self,
        session_id: &str,
        channel_id: u32,
        file: File,
        target_host: String,
        target_port: u16,
        opened_at_us: u64,
    ) {
        let session = self.sessions.entry(session_id.to_string()).or_insert_with(|| {
            IacsRecordingSession {
                base_dir: Self::compute_base_dir(session_id),
                channels: HashMap::new(),
                completed: Vec::new(),
                session_opened_at_us: Some(opened_at_us),
            }
        });

        if session.channels.contains_key(&channel_id) {
            warn!(
                session_id = %session_id,
                channel_id,
                "Duplicate IACS channel start, ignoring"
            );
            return;
        }

        let pcap_relative = format!(
            "{}/channels/{:03}.pcap",
            session.base_dir, channel_id
        );
        let gz_relative = format!(
            "{}/channels/{:03}.pcap.gz",
            session.base_dir, channel_id
        );

        let mut writer = BufWriter::new(file);
        let header = build_global_header();
        if writer.write_all(&header).is_err() {
            warn!(session_id = %session_id, channel_id, "Failed to write PCAP global header");
            return;
        }

        session.channels.insert(
            channel_id,
            ActiveChannel {
                writer,
                batch_buf: Vec::new(),
                batch_started: Instant::now(),
                expected_batch_seq: 0,
                packet_count: 0,
                bytes_ews_to_asset: 0,
                bytes_asset_to_ews: 0,
                opened_at_us,
                last_timestamp_us: opened_at_us,
                target_host,
                target_port,
                pcap_relative,
                gz_relative,
                channel_index: channel_id,
            },
        );

        debug!(session_id = %session_id, channel_id, "IACS channel recording started");
    }

    /// Persist one relay batch. Returns the acknowledged `batch_seq` on success.
    pub fn handle_data(
        &mut self,
        session_id: &str,
        channel_id: u32,
        batch_seq: u64,
        direction: IacsRecordingDirection,
        timestamp_us: u64,
        data: &[u8],
    ) -> Result<u64, IacsRecordingError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(IacsRecordingError::UnknownSession)?;

        let channel = session
            .channels
            .get_mut(&channel_id)
            .ok_or(IacsRecordingError::UnknownChannel)?;

        if batch_seq != channel.expected_batch_seq {
            return Err(IacsRecordingError::UnexpectedBatchSeq {
                expected: channel.expected_batch_seq,
                got: batch_seq,
            });
        }

        if !data.is_empty() {
            let record = build_packet_record(timestamp_us, data);
            channel.batch_buf.extend_from_slice(&record);
            channel.packet_count += 1;
            channel.last_timestamp_us = timestamp_us;
            match direction {
                IacsRecordingDirection::EwsToAsset => {
                    channel.bytes_ews_to_asset += data.len() as u64;
                }
                IacsRecordingDirection::AssetToEws => {
                    channel.bytes_asset_to_ews += data.len() as u64;
                }
            }
        }

        let should_flush = !channel.batch_buf.is_empty()
            && (channel.batch_buf.len() >= self.config.batch_max_bytes
                || channel.batch_started.elapsed()
                    >= Duration::from_millis(self.config.batch_max_ms));

        if should_flush {
            flush_batch(channel)?;
        } else if data.is_empty() {
            // Empty keep-alive batch: still durable-ack after optional flush above.
        }

        // Always fdatasync after processing a batch boundary from the proxy.
        durable_sync(channel)?;
        channel.expected_batch_seq += 1;
        Ok(batch_seq)
    }

    /// Flush and close a channel. Returns gzip paths for the supervisor broker.
    pub fn end_channel(
        &mut self,
        session_id: &str,
        channel_id: u32,
        closed_at_us: u64,
    ) -> Option<IacsChannelEndPaths> {
        let session = self.sessions.get_mut(session_id)?;
        let mut channel = session.channels.remove(&channel_id)?;

        if !channel.batch_buf.is_empty()
            && flush_batch(&mut channel).is_err()
        {
            return None;
        }
        let _ = durable_sync(&mut channel);
        let _ = channel.writer.flush();

        let paths = IacsChannelEndPaths {
            src_relative: channel.pcap_relative.clone(),
            dst_relative: channel.gz_relative.clone(),
        };

        // Placeholder meta; blake3/size filled after supervisor gzip response.
        session.completed.push(IacsChannelMeta {
            index: channel.channel_index,
            target_host: channel.target_host.clone(),
            target_port: channel.target_port,
            file: format!("channels/{:03}.pcap.gz", channel.channel_index),
            blake3_hex: String::new(),
            file_size: 0,
            packet_count: channel.packet_count,
            bytes_ews_to_asset: channel.bytes_ews_to_asset,
            bytes_asset_to_ews: channel.bytes_asset_to_ews,
            opened_at_us: channel.opened_at_us,
            closed_at_us,
        });

        debug!(session_id = %session_id, channel_id, "IACS channel recording ended");
        Some(paths)
    }

    /// Attach gzip integrity metadata returned by the supervisor.
    pub fn finalize_channel_gzip(
        &mut self,
        session_id: &str,
        channel_id: u32,
        blake3_hex: String,
        file_size: u64,
    ) {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return;
        };
        if let Some(meta) = session
            .completed
            .iter_mut()
            .find(|m| m.index == channel_id)
        {
            meta.blake3_hex = blake3_hex;
            meta.file_size = file_size;
        }
    }

    pub fn end_session(&mut self, session_id: &str) -> Option<IacsSessionEndResult> {
        let session = self.sessions.remove(session_id)?;
        if !session.channels.is_empty() {
            warn!(
                session_id = %session_id,
                open = session.channels.len(),
                "IACS session ended with open channels"
            );
        }

        let total_packets: u64 = session.completed.iter().map(|c| c.packet_count).sum();
        let total_bytes: u64 = session.completed.iter().map(|c| c.file_size).sum();
        let opened = session.session_opened_at_us.unwrap_or(0);
        let closed = session
            .completed
            .iter()
            .map(|c| c.closed_at_us)
            .max()
            .unwrap_or(opened);
        let duration_ms = closed.saturating_sub(opened) / 1000;

        let blake3_hex = aggregate_channel_blake3(&session.completed);

        Some(IacsSessionEndResult {
            meta_json_relative_path: format!("{}/meta.json", session.base_dir),
            channels: session.completed,
            blake3_hex,
            total_bytes,
            total_packets,
            duration_ms,
        })
    }

    pub fn serialize_meta_json(result: &IacsSessionEndResult) -> String {
        #[derive(serde::Serialize)]
        struct Meta<'a> {
            format: &'a str,
            channels: &'a [IacsChannelMeta],
            blake3_hex: &'a str,
            total_bytes: u64,
            total_packets: u64,
            duration_ms: u64,
        }

        let meta = Meta {
            format: "pcap-bundle",
            channels: &result.channels,
            blake3_hex: &result.blake3_hex,
            total_bytes: result.total_bytes,
            total_packets: result.total_packets,
            duration_ms: result.duration_ms,
        };

        serde_json::to_string_pretty(&meta).unwrap_or_else(|_| "{}".to_string())
    }

    #[cfg(test)]
    pub fn active_channel_count(&self, session_id: &str) -> usize {
        self.sessions
            .get(session_id)
            .map(|s| s.channels.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn session_base_dir(&self, session_id: &str) -> Option<String> {
        self.sessions.get(session_id).map(|s| s.base_dir.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IacsRecordingError {
    UnknownSession,
    UnknownChannel,
    UnexpectedBatchSeq { expected: u64, got: u64 },
    Io(String),
}

fn flush_batch(channel: &mut ActiveChannel) -> Result<(), IacsRecordingError> {
    if channel.batch_buf.is_empty() {
        return Ok(());
    }
    channel
        .writer
        .write_all(&channel.batch_buf)
        .map_err(|e| IacsRecordingError::Io(e.to_string()))?;
    channel.batch_buf.clear();
    channel.batch_started = Instant::now();
    Ok(())
}

fn durable_sync(channel: &mut ActiveChannel) -> Result<(), IacsRecordingError> {
    channel
        .writer
        .flush()
        .map_err(|e| IacsRecordingError::Io(e.to_string()))?;
    channel
        .writer
        .get_mut()
        .sync_data()
        .map_err(|e| IacsRecordingError::Io(e.to_string()))
}

pub fn aggregate_channel_blake3(channels: &[IacsChannelMeta]) -> String {
    let mut hasher = blake3::Hasher::new();
    for ch in channels {
        if let Ok(bytes) = hex::decode(ch.blake3_hex.as_str()) {
            hasher.update(&bytes);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn build_global_header() -> [u8; PCAP_GLOBAL_HEADER_LEN] {
    let mut buf = [0u8; PCAP_GLOBAL_HEADER_LEN];
    buf[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes());
    buf[6..8].copy_from_slice(&4u16.to_le_bytes());
    buf[16..20].copy_from_slice(&65_535u32.to_le_bytes());
    buf[20..24].copy_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    buf
}

fn build_packet_record(timestamp_us: u64, data: &[u8]) -> Vec<u8> {
    let ts_sec = (timestamp_us / 1_000_000) as u32;
    let ts_usec = (timestamp_us % 1_000_000) as u32;
    let incl_len = data.len() as u32;
    let mut record = Vec::with_capacity(PCAP_RECORD_HEADER_LEN + data.len());
    record.extend_from_slice(&ts_sec.to_le_bytes());
    record.extend_from_slice(&ts_usec.to_le_bytes());
    record.extend_from_slice(&incl_len.to_le_bytes());
    record.extend_from_slice(&incl_len.to_le_bytes());
    record.extend_from_slice(data);
    record
}

fn unix_days_to_year_month(days: u64) -> (u32, u32) {
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

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    fn temp_pair() -> (File, File) {
        let f = tempfile::tempfile().unwrap();
        let f2 = f.try_clone().unwrap();
        (f, f2)
    }

    fn read_all(mut f: File) -> Vec<u8> {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_pcap_global_header_magic_and_linktype() {
        let h = build_global_header();
        assert_eq!(&h[0..4], &PCAP_MAGIC.to_le_bytes());
        assert_eq!(&h[20..24], &PCAP_LINKTYPE_RAW.to_le_bytes());
    }

    #[test]
    fn test_handle_data_writes_pcap_record() {
        let mut mgr = IacsRecordingManager::new();
        let (f, reader) = temp_pair();
        mgr.start_channel(
            "s1",
            1,
            f,
            "plc".into(),
            502,
            0,
        );
        mgr.handle_data(
            "s1",
            1,
            0,
            IacsRecordingDirection::EwsToAsset,
            1_000,
            b"\x00\x01",
        )
        .unwrap();
        mgr.end_channel("s1", 1, 2_000);

        let bytes = read_all(reader);
        assert!(bytes.len() >= PCAP_GLOBAL_HEADER_LEN + PCAP_RECORD_HEADER_LEN + 2);
    }

    #[test]
    fn test_batch_seq_must_be_monotonic() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0);
        mgr.handle_data(
            "s1",
            1,
            0,
            IacsRecordingDirection::EwsToAsset,
            0,
            b"a",
        )
        .unwrap();
        let err = mgr
            .handle_data(
                "s1",
                1,
                2,
                IacsRecordingDirection::EwsToAsset,
                0,
                b"b",
            )
            .unwrap_err();
        assert_eq!(
            err,
            IacsRecordingError::UnexpectedBatchSeq {
                expected: 1,
                got: 2
            }
        );
    }

    #[test]
    fn test_meta_json_path_reuses_channel_base_dir() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0);
        let base_dir = mgr.session_base_dir("s1").expect("session");
        mgr.end_channel("s1", 1, 1_000);
        let end = mgr.end_session("s1").expect("session");
        assert_eq!(end.meta_json_relative_path, format!("{base_dir}/meta.json"));
    }

    #[test]
    fn test_end_session_meta_json_format() {
        let result = IacsSessionEndResult {
            meta_json_relative_path: "2026/05/s1/meta.json".into(),
            channels: vec![IacsChannelMeta {
                index: 1,
                target_host: "plc".into(),
                target_port: 502,
                file: "channels/001.pcap.gz".into(),
                blake3_hex: "aa".repeat(32),
                file_size: 100,
                packet_count: 3,
                bytes_ews_to_asset: 50,
                bytes_asset_to_ews: 50,
                opened_at_us: 0,
                closed_at_us: 1_000_000,
            }],
            blake3_hex: "bb".repeat(32),
            total_bytes: 100,
            total_packets: 3,
            duration_ms: 1000,
        };
        let json = IacsRecordingManager::serialize_meta_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["format"], "pcap-bundle");
        assert_eq!(parsed["channels"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_crash_resilience_partial_pcap() {
        let mut mgr = IacsRecordingManager::new();
        let (f, reader) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0);
        let _ = mgr.handle_data(
            "s1",
            1,
            0,
            IacsRecordingDirection::EwsToAsset,
            0,
            b"partial",
        );
        drop(mgr);
        let bytes = read_all(reader);
        assert!(bytes.len() >= PCAP_GLOBAL_HEADER_LEN);
    }

    #[test]
    fn test_compute_channel_paths() {
        let base = IacsRecordingManager::compute_base_dir("uuid");
        let pcap = IacsRecordingManager::compute_channel_pcap_path("uuid", 3);
        assert_eq!(pcap, format!("{base}/channels/003.pcap"));
        assert!(pcap.ends_with("/uuid/channels/003.pcap"));
    }

    #[test]
    fn test_multi_channel_session() {
        let mut mgr = IacsRecordingManager::new();
        let (f1, _) = temp_pair();
        let (f2, _) = temp_pair();
        mgr.start_channel("s1", 1, f1, "a".into(), 502, 0);
        mgr.start_channel("s1", 2, f2, "b".into(), 4840, 0);
        assert_eq!(mgr.active_channel_count("s1"), 2);
        mgr.end_channel("s1", 1, 100);
        mgr.end_channel("s1", 2, 200);
        let result = mgr.end_session("s1").unwrap();
        assert_eq!(result.channels.len(), 2);
    }

    #[test]
    fn test_aggregate_channel_blake3() {
        let channels = vec![
            IacsChannelMeta {
                index: 1,
                target_host: "a".into(),
                target_port: 1,
                file: "f".into(),
                blake3_hex: "00".repeat(32),
                file_size: 1,
                packet_count: 1,
                bytes_ews_to_asset: 1,
                bytes_asset_to_ews: 0,
                opened_at_us: 0,
                closed_at_us: 1,
            },
            IacsChannelMeta {
                index: 2,
                target_host: "b".into(),
                target_port: 2,
                file: "f2".into(),
                blake3_hex: "ff".repeat(32),
                file_size: 2,
                packet_count: 1,
                bytes_ews_to_asset: 0,
                bytes_asset_to_ews: 2,
                opened_at_us: 0,
                closed_at_us: 2,
            },
        ];
        let agg = aggregate_channel_blake3(&channels);
        assert_eq!(agg.len(), 64);
    }

    #[test]
    fn test_batch_flush_on_size_threshold() {
        let mut mgr = IacsRecordingManager::with_config(IacsRecordingConfig {
            batch_max_bytes: 32,
            batch_max_ms: 60_000,
        });
        let (f, reader) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0);
        let payload = vec![0xAB; 40];
        mgr.handle_data(
            "s1",
            1,
            0,
            IacsRecordingDirection::EwsToAsset,
            0,
            &payload,
        )
        .unwrap();
        let bytes = read_all(reader);
        assert!(bytes.len() > PCAP_GLOBAL_HEADER_LEN + 40);
    }

    #[test]
    fn test_unknown_session_and_channel_errors() {
        let mut mgr = IacsRecordingManager::new();
        assert_eq!(
            mgr.handle_data(
                "missing",
                1,
                0,
                IacsRecordingDirection::EwsToAsset,
                0,
                b"x"
            )
            .unwrap_err(),
            IacsRecordingError::UnknownSession
        );
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0);
        assert_eq!(
            mgr.handle_data(
                "s1",
                9,
                0,
                IacsRecordingDirection::EwsToAsset,
                0,
                b"x"
            )
            .unwrap_err(),
            IacsRecordingError::UnknownChannel
        );
    }
}
