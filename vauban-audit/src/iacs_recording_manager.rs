//! IACS tunnel PCAP recording manager.
//!
//! Writes one PCAP file per `direct-tcpip` channel with batching,
//! `fdatasync`, and a session-level `meta.json` for the
//! `pcap-bundle` recording format. File creation, gzip and unlink
//! are delegated to the supervisor (vauban-audit runs under
//! Capsicum and cannot `open()` / `unlink()` directly).
//!
//! Each recorded chunk is wrapped in a synthetic IPv4 (or IPv6)
//! plus TCP layer (see [`crate::iacs_pcap_synth`]) so the resulting
//! `.pcap.gz` files dissect natively in tcpdump, Wireshark and Zeek
//! -- industrial protocol dissectors (Modbus/TCP, OPC-UA, S7,
//! EtherNet/IP, ...) recognise the application bytes without any
//! post-processing.
//!
//! Determinism: directory layout (`YYYY/MM/UUID/`) is anchored on
//! the proxy-supplied `connected_at_us` timestamp. The audit
//! service never calls `SystemTime::now()` to compute paths, so a
//! tunnel that straddles a month boundary cannot split its
//! artefacts across two month folders.

use crate::iacs_pcap_synth::{
    self, Direction, Endpoints, TcpFlow, build_global_header, build_handshake,
};
use shared::messages::IacsRecordingDirection;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

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

/// Metadata for a finalized channel after gzip.
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

/// Session identity received in `IacsRecordingSessionStart` at
/// SSH-auth time. Serialized into `{base_dir}/session.json` so even
/// a zero-channel login leaves an audit artefact: who, which key,
/// from where, when.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IacsSessionStartInfo {
    pub user_uuid: String,
    pub asset_uuid: String,
    pub ews_fingerprint: String,
    pub peer_ip: String,
    pub authenticated_at_us: u64,
    pub connected_at_us: u64,
}

/// Result of finalizing an entire IACS SSH session recording.
pub struct IacsSessionEndResult {
    pub meta_json_relative_path: String,
    pub channels: Vec<IacsChannelMeta>,
    pub blake3_hex: String,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub duration_ms: u64,
    /// `session.json` path + identity when a
    /// `IacsRecordingSessionStart` was received (sessions born
    /// after the `ews_connected` rollout). `None` for legacy
    /// sessions created lazily by the first channel.
    pub session_json_relative_path: Option<String>,
    pub start_info: Option<IacsSessionStartInfo>,
}

/// Paths needed to gzip a channel PCAP via the supervisor.
pub struct IacsChannelEndPaths {
    pub src_relative: String,
    pub dst_relative: String,
}

/// Endpoints supplied by the proxy at channel-open time, used to
/// build the synthetic IPv4/v6 + TCP layer.
#[derive(Debug, Clone)]
pub struct IacsChannelEndpoints {
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
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
    target_host: String,
    target_port: u16,
    pcap_relative: String,
    gz_relative: String,
    channel_index: u32,
    flow: TcpFlow,
}

struct IacsRecordingSession {
    /// Captured at session creation from `connected_at_us`; reused
    /// for every PCAP path and `meta.json` so a long-lived tunnel
    /// cannot split artefacts across two month directories.
    base_dir: String,
    channels: HashMap<u32, ActiveChannel>,
    completed: Vec<IacsChannelMeta>,
    session_opened_at_us: Option<u64>,
    /// Set by `start_session` (auth-time `SessionStart` IPC);
    /// `None` for legacy sessions created lazily by the first
    /// channel.
    start_info: Option<IacsSessionStartInfo>,
}

/// Manages concurrent IACS PCAP recordings keyed by Vauban session UUID.
pub struct IacsRecordingManager {
    sessions: HashMap<String, IacsRecordingSession>,
    config: IacsRecordingConfig,
}

impl Default for IacsRecordingManager {
    fn default() -> Self {
        Self::new()
    }
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

    /// Compute the base directory (relative to the recording
    /// storage root) for a session anchored on a wall-clock
    /// timestamp in microseconds since the UNIX epoch. The audit
    /// process MUST pass the proxy-supplied `connected_at_us`
    /// rather than `SystemTime::now()` so the directory is
    /// stable even when the first channel opens minutes after the
    /// tunnel went `tunnel_active` and across month boundaries.
    pub fn compute_base_dir(session_id: &str, connected_at_us: u64) -> String {
        let secs = connected_at_us / 1_000_000;
        let days = secs / 86_400;
        let (year, month) = unix_days_to_year_month(days);
        format!("{year}/{month:02}/{session_id}")
    }

    /// Compute the relative `.pcap` path for a channel, anchored on
    /// `connected_at_us` (same rule as `compute_base_dir`).
    pub fn compute_channel_pcap_path(
        session_id: &str,
        channel_id: u32,
        connected_at_us: u64,
    ) -> String {
        format!(
            "{}/channels/{:03}.pcap",
            Self::compute_base_dir(session_id, connected_at_us),
            channel_id
        )
    }

    /// Create the session recording state at SSH-auth time
    /// (`IacsRecordingSessionStart`). The base directory is anchored
    /// on `info.connected_at_us` -- the SAME anchor every subsequent
    /// `start_channel` carries -- so `session.json`, `meta.json`
    /// and the channel PCAPs always land in one directory.
    ///
    /// Returns the relative path of `session.json` so the caller
    /// can broker the file from the supervisor and write the
    /// serialized identity immediately. Idempotent: a re-delivered
    /// `SessionStart` refreshes `start_info` but never moves an
    /// existing `base_dir`.
    pub fn start_session(&mut self, session_id: &str, info: IacsSessionStartInfo) -> String {
        let connected_at_us = info.connected_at_us;
        let session = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| IacsRecordingSession {
                base_dir: Self::compute_base_dir(session_id, connected_at_us),
                channels: HashMap::new(),
                completed: Vec::new(),
                session_opened_at_us: Some(info.authenticated_at_us),
                start_info: None,
            });
        session.start_info = Some(info);
        format!("{}/session.json", session.base_dir)
    }

    /// Serialize the `session.json` document. `ended` carries
    /// `(ended_at_us, reason)` at session end; `None` at start.
    pub fn serialize_session_json(
        session_id: &str,
        info: &IacsSessionStartInfo,
        ended: Option<(u64, &str)>,
    ) -> String {
        #[derive(serde::Serialize)]
        struct SessionJson<'a> {
            session_id: &'a str,
            user_uuid: &'a str,
            asset_uuid: &'a str,
            ews_fingerprint: &'a str,
            peer_ip: &'a str,
            authenticated_at_us: u64,
            connected_at_us: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            ended_at_us: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<&'a str>,
        }
        let doc = SessionJson {
            session_id,
            user_uuid: &info.user_uuid,
            asset_uuid: &info.asset_uuid,
            ews_fingerprint: &info.ews_fingerprint,
            peer_ip: &info.peer_ip,
            authenticated_at_us: info.authenticated_at_us,
            connected_at_us: info.connected_at_us,
            ended_at_us: ended.map(|(us, _)| us),
            reason: ended.map(|(_, r)| r),
        };
        serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
    }

    /// Open a new channel recording. The supervisor-brokered `file`
    /// is used as the write FD; vauban-audit never `open()`s
    /// directly. The `endpoints` are used to build the synthetic
    /// IPv4/v6 + TCP layer wrapped around every captured chunk so
    /// the resulting PCAP dissects natively in Wireshark / tcpdump
    /// (Modbus/TCP, OPC-UA, S7 etc. are recognised by the
    /// application dissectors).
    #[allow(clippy::too_many_arguments)]
    pub fn start_channel(
        &mut self,
        session_id: &str,
        channel_id: u32,
        file: File,
        target_host: String,
        target_port: u16,
        opened_at_us: u64,
        connected_at_us: u64,
        endpoints: IacsChannelEndpoints,
    ) {
        let session = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| IacsRecordingSession {
                base_dir: Self::compute_base_dir(session_id, connected_at_us),
                channels: HashMap::new(),
                completed: Vec::new(),
                session_opened_at_us: Some(opened_at_us),
                start_info: None,
            });

        if session.channels.contains_key(&channel_id) {
            warn!(
                session_id = %session_id,
                channel_id,
                "Duplicate IACS channel start, ignoring"
            );
            return;
        }

        let pcap_relative = format!("{}/channels/{:03}.pcap", session.base_dir, channel_id);
        let gz_relative = format!("{}/channels/{:03}.pcap.gz", session.base_dir, channel_id);

        let parsed_endpoints = Endpoints::parse(
            &endpoints.client_ip,
            endpoints.client_port,
            &endpoints.server_ip,
            endpoints.server_port,
        );
        let flow = TcpFlow::new(session_id, channel_id, parsed_endpoints);

        let mut writer = BufWriter::new(file);
        if writer.write_all(&build_global_header()).is_err() {
            warn!(session_id = %session_id, channel_id, "Failed to write PCAP global header");
            return;
        }

        // Emit the SYN / SYN-ACK / ACK three-way handshake before
        // any data segment. Wireshark / tcpdump rely on the SYNs to
        // anchor the conversation and offer the application
        // dissectors (Modbus, OPC-UA, ...).
        for record in build_handshake(&flow, opened_at_us) {
            if writer.write_all(&record).is_err() {
                warn!(session_id = %session_id, channel_id, "Failed to write IACS handshake records");
                return;
            }
        }

        // 3 records (SYN/SYN-ACK/ACK) emitted on disk; counted at
        // end_session via `packet_count + 3` so duplicate-start /
        // early-return paths do not accidentally include them.

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
                target_host,
                target_port,
                pcap_relative,
                gz_relative,
                channel_index: channel_id,
                flow,
            },
        );

        debug!(session_id = %session_id, channel_id, "IACS channel recording started");
    }

    /// Persist one relay batch. Returns the acknowledged `batch_seq`
    /// on success.
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
            let synth_dir = match direction {
                IacsRecordingDirection::EwsToAsset => Direction::ClientToServer,
                IacsRecordingDirection::AssetToEws => Direction::ServerToClient,
            };
            let records = iacs_pcap_synth::build_data_records(
                &mut channel.flow,
                synth_dir,
                data,
                timestamp_us,
            );
            for record in &records {
                channel.batch_buf.extend_from_slice(record);
            }
            // build_data_records emits 2 records per IP-segment (data
            // + cumulative ACK). One application chunk may straddle
            // multiple segments under MTU pressure but we surface the
            // exact PCAP record count here so meta.json reflects what
            // is actually on disk.
            channel.packet_count += records.len() as u64;
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
        }

        // Always fdatasync after processing a batch boundary from
        // the proxy: the relay only forwards bytes after the audit
        // ack, so the durability invariant is "every byte the asset
        // saw was synced before".
        durable_sync(channel)?;
        channel.expected_batch_seq += 1;
        Ok(batch_seq)
    }

    /// Flush, write the FIN-FIN close, and close a channel. Returns
    /// gzip paths for the supervisor broker.
    pub fn end_channel(
        &mut self,
        session_id: &str,
        channel_id: u32,
        closed_at_us: u64,
    ) -> Option<IacsChannelEndPaths> {
        let session = self.sessions.get_mut(session_id)?;
        let mut channel = session.channels.remove(&channel_id)?;

        // Drain any pending batched records before the FIN sequence
        // so the close is always the last 4 records on disk.
        if !channel.batch_buf.is_empty() && flush_batch(&mut channel).is_err() {
            return None;
        }

        let close_records = iacs_pcap_synth::build_close(&channel.flow, closed_at_us);
        for record in &close_records {
            if channel.writer.write_all(record).is_err() {
                warn!(session_id = %session_id, channel_id, "Failed to write IACS close records");
                return None;
            }
        }
        channel.packet_count += close_records.len() as u64;

        let _ = durable_sync(&mut channel);
        let _ = channel.writer.flush();

        let paths = IacsChannelEndPaths {
            src_relative: channel.pcap_relative.clone(),
            dst_relative: channel.gz_relative.clone(),
        };

        // Placeholder meta; blake3/size filled after supervisor gzip
        // response.
        session.completed.push(IacsChannelMeta {
            index: channel.channel_index,
            target_host: channel.target_host.clone(),
            target_port: channel.target_port,
            file: format!("channels/{:03}.pcap.gz", channel.channel_index),
            blake3_hex: String::new(),
            file_size: 0,
            // Account for the 3 handshake records emitted at
            // start_channel (data segments + ACKs were already
            // counted; close records were just counted above).
            packet_count: channel.packet_count + 3,
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
        if let Some(meta) = session.completed.iter_mut().find(|m| m.index == channel_id) {
            meta.blake3_hex = blake3_hex;
            meta.file_size = file_size;
        }
    }

    /// Finalize a session. Returns `Some` for every known session,
    /// INCLUDING zero-channel logins created by `start_session`
    /// (`channels` is then empty and `meta.json` still gets
    /// written -- the pre-`ews_connected` behaviour of swallowing
    /// channel-less sessions is exactly what this fixes). `None`
    /// only for sessions the manager never heard about.
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
            session_json_relative_path: session
                .start_info
                .as_ref()
                .map(|_| format!("{}/session.json", session.base_dir)),
            start_info: session.start_info,
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

/// BLAKE3 over the concatenated ASCII hex digests of every channel
/// (in `completed` order). Mirrors the RDP segment aggregation rule
/// (see `vauban-web::recording_hydrator::aggregate_rdp_blake3`) so
/// the documentation claim that "IACS aggregate follows the same
/// concat-of-channel-digests rule as RDP" is literally true.
pub fn aggregate_channel_blake3(channels: &[IacsChannelMeta]) -> String {
    let mut hasher = blake3::Hasher::new();
    for ch in channels {
        hasher.update(ch.blake3_hex.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Civil date conversion (Howard Hinnant's algorithm). Pure
/// arithmetic, no allocations, no `chrono` dep.
fn unix_days_to_year_month(days: u64) -> (u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
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

    fn endpoints() -> IacsChannelEndpoints {
        IacsChannelEndpoints {
            client_ip: "192.0.2.10".to_string(),
            client_port: 49_152,
            server_ip: "198.51.100.20".to_string(),
            server_port: 502,
        }
    }

    fn ipv6_endpoints() -> IacsChannelEndpoints {
        IacsChannelEndpoints {
            client_ip: "2001:db8::1".to_string(),
            client_port: 49_152,
            server_ip: "2001:db8::2".to_string(),
            server_port: 4840,
        }
    }

    #[test]
    fn pcap_global_header_magic_and_linktype_match_synth() {
        let h = build_global_header();
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let linktype = u32::from_le_bytes([h[20], h[21], h[22], h[23]]);
        assert_eq!(magic, iacs_pcap_synth::PCAP_GLOBAL_MAGIC);
        assert_eq!(linktype, iacs_pcap_synth::LINKTYPE_RAW);
    }

    #[test]
    fn handle_data_writes_synthetic_ip_tcp_records() {
        let mut mgr = IacsRecordingManager::new();
        let (f, reader) = temp_pair();
        mgr.start_channel("s1", 1, f, "plc".into(), 502, 0, 0, endpoints());
        mgr.handle_data(
            "s1",
            1,
            0,
            IacsRecordingDirection::EwsToAsset,
            1_000,
            b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",
        )
        .unwrap();
        mgr.end_channel("s1", 1, 2_000);

        let bytes = read_all(reader);
        // Global header (24) + 3 handshake records + 2 data records
        // (PSH+ACK + ACK) + 4 close records.
        assert!(bytes.len() > 24);
        let global_magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(global_magic, iacs_pcap_synth::PCAP_GLOBAL_MAGIC);
    }

    #[test]
    fn batch_seq_must_be_monotonic() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
        mgr.handle_data("s1", 1, 0, IacsRecordingDirection::EwsToAsset, 0, b"a")
            .unwrap();
        let err = mgr
            .handle_data("s1", 1, 2, IacsRecordingDirection::EwsToAsset, 0, b"b")
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
    fn meta_json_path_reuses_session_base_dir() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        // 1714521600_000_000 = 2024-05-01 00:00:00 UTC
        let connected_at_us: u64 = 1_714_521_600_000_000;
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, connected_at_us, endpoints());
        let base_dir = mgr.session_base_dir("s1").expect("session");
        assert_eq!(base_dir, "2024/05/s1");
        mgr.end_channel("s1", 1, 1_000);
        let end = mgr.end_session("s1").expect("session");
        assert_eq!(end.meta_json_relative_path, format!("{base_dir}/meta.json"));
    }

    #[test]
    fn compute_base_dir_is_deterministic_across_month_boundary() {
        // 2024-04-30 23:59:59.999999 UTC
        let just_before = 1_714_521_599_999_999u64;
        // 2024-05-01 00:00:00.000000 UTC
        let on_dot = 1_714_521_600_000_000u64;
        assert_eq!(
            IacsRecordingManager::compute_base_dir("uuid", just_before),
            "2024/04/uuid"
        );
        assert_eq!(
            IacsRecordingManager::compute_base_dir("uuid", on_dot),
            "2024/05/uuid"
        );
    }

    #[test]
    fn compute_channel_pcap_path_uses_anchor() {
        let connected_at_us: u64 = 1_714_521_600_000_000; // 2024-05-01
        let path = IacsRecordingManager::compute_channel_pcap_path("uuid", 3, connected_at_us);
        assert_eq!(path, "2024/05/uuid/channels/003.pcap");
    }

    #[test]
    fn end_session_meta_json_format() {
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
            session_json_relative_path: None,
            start_info: None,
        };
        let json = IacsRecordingManager::serialize_meta_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["format"], "pcap-bundle");
        assert_eq!(parsed["channels"].as_array().unwrap().len(), 1);
    }

    fn start_info(connected_at_us: u64) -> IacsSessionStartInfo {
        IacsSessionStartInfo {
            user_uuid: "0d9f5bd8-0000-0000-0000-000000000001".into(),
            asset_uuid: "0d9f5bd8-0000-0000-0000-000000000002".into(),
            ews_fingerprint: "ab".repeat(32),
            peer_ip: "203.0.113.9".into(),
            authenticated_at_us: connected_at_us,
            connected_at_us,
        }
    }

    #[test]
    fn start_session_anchors_base_dir_on_connected_at() {
        let mut mgr = IacsRecordingManager::new();
        // 1714521600_000_000 = 2024-05-01 00:00:00 UTC
        let rel = mgr.start_session("s1", start_info(1_714_521_600_000_000));
        assert_eq!(rel, "2024/05/s1/session.json");
        assert_eq!(mgr.session_base_dir("s1").as_deref(), Some("2024/05/s1"));
    }

    #[test]
    fn start_channel_after_start_session_reuses_the_same_base_dir() {
        // The session/channel anchor identity: `session.json`,
        // `meta.json` and every channel PCAP land in ONE directory.
        let mut mgr = IacsRecordingManager::new();
        let anchor = 1_714_521_600_000_000u64;
        let rel = mgr.start_session("s1", start_info(anchor));
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, anchor + 5, anchor, endpoints());
        let base = mgr.session_base_dir("s1").expect("session");
        assert!(rel.starts_with(&base));
        mgr.end_channel("s1", 1, anchor + 10);
        let end = mgr.end_session("s1").expect("session");
        assert_eq!(end.meta_json_relative_path, format!("{base}/meta.json"));
        assert_eq!(
            end.session_json_relative_path.as_deref(),
            Some("2024/05/s1/session.json")
        );
    }

    #[test]
    fn end_session_zero_channel_still_returns_meta_json() {
        // The pre-`ews_connected` regression: a session that never
        // opened a channel was swallowed (`remove(...)? -> None`)
        // and left NO artefact. With `start_session` the entry
        // exists, `end_session` returns `Some`, and `meta.json`
        // is written with `channels: []`.
        let mut mgr = IacsRecordingManager::new();
        mgr.start_session("s1", start_info(1_714_521_600_000_000));
        let end = mgr.end_session("s1").expect("zero-channel session");
        assert!(end.channels.is_empty());
        assert_eq!(end.meta_json_relative_path, "2024/05/s1/meta.json");
        assert!(end.start_info.is_some());

        let json = IacsRecordingManager::serialize_meta_json(&end);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["format"], "pcap-bundle");
        assert_eq!(parsed["channels"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["total_bytes"], 0);
        // Aggregate of zero channels: BLAKE3 of the empty input --
        // still a valid 64-char hex the hydrator accepts.
        assert_eq!(parsed["blake3_hex"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn end_session_unknown_session_stays_none() {
        let mut mgr = IacsRecordingManager::new();
        assert!(mgr.end_session("never-seen").is_none());
    }

    #[test]
    fn start_session_is_idempotent_and_never_moves_base_dir() {
        let mut mgr = IacsRecordingManager::new();
        let first = mgr.start_session("s1", start_info(1_714_521_600_000_000));
        // Re-delivery with a different (later) anchor must NOT
        // relocate the directory.
        let second = mgr.start_session("s1", start_info(1_717_200_000_000_000));
        assert_eq!(first, second);
        assert_eq!(mgr.session_base_dir("s1").as_deref(), Some("2024/05/s1"));
    }

    #[test]
    fn session_json_start_and_end_forms() {
        let info = start_info(1_714_521_600_000_000);
        let at_start = IacsRecordingManager::serialize_session_json("s1", &info, None);
        let parsed: serde_json::Value = serde_json::from_str(&at_start).unwrap();
        assert_eq!(parsed["session_id"], "s1");
        assert_eq!(parsed["peer_ip"], "203.0.113.9");
        assert_eq!(parsed["ews_fingerprint"], "ab".repeat(32));
        assert!(parsed.get("ended_at_us").is_none());
        assert!(parsed.get("reason").is_none());

        let at_end = IacsRecordingManager::serialize_session_json(
            "s1",
            &info,
            Some((1_714_521_660_000_000, "admin_terminate")),
        );
        let parsed: serde_json::Value = serde_json::from_str(&at_end).unwrap();
        assert_eq!(parsed["ended_at_us"], 1_714_521_660_000_000u64);
        assert_eq!(parsed["reason"], "admin_terminate");
    }

    #[test]
    fn crash_resilience_partial_pcap_still_starts_with_global_header() {
        let mut mgr = IacsRecordingManager::new();
        let (f, reader) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
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
        // Even if the writer was dropped mid-stream the global
        // header was the first thing flushed (BufWriter drops do
        // not panic on flush failure but our test uses a tempfile
        // so the flush is guaranteed best-effort).
        assert!(bytes.len() >= iacs_pcap_synth::PCAP_GLOBAL_HEADER_LEN);
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(magic, iacs_pcap_synth::PCAP_GLOBAL_MAGIC);
    }

    #[test]
    fn multi_channel_session_keeps_disjoint_state() {
        let mut mgr = IacsRecordingManager::new();
        let (f1, _) = temp_pair();
        let (f2, _) = temp_pair();
        mgr.start_channel("s1", 1, f1, "a".into(), 502, 0, 0, endpoints());
        mgr.start_channel("s1", 2, f2, "b".into(), 4840, 0, 0, ipv6_endpoints());
        assert_eq!(mgr.active_channel_count("s1"), 2);
        mgr.end_channel("s1", 1, 100);
        mgr.end_channel("s1", 2, 200);
        let result = mgr.end_session("s1").unwrap();
        assert_eq!(result.channels.len(), 2);
    }

    #[test]
    fn aggregate_channel_blake3_uses_ascii_hex_bytes_like_rdp() {
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

        // Cross-validate with a hand-rolled BLAKE3 over the ASCII
        // hex bytes (NOT the decoded bytes -- the previous
        // behaviour was decoded; v0.7.20 aligns IACS with RDP).
        let mut h = blake3::Hasher::new();
        h.update(channels[0].blake3_hex.as_bytes());
        h.update(channels[1].blake3_hex.as_bytes());
        let expected = h.finalize().to_hex().to_string();
        assert_eq!(agg, expected);
    }

    #[test]
    fn aggregate_channel_blake3_matches_rdp_aggregate_rule() {
        // Two synthetic per-channel digests. We hand-implement the
        // RDP aggregation (BLAKE3 over the concatenated ASCII hex
        // digests in order) and assert IACS produces the same
        // bytes given the same input sequence.
        let digests = ["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)];

        let iacs_input: Vec<IacsChannelMeta> = digests
            .iter()
            .enumerate()
            .map(|(i, d)| IacsChannelMeta {
                index: i as u32,
                target_host: "h".into(),
                target_port: 0,
                file: "f".into(),
                blake3_hex: d.clone(),
                file_size: 0,
                packet_count: 0,
                bytes_ews_to_asset: 0,
                bytes_asset_to_ews: 0,
                opened_at_us: 0,
                closed_at_us: 0,
            })
            .collect();

        let mut hasher = blake3::Hasher::new();
        for d in &digests {
            hasher.update(d.as_bytes());
        }
        let rdp_style = hasher.finalize().to_hex().to_string();

        assert_eq!(aggregate_channel_blake3(&iacs_input), rdp_style);
    }

    #[test]
    fn batch_flush_on_size_threshold() {
        let mut mgr = IacsRecordingManager::with_config(IacsRecordingConfig {
            batch_max_bytes: 32,
            batch_max_ms: 60_000,
        });
        let (f, reader) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
        let payload = vec![0xAB; 40];
        mgr.handle_data("s1", 1, 0, IacsRecordingDirection::EwsToAsset, 0, &payload)
            .unwrap();
        let bytes = read_all(reader);
        // Global header + handshake (3 records) + at least the
        // 40-byte data record plus its IPv4+TCP headers + cumulative
        // ACK = >= 24 + 3*(16+40) + (16+60) + (16+40) bytes
        assert!(bytes.len() > 24 + 100);
    }

    #[test]
    fn unknown_session_and_channel_errors() {
        let mut mgr = IacsRecordingManager::new();
        assert_eq!(
            mgr.handle_data("missing", 1, 0, IacsRecordingDirection::EwsToAsset, 0, b"x")
                .unwrap_err(),
            IacsRecordingError::UnknownSession
        );
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
        assert_eq!(
            mgr.handle_data("s1", 9, 0, IacsRecordingDirection::EwsToAsset, 0, b"x")
                .unwrap_err(),
            IacsRecordingError::UnknownChannel
        );
    }

    #[test]
    fn duplicate_channel_start_is_ignored() {
        let mut mgr = IacsRecordingManager::new();
        let (f1, _) = temp_pair();
        let (f2, _) = temp_pair();
        mgr.start_channel("s1", 1, f1, "h".into(), 502, 0, 0, endpoints());
        mgr.start_channel("s1", 1, f2, "h".into(), 502, 0, 0, endpoints());
        assert_eq!(mgr.active_channel_count("s1"), 1);
    }

    #[test]
    fn end_channel_returns_gzip_paths() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
        let paths = mgr.end_channel("s1", 1, 1_000).unwrap();
        assert!(paths.src_relative.ends_with("/channels/001.pcap"));
        assert!(paths.dst_relative.ends_with("/channels/001.pcap.gz"));
    }

    #[test]
    fn finalize_channel_gzip_attaches_blake3_to_completed_meta() {
        let mut mgr = IacsRecordingManager::new();
        let (f, _) = temp_pair();
        mgr.start_channel("s1", 1, f, "h".into(), 502, 0, 0, endpoints());
        let _ = mgr.end_channel("s1", 1, 1_000);
        mgr.finalize_channel_gzip("s1", 1, "ab".repeat(32), 4242);
        let result = mgr.end_session("s1").unwrap();
        assert_eq!(result.channels.len(), 1);
        assert_eq!(result.channels[0].blake3_hex, "ab".repeat(32));
        assert_eq!(result.channels[0].file_size, 4242);
        assert_eq!(result.total_bytes, 4242);
    }
}
