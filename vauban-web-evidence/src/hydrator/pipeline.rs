//! Recording integrity hydrator pipeline (trait-parameterized, no web deps).

use std::sync::Arc;
use std::time::Duration;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::deps::{HydratorDb, MetaFd, MetaFdOutcome, Notify, PendingCandidate, SessionKind};

/// Stable identifier used by [`shared::tasks::spawn_periodic`] for
/// the recording hydrator's daily reconciliation cron.
pub const TASK_NAME: &str = "recording_hydrator";

pub const FORMAT_ASCIICAST_V2: &str = "asciicast-v2";
pub const FORMAT_FMP4_DASH: &str = "fmp4-dash";
pub const FORMAT_FMP4_FLAT: &str = "fmp4-flat";
pub const FORMAT_PCAP_BUNDLE: &str = "pcap-bundle";

#[derive(Debug, Deserialize)]
struct SshMeta {
    #[serde(default)]
    format: Option<String>,
    blake3_hex: String,
    total_bytes: u64,
    total_events: u64,
    duration_secs: f64,
    width: u16,
    height: u16,
}

#[derive(Debug, Deserialize)]
struct RdpSegment {
    #[allow(dead_code)]
    index: u32,
    width: u16,
    height: u16,
    duration_ticks: u64,
    #[allow(dead_code)]
    init_size: u64,
    file_size: u64,
    blake3_hex: String,
    codec_string: String,
}

#[derive(Debug, Deserialize)]
struct RdpMeta {
    segments: Vec<RdpSegment>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IacsChannelMeta {
    index: u32,
    target_host: String,
    target_port: u16,
    file: String,
    blake3_hex: String,
    file_size: u64,
    packet_count: u64,
}

#[derive(Debug, Deserialize)]
struct IacsPcapMeta {
    format: Option<String>,
    blake3_hex: String,
    total_bytes: u64,
    total_packets: u64,
    duration_ms: u64,
    channels: Vec<IacsChannelMeta>,
}

/// Bundle persisted on `proxy_sessions` after a successful tick.
#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityBundle {
    pub blake3_hex: String,
    pub size_bytes: i64,
    pub duration_ms: i64,
    pub event_count: Option<i32>,
    pub format: String,
    pub width: i16,
    pub height: i16,
    pub segment_count: Option<i32>,
    pub codec: Option<String>,
}

/// Outcome of a single tick (used by tests and metrics).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HydrationReport {
    pub scanned: usize,
    pub finalized: usize,
    pub skipped_missing_meta: usize,
    pub marked_finalized_lost: usize,
    pub marked_finalized_legacy_flat: usize,
    pub marked_finalized_corrupt: usize,
    pub errored: usize,
}

/// Errors raised by the hydrator's tick loop.
#[derive(Debug, thiserror::Error)]
pub enum HydrationError {
    #[error("database error: {0}")]
    Database(String),
    #[error("supervisor unavailable")]
    SupervisorMissing,
}

/// Lazy background hydrator parameterized over DB, meta FD, and notify seams.
pub struct RecordingHydrator<D, F, N> {
    db: D,
    meta_fd: F,
    batch_size: i64,
    storage_base: String,
    missing_meta_grace: Duration,
    notify: Option<Arc<N>>,
}

impl<D, F, N> RecordingHydrator<D, F, N>
where
    D: HydratorDb,
    F: MetaFd,
    N: Notify,
{
    pub fn new(
        db: D,
        meta_fd: F,
        batch_size: i64,
        storage_base: String,
        missing_meta_grace: Duration,
        notify: Option<Arc<N>>,
    ) -> Self {
        Self {
            db,
            meta_fd,
            batch_size,
            storage_base,
            missing_meta_grace,
            notify,
        }
    }

    pub async fn tick(&self) -> Result<HydrationReport, HydrationError> {
        let candidates = self
            .db
            .load_pending_candidates(self.batch_size)
            .await
            .map_err(HydrationError::Database)?;

        let mut report = HydrationReport {
            scanned: candidates.len(),
            ..Default::default()
        };

        let now = Utc::now();
        for candidate in candidates {
            self.process_candidate(&mut report, &candidate, now).await;
        }

        Ok(report)
    }

    pub async fn hydrate_session_id(
        &self,
        session_id: i32,
    ) -> Result<HydrationReport, HydrationError> {
        let mut report = HydrationReport::default();
        let candidate = self
            .db
            .load_pending_by_id(session_id)
            .await
            .map_err(HydrationError::Database)?;

        let candidate = match candidate {
            Some(c) => c,
            None => {
                debug!(
                    session_id,
                    "hydrator: nothing to hydrate (already finalized, not recorded, or no path)"
                );
                return Ok(report);
            }
        };
        report.scanned = 1;
        self.process_candidate(&mut report, &candidate, Utc::now())
            .await;
        Ok(report)
    }

    async fn process_candidate(
        &self,
        report: &mut HydrationReport,
        candidate: &PendingCandidate,
        now: DateTime<Utc>,
    ) {
        let PendingCandidate {
            id,
            uuid,
            session_kind,
            recording_path,
            disconnected_at,
            created_at,
        } = candidate;

        if !recording_path.ends_with('/') {
            match self.db.mark_finalized_legacy_flat(*id).await {
                Ok(()) => {
                    info!(
                        session_uuid = %uuid,
                        recording_path = %recording_path,
                        "hydrator: legacy flat .mp4 recording, marking finalized as fmp4-flat"
                    );
                    report.marked_finalized_legacy_flat += 1;
                    self.notify_hydrated(uuid).await;
                }
                Err(e) => {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to mark legacy flat .mp4 as finalized"
                    );
                    report.errored += 1;
                }
            }
            return;
        }

        match self.hydrate_one(uuid, *session_kind, recording_path).await {
            HydrationOutcome::Bundle(bundle) => {
                if let Err(e) = self.db.persist_bundle(*id, &bundle).await {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to persist integrity bundle"
                    );
                    report.errored += 1;
                } else {
                    if report.scanned == 1 {
                        info!(
                            session_uuid = %uuid,
                            "hydration_finalized: integrity bundle persisted"
                        );
                    }
                    report.finalized += 1;
                    self.notify_hydrated(uuid).await;
                }
            }
            HydrationOutcome::MissingMeta => {
                let reference = disconnected_at.unwrap_or(*created_at);
                let age = now.signed_duration_since(reference);
                let grace = chrono::Duration::from_std(self.missing_meta_grace)
                    .unwrap_or(chrono::Duration::seconds(300));
                if age > grace {
                    match self.db.mark_finalized_corrupt(*id).await {
                        Ok(()) => {
                            warn!(
                                session_uuid = %uuid,
                                age_secs = age.num_seconds(),
                                "hydrator: meta.json missing past grace period, marking finalized (integrity unavailable)"
                            );
                            report.marked_finalized_lost += 1;
                            self.notify_hydrated(uuid).await;
                        }
                        Err(e) => {
                            error!(
                                session_uuid = %uuid,
                                error = %e,
                                "hydrator: failed to mark lost recording as finalized"
                            );
                            report.errored += 1;
                        }
                    }
                } else {
                    debug!(
                        session_uuid = %uuid,
                        age_secs = age.num_seconds(),
                        "hydrator: meta.json missing within grace period, will retry next tick"
                    );
                    report.skipped_missing_meta += 1;
                }
            }
            HydrationOutcome::CorruptMeta(reason) => {
                error!(
                    session_uuid = %uuid,
                    reason = %reason,
                    "hydrator: meta.json corrupt, marking finalized with NULL format"
                );
                if let Err(e) = self.db.mark_finalized_corrupt(*id).await {
                    error!(
                        session_uuid = %uuid,
                        error = %e,
                        "hydrator: failed to mark corrupt row as finalized"
                    );
                    report.errored += 1;
                } else {
                    report.marked_finalized_corrupt += 1;
                    self.notify_hydrated(uuid).await;
                }
            }
            HydrationOutcome::Error(e) => {
                error!(
                    session_uuid = %uuid,
                    error = %e,
                    "hydrator: unrecoverable error on session"
                );
                report.errored += 1;
            }
        }
    }

    async fn hydrate_one(
        &self,
        uuid: &Uuid,
        session_kind: SessionKind,
        recording_path: &str,
    ) -> HydrationOutcome {
        let meta_relative = match meta_relative_for(&self.storage_base, recording_path) {
            Some(p) => p,
            None => {
                return HydrationOutcome::Error(
                    "recording_path does not yield a meta.json relative path (flat .mp4?)"
                        .to_string(),
                );
            }
        };

        let outcome = match self.meta_fd.read_meta(uuid, &meta_relative).await {
            Ok(o) => o,
            Err(e) => return HydrationOutcome::Error(format!("meta fd: {e}")),
        };

        let json = match outcome {
            MetaFdOutcome::Found(open) => open.json,
            MetaFdOutcome::Missing => return HydrationOutcome::MissingMeta,
        };

        match parse_meta(session_kind, &json) {
            Ok(bundle) => HydrationOutcome::Bundle(bundle),
            Err(reason) => HydrationOutcome::CorruptMeta(reason),
        }
    }

    async fn notify_hydrated(&self, session_uuid: &Uuid) {
        if let Some(n) = &self.notify {
            n.recording_hydrated(session_uuid).await;
        }
    }
}

enum HydrationOutcome {
    Bundle(IntegrityBundle),
    MissingMeta,
    CorruptMeta(String),
    Error(String),
}

pub fn recording_dir_for_session(
    storage_path: &str,
    session_uuid: &str,
    anchor: chrono::DateTime<chrono::Utc>,
) -> String {
    format!(
        "{}/{}/{:02}/{}/",
        storage_path.trim_end_matches('/'),
        anchor.format("%Y"),
        anchor.format("%m"),
        session_uuid
    )
}

pub fn meta_relative_for(storage_base: &str, recording_path: &str) -> Option<String> {
    if !recording_path.ends_with('/') {
        return None;
    }
    let stripped = recording_path
        .strip_prefix(storage_base)
        .unwrap_or(recording_path)
        .trim_start_matches('/');
    Some(format!("{stripped}meta.json"))
}

pub fn parse_meta(session_kind: SessionKind, buf: &str) -> Result<IntegrityBundle, String> {
    match session_kind {
        SessionKind::Ssh => {
            let meta: SshMeta =
                serde_json::from_str(buf).map_err(|e| format!("invalid SSH meta.json: {e}"))?;
            if !is_valid_blake3_hex(&meta.blake3_hex) {
                return Err(format!(
                    "SSH blake3_hex is not 64-char lowercase hex: {}",
                    meta.blake3_hex
                ));
            }
            Ok(IntegrityBundle {
                blake3_hex: meta.blake3_hex,
                size_bytes: i64::try_from(meta.total_bytes).unwrap_or(i64::MAX),
                duration_ms: (meta.duration_secs * 1000.0).round() as i64,
                event_count: i32::try_from(meta.total_events).ok(),
                format: meta
                    .format
                    .unwrap_or_else(|| FORMAT_ASCIICAST_V2.to_string()),
                width: meta.width as i16,
                height: meta.height as i16,
                segment_count: None,
                codec: None,
            })
        }
        SessionKind::Rdp => {
            let meta: RdpMeta =
                serde_json::from_str(buf).map_err(|e| format!("invalid RDP meta.json: {e}"))?;
            if meta.segments.is_empty() {
                return Err("RDP meta.json has no segments".to_string());
            }
            for seg in &meta.segments {
                if !is_valid_blake3_hex(&seg.blake3_hex) {
                    return Err(format!(
                        "RDP segment {} blake3_hex not 64-char hex",
                        seg.index
                    ));
                }
            }
            let aggregated = aggregate_rdp_blake3(&meta.segments);
            let size_bytes: i64 = meta
                .segments
                .iter()
                .map(|s| i64::try_from(s.file_size).unwrap_or(i64::MAX))
                .sum();
            let total_ticks: u64 = meta.segments.iter().map(|s| s.duration_ticks).sum();
            let duration_ms = (total_ticks as i64 * 1000) / 90_000;
            let last = meta
                .segments
                .last()
                .ok_or_else(|| "unreachable: empty after non-empty check".to_string())?;
            let first = &meta.segments[0];
            let segment_count = i32::try_from(meta.segments.len()).unwrap_or(i32::MAX);
            Ok(IntegrityBundle {
                blake3_hex: aggregated,
                size_bytes,
                duration_ms,
                event_count: None,
                format: FORMAT_FMP4_DASH.to_string(),
                width: last.width as i16,
                height: last.height as i16,
                segment_count: Some(segment_count),
                codec: Some(first.codec_string.clone()),
            })
        }
        SessionKind::Iacs => {
            let meta: IacsPcapMeta =
                serde_json::from_str(buf).map_err(|e| format!("iacs meta.json parse: {e}"))?;
            if !is_valid_blake3_hex(&meta.blake3_hex) {
                return Err("iacs meta.json: invalid blake3_hex".to_string());
            }
            let format = meta
                .format
                .unwrap_or_else(|| FORMAT_PCAP_BUNDLE.to_string());
            if format != FORMAT_PCAP_BUNDLE {
                return Err(format!("iacs meta.json: unexpected format {format}"));
            }
            Ok(IntegrityBundle {
                blake3_hex: meta.blake3_hex,
                size_bytes: meta.total_bytes as i64,
                duration_ms: meta.duration_ms as i64,
                event_count: Some(meta.total_packets as i32),
                format,
                width: 0,
                height: 0,
                segment_count: Some(meta.channels.len() as i32),
                codec: None,
            })
        }
    }
}

pub fn aggregate_rdp_blake3<S: HasSegmentHash>(segments: &[S]) -> String {
    let mut hasher = Hasher::new();
    for s in segments {
        hasher.update(s.blake3_hex().as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

pub trait HasSegmentHash {
    fn blake3_hex(&self) -> &str;
}

impl HasSegmentHash for RdpSegment {
    fn blake3_hex(&self) -> &str {
        &self.blake3_hex
    }
}

pub fn is_valid_blake3_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub const RECORDING_HYDRATED_RETRY_SECS: u64 = 2;
pub const RECORDING_HYDRATED_EVENT: &str = "recording_hydrated";

pub fn recording_hydrated_json_payload(session_uuid: &Uuid) -> String {
    format!(
        r#"{{"type":"{}","session_uuid":"{}"}}"#,
        RECORDING_HYDRATED_EVENT, session_uuid
    )
}

pub fn recording_detail_ws_filter_matches(message: &str, session_uuid: &Uuid) -> bool {
    message.contains(RECORDING_HYDRATED_EVENT) && message.contains(&session_uuid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    struct TestSegment {
        hex: String,
    }

    impl HasSegmentHash for TestSegment {
        fn blake3_hex(&self) -> &str {
            &self.hex
        }
    }

    #[test]
    fn test_is_valid_blake3_hex_accepts_lowercase_64_hex() {
        let s = "0".repeat(64);
        assert!(is_valid_blake3_hex(&s));
        let s2: String = (0..64).map(|i| (b'a' + (i % 6) as u8) as char).collect();
        assert!(is_valid_blake3_hex(&s2));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_uppercase() {
        let s = "A".repeat(64);
        assert!(!is_valid_blake3_hex(&s));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_wrong_length() {
        assert!(!is_valid_blake3_hex(&"a".repeat(63)));
        assert!(!is_valid_blake3_hex(&"a".repeat(65)));
        assert!(!is_valid_blake3_hex(""));
    }

    #[test]
    fn test_is_valid_blake3_hex_rejects_non_hex_chars() {
        let mut s = "a".repeat(63);
        s.push('z');
        assert!(!is_valid_blake3_hex(&s));
    }

    #[test]
    fn test_meta_relative_for_directory_path() {
        let r = meta_relative_for("recordings", "recordings/2026/04/abc-123/").unwrap();
        assert_eq!(r, "2026/04/abc-123/meta.json");
    }

    #[test]
    fn test_meta_relative_for_directory_path_no_prefix_strip() {
        let r = meta_relative_for("/var/vauban", "recordings/2026/04/abc-123/").unwrap();
        assert_eq!(r, "recordings/2026/04/abc-123/meta.json");
    }

    #[test]
    fn test_meta_relative_for_flat_mp4_returns_none() {
        assert_eq!(
            meta_relative_for("recordings", "recordings/legacy/abc.mp4"),
            None
        );
    }

    #[test]
    fn test_aggregate_rdp_blake3_is_deterministic() {
        let segs = vec![
            TestSegment {
                hex: "11".repeat(32),
            },
            TestSegment {
                hex: "22".repeat(32),
            },
        ];
        let h1 = aggregate_rdp_blake3(&segs);
        let h2 = aggregate_rdp_blake3(&segs);
        assert_eq!(h1, h2);
        assert!(is_valid_blake3_hex(&h1));
    }

    #[test]
    fn test_aggregate_rdp_blake3_is_order_sensitive() {
        let a = vec![
            TestSegment {
                hex: "11".repeat(32),
            },
            TestSegment {
                hex: "22".repeat(32),
            },
        ];
        let b = vec![
            TestSegment {
                hex: "22".repeat(32),
            },
            TestSegment {
                hex: "11".repeat(32),
            },
        ];
        assert_ne!(aggregate_rdp_blake3(&a), aggregate_rdp_blake3(&b));
    }

    #[test]
    fn test_parse_meta_iacs_happy_path() {
        let json = r#"{
            "format": "pcap-bundle",
            "blake3_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "total_bytes": 4096,
            "total_packets": 42,
            "duration_ms": 13000,
            "channels": [{
                "index": 1,
                "target_host": "127.0.0.1",
                "target_port": 502,
                "file": "channels/001.pcap.gz",
                "blake3_hex": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "file_size": 4096,
                "packet_count": 42
            }]
        }"#;
        let bundle = parse_meta(SessionKind::Iacs, json).unwrap();
        assert_eq!(bundle.format, "pcap-bundle");
        assert_eq!(bundle.size_bytes, 4096);
        assert_eq!(bundle.duration_ms, 13000);
        assert_eq!(bundle.event_count, Some(42));
        assert_eq!(bundle.segment_count, Some(1));
        assert_eq!(bundle.width, 0);
        assert_eq!(bundle.codec, None);
    }

    #[test]
    fn test_parse_meta_iacs_zero_channel_bundle() {
        let empty_agg = blake3::Hasher::new().finalize().to_hex().to_string();
        let json = format!(
            r#"{{
            "format": "pcap-bundle",
            "blake3_hex": "{empty_agg}",
            "total_bytes": 0,
            "total_packets": 0,
            "duration_ms": 0,
            "channels": []
        }}"#
        );
        let bundle = parse_meta(SessionKind::Iacs, &json).unwrap();
        assert_eq!(bundle.format, "pcap-bundle");
        assert_eq!(bundle.size_bytes, 0);
        assert_eq!(bundle.event_count, Some(0));
        assert_eq!(bundle.segment_count, Some(0));
    }

    #[test]
    fn test_recording_dir_for_session_uses_anchor_month() {
        let anchor = chrono::Utc.with_ymd_and_hms(2026, 4, 15, 12, 0, 0).unwrap();
        let path =
            recording_dir_for_session("recordings", "00000000-0000-0000-0000-000000000001", anchor);
        assert_eq!(
            path,
            "recordings/2026/04/00000000-0000-0000-0000-000000000001/"
        );
    }

    #[test]
    fn test_parse_meta_ssh_happy_path() {
        let json = r#"{
            "format": "asciicast-v2",
            "blake3_hex": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "total_bytes": 91234,
            "total_events": 1847,
            "duration_secs": 14.567,
            "width": 132,
            "height": 43
        }"#;
        let bundle = parse_meta(SessionKind::Ssh, json).unwrap();
        assert_eq!(bundle.blake3_hex.len(), 64);
        assert_eq!(bundle.size_bytes, 91234);
        assert_eq!(bundle.duration_ms, 14567);
        assert_eq!(bundle.event_count, Some(1847));
        assert_eq!(bundle.format, "asciicast-v2");
        assert_eq!(bundle.width, 132);
        assert_eq!(bundle.height, 43);
        assert_eq!(bundle.segment_count, None);
        assert_eq!(bundle.codec, None);
    }

    #[test]
    fn test_parse_meta_ssh_rejects_uppercase_hash() {
        let json = r#"{
            "blake3_hex": "ABCDEF7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "total_bytes": 1,
            "total_events": 1,
            "duration_secs": 1.0,
            "width": 80,
            "height": 24
        }"#;
        let r = parse_meta(SessionKind::Ssh, json);
        assert!(r.is_err(), "uppercase blake3_hex must be rejected");
    }

    #[test]
    fn test_parse_meta_ssh_rejects_invalid_json() {
        let r = parse_meta(SessionKind::Ssh, "{not json");
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_meta_rdp_happy_path() {
        let json = r#"{
            "segments": [
                {
                    "index": 1,
                    "width": 1920,
                    "height": 1080,
                    "duration_ticks": 900000,
                    "init_size": 1024,
                    "file_size": 50000,
                    "blake3_hex": "11111111111111111111111111111111111111111111111111111111111111aa",
                    "codec_string": "avc1.42c01e"
                },
                {
                    "index": 2,
                    "width": 1920,
                    "height": 1080,
                    "duration_ticks": 900000,
                    "init_size": 1024,
                    "file_size": 60000,
                    "blake3_hex": "22222222222222222222222222222222222222222222222222222222222222bb",
                    "codec_string": "avc1.42c01e"
                }
            ]
        }"#;
        let bundle = parse_meta(SessionKind::Rdp, json).unwrap();
        assert_eq!(bundle.size_bytes, 110_000);
        assert_eq!(bundle.duration_ms, 20_000);
        assert_eq!(bundle.format, "fmp4-dash");
        assert_eq!(bundle.width, 1920);
        assert_eq!(bundle.height, 1080);
        assert_eq!(bundle.segment_count, Some(2));
        assert_eq!(bundle.codec.as_deref(), Some("avc1.42c01e"));
        assert_eq!(bundle.event_count, None);
        assert!(is_valid_blake3_hex(&bundle.blake3_hex));
    }

    #[test]
    fn test_parse_meta_rdp_rejects_empty_segments() {
        let r = parse_meta(SessionKind::Rdp, r#"{"segments":[]}"#);
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_meta_rdp_rejects_segment_with_bad_hash() {
        let json = r#"{
            "segments": [{
                "index": 1, "width": 1, "height": 1, "duration_ticks": 1,
                "init_size": 1, "file_size": 1,
                "blake3_hex": "TOOSHORT",
                "codec_string": "avc1.42c01e"
            }]
        }"#;
        assert!(parse_meta(SessionKind::Rdp, json).is_err());
    }

    #[test]
    fn test_parse_meta_rdp_geometry_uses_last_segment() {
        let json = r#"{
            "segments": [
                {"index": 1, "width": 800, "height": 600, "duration_ticks": 90000,
                 "init_size": 100, "file_size": 1000,
                 "blake3_hex": "11111111111111111111111111111111111111111111111111111111111111aa",
                 "codec_string": "avc1.42c01e"},
                {"index": 2, "width": 1920, "height": 1080, "duration_ticks": 90000,
                 "init_size": 100, "file_size": 1000,
                 "blake3_hex": "22222222222222222222222222222222222222222222222222222222222222bb",
                 "codec_string": "avc1.640028"}
            ]
        }"#;
        let bundle = parse_meta(SessionKind::Rdp, json).unwrap();
        assert_eq!(bundle.width, 1920);
        assert_eq!(bundle.height, 1080);
        assert_eq!(bundle.codec.as_deref(), Some("avc1.42c01e"));
    }

    #[test]
    fn test_format_constants_match_check_constraint() {
        assert_eq!(FORMAT_ASCIICAST_V2, "asciicast-v2");
        assert_eq!(FORMAT_FMP4_DASH, "fmp4-dash");
        assert_eq!(FORMAT_FMP4_FLAT, "fmp4-flat");
        assert_eq!(FORMAT_PCAP_BUNDLE, "pcap-bundle");
    }

    fn fn_body(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("signature `{signature}` not found in source"));
        let tail = &source[start..];
        let open = tail
            .find('{')
            .unwrap_or_else(|| panic!("no `{{` after signature `{signature}`"));
        let mut depth: i32 = 0;
        let mut end = tail.len();
        for (i, ch) in tail[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        tail[..end].to_string()
    }

    fn line_before(body: &str, from: usize, needle: &str) -> String {
        let idx = body[from..]
            .find(needle)
            .map(|i| from + i)
            .unwrap_or_else(|| panic!("`{needle}` not found from offset {from}"));
        let prefix = &body[..idx];
        let line_end = prefix
            .rfind('\n')
            .unwrap_or_else(|| panic!("no newline before `{needle}`"));
        let line_start = prefix[..line_end].rfind('\n').map(|i| i + 1).unwrap_or(0);
        prefix[line_start..line_end].trim().to_string()
    }

    #[test]
    fn tick_broadcasts_after_every_finalization_transition() {
        let src = include_str!("pipeline.rs");
        let body = fn_body(src, "async fn process_candidate(");
        let count = body.matches("self.notify_hydrated(").count();
        assert_eq!(
            count, 4,
            "tick() must notify on EXACTLY 4 transitions; found {count}"
        );
        let mut cursor = 0usize;
        let mut visited = 0usize;
        while let Some(found) = body[cursor..].find("self.notify_hydrated(") {
            let prev = line_before(&body, cursor, "self.notify_hydrated(");
            assert!(
                prev.starts_with("report.") && prev.contains("+= 1;"),
                "tick() notify call #{} must follow a success counter; found: `{prev}`",
                visited + 1
            );
            assert!(
                !prev.contains("errored"),
                "tick() must NOT notify in an error branch; found: `{prev}`"
            );
            cursor += found + "self.notify_hydrated(".len();
            visited += 1;
        }
        assert_eq!(visited, 4);
    }

    #[test]
    fn hydrate_session_id_delegates_to_shared_process_path() {
        let src = include_str!("pipeline.rs");
        let body = fn_body(src, "pub async fn hydrate_session_id(");
        assert!(
            body.contains("self.process_candidate("),
            "hydrate_session_id must delegate to process_candidate (shared notify paths)"
        );
    }
}
