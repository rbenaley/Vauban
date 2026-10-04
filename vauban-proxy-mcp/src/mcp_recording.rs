// Relax strict clippy lints in test code where unwrap/expect/panic are idiomatic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! MCP recording — JSONL source of truth + bit-faithful asciicast v2 mirror.
//!
//! Layout (06 + solution E):
//! ```text
//! {storage}/YYYY/MM/{uuid}/
//!   session.mcp.jsonl   ← integrity / WORM (blake3)
//!   session.cast        ← same payloads in asciicast frames (player SSH)
//!   meta.json
//! ```
//!
//! Each event is serialized once (`redact` → compact JSON). That exact string
//! is appended to the JSONL (plus `\n`) and embedded as the asciicast `o`
//! payload. Finalize re-reads both files and refuses a clean seal unless
//! `join(cast_o_payloads, "\n") + "\n" == jsonl_bytes`.
//!
//! **FD lease vs local open:** when a supervisor recording lease channel is
//! wired (`lease_tx = Some`), all opens/writes go through that channel and
//! **fail closed** on lease error/timeout — never fall back to a local
//! `OpenOptions` (Capsicum leaf must not open recording paths itself).
//! Local open remains the lab path when `lease_tx` is `None`.

use serde_json::{Value, json};
use shared::json_redact::redact_sensitive_json;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

pub const FORMAT_MCP_JSONL_V1: &str = "mcp-jsonl-v1";
pub const PLAYBACK_ASCIICAST_V2: &str = "asciicast-v2";
pub const PAYLOAD_ENCODING_JSON_EVENTS_V1: &str = "json-events-v1";
pub const JSONL_FILE_NAME: &str = "session.mcp.jsonl";
pub const CAST_FILE_NAME: &str = "session.cast";
pub const META_FILE_NAME: &str = "meta.json";
const CAST_WIDTH: u16 = 120;
const CAST_HEIGHT: u16 = 40;
/// Playback spacing between MCP events in the asciicast mirror.
/// Wall-clock session time is often under 10 ms (unplayable in asciinema);
/// payloads stay bit-identical — only frame timestamps stretch.
const CAST_EVENT_SPACING_SECS: f64 = 0.35;

/// Request a recording file FD from the supervisor control loop.
pub struct RecordingLeaseReq {
    pub session_id: String,
    pub relative_path: String,
    pub read_only: bool,
    pub reply: oneshot::Sender<Result<File, String>>,
}

pub type RecordingLeaseTx = mpsc::Sender<RecordingLeaseReq>;

/// Date-partitioned session directory relative to storage root.
pub fn compute_base_dir(session_id: &str) -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    let (year, month) = unix_days_to_year_month(days);
    let safe = sanitize_session_id(session_id);
    format!("{year}/{month:02}/{safe}")
}

pub fn compute_jsonl_relative_path(session_id: &str) -> String {
    format!("{}/{}", compute_base_dir(session_id), JSONL_FILE_NAME)
}

pub fn compute_cast_relative_path(session_id: &str) -> String {
    format!("{}/{}", compute_base_dir(session_id), CAST_FILE_NAME)
}

pub fn compute_meta_relative_path(session_id: &str) -> String {
    format!("{}/{}", compute_base_dir(session_id), META_FILE_NAME)
}

fn sanitize_session_id(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn unix_days_to_year_month(days: u64) -> (i32, u32) {
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32)
}

/// Build one asciicast v2 header line (includes trailing newline).
pub fn cast_header_line(session_id: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let title = format!("MCP:{session_id}");
    let title_json = serde_json::to_string(&title).unwrap_or_else(|_| "\"MCP\"".to_string());
    format!(
        "{{\"version\":2,\"width\":{CAST_WIDTH},\"height\":{CAST_HEIGHT},\
         \"timestamp\":{timestamp},\"title\":{title_json}}}\n"
    )
}

/// Encode one event payload string as an asciicast `o` frame (trailing newline).
pub fn cast_frame_line(t_rel_secs: f64, payload: &str) -> io::Result<String> {
    let payload_json = serde_json::to_string(payload).map_err(io::Error::other)?;
    Ok(format!("[{t_rel_secs:.6},\"o\",{payload_json}]\n"))
}

/// Extract `o` payload strings from an asciicast v2 file (skips header).
pub fn extract_payloads_from_cast(cast_bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(cast_bytes).map_err(|e| format!("cast utf8: {e}"))?;
    let mut lines = text.lines().filter(|l| !l.is_empty());
    let header = lines
        .next()
        .ok_or_else(|| "cast missing header".to_string())?;
    let header_v: Value =
        serde_json::from_str(header).map_err(|e| format!("cast header json: {e}"))?;
    let version = header_v
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "cast header missing version".to_string())?;
    if version != 2 {
        return Err(format!("cast unsupported version {version}"));
    }
    let mut out = Vec::new();
    for (idx, line) in lines.enumerate() {
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("cast event {idx} json: {e}"))?;
        let arr = v
            .as_array()
            .ok_or_else(|| format!("cast event {idx}: not an array"))?;
        if arr.len() < 3 {
            return Err(format!("cast event {idx}: short array"));
        }
        let code = arr[1]
            .as_str()
            .ok_or_else(|| format!("cast event {idx}: code not string"))?;
        if code != "o" {
            return Err(format!("cast event {idx}: expected o, got {code}"));
        }
        let payload = arr[2]
            .as_str()
            .ok_or_else(|| format!("cast event {idx}: payload not string"))?;
        out.push(payload.to_string());
    }
    Ok(out)
}

/// Rebuild JSONL bytes from cast `o` payloads (each payload + `\n`).
pub fn jsonl_bytes_from_payloads(payloads: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(p.as_bytes());
        out.push(b'\n');
    }
    out
}

/// True iff cast `o` payloads reconstruct `jsonl_bytes` exactly.
pub fn cast_mirrors_jsonl(jsonl_bytes: &[u8], cast_bytes: &[u8]) -> Result<bool, String> {
    let payloads = extract_payloads_from_cast(cast_bytes)?;
    Ok(jsonl_bytes_from_payloads(&payloads) == jsonl_bytes)
}

struct ActiveRecording {
    jsonl: File,
    cast: File,
    hasher: blake3::Hasher,
    cast_hasher: blake3::Hasher,
    total_bytes: u64,
    total_events: u64,
    started: Instant,
    /// Next asciicast timestamp (stretched for playability).
    cast_t_rel: f64,
    relative_jsonl: String,
    relative_cast: String,
    relative_meta: String,
    /// Absolute dir for lab meta write when FD lease unavailable.
    abs_dir: Option<PathBuf>,
}

/// Per-process recording hub (JSONL + cast mirror).
#[derive(Clone)]
pub struct McpRecording {
    inner: Arc<McpRecordingInner>,
}

struct McpRecordingInner {
    storage_base: PathBuf,
    lease_tx: Option<RecordingLeaseTx>,
    sessions: Mutex<HashMap<String, ActiveRecording>>,
}

impl McpRecording {
    pub fn from_env(lease_tx: Option<RecordingLeaseTx>) -> Self {
        let storage_base = std::env::var("VAUBAN_RECORDING_STORAGE_PATH")
            .or_else(|_| std::env::var("MCP_RECORDING_DIR"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("recordings"));
        Self::with_storage(storage_base, lease_tx)
    }

    pub(crate) fn with_storage(storage_base: PathBuf, lease_tx: Option<RecordingLeaseTx>) -> Self {
        if let Err(e) = fs::create_dir_all(&storage_base) {
            warn!(
                dir = %storage_base.display(),
                error = %e,
                "MCP recording storage create failed"
            );
        }
        Self {
            inner: Arc::new(McpRecordingInner {
                storage_base,
                lease_tx,
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Test / lab helper with an explicit storage root (no FD lease).
    #[cfg(test)]
    pub fn with_storage_base(storage_base: PathBuf) -> Self {
        Self::with_storage(storage_base, None)
    }

    /// Test helper: storage root + FD lease channel (production-shaped).
    #[cfg(test)]
    pub fn with_storage_base_and_lease(storage_base: PathBuf, lease_tx: RecordingLeaseTx) -> Self {
        Self::with_storage(storage_base, Some(lease_tx))
    }

    /// When a lease channel is wired, local `open` is forbidden (Capsicum).
    fn fd_lease_required(&self) -> bool {
        self.inner.lease_tx.is_some()
    }

    pub fn storage_base(&self) -> &Path {
        &self.inner.storage_base
    }

    /// Open JSONL + cast for a session. Idempotent.
    pub async fn open_session(&self, session_id: &str) -> io::Result<()> {
        {
            let guard = self
                .inner
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if guard.contains_key(session_id) {
                return Ok(());
            }
        }
        let relative_jsonl = compute_jsonl_relative_path(session_id);
        let relative_cast = compute_cast_relative_path(session_id);
        let relative_meta = compute_meta_relative_path(session_id);
        let (jsonl, abs_dir) = self.open_write_file(session_id, &relative_jsonl).await?;
        let (mut cast, _) = self.open_write_file(session_id, &relative_cast).await?;

        let header = cast_header_line(session_id);
        let header_bytes = header.as_bytes();
        cast.write_all(header_bytes)?;
        cast.sync_all()?;

        let mut cast_hasher = blake3::Hasher::new();
        cast_hasher.update(header_bytes);

        let rec = ActiveRecording {
            jsonl,
            cast,
            hasher: blake3::Hasher::new(),
            cast_hasher,
            total_bytes: 0,
            total_events: 0,
            started: Instant::now(),
            cast_t_rel: 0.0,
            relative_jsonl,
            relative_cast,
            relative_meta,
            abs_dir,
        };
        let mut guard = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.insert(session_id.to_string(), rec);
        info!(session_id = %session_id, "MCP JSONL+cast recording opened");
        Ok(())
    }

    async fn open_write_file(
        &self,
        session_id: &str,
        relative_path: &str,
    ) -> io::Result<(File, Option<PathBuf>)> {
        if let Some(ref tx) = self.inner.lease_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            let req = RecordingLeaseReq {
                session_id: session_id.to_string(),
                relative_path: relative_path.to_string(),
                read_only: false,
                reply: reply_tx,
            };
            if tx.send(req).await.is_err() {
                return Err(io::Error::other(
                    "recording lease channel closed (fail-closed; no local open)",
                ));
            }
            match tokio::time::timeout(Duration::from_secs(3), reply_rx).await {
                Ok(Ok(Ok(file))) => return Ok((file, None)),
                Ok(Ok(Err(e))) => {
                    return Err(io::Error::other(format!(
                        "FD recording lease failed (fail-closed; no local open): {e}"
                    )));
                }
                Ok(Err(_)) => {
                    return Err(io::Error::other(
                        "recording lease reply dropped (fail-closed; no local open)",
                    ));
                }
                Err(_) => {
                    return Err(io::Error::other(
                        "recording lease timed out (fail-closed; no local open)",
                    ));
                }
            }
        }
        // Lab path only: no lease channel wired.
        let abs = self.inner.storage_base.join(relative_path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&abs)?;
        Ok((file, abs.parent().map(Path::to_path_buf)))
    }

    /// Append one redacted event to JSONL + cast (same payload). Maps to `-32010` on failure.
    pub fn append_jsonl(&self, session_id: &str, event: Value) -> io::Result<()> {
        let redacted = redact_sensitive_json(&event);
        let payload = redacted.to_string();
        let mut jsonl_line = payload.clone();
        jsonl_line.push('\n');
        let jsonl_bytes = jsonl_line.into_bytes();

        let mut guard = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(rec) = guard.get_mut(session_id) else {
            drop(guard);
            if self.fd_lease_required() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no active MCP recording session (fail-closed; FD lease mode forbids local fallback)",
                ));
            }
            return self.append_fallback(session_id, &payload, &jsonl_bytes);
        };

        let t_rel = rec.cast_t_rel;
        let cast_line = cast_frame_line(t_rel, &payload)?;
        let cast_bytes = cast_line.as_bytes();

        rec.jsonl.write_all(&jsonl_bytes)?;
        rec.cast.write_all(cast_bytes)?;
        rec.jsonl.sync_all()?;
        rec.cast.sync_all()?;
        rec.hasher.update(&jsonl_bytes);
        rec.cast_hasher.update(cast_bytes);
        rec.total_bytes += jsonl_bytes.len() as u64;
        rec.total_events += 1;
        rec.cast_t_rel += CAST_EVENT_SPACING_SECS;
        Ok(())
    }

    /// Lab-only: append when no in-memory session (lease channel not wired).
    fn append_fallback(
        &self,
        session_id: &str,
        payload: &str,
        jsonl_bytes: &[u8],
    ) -> io::Result<()> {
        debug_assert!(
            !self.fd_lease_required(),
            "append_fallback must not run when FD lease is wired"
        );
        let rel_j = compute_jsonl_relative_path(session_id);
        let rel_c = compute_cast_relative_path(session_id);
        let abs_j = self.inner.storage_base.join(&rel_j);
        let abs_c = self.inner.storage_base.join(&rel_c);
        if let Some(parent) = abs_j.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut fj = OpenOptions::new().create(true).append(true).open(&abs_j)?;
        fj.write_all(jsonl_bytes)?;
        fj.sync_all()?;

        let cast_exists = abs_c.exists() && abs_c.metadata().map(|m| m.len() > 0).unwrap_or(false);
        let mut fc = OpenOptions::new().create(true).append(true).open(&abs_c)?;
        if !cast_exists {
            let header = cast_header_line(session_id);
            fc.write_all(header.as_bytes())?;
        }
        // Fallback: space events by counting existing o-frames.
        let n_events = std::fs::read_to_string(&abs_c)
            .map(|s| s.lines().skip(1).filter(|l| !l.is_empty()).count())
            .unwrap_or(0);
        let t_rel = n_events as f64 * CAST_EVENT_SPACING_SECS;
        let cast_line = cast_frame_line(t_rel, payload)?;
        fc.write_all(cast_line.as_bytes())?;
        fc.sync_all()?;
        debug!(session_id = %session_id, "MCP JSONL+cast appended via lab local-open path");
        Ok(())
    }

    /// Write session_end, verify cast≡jsonl, seal meta.json.
    pub async fn finalize(
        &self,
        session_id: &str,
        reason: &str,
        partial: bool,
    ) -> Option<FinalizeStats> {
        let end = json!({
            "ts": rfc3339_now(),
            "session_id": session_id,
            "event": "session_end",
            "reason": reason,
            "partial": partial,
        });
        if let Err(e) = self.append_jsonl(session_id, end) {
            error!(session_id = %session_id, error = %e, "JSONL session_end write failed");
        }

        let extracted = {
            let mut guard = self
                .inner
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.remove(session_id)
        };

        let Some(mut rec) = extracted else {
            return self.finalize_from_disk(session_id, partial).await;
        };

        let _ = rec.jsonl.sync_all();
        let _ = rec.cast.sync_all();

        let mut jsonl_bytes = Vec::new();
        let mut cast_bytes = Vec::new();
        if let Err(e) = rec.jsonl.seek(SeekFrom::Start(0)).and_then(|_| {
            rec.jsonl.read_to_end(&mut jsonl_bytes)?;
            Ok(())
        }) {
            error!(session_id = %session_id, error = %e, "JSONL re-read failed at finalize");
            return self
                .seal_after_read(
                    session_id,
                    &rec.relative_jsonl,
                    &rec.relative_cast,
                    &rec.relative_meta,
                    rec.abs_dir.as_deref(),
                    &[],
                    &[],
                    rec.hasher.finalize().to_hex().to_string(),
                    rec.cast_hasher.finalize().to_hex().to_string(),
                    rec.total_bytes,
                    rec.total_events,
                    rec.started.elapsed().as_millis() as u64,
                    true,
                    false,
                )
                .await;
        }
        if let Err(e) = rec.cast.seek(SeekFrom::Start(0)).and_then(|_| {
            rec.cast.read_to_end(&mut cast_bytes)?;
            Ok(())
        }) {
            error!(session_id = %session_id, error = %e, "cast re-read failed at finalize");
            return self
                .seal_after_read(
                    session_id,
                    &rec.relative_jsonl,
                    &rec.relative_cast,
                    &rec.relative_meta,
                    rec.abs_dir.as_deref(),
                    &jsonl_bytes,
                    &[],
                    blake3::hash(&jsonl_bytes).to_hex().to_string(),
                    String::new(),
                    jsonl_bytes.len() as u64,
                    jsonl_bytes.iter().filter(|&&b| b == b'\n').count() as u64,
                    rec.started.elapsed().as_millis() as u64,
                    true,
                    false,
                )
                .await;
        }

        let digest = blake3::hash(&jsonl_bytes).to_hex().to_string();
        let cast_digest = blake3::hash(&cast_bytes).to_hex().to_string();
        let total_events = jsonl_bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        let duration_ms = rec.started.elapsed().as_millis() as u64;

        let (equivalence_verified, forced_partial) =
            match cast_mirrors_jsonl(&jsonl_bytes, &cast_bytes) {
                Ok(true) => (true, partial),
                Ok(false) => {
                    error!(
                        session_id = %session_id,
                        "MCP cast≢jsonl at finalize — sealing as partial"
                    );
                    (false, true)
                }
                Err(e) => {
                    error!(
                        session_id = %session_id,
                        error = %e,
                        "MCP cast parse failed at finalize — sealing as partial"
                    );
                    (false, true)
                }
            };

        self.seal_after_read(
            session_id,
            &rec.relative_jsonl,
            &rec.relative_cast,
            &rec.relative_meta,
            rec.abs_dir.as_deref(),
            &jsonl_bytes,
            &cast_bytes,
            digest,
            cast_digest,
            jsonl_bytes.len() as u64,
            total_events,
            duration_ms,
            forced_partial,
            equivalence_verified,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn seal_after_read(
        &self,
        session_id: &str,
        relative_jsonl: &str,
        relative_cast: &str,
        relative_meta: &str,
        abs_dir: Option<&Path>,
        _jsonl_bytes: &[u8],
        _cast_bytes: &[u8],
        digest: String,
        cast_digest: String,
        total_bytes: u64,
        total_events: u64,
        duration_ms: u64,
        partial: bool,
        equivalence_verified: bool,
    ) -> Option<FinalizeStats> {
        let meta = json!({
            "format": FORMAT_MCP_JSONL_V1,
            "playback": PLAYBACK_ASCIICAST_V2,
            "payload_encoding": PAYLOAD_ENCODING_JSON_EVENTS_V1,
            "blake3_hex": digest,
            "cast_blake3_hex": cast_digest,
            "cast_path": relative_cast,
            "equivalence_verified": equivalence_verified,
            "total_bytes": total_bytes,
            "total_events": total_events,
            "duration_ms": duration_ms,
            "partial": partial,
        });
        if let Err(e) = self
            .write_meta(session_id, relative_meta, abs_dir, &meta)
            .await
        {
            error!(session_id = %session_id, error = %e, "MCP meta.json write failed");
        } else {
            info!(
                session_id = %session_id,
                blake3 = %digest,
                cast_blake3 = %cast_digest,
                equivalence_verified,
                path = %relative_jsonl,
                "MCP recording finalized"
            );
        }

        Some(FinalizeStats {
            blake3_hex: digest,
            cast_blake3_hex: cast_digest,
            relative_jsonl: relative_jsonl.to_string(),
            relative_cast: relative_cast.to_string(),
            relative_meta: relative_meta.to_string(),
            total_bytes,
            total_events,
            partial,
            equivalence_verified,
        })
    }

    async fn finalize_from_disk(&self, session_id: &str, partial: bool) -> Option<FinalizeStats> {
        let relative_jsonl = compute_jsonl_relative_path(session_id);
        let relative_cast = compute_cast_relative_path(session_id);
        let relative_meta = compute_meta_relative_path(session_id);
        let abs_j = self.inner.storage_base.join(&relative_jsonl);
        let abs_c = self.inner.storage_base.join(&relative_cast);
        let jsonl_bytes = fs::read(&abs_j).ok()?;
        let digest = blake3::hash(&jsonl_bytes).to_hex().to_string();
        let total_events = jsonl_bytes.iter().filter(|&&b| b == b'\n').count() as u64;

        // Orphan path: rebuild cast from JSONL so player + equivalence hold.
        let (cast_bytes, equivalence_verified, forced_partial) =
            match rebuild_cast_from_jsonl(session_id, &jsonl_bytes) {
                Ok(bytes) => {
                    if let Err(e) = write_bytes_synced(&abs_c, &bytes) {
                        error!(
                            session_id = %session_id,
                            error = %e,
                            "orphan cast rebuild write failed"
                        );
                        (Vec::new(), false, true)
                    } else {
                        (bytes, true, partial)
                    }
                }
                Err(e) => {
                    error!(
                        session_id = %session_id,
                        error = %e,
                        "orphan cast rebuild failed"
                    );
                    (Vec::new(), false, true)
                }
            };
        let cast_digest = if cast_bytes.is_empty() {
            String::new()
        } else {
            blake3::hash(&cast_bytes).to_hex().to_string()
        };
        let abs_dir = abs_j.parent().map(Path::to_path_buf);
        self.seal_after_read(
            session_id,
            &relative_jsonl,
            &relative_cast,
            &relative_meta,
            abs_dir.as_deref(),
            &jsonl_bytes,
            &cast_bytes,
            digest,
            cast_digest,
            jsonl_bytes.len() as u64,
            total_events,
            0,
            forced_partial,
            equivalence_verified,
        )
        .await
    }

    async fn write_meta(
        &self,
        session_id: &str,
        relative_meta: &str,
        abs_dir: Option<&Path>,
        meta: &Value,
    ) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
        if let Some(ref tx) = self.inner.lease_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            let req = RecordingLeaseReq {
                session_id: session_id.to_string(),
                relative_path: relative_meta.to_string(),
                read_only: false,
                reply: reply_tx,
            };
            if tx.send(req).await.is_err() {
                return Err(io::Error::other(
                    "meta.json lease channel closed (fail-closed; no local open)",
                ));
            }
            match tokio::time::timeout(Duration::from_secs(3), reply_rx).await {
                Ok(Ok(Ok(mut file))) => {
                    file.write_all(&payload)?;
                    file.sync_all()?;
                    return Ok(());
                }
                Ok(Ok(Err(e))) => {
                    return Err(io::Error::other(format!(
                        "meta.json FD lease failed (fail-closed; no local open): {e}"
                    )));
                }
                Ok(Err(_)) => {
                    return Err(io::Error::other(
                        "meta.json lease reply dropped (fail-closed; no local open)",
                    ));
                }
                Err(_) => {
                    return Err(io::Error::other(
                        "meta.json lease timed out (fail-closed; no local open)",
                    ));
                }
            }
        }
        let path = if let Some(dir) = abs_dir {
            dir.join(META_FILE_NAME)
        } else {
            self.inner.storage_base.join(relative_meta)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        f.write_all(&payload)?;
        f.sync_all()?;
        Ok(())
    }
}

fn write_bytes_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Rebuild a cast file from JSONL lines (orphan / recovery). Timestamps are
/// synthetic (0.0, 0.001, …) — payloads are byte-identical to JSONL lines.
pub fn rebuild_cast_from_jsonl(session_id: &str, jsonl_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(jsonl_bytes).map_err(|e| format!("jsonl utf8: {e}"))?;
    let mut out = Vec::new();
    out.extend_from_slice(cast_header_line(session_id).as_bytes());
    let mut t = 0.0_f64;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let frame = cast_frame_line(t, line).map_err(|e| e.to_string())?;
        out.extend_from_slice(frame.as_bytes());
        t += CAST_EVENT_SPACING_SECS;
    }
    // Trailing empty lines in jsonl: preserve exact bytes via extract check.
    if !cast_mirrors_jsonl(jsonl_bytes, &out).unwrap_or(false) {
        // If jsonl ends without newline on last line, still try payloads-only rebuild.
        let payloads: Vec<String> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        let mut out2 = Vec::new();
        out2.extend_from_slice(cast_header_line(session_id).as_bytes());
        let mut t = 0.0_f64;
        for p in &payloads {
            let frame = cast_frame_line(t, p).map_err(|e| e.to_string())?;
            out2.extend_from_slice(frame.as_bytes());
            t += CAST_EVENT_SPACING_SECS;
        }
        if cast_mirrors_jsonl(jsonl_bytes, &out2).unwrap_or(false) {
            return Ok(out2);
        }
        return Err("rebuild_cast_from_jsonl: equivalence check failed".into());
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct FinalizeStats {
    pub blake3_hex: String,
    pub cast_blake3_hex: String,
    pub relative_jsonl: String,
    pub relative_cast: String,
    pub relative_meta: String,
    pub total_bytes: u64,
    pub total_events: u64,
    pub partial: bool,
    pub equivalence_verified: bool,
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn layout_contains_session_and_filenames() {
        let sid = "550e8400-e29b-41d4-a716-446655440000";
        let j = compute_jsonl_relative_path(sid);
        let c = compute_cast_relative_path(sid);
        let m = compute_meta_relative_path(sid);
        assert!(j.contains(sid));
        assert!(j.ends_with(JSONL_FILE_NAME));
        assert!(c.ends_with(CAST_FILE_NAME));
        assert!(m.ends_with(META_FILE_NAME));
    }

    #[test]
    fn cast_frame_round_trip_payload() {
        let payload = r#"{"event":"tools/call","args":{"secret":"***"},"msg":"a\"b"}"#;
        let line = cast_frame_line(1.5, payload).unwrap();
        let mut fake = cast_header_line("sid");
        fake.push_str(&line);
        let got = extract_payloads_from_cast(fake.as_bytes()).unwrap();
        assert_eq!(got, vec![payload.to_string()]);
    }

    #[test]
    fn mirrors_detects_tamper() {
        let jsonl = b"{\"a\":1}\n{\"b\":2}\n";
        let cast = rebuild_cast_from_jsonl("sid", jsonl).unwrap();
        assert!(cast_mirrors_jsonl(jsonl, &cast).unwrap());
        let mut bad = cast.clone();
        // Flip a byte inside a payload frame (not the header).
        let idx = bad.len() - 5;
        bad[idx] ^= 0x01;
        assert!(!cast_mirrors_jsonl(jsonl, &bad).unwrap_or(true));
    }

    #[tokio::test]
    async fn dual_write_finalize_equivalence() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vauban-mcp-rec-{stamp}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let rec = McpRecording::with_storage_base(dir.clone());
        let sid = "11111111-2222-3333-4444-555555555555";
        rec.open_session(sid).await.unwrap();
        rec.append_jsonl(
            sid,
            json!({"event":"session_open","session_id":sid,"secret":"should-redact"}),
        )
        .unwrap();
        rec.append_jsonl(
            sid,
            json!({"event":"tools/call","decision":"allow","tool_name":"echo","args":{"message":"hi"}}),
        )
        .unwrap();
        let stats = rec.finalize(sid, "test", false).await.unwrap();
        assert!(stats.equivalence_verified, "cast must mirror jsonl");
        assert!(!stats.partial);
        assert!(!stats.blake3_hex.is_empty());
        assert!(!stats.cast_blake3_hex.is_empty());

        let jsonl_path = dir.join(&stats.relative_jsonl);
        let cast_path = dir.join(&stats.relative_cast);
        let jsonl_bytes = fs::read(&jsonl_path).unwrap();
        let cast_bytes = fs::read(&cast_path).unwrap();
        assert!(cast_mirrors_jsonl(&jsonl_bytes, &cast_bytes).unwrap());
        // Redaction applied before both planes.
        let text = String::from_utf8_lossy(&jsonl_bytes);
        assert!(text.contains("***"));
        assert!(!text.contains("should-redact"));

        let meta: Value =
            serde_json::from_slice(&fs::read(dir.join(&stats.relative_meta)).unwrap()).unwrap();
        assert_eq!(meta["format"], FORMAT_MCP_JSONL_V1);
        assert_eq!(meta["playback"], PLAYBACK_ASCIICAST_V2);
        assert_eq!(meta["equivalence_verified"], true);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn finalize_marks_partial_when_cast_tampered() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vauban-mcp-rec-tamper-{stamp}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let rec = McpRecording::with_storage_base(dir.clone());
        let sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        rec.open_session(sid).await.unwrap();
        rec.append_jsonl(sid, json!({"event":"initialize","decision":"allow"}))
            .unwrap();

        // Tamper cast while session still open.
        {
            let mut guard = rec.inner.sessions.lock().unwrap();
            let active = guard.get_mut(sid).unwrap();
            active.cast.write_all(b"TAMPER\n").unwrap();
            active.cast.sync_all().unwrap();
        }

        let stats = rec.finalize(sid, "test", false).await.unwrap();
        assert!(!stats.equivalence_verified);
        assert!(stats.partial);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lease_failure_fail_closed_no_local_open() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vauban-mcp-rec-failclosed-{stamp}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (tx, mut rx) = mpsc::channel::<RecordingLeaseReq>(8);
        let lease_task = tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let _ = req.reply.send(Err("supervisor denied".into()));
            }
        });

        let rec = McpRecording::with_storage_base_and_lease(dir.clone(), tx);
        let sid = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb";
        let err = rec
            .open_session(sid)
            .await
            .expect_err("lease denial must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("fail-closed") || msg.contains("lease failed"),
            "unexpected error: {msg}"
        );

        // No session dir / files created under storage (no local open escape).
        let entries: Vec<_> = walkdir_shallow(&dir);
        assert!(
            entries.is_empty(),
            "fail-closed must not create recording files via local open, got {entries:?}"
        );

        // Append without open also fail-closed (no append_fallback).
        let append_err = rec
            .append_jsonl(sid, json!({"event":"tools/call"}))
            .expect_err("append without session must fail closed under lease mode");
        assert!(
            append_err.to_string().contains("fail-closed"),
            "unexpected: {append_err}"
        );

        drop(rec);
        lease_task.abort();
        let _ = fs::remove_dir_all(&dir);
    }

    fn walkdir_shallow(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(root) else {
            return out;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                out.extend(walkdir_shallow(&p));
            } else {
                out.push(p);
            }
        }
        out
    }
}
