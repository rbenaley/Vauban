//! WORM (Write-Once-Read-Many) tamper-evident audit log.
//!
//! The audit service is the durable, append-only, inviolable record of every
//! security-relevant action on the bastion. This module implements the on-disk
//! format and the cryptographic integrity it relies on; it is deliberately
//! free of any IPC / supervisor knowledge so it can be unit-tested in full and
//! reused by the `verify` subcommand. Orchestration (obtaining append-only
//! segment FDs from the supervisor broker, deciding when to rotate/seal,
//! unsealing the signing key from the vault) lives in `main.rs`.
//!
//! # On-disk format
//!
//! A segment is a JSON-Lines file: one self-describing JSON object per line.
//! Two record kinds share the same envelope (`WormLine = core + hash`):
//!
//! - `event`: an audit event (auth, session, policy, ...).
//! - `seal`: an Ed25519 signature over the chain head at seal time. Emitted on
//!   a size threshold, on segment rotation, and on drain/shutdown.
//!
//! # Tamper-evidence (defence in depth)
//!
//! 1. **Hash chain (BLAKE3)** -- each record carries `prev` (the previous
//!    record's hash) and its own `hash = BLAKE3(prev_hash || canonical(core))`.
//!    Flipping a byte, deleting a line (sequence gap), or reordering records
//!    breaks the chain and is detected by [`verify_reader`]. The chain head
//!    crosses segment boundaries (a new segment continues the previous head).
//! 2. **Sequence numbers** -- strictly monotonic `seq`, so a removed record
//!    leaves a detectable gap even before the hash check.
//! 3. **Ed25519 seal** -- `seal` records sign the raw chain head with the
//!    audit signing key (seed unsealed from the vault at boot).
//!    [`verify_reader`] takes an **out-of-band** [`VerifyingKey`] (the
//!    `.pub` written by `vauban-vault seal-audit-key`). An attacker who
//!    rewrites the file and embeds a new keypair cannot obtain `OK`:
//!    the in-band `pubkey` field is compared to the pin and a mismatch
//!    is [`VerifyError::PubkeyMismatch`]. Truncation *after* the last
//!    seal remains a known residual (the chain cannot be edited in
//!    place without breaking hashes).
//!
//! The genesis `prev` is 32 zero bytes.

use std::fs::File;
use std::io::{BufRead, BufWriter, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Genesis chain head (the `prev` of the very first record).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Wire `kind` discriminants.
const KIND_EVENT: &str = "event";
const KIND_SEAL: &str = "seal";

/// An audit event to be appended, borrowed from the caller's message.
///
/// `source_ip` is pre-rendered to a `String` by the caller (the IPC message
/// carries an `IpAddr`) to keep this module dependency-light.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub event_type: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub source_ip: Option<String>,
    pub details: String,
}

/// The hashed body of a record. Field order is FIXED (struct order) so the
/// canonical serialization is deterministic and reproducible at verify time.
///
/// All fields are always serialized (absent optionals become JSON `null`) so a
/// deserialize -> reserialize round-trip yields byte-identical canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordCore {
    /// Strictly monotonic sequence number (starts at 0).
    seq: u64,
    /// `"event"` or `"seal"`.
    kind: String,
    /// Hex of the previous record's hash (genesis = 64 zeros).
    prev: String,
    /// Unix timestamp (seconds).
    timestamp: u64,
    // ---- event payload (null on seal records) ----
    event_type: Option<String>,
    user_id: Option<String>,
    session_id: Option<String>,
    source_ip: Option<String>,
    details: Option<String>,
    // ---- seal payload (null on event records) ----
    /// Hex of the chain head being sealed (equals `prev` on a seal record).
    sealed_head: Option<String>,
    /// Base64 of the Ed25519 public key (for third-party verification).
    pubkey: Option<String>,
    /// Base64 of the Ed25519 signature over the raw 32-byte `sealed_head`.
    signature: Option<String>,
}

/// One serialized line: the hashed `core` plus its BLAKE3 `hash` (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WormLine {
    #[serde(flatten)]
    core: RecordCore,
    /// Hex of `BLAKE3(prev_hash || canonical(core))`.
    hash: String,
}

/// Errors raised while writing the WORM log.
#[derive(Debug, thiserror::Error)]
pub enum WormError {
    #[error("worm io: {0}")]
    Io(#[from] std::io::Error),
    #[error("worm serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Errors raised while verifying a WORM segment.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("line {line}: malformed JSON")]
    Malformed { line: usize },
    #[error("line {line}: sequence gap (expected {expected}, got {got})")]
    SequenceGap {
        line: usize,
        expected: u64,
        got: u64,
    },
    #[error("line {line}: broken chain link (prev mismatch)")]
    BrokenLink { line: usize },
    #[error("line {line}: hash mismatch (record tampered)")]
    HashMismatch { line: usize },
    #[error("line {line}: invalid seal signature")]
    BadSignature { line: usize },
    #[error("line {line}: seal head does not match chain head")]
    SealHeadMismatch { line: usize },
    #[error("line {line}: malformed seal record (missing field)")]
    MalformedSeal { line: usize },
    #[error("line {line}: seal public key does not match the pinned verifying key")]
    PubkeyMismatch { line: usize },
}

/// Outcome of verifying one or more segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: u64,
    pub events: u64,
    pub seals: u64,
    /// Final chain head after the last verified record.
    pub head: [u8; 32],
    /// Highest sequence number seen + 1 (the next expected `seq`).
    pub next_seq: u64,
}

/// Compute `BLAKE3(prev_hash || canonical_core_bytes)`.
fn record_hash(prev_hash: &[u8; 32], canonical_core: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(canonical_core);
    *hasher.finalize().as_bytes()
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

/// An append-only WORM segment writer with a running hash chain.
///
/// The writer NEVER truncates: the underlying `File` is opened `O_APPEND` by
/// the supervisor broker. `prev_hash`/`seq` survive segment rotation so the
/// chain is continuous across files.
pub struct WormLog {
    writer: BufWriter<File>,
    segment_name: String,
    prev_hash: [u8; 32],
    seq: u64,
    records_in_segment: u64,
}

impl WormLog {
    /// Open a new segment. `prev_hash`/`start_seq` continue an existing chain
    /// (use [`GENESIS_HASH`] / `0` for a brand-new log).
    #[must_use]
    pub fn new(file: File, segment_name: String, prev_hash: [u8; 32], start_seq: u64) -> Self {
        Self {
            writer: BufWriter::new(file),
            segment_name,
            prev_hash,
            seq: start_seq,
            records_in_segment: 0,
        }
    }

    /// Current chain head (hash of the last written record, or genesis).
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.prev_hash
    }

    /// Next sequence number that will be assigned.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// Records written into the CURRENT segment (reset on rotation).
    #[must_use]
    pub fn records_in_segment(&self) -> u64 {
        self.records_in_segment
    }

    /// Current segment file name.
    #[must_use]
    pub fn segment_name(&self) -> &str {
        &self.segment_name
    }

    /// Write a line, fsync, and advance the chain. Durable before returning so
    /// the caller may ack only after this succeeds (fail-closed contract).
    fn write_line(&mut self, core: RecordCore) -> Result<[u8; 32], WormError> {
        let canonical = serde_json::to_vec(&core)?;
        let hash = record_hash(&self.prev_hash, &canonical);
        let line = WormLine {
            core,
            hash: hex32(&hash),
        };
        let json = serde_json::to_string(&line)?;
        self.writer.write_all(json.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        // Durability: the ack means "persisted", so force the bytes to disk.
        self.writer.get_ref().sync_all()?;
        self.prev_hash = hash;
        self.seq += 1;
        self.records_in_segment += 1;
        Ok(hash)
    }

    /// Append an audit event and advance the chain. Returns the new head.
    pub fn append_event(&mut self, ev: &AuditRecord) -> Result<[u8; 32], WormError> {
        let core = RecordCore {
            seq: self.seq,
            kind: KIND_EVENT.to_string(),
            prev: hex32(&self.prev_hash),
            timestamp: ev.timestamp,
            event_type: Some(ev.event_type.clone()),
            user_id: ev.user_id.clone(),
            session_id: ev.session_id.clone(),
            source_ip: ev.source_ip.clone(),
            details: Some(ev.details.clone()),
            sealed_head: None,
            pubkey: None,
            signature: None,
        };
        self.write_line(core)
    }

    /// Append an Ed25519 seal over the current chain head.
    pub fn seal(&mut self, key: &SigningKey, timestamp: u64) -> Result<[u8; 32], WormError> {
        let head = self.prev_hash;
        let signature: Signature = key.sign(&head);
        let core = RecordCore {
            seq: self.seq,
            kind: KIND_SEAL.to_string(),
            prev: hex32(&head),
            timestamp,
            event_type: None,
            user_id: None,
            session_id: None,
            source_ip: None,
            details: None,
            sealed_head: Some(hex32(&head)),
            pubkey: Some(BASE64.encode(key.verifying_key().to_bytes())),
            signature: Some(BASE64.encode(signature.to_bytes())),
        };
        self.write_line(core)
    }

    /// Swap to a fresh append-only segment, continuing the chain. The caller
    /// is expected to have sealed the previous segment first (when a signing
    /// key is available).
    pub fn rotate(&mut self, file: File, segment_name: String) -> Result<(), WormError> {
        self.writer.flush()?;
        self.writer = BufWriter::new(file);
        self.segment_name = segment_name;
        self.records_in_segment = 0;
        Ok(())
    }
}

/// Replay and verify a segment from `start_prev`, returning the final report.
///
/// Detects: malformed JSON, sequence gaps, broken chain links, per-record hash
/// tampering, seal pubkey mismatch against `expected`, and invalid Ed25519
/// seals. For a standalone segment pass [`GENESIS_HASH`] and `start_seq = 0`;
/// to chain multiple segments, feed the previous report's `head` / `next_seq`.
///
/// `expected` is the out-of-band audit verifying key (vault `.pub`). The
/// in-band `pubkey` field is never used as the trust anchor.
pub fn verify_reader<R: BufRead>(
    reader: R,
    start_prev: [u8; 32],
    start_seq: u64,
    expected: &VerifyingKey,
) -> Result<VerifyReport, VerifyError> {
    let mut prev = start_prev;
    let mut expected_seq = start_seq;
    let mut events = 0u64;
    let mut seals = 0u64;
    let mut records = 0u64;

    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let raw = line.map_err(|_| VerifyError::Malformed { line: line_no })?;
        if raw.trim().is_empty() {
            continue;
        }
        let parsed: WormLine =
            serde_json::from_str(&raw).map_err(|_| VerifyError::Malformed { line: line_no })?;

        // Sequence continuity.
        if parsed.core.seq != expected_seq {
            return Err(VerifyError::SequenceGap {
                line: line_no,
                expected: expected_seq,
                got: parsed.core.seq,
            });
        }
        // Chain link: the record's declared prev must equal the running head.
        let declared_prev =
            parse_hex32(&parsed.core.prev).ok_or(VerifyError::Malformed { line: line_no })?;
        if declared_prev != prev {
            return Err(VerifyError::BrokenLink { line: line_no });
        }
        // Recompute the hash over the canonical core and compare.
        let canonical = serde_json::to_vec(&parsed.core)
            .map_err(|_| VerifyError::Malformed { line: line_no })?;
        let computed = record_hash(&prev, &canonical);
        let declared_hash =
            parse_hex32(&parsed.hash).ok_or(VerifyError::Malformed { line: line_no })?;
        if computed != declared_hash {
            return Err(VerifyError::HashMismatch { line: line_no });
        }

        // Seal-specific cryptographic verification.
        if parsed.core.kind == KIND_SEAL {
            let sealed_head = parsed
                .core
                .sealed_head
                .as_deref()
                .and_then(parse_hex32)
                .ok_or(VerifyError::MalformedSeal { line: line_no })?;
            if sealed_head != prev {
                return Err(VerifyError::SealHeadMismatch { line: line_no });
            }
            let pubkey_b64 = parsed
                .core
                .pubkey
                .as_deref()
                .ok_or(VerifyError::MalformedSeal { line: line_no })?;
            let sig_b64 = parsed
                .core
                .signature
                .as_deref()
                .ok_or(VerifyError::MalformedSeal { line: line_no })?;
            let pubkey_bytes = BASE64
                .decode(pubkey_b64)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .ok_or(VerifyError::MalformedSeal { line: line_no })?;
            if pubkey_bytes != expected.to_bytes() {
                return Err(VerifyError::PubkeyMismatch { line: line_no });
            }
            let sig_bytes = BASE64
                .decode(sig_b64)
                .ok()
                .and_then(|v| <[u8; 64]>::try_from(v).ok())
                .ok_or(VerifyError::MalformedSeal { line: line_no })?;
            let sig = Signature::from_bytes(&sig_bytes);
            expected
                .verify(&sealed_head, &sig)
                .map_err(|_| VerifyError::BadSignature { line: line_no })?;
            seals += 1;
        } else {
            events += 1;
        }

        prev = computed;
        expected_seq += 1;
        records += 1;
    }

    Ok(VerifyReport {
        records,
        events,
        seals,
        head: prev,
        next_seq: expected_seq,
    })
}

/// Parse a vault `.pub` file (standard base64) or a 64-char hex string
/// into the pinned [`VerifyingKey`].
pub fn parse_pinned_verifying_key(input: &str) -> Result<VerifyingKey, PinKeyError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PinKeyError::Empty);
    }
    if let Ok(bytes) = hex::decode(trimmed)
        && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return VerifyingKey::from_bytes(&arr).map_err(|_| PinKeyError::Invalid);
    }
    let decoded = BASE64.decode(trimmed).map_err(|_| PinKeyError::Invalid)?;
    let arr = <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| PinKeyError::Invalid)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| PinKeyError::Invalid)
}

/// Error loading the out-of-band WORM verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinKeyError {
    #[error("pinned verifying key file is empty")]
    Empty,
    #[error("pinned verifying key is not 32-byte hex or standard base64")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    fn signing_key() -> SigningKey {
        // Deterministic test seed (NOT used in production; the real seed is
        // unsealed from the vault).
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pin() -> VerifyingKey {
        signing_key().verifying_key()
    }

    fn event(seq_hint: u64) -> AuditRecord {
        AuditRecord {
            timestamp: 1_700_000_000 + seq_hint,
            event_type: "AuthFailure".to_string(),
            user_id: Some(format!("user{seq_hint}")),
            session_id: None,
            source_ip: Some("203.0.113.7".to_string()),
            details: "bad password".to_string(),
        }
    }

    /// Write N events + a final seal into a tempfile, return its bytes.
    fn build_log(n: u64, seal: bool) -> Vec<u8> {
        let tmp = tempfile::tempfile().unwrap();
        let mut log = WormLog::new(tmp, "seg-0".to_string(), GENESIS_HASH, 0);
        for i in 0..n {
            log.append_event(&event(i)).unwrap();
        }
        if seal {
            log.seal(&signing_key(), 1_700_000_999).unwrap();
        }
        // Recover the written bytes from the underlying file.
        log.writer.flush().unwrap();
        let mut file = log.writer.into_inner().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn build_then_verify_roundtrips() {
        let bytes = build_log(5, true);
        let report = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin()).unwrap();
        assert_eq!(report.records, 6);
        assert_eq!(report.events, 5);
        assert_eq!(report.seals, 1);
        assert_eq!(report.next_seq, 6);
    }

    #[test]
    fn empty_log_verifies_to_genesis() {
        let bytes = build_log(0, false);
        let report = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin()).unwrap();
        assert_eq!(report.records, 0);
        assert_eq!(report.head, GENESIS_HASH);
    }

    #[test]
    fn flipping_a_byte_breaks_verification() {
        let mut bytes = build_log(3, true);
        // Flip a byte inside the first record's details payload region.
        let pos = bytes
            .windows(b"bad password".len())
            .position(|w| w == b"bad password")
            .unwrap();
        bytes[pos] ^= 0x20;
        let err = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin()).unwrap_err();
        assert!(
            matches!(err, VerifyError::HashMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn deleting_a_line_is_detected_as_sequence_gap() {
        let bytes = build_log(4, false);
        let text = String::from_utf8(bytes).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        // Drop the 2nd record -> seq jumps 0,2,... -> gap (and broken link).
        lines.remove(1);
        let rejoined = lines.join("\n");
        let err =
            verify_reader(Cursor::new(rejoined.into_bytes()), GENESIS_HASH, 0, &pin()).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::SequenceGap { .. } | VerifyError::BrokenLink { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn reordering_records_breaks_the_chain() {
        let bytes = build_log(4, false);
        let text = String::from_utf8(bytes).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(1, 2);
        let rejoined = lines.join("\n");
        let err =
            verify_reader(Cursor::new(rejoined.into_bytes()), GENESIS_HASH, 0, &pin()).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyError::SequenceGap { .. } | VerifyError::BrokenLink { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn tampering_after_seal_with_wrong_key_is_detected() {
        // Build a sealed log, then forge an extra event + reseal with a DIFFERENT
        // key. The forged seal signature will not verify against its own pubkey?
        // It will (self-consistent), so instead simulate an attacker who edits a
        // sealed record's payload: the seal's signed head no longer matches.
        let mut bytes = build_log(2, true);
        // Corrupt the sealed_head hex inside the seal line.
        let needle = b"\"sealed_head\":\"";
        let start = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
            + needle.len();
        bytes[start] = if bytes[start] == b'0' { b'1' } else { b'0' };
        let err = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin()).unwrap_err();
        // Editing sealed_head changes the core -> hash mismatch fires first.
        assert!(
            matches!(
                err,
                VerifyError::HashMismatch { .. }
                    | VerifyError::SealHeadMismatch { .. }
                    | VerifyError::BadSignature { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn seal_signature_verifies_against_pinned_pubkey() {
        let bytes = build_log(1, true);
        // A clean sealed log must verify end to end against the out-of-band pin.
        let report = verify_reader(Cursor::new(bytes), GENESIS_HASH, 0, &pin()).unwrap();
        assert_eq!(report.seals, 1);
    }

    #[test]
    fn forged_seal_with_alien_key_is_rejected() {
        let alien = SigningKey::from_bytes(&[9u8; 32]);
        let tmp = tempfile::tempfile().unwrap();
        let mut log = WormLog::new(tmp, "seg-0".to_string(), GENESIS_HASH, 0);
        log.append_event(&event(0)).unwrap();
        log.seal(&alien, 1_700_000_999).unwrap();
        log.writer.flush().unwrap();
        let mut file = log.writer.into_inner().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let err = verify_reader(Cursor::new(buf), GENESIS_HASH, 0, &pin()).unwrap_err();
        assert!(
            matches!(err, VerifyError::PubkeyMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_pinned_verifying_key_accepts_hex_and_base64() {
        let vk = pin();
        let hex_s = hex::encode(vk.to_bytes());
        let b64 = BASE64.encode(vk.to_bytes());
        assert_eq!(parse_pinned_verifying_key(&hex_s).unwrap(), vk);
        assert_eq!(parse_pinned_verifying_key(&b64).unwrap(), vk);
        assert_eq!(
            parse_pinned_verifying_key("not-a-key"),
            Err(PinKeyError::Invalid)
        );
        assert_eq!(parse_pinned_verifying_key("  "), Err(PinKeyError::Empty));
    }

    #[test]
    fn chain_is_continuous_across_segments() {
        // Segment 1: 3 events. Capture head/seq, then continue in segment 2.
        let tmp1 = tempfile::tempfile().unwrap();
        let mut log = WormLog::new(tmp1, "seg-1".to_string(), GENESIS_HASH, 0);
        for i in 0..3 {
            log.append_event(&event(i)).unwrap();
        }
        let head_after_1 = log.head();
        let seq_after_1 = log.next_seq();

        // Rotate into a fresh file (same WormLog -> chain continues).
        let tmp2 = tempfile::tempfile().unwrap();
        log.rotate(tmp2, "seg-2".to_string()).unwrap();
        assert_eq!(log.records_in_segment(), 0);
        for i in 3..5 {
            log.append_event(&event(i)).unwrap();
        }
        log.seal(&signing_key(), 1).unwrap();

        log.writer.flush().unwrap();
        let mut f2 = log.writer.into_inner().unwrap();
        f2.seek(SeekFrom::Start(0)).unwrap();
        let mut seg2 = Vec::new();
        f2.read_to_end(&mut seg2).unwrap();

        // Verifying segment 2 standalone from genesis MUST fail (the first
        // record's prev points at segment 1's head, not genesis).
        let standalone = verify_reader(Cursor::new(seg2.clone()), GENESIS_HASH, 0, &pin());
        assert!(standalone.is_err());

        // Verifying segment 2 from segment 1's head/seq MUST succeed.
        let report = verify_reader(Cursor::new(seg2), head_after_1, seq_after_1, &pin()).unwrap();
        assert_eq!(report.events, 2);
        assert_eq!(report.seals, 1);
    }
}
