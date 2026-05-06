//! IACS / EWS service.
//!
//! Splits cleanly into three responsibilities:
//!
//! 1. **SSH public key parsing + fingerprinting** ([`parse_and_validate_public_key`]).
//!    Pure function: takes the raw `id_VAUBAN.pub` content, validates the
//!    algorithm whitelist (`ssh-ed25519`, `sk-ssh-ed25519@openssh.com`),
//!    decodes the base64 payload, computes the SHA-256 hex fingerprint
//!    (lowercased) and returns a [`ParsedKey`]. This runs at form-submit
//!    time so the user gets an immediate 400 with a clear message.
//!
//! 2. **Advisory uniqueness check** ([`check_fingerprint_uniqueness_advisory`]).
//!    Read-only DB lookup, runs in vauban-web before the IPC round-trip.
//!    Authoritative re-check is on the `vauban-access` side inside the
//!    `SubmitEwsOnboarding` transaction; this function only exists for UX
//!    (so a duplicate fingerprint surfaces in the form, not after the
//!    PRG redirect).
//!
//! 3. **IPC wrappers** ([`submit_onboarding`], [`record_decision`], ...).
//!    Thin adapters over [`crate::ipc::access::AccessIpcClient`] that
//!    map [`shared::messages::EwsDenyReason`] onto a localised flash
//!    message via [`IacsError`].

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use sha2::{Digest, Sha256};
use shared::messages::{EwsDecisionKind, EwsDenyReason};

use crate::db::DbConnection;
use crate::error::AppError;
use crate::ipc::access::AccessIpcClient;
use crate::schema::{ews, ews_onboarding_requests};

// ===================================================================
// Public-key parsing
// ===================================================================

/// Whitelist of SSH key algorithms accepted by the IACS onboarding
/// flow. Adding a variant here is a deliberate operator decision --
/// every new entry SHOULD come with an updated lint script
/// (`scripts/check_iacs_kill_switch.sh`) and an E2E test in
/// `tests/web/iacs_test.rs`.
pub const ALLOWED_KEY_ALGOS: &[&str] = &["ssh-ed25519", "sk-ssh-ed25519@openssh.com"];

/// Parsed and validated SSH public key, ready to be persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKey {
    /// Algorithm label as written by `ssh-keygen` (first whitespace-
    /// separated field of the input). One of [`ALLOWED_KEY_ALGOS`].
    pub algo: String,
    /// Original base64 payload (middle field), kept for storage so the
    /// admin UI can show the exact key the user submitted -- never re-
    /// encoded by us.
    pub public_key: String,
    /// SHA-256 of the base64-decoded payload, lowercase hex (64 chars).
    /// This is the authoritative uniqueness key; the OpenSSH-style
    /// "SHA256:..." rendering is computed lazily for templates only.
    pub fingerprint_sha256_hex: String,
}

impl ParsedKey {
    /// Render the OpenSSH `SHA256:` fingerprint (base64-encoded SHA-256
    /// without padding, prefixed with `SHA256:`) for display in
    /// templates. Stable across runs for the same key.
    pub fn openssh_fingerprint(&self) -> String {
        // Re-derive bytes from hex since we only kept the hex form.
        let bytes = (0..self.fingerprint_sha256_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.fingerprint_sha256_hex[i..i + 2], 16).unwrap_or(0))
            .collect::<Vec<u8>>();
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
        format!("SHA256:{}", engine.encode(&bytes))
    }
}

/// Parsing / validation error. Mapped 1:1 to a flash message in the
/// onboarding handler; never leaked verbatim to the user (the messages
/// are already user-facing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyParseError {
    /// Empty input (form blank).
    Empty,
    /// Could not split into the expected `algo <base64>` shape.
    Malformed,
    /// Algorithm not in [`ALLOWED_KEY_ALGOS`].
    AlgoNotAllowed { found: String },
    /// Base64 decode failure.
    InvalidBase64,
    /// The base64 decodes successfully but the embedded
    /// algorithm-name length-prefix does not match the outer `algo`
    /// label. Catches a corrupt or hand-crafted payload before it
    /// reaches the DB.
    AlgoLabelMismatch,
}

impl KeyParseError {
    pub fn as_message(&self) -> String {
        match self {
            Self::Empty => "Please paste the contents of your id_VAUBAN.pub file".to_string(),
            Self::Malformed => {
                "The public key does not look like an OpenSSH `ssh-ed25519` key".to_string()
            }
            Self::AlgoNotAllowed { found } => format!(
                "Only `ssh-ed25519` and `sk-ssh-ed25519@openssh.com` keys are accepted; \
                 your key uses `{}`. Please re-generate with `ssh-keygen -t ed25519 -C VAUBAN -N \"\"`.",
                found
            ),
            Self::InvalidBase64 => "The public key payload is not valid base64".to_string(),
            Self::AlgoLabelMismatch => {
                "The algorithm label inside the key does not match the prefix".to_string()
            }
        }
    }
}

/// Parse and validate an OpenSSH public key (the content of
/// `~/.ssh/id_VAUBAN.pub`). Accepts and ignores any trailing comment
/// (`user@host`) and surrounding whitespace. Returns a [`ParsedKey`]
/// on success; map to [`AppError`] in handlers via [`IacsError`].
pub fn parse_and_validate_public_key(raw: &str) -> Result<ParsedKey, KeyParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KeyParseError::Empty);
    }
    let mut parts = trimmed.split_ascii_whitespace();
    let algo = parts.next().ok_or(KeyParseError::Malformed)?;
    let payload_b64 = parts.next().ok_or(KeyParseError::Malformed)?;
    if !ALLOWED_KEY_ALGOS.contains(&algo) {
        return Err(KeyParseError::AlgoNotAllowed {
            found: algo.to_string(),
        });
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let payload_bytes = engine
        .decode(payload_b64.as_bytes())
        .map_err(|_| KeyParseError::InvalidBase64)?;

    // OpenSSH wire format: each field is a length-prefixed (4-byte BE
    // u32) blob. The first field is the algorithm name -- it MUST
    // match the outer label, otherwise the file was hand-crafted /
    // corrupted. Defense in depth: a malicious user could not paste
    // an `ssh-rsa` key under the `ssh-ed25519` label without us
    // catching it here AND on the proxy at session time.
    if payload_bytes.len() < 4 {
        return Err(KeyParseError::Malformed);
    }
    let algo_len = u32::from_be_bytes([
        payload_bytes[0],
        payload_bytes[1],
        payload_bytes[2],
        payload_bytes[3],
    ]) as usize;
    if 4 + algo_len > payload_bytes.len() {
        return Err(KeyParseError::Malformed);
    }
    let inner_algo = std::str::from_utf8(&payload_bytes[4..4 + algo_len])
        .map_err(|_| KeyParseError::Malformed)?;
    if inner_algo != algo {
        return Err(KeyParseError::AlgoLabelMismatch);
    }

    let mut hasher = Sha256::new();
    hasher.update(&payload_bytes);
    let digest = hasher.finalize();
    let fingerprint_sha256_hex = digest.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(ParsedKey {
        algo: algo.to_string(),
        public_key: payload_b64.to_string(),
        fingerprint_sha256_hex,
    })
}

// ===================================================================
// Advisory uniqueness
// ===================================================================

/// Outcome of the advisory uniqueness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryUniqueness {
    Available,
    /// Fingerprint claimed by an active or disabled `ews` row. The
    /// authoritative re-check inside `SubmitEwsOnboarding` will also
    /// catch this -- this advisory check exists for UX so the form
    /// surfaces a 400 immediately.
    LockedByActive,
    /// Fingerprint claimed by another pending request (any user).
    LockedByPending,
}

/// Read-only fingerprint uniqueness lookup. Runs BEFORE the IPC
/// round-trip; in-transaction re-check on `vauban-access` is the
/// authoritative gate (TOCTOU-safe).
pub async fn check_fingerprint_uniqueness_advisory(
    conn: &mut DbConnection,
    fingerprint: &str,
    exclude_request_uuid: Option<uuid::Uuid>,
) -> Result<AdvisoryUniqueness, AppError> {
    let active: i64 = ews::table
        .filter(ews::public_key_fingerprint.eq(fingerprint))
        .filter(ews::offboarded_at.is_null())
        .count()
        .get_result(conn)
        .await?;
    if active > 0 {
        return Ok(AdvisoryUniqueness::LockedByActive);
    }
    let mut q = ews_onboarding_requests::table
        .filter(ews_onboarding_requests::public_key_fingerprint.eq(fingerprint))
        .filter(ews_onboarding_requests::status.eq("pending"))
        .into_boxed();
    if let Some(uuid) = exclude_request_uuid {
        q = q.filter(ews_onboarding_requests::uuid.ne(uuid));
    }
    let pending: i64 = q.count().get_result(conn).await?;
    if pending > 0 {
        return Ok(AdvisoryUniqueness::LockedByPending);
    }
    Ok(AdvisoryUniqueness::Available)
}

// ===================================================================
// Service-level error type used by handlers
// ===================================================================

/// Unified error surface for the IACS handlers. Handlers map any
/// service call onto either an HTTP redirect with a flash message
/// (business denial via `Deny`) or an `AppError` (DB/IPC failure).
///
/// Not `Clone`: `AppError` carries non-cloneable variants (DB error
/// types). Pass by value or by reference; never duplicate.
#[derive(Debug)]
pub enum IacsError {
    /// User input failed validation. Contains a ready-to-flash
    /// localised message.
    InvalidInput(String),
    /// Business-level deny from the in-transaction re-check on
    /// `vauban-access`. Handlers map the `EwsDenyReason` variant to
    /// either a flash message + redirect (most cases) or a 404
    /// (anti-enumeration: `RequestNotFound`, `EwsNotFound`,
    /// `NotOwner`).
    Deny(EwsDenyReason),
    /// Underlying DB / IPC failure. Bubbled up as a 500.
    Internal(AppError),
}

impl From<KeyParseError> for IacsError {
    fn from(e: KeyParseError) -> Self {
        Self::InvalidInput(e.as_message())
    }
}

impl From<AppError> for IacsError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

// ===================================================================
// IPC wrappers (thin)
// ===================================================================

/// Submit an EWS onboarding request via IPC.
#[allow(clippy::too_many_arguments)]
pub async fn submit_onboarding(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    name: String,
    parsed: &ParsedKey,
    justification: String,
    max_ews_per_user: u32,
    actor_ip: Option<String>,
) -> Result<(String, i64), IacsError> {
    match client
        .submit_ews_onboarding(
            actor_user_uuid,
            name,
            parsed.public_key.clone(),
            parsed.fingerprint_sha256_hex.clone(),
            parsed.algo.clone(),
            justification,
            max_ews_per_user,
            actor_ip,
        )
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(pair) => Ok(pair),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Edit a pending EWS request via IPC.
#[allow(clippy::too_many_arguments)]
pub async fn edit_request(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    request_uuid: &str,
    name: String,
    parsed: &ParsedKey,
    justification: String,
    actor_ip: Option<String>,
) -> Result<i64, IacsError> {
    match client
        .edit_ews_request(
            actor_user_uuid,
            request_uuid,
            name,
            parsed.public_key.clone(),
            parsed.fingerprint_sha256_hex.clone(),
            parsed.algo.clone(),
            justification,
            actor_ip,
        )
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(id) => Ok(id),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Cancel a pending EWS request via IPC.
pub async fn cancel_request(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    request_uuid: &str,
    actor_ip: Option<String>,
) -> Result<i64, IacsError> {
    match client
        .cancel_ews_request(actor_user_uuid, request_uuid, actor_ip)
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(id) => Ok(id),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Record an admin decision (approve / reject) via IPC.
pub async fn record_decision(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    request_uuid: &str,
    decision: EwsDecisionKind,
    decision_reason: Option<String>,
    actor_ip: Option<String>,
) -> Result<(i64, Option<String>), IacsError> {
    match client
        .record_ews_decision(
            actor_user_uuid,
            request_uuid,
            decision,
            decision_reason,
            actor_ip,
        )
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(pair) => Ok(pair),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Disable an active EWS via IPC.
pub async fn disable(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    ews_uuid: &str,
    actor_ip: Option<String>,
) -> Result<i64, IacsError> {
    match client
        .disable_ews(actor_user_uuid, ews_uuid, actor_ip)
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(id) => Ok(id),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Re-enable a disabled EWS via IPC.
pub async fn enable(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    ews_uuid: &str,
    actor_ip: Option<String>,
) -> Result<i64, IacsError> {
    match client
        .enable_ews(actor_user_uuid, ews_uuid, actor_ip)
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(id) => Ok(id),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

/// Offboard an EWS via IPC.
pub async fn offboard(
    client: &AccessIpcClient,
    actor_user_uuid: &str,
    ews_uuid: &str,
    on_behalf_of_self: bool,
    decision_reason: Option<String>,
    actor_ip: Option<String>,
) -> Result<i64, IacsError> {
    match client
        .offboard_ews(
            actor_user_uuid,
            ews_uuid,
            on_behalf_of_self,
            decision_reason,
            actor_ip,
        )
        .await
        .map_err(IacsError::Internal)?
    {
        Ok(id) => Ok(id),
        Err(reason) => Err(IacsError::Deny(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid OpenSSH ed25519 line by injecting a
    /// reproducible "fake" payload. The function under test only
    /// inspects the algorithm name + base64 + length-prefixed inner
    /// algo; we don't need a real ed25519 public key.
    fn make_ed25519_line(comment: Option<&str>) -> String {
        // Wire format: u32 len (=11 = b"ssh-ed25519".len()) || "ssh-ed25519" || u32(32) || 32 bytes
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[0xAB; 32]);
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(&blob);
        match comment {
            Some(c) => format!("ssh-ed25519 {} {}", payload, c),
            None => format!("ssh-ed25519 {}", payload),
        }
    }

    #[test]
    fn parse_empty_input() {
        assert_eq!(parse_and_validate_public_key(""), Err(KeyParseError::Empty));
        assert_eq!(
            parse_and_validate_public_key("   \n\t  "),
            Err(KeyParseError::Empty)
        );
    }

    #[test]
    fn parse_malformed_no_payload() {
        assert_eq!(
            parse_and_validate_public_key("ssh-ed25519"),
            Err(KeyParseError::Malformed)
        );
    }

    #[test]
    fn parse_rejects_unsupported_algo() {
        let line = "ssh-rsa AAAAB3NzaC1yc2E= test@host";
        let res = parse_and_validate_public_key(line);
        match res {
            Err(KeyParseError::AlgoNotAllowed { found }) => assert_eq!(found, "ssh-rsa"),
            other => panic!("expected AlgoNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_ecdsa() {
        let line = "ecdsa-sha2-nistp256 AAAAE2VjZHNh test@host";
        assert!(matches!(
            parse_and_validate_public_key(line),
            Err(KeyParseError::AlgoNotAllowed { .. })
        ));
    }

    #[test]
    fn parse_rejects_invalid_base64() {
        let line = "ssh-ed25519 not-base64!!!";
        assert_eq!(
            parse_and_validate_public_key(line),
            Err(KeyParseError::InvalidBase64)
        );
    }

    #[test]
    fn parse_accepts_well_formed_ed25519() {
        let line = make_ed25519_line(Some("VAUBAN"));
        let parsed = parse_and_validate_public_key(&line).unwrap();
        assert_eq!(parsed.algo, "ssh-ed25519");
        assert_eq!(parsed.fingerprint_sha256_hex.len(), 64);
        assert!(
            parsed
                .fingerprint_sha256_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn parse_ignores_optional_comment() {
        let with = parse_and_validate_public_key(&make_ed25519_line(Some("user@host"))).unwrap();
        let without = parse_and_validate_public_key(&make_ed25519_line(None)).unwrap();
        assert_eq!(
            with.fingerprint_sha256_hex, without.fingerprint_sha256_hex,
            "comment must not affect fingerprint"
        );
    }

    #[test]
    fn parse_detects_inner_algo_label_mismatch() {
        // Build a payload whose outer label says ssh-ed25519 but the
        // inner algorithm-name length-prefix says "ssh-rsa".
        let mut blob = Vec::new();
        blob.extend_from_slice(&7u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-rsa");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[0u8; 32]);
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(&blob);
        let line = format!("ssh-ed25519 {}", payload);
        assert_eq!(
            parse_and_validate_public_key(&line),
            Err(KeyParseError::AlgoLabelMismatch)
        );
    }

    #[test]
    fn parse_accepts_sk_ed25519() {
        // Build a sk-ssh-ed25519@openssh.com payload (algo name is
        // longer; we only check the prefix matches).
        let algo = "sk-ssh-ed25519@openssh.com";
        let mut blob = Vec::new();
        blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        blob.extend_from_slice(algo.as_bytes());
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[0u8; 32]);
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(&blob);
        let line = format!("{} {}", algo, payload);
        let parsed = parse_and_validate_public_key(&line).unwrap();
        assert_eq!(parsed.algo, algo);
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_key() {
        let line = make_ed25519_line(None);
        let a = parse_and_validate_public_key(&line).unwrap();
        let b = parse_and_validate_public_key(&line).unwrap();
        assert_eq!(a.fingerprint_sha256_hex, b.fingerprint_sha256_hex);
    }

    #[test]
    fn openssh_fingerprint_starts_with_sha256_prefix() {
        let line = make_ed25519_line(None);
        let parsed = parse_and_validate_public_key(&line).unwrap();
        let fp = parsed.openssh_fingerprint();
        assert!(fp.starts_with("SHA256:"));
        // Standard SHA-256 base64-no-pad is 43 chars.
        assert_eq!(fp.len(), "SHA256:".len() + 43);
    }

    #[test]
    fn key_parse_error_messages_are_actionable() {
        for e in [
            KeyParseError::Empty,
            KeyParseError::Malformed,
            KeyParseError::AlgoNotAllowed {
                found: "ssh-rsa".into(),
            },
            KeyParseError::InvalidBase64,
            KeyParseError::AlgoLabelMismatch,
        ] {
            let msg = e.as_message();
            assert!(!msg.is_empty(), "every variant must surface a message");
        }
    }

    #[test]
    fn allowed_algos_are_stable() {
        // Pin the whitelist so a future PR that loosens it must do so
        // explicitly.
        assert_eq!(ALLOWED_KEY_ALGOS.len(), 2);
        assert!(ALLOWED_KEY_ALGOS.contains(&"ssh-ed25519"));
        assert!(ALLOWED_KEY_ALGOS.contains(&"sk-ssh-ed25519@openssh.com"));
    }
}
