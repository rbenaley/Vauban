//! Cryptographic session-token module.
//!
//! Layout:
//!
//! - This file holds the wire-format primitives ([`SessionToken`],
//!   [`TokenKey`], [`Verifier`], [`TokenError`]) and the constants
//!   shared by every consumer.
//! - [`replay_cache`] holds the bounded, TTL-aware
//!   `(session_id, nonce)` LRU. Re-used identically by
//!   `vauban-supervisor` and by every protocol proxy.
//! - [`proxy_gate`] holds the proxy-boundary verification helpers
//!   (`init_from_env` + `verify_proxy`) and is consumed verbatim by
//!   `vauban-proxy-ssh`, `vauban-proxy-rdp`, and any future proxy.
//!
//! The shared layout exists for the same reason as
//! [`crate::access_guard`]: every protocol proxy must enforce the
//! exact same crypto contract, and divergence between two copies of
//! 150 lines of fail-closed code is a security liability we refuse
//! to ship.
//!
//! ---
//!
//! Cryptographic session token: a third, end-to-end gate on the
//! session-open path.
//!
//! Where [`crate::access_guard`] re-checks the live RBAC policy at the
//! proxy boundary, this module binds every irreversible side-effect of
//! a session-open (TCP connect by the supervisor, upstream protocol
//! handshake by the proxy) to a fresh, MAC-signed authorization
//! attesting that vauban-access has just verified the request.
//!
//! Architecture (see `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md`
//! for the full threat model):
//!
//! - The supervisor generates a 32-byte secret key with `OsRng` at boot
//!   and disseminates it to vauban-access (the minter) and to every
//!   verifier (the supervisor itself, vauban-proxy-ssh, vauban-proxy-rdp)
//!   via the `VAUBAN_SESSION_TOKEN_KEY` env var. Children consume and
//!   immediately remove the variable; vauban-web does NOT receive the
//!   key (it is a pure transport for the opaque token bytes).
//! - vauban-access mints a [`SessionToken`] for each session-open after
//!   re-running the policy check; the token binds
//!   `(user, asset, protocol, host, port, target_service, session_id)`
//!   to a 30-second TTL.
//! - The supervisor verifies the token in the [`Verifier::Supervisor`]
//!   role (host/port/target_service/session_id) before performing DNS
//!   resolution and `connect()`.
//! - Each protocol proxy verifies the token in the [`Verifier::Proxy`]
//!   role (user/asset/protocol/session_id) before invoking
//!   [`crate::access_guard::AccessGuard::authorize`].
//!
//! Security properties this module guarantees, in their own scope:
//!
//! 1. A correctly verified [`SessionToken`] proves that vauban-access
//!    saw and approved the EXACT tuple the verifier was about to act
//!    on, no earlier than `TOKEN_TTL_SECONDS` ago.
//! 2. Any tampering with any field invalidates the MAC (BLAKE3 keyed
//!    hash, constant-time comparison via [`subtle`]).
//! 3. Replay of a valid token is detected by the verifier's anti-replay
//!    cache (lives outside this module: see
//!    `vauban-supervisor/src/replay_cache.rs` and the per-proxy
//!    equivalents).
//!
//! Security properties this module does NOT cover:
//!
//! - **Live revocation inside the TTL window**. The token attests the
//!   policy decision at issue time; if the operator revokes the access
//!   rule one second after issuance, this module will still verify the
//!   token. [`crate::access_guard::AccessGuard`] is the line of defense
//!   for live revocation and remains required.
//! - **A misconfigured Casbin policy in vauban-access**. The token
//!   signs the decision as it stands.
//! - **A leaked MAC key**. Mitigation: in-process-only storage, env
//!   var scrubbed after read, [`secrecy::SecretBox`] with zeroize on
//!   drop, no persistence, no network egress.

use base64::Engine as _;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Token lifetime, from `issued_at` (supervisor wall-clock seconds) to
/// `expires_at`. 30 s comfortably covers the typical session-open
/// latency budget (web round-trip + access policy evaluation + supervisor
/// queue latency + proxy handshake) while keeping the replay window
/// tight.
pub const TOKEN_TTL_SECONDS: u64 = 30;

/// Tolerance for clock skew between the minter (vauban-access) and the
/// verifier (supervisor / proxy). All four processes share a host kernel
/// clock in the privsep model, so 2 s is generous; tightening it
/// further would risk spurious denials on heavily loaded hosts.
pub const CLOCK_SKEW_TOLERANCE_SECONDS: u64 = 2;

/// Domain-separation tag prefixed before every byte serialization that
/// feeds the MAC. Including the wire-format version here means a future
/// `v2` SessionToken cannot be confused with a `v1` one even if an
/// attacker controls the field encoding.
const DOMAIN_SEPARATION_TAG: &[u8] = b"vauban:v1:session_token\0";

/// Wire-format version. Bumped when the byte layout of `SessionToken`
/// changes in a way that breaks deterministic serialization (new field
/// placement, type change, etc.).
pub const TOKEN_VERSION: u8 = 1;

/// Length of the keyed-MAC tag (BLAKE3 output, in bytes).
pub const MAC_LENGTH: usize = 32;

/// Length of the per-token nonce.
pub const NONCE_LENGTH: usize = 16;

/// Length of the secret key, in bytes.
pub const KEY_LENGTH: usize = 32;

/// Env var carrying the base64-encoded 32-byte MAC key, set by the
/// supervisor before fork/exec for every consumer.
pub const SESSION_TOKEN_KEY_ENV: &str = "VAUBAN_SESSION_TOKEN_KEY";

/// Canonical protocol strings re-exported from
/// [`crate::access_guard`] so the call sites do not need both imports.
/// Re-export rather than redefining to guarantee a single source of
/// truth.
#[cfg(feature = "access-guard")]
pub use crate::access_guard::{PROTOCOL_RDP, PROTOCOL_SSH};

#[cfg(not(feature = "access-guard"))]
pub const PROTOCOL_SSH: &str = "ssh";
#[cfg(not(feature = "access-guard"))]
pub const PROTOCOL_RDP: &str = "rdp";

// ============================================================================
// TokenKey
// ============================================================================

/// 32-byte symmetric key used to sign and verify [`SessionToken`]s.
///
/// Stored inside [`SecretBox`] so the buffer is zeroized on drop and is
/// excluded from `Debug` output. The supervisor generates one of these
/// at boot (`OsRng`) and ships the bytes to its children via the
/// [`SESSION_TOKEN_KEY_ENV`] env var.
pub struct TokenKey {
    inner: SecretBox<[u8; KEY_LENGTH]>,
}

impl TokenKey {
    /// Build a key from the raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self {
            inner: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Generate a fresh random key using the OS random source.
    ///
    /// MUST be called by the supervisor exactly once at boot, BEFORE
    /// any fork/exec. The returned key is then base64-encoded into
    /// [`SESSION_TOKEN_KEY_ENV`] for dissemination.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Read [`SESSION_TOKEN_KEY_ENV`] and remove it from the
    /// environment.
    ///
    /// Fail-closed boot: returns `Err` if the variable is missing,
    /// not valid base64, or not exactly [`KEY_LENGTH`] bytes after
    /// decoding.
    ///
    /// # Safety
    ///
    /// Must be called from the main thread BEFORE any other thread is
    /// spawned, because `std::env::remove_var` is not thread-safe under
    /// the 2024 edition's lints.
    pub fn from_env() -> Result<Self, TokenKeyError> {
        let raw = std::env::var(SESSION_TOKEN_KEY_ENV)
            .map_err(|_| TokenKeyError::MissingEnvVar)?;
        // SAFETY: caller invariant -- single-threaded at this point.
        unsafe {
            std::env::remove_var(SESSION_TOKEN_KEY_ENV);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(raw.as_bytes())
            .map_err(|e| TokenKeyError::InvalidEnvVar(e.to_string()))?;
        if decoded.len() != KEY_LENGTH {
            return Err(TokenKeyError::InvalidEnvVar(format!(
                "decoded key has {} bytes, expected {}",
                decoded.len(),
                KEY_LENGTH
            )));
        }
        let mut bytes = [0u8; KEY_LENGTH];
        bytes.copy_from_slice(&decoded);
        Ok(Self::from_bytes(bytes))
    }

    /// Base64-encode the key for transport via env var.
    ///
    /// SECURITY: do NOT log, persist, or send this string over the
    /// network. The supervisor uses it exactly once before fork/exec,
    /// and removes the env var from its own environment immediately
    /// after.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.inner.expose_secret())
    }

    fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        self.inner.expose_secret()
    }
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenKey").field("inner", &"[REDACTED]").finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenKeyError {
    #[error(
        "missing env var VAUBAN_SESSION_TOKEN_KEY: vauban-supervisor did not \
         disseminate the session-token MAC key; this consumer cannot \
         {} sessions without it (refusing to start)",
        "verify"
    )]
    MissingEnvVar,
    #[error("invalid env var VAUBAN_SESSION_TOKEN_KEY: {0}")]
    InvalidEnvVar(String),
}

// ============================================================================
// SessionToken
// ============================================================================

/// The cryptographic session token.
///
/// Produced by vauban-access, transported opaquely by vauban-web,
/// verified by vauban-supervisor (before TCP connect) and by the
/// protocol proxy (before [`crate::access_guard::AccessGuard::authorize`]).
///
/// The structure is serialized with bincode for IPC transport. The MAC
/// is computed over the concatenation of [`DOMAIN_SEPARATION_TAG`] and
/// the deterministic byte serialization of every field except `mac`
/// itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionToken {
    /// Wire-format version. Always [`TOKEN_VERSION`] for tokens minted
    /// by this implementation.
    pub version: u8,
    /// UUID of the session this token authorizes. Used by the
    /// anti-replay cache as the cache key.
    pub session_id: String,
    /// UUID of the user authorized to open the session, as known to
    /// vauban-access at issue time.
    pub user_uuid: String,
    /// UUID of the asset the session targets.
    pub asset_uuid: String,
    /// Protocol identifier (`"ssh"`, `"rdp"`, ...). MUST match
    /// [`PROTOCOL_SSH`] / [`PROTOCOL_RDP`] etc.
    pub protocol: String,
    /// Target host (verified by the supervisor before DNS+connect).
    pub host: String,
    /// Target port (verified by the supervisor).
    pub port: u16,
    /// Target service that will receive the FD (encoded as its
    /// bincode discriminant via the existing
    /// [`crate::messages::Service`] enum). Verified by the supervisor.
    pub target_service: u8,
    /// Issuance time, in Unix seconds (vauban-access wall clock).
    pub issued_at: u64,
    /// Expiry time, in Unix seconds. Always equal to
    /// `issued_at + TOKEN_TTL_SECONDS`.
    pub expires_at: u64,
    /// Random nonce, included in the MAC input. Prevents two tokens
    /// for the same (user, asset, ...) at the same `issued_at` from
    /// being byte-identical.
    pub nonce: [u8; NONCE_LENGTH],
    /// BLAKE3 keyed-hash MAC over `DOMAIN_SEPARATION_TAG || sig_input`.
    pub mac: [u8; MAC_LENGTH],
}

/// Verifier role.
///
/// Different verifiers care about different fields:
///
/// - The supervisor cares about `(host, port, target_service,
///   session_id)`: it owns DNS+connect and FD passing.
/// - The proxy cares about `(user_uuid, asset_uuid, protocol,
///   session_id)`: it owns the upstream protocol handshake.
///
/// Both verifiers always check the MAC, version, and expiry. Splitting
/// the field-binding check by role is a deliberate choice: it lets each
/// verifier reject tokens that were valid at the other layer but not at
/// its own (e.g. a token forged with a matching host/port at the
/// supervisor but the wrong user/asset would be rejected at the proxy).
#[derive(Debug, Clone)]
pub enum Verifier {
    Supervisor {
        host: String,
        port: u16,
        target_service: u8,
        session_id: String,
    },
    Proxy {
        user_uuid: String,
        asset_uuid: String,
        protocol: String,
        session_id: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("malformed token bytes")]
    Malformed,
    #[error("unknown token version {0}")]
    UnknownVersion(u8),
    #[error("MAC mismatch")]
    MacMismatch,
    #[error("token expired")]
    Expired,
    #[error("token issued in the future beyond clock skew tolerance")]
    NotYetValid,
    #[error("expected_field mismatch: {0}")]
    FieldMismatch(&'static str),
    #[error("empty token bytes")]
    Empty,
}

/// Owned parameter bundle for [`SessionToken::mint`] and the IPC
/// surface around it (`AccessRequest::IssueSessionToken`,
/// `vauban-access::handle_issue_session_token`,
/// `vauban-web::AccessIpcClient::issue_session_token`).
///
/// Factored out so the same seven fields don't have to be threaded as
/// individual parameters through four call sites — the previous shape
/// triggered `clippy::too_many_arguments` at every layer and was a
/// drift hazard: adding or renaming a field would have required
/// touching four signatures and every test constructor in lock-step.
#[derive(Debug, Clone)]
pub struct SessionTokenParams {
    pub session_id: String,
    pub user_uuid: String,
    pub asset_uuid: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub target_service: crate::messages::Service,
}

impl SessionToken {
    /// Mint a new token, signed with `key`. `now` is the supervisor's
    /// idea of wall-clock seconds at issuance time (`SystemTime::UNIX_EPOCH`
    /// based). The function also draws a fresh nonce from the OS RNG.
    pub fn mint(key: &TokenKey, now: u64, params: SessionTokenParams) -> Self {
        let SessionTokenParams {
            session_id,
            user_uuid,
            asset_uuid,
            protocol,
            host,
            port,
            target_service,
        } = params;
        let mut nonce = [0u8; NONCE_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut token = Self {
            version: TOKEN_VERSION,
            session_id,
            user_uuid,
            asset_uuid,
            protocol,
            host,
            port,
            target_service: target_service.as_token_discriminant(),
            issued_at: now,
            expires_at: now.saturating_add(TOKEN_TTL_SECONDS),
            nonce,
            mac: [0u8; MAC_LENGTH],
        };
        token.mac = compute_mac(key, &token);
        token
    }

    /// Serialize the token to bytes for IPC transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TokenError> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|_| TokenError::Malformed)
    }

    /// Deserialize a token from bytes. Does NOT verify the MAC -- call
    /// [`SessionToken::verify`] afterwards.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.is_empty() {
            return Err(TokenError::Empty);
        }
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(t, _)| t)
            .map_err(|_| TokenError::Malformed)
    }

    /// Convenience helper used by every verifier: deserialize, then
    /// verify in the chosen role.
    ///
    /// Strict order: Empty > Malformed > UnknownVersion > MacMismatch >
    /// Expired > NotYetValid > FieldMismatch. The order is part of the
    /// security contract: a caller leaking the variant to the client
    /// would only ever distinguish "your token is broken" from "your
    /// token is for a different request" -- both of which collapse to
    /// the same generic `Access denied` reply at the call site.
    pub fn verify_bytes(
        bytes: &[u8],
        key: &TokenKey,
        now: u64,
        verifier: &Verifier,
    ) -> Result<Self, TokenError> {
        let token = Self::from_bytes(bytes)?;
        token.verify(key, now, verifier)?;
        Ok(token)
    }

    /// Verify a deserialized token against the key, the current time
    /// (Unix seconds), and the verifier's expected field bindings.
    pub fn verify(&self, key: &TokenKey, now: u64, verifier: &Verifier) -> Result<(), TokenError> {
        if self.version != TOKEN_VERSION {
            return Err(TokenError::UnknownVersion(self.version));
        }
        let expected_mac = compute_mac(key, self);
        if !bool::from(self.mac.as_ref().ct_eq(expected_mac.as_ref())) {
            return Err(TokenError::MacMismatch);
        }
        if now > self.expires_at {
            return Err(TokenError::Expired);
        }
        // self.issued_at is in the future beyond skew tolerance?
        if self.issued_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECONDS) {
            return Err(TokenError::NotYetValid);
        }
        match verifier {
            Verifier::Supervisor {
                host,
                port,
                target_service,
                session_id,
            } => {
                if self.session_id != *session_id {
                    return Err(TokenError::FieldMismatch("session_id"));
                }
                if self.host != *host {
                    return Err(TokenError::FieldMismatch("host"));
                }
                if self.port != *port {
                    return Err(TokenError::FieldMismatch("port"));
                }
                if self.target_service != *target_service {
                    return Err(TokenError::FieldMismatch("target_service"));
                }
            }
            Verifier::Proxy {
                user_uuid,
                asset_uuid,
                protocol,
                session_id,
            } => {
                if self.session_id != *session_id {
                    return Err(TokenError::FieldMismatch("session_id"));
                }
                if self.user_uuid != *user_uuid {
                    return Err(TokenError::FieldMismatch("user_uuid"));
                }
                if self.asset_uuid != *asset_uuid {
                    return Err(TokenError::FieldMismatch("asset_uuid"));
                }
                if self.protocol != *protocol {
                    return Err(TokenError::FieldMismatch("protocol"));
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// MAC computation
// ============================================================================

/// Compute the MAC over the deterministic serialization of `token`
/// with `mac` blanked. The serializer used here is bincode-standard, the
/// same one all IPC messages already use, so two minters producing the
/// same `(version, session_id, ..., nonce)` will produce the same MAC.
///
/// SECURITY: the domain-separation prefix is part of the MAC input.
/// Without it, a future code path that hashed `SessionToken`-shaped
/// bytes for a different purpose (audit fingerprint, cache key, ...)
/// could produce a MAC collision with this one, allowing an attacker to
/// replay the audit fingerprint as a session-open token. Any new MAC
/// usage in this codebase MUST pick its own DST.
fn compute_mac(key: &TokenKey, token: &SessionToken) -> [u8; MAC_LENGTH] {
    let mut blanked = token.clone();
    blanked.mac = [0u8; MAC_LENGTH];
    let serialized = bincode::serde::encode_to_vec(&blanked, bincode::config::standard())
        .unwrap_or_default();
    let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
    hasher.update(DOMAIN_SEPARATION_TAG);
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let mut out = [0u8; MAC_LENGTH];
    out.copy_from_slice(hash.as_bytes());
    out
}

// ============================================================================
// Submodules
// ============================================================================

pub mod replay_cache;
pub mod proxy_gate;

// ============================================================================
// Tests (Tier 1: crypto unit tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_key() -> TokenKey {
        TokenKey::generate()
    }

    fn sample_token(key: &TokenKey, now: u64) -> SessionToken {
        SessionToken::mint(
            key,
            now,
            SessionTokenParams {
                session_id: "11111111-1111-1111-1111-111111111111".to_string(),
                user_uuid: "22222222-2222-2222-2222-222222222222".to_string(),
                asset_uuid: "33333333-3333-3333-3333-333333333333".to_string(),
                protocol: PROTOCOL_SSH.to_string(),
                host: "host.example.test".to_string(),
                port: 22,
                target_service: crate::messages::Service::ProxySsh,
            },
        )
    }

    fn supervisor_view(token: &SessionToken) -> Verifier {
        Verifier::Supervisor {
            host: token.host.clone(),
            port: token.port,
            target_service: token.target_service,
            session_id: token.session_id.clone(),
        }
    }

    fn proxy_view(token: &SessionToken) -> Verifier {
        Verifier::Proxy {
            user_uuid: token.user_uuid.clone(),
            asset_uuid: token.asset_uuid.clone(),
            protocol: token.protocol.clone(),
            session_id: token.session_id.clone(),
        }
    }

    // ── happy paths ───────────────────────────────────────────────

    #[test]
    fn test_mint_then_verify_supervisor_role() {
        let key = fresh_key();
        let now = 1_700_000_000;
        let token = sample_token(&key, now);
        token
            .verify(&key, now, &supervisor_view(&token))
            .expect("freshly minted token must verify in supervisor role");
    }

    #[test]
    fn test_mint_then_verify_proxy_role() {
        let key = fresh_key();
        let now = 1_700_000_000;
        let token = sample_token(&key, now);
        token
            .verify(&key, now, &proxy_view(&token))
            .expect("freshly minted token must verify in proxy role");
    }

    #[test]
    fn test_roundtrip_serde() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let bytes = token.to_bytes().expect("serialize");
        let decoded = SessionToken::from_bytes(&bytes).expect("deserialize");
        assert_eq!(token, decoded);
    }

    // ── tampering vectors: each field flipped ────────────────────

    macro_rules! tamper_test {
        ($name:ident, |$tok:ident| $mutate:block) => {
            #[test]
            fn $name() {
                let key = fresh_key();
                let now = 1_700_000_000;
                let mut $tok = sample_token(&key, now);
                $mutate
                let result = $tok.verify(&key, now, &supervisor_view(&$tok));
                assert!(matches!(result, Err(TokenError::MacMismatch)
                                 | Err(TokenError::UnknownVersion(_))
                                 | Err(TokenError::FieldMismatch(_))),
                    "expected MAC/version/field mismatch on tampered field, got {result:?}");
            }
        };
    }

    tamper_test!(test_tampered_session_id, |t| {
        t.session_id = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
    });
    tamper_test!(test_tampered_user_uuid, |t| {
        t.user_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
    });
    tamper_test!(test_tampered_asset_uuid, |t| {
        t.asset_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
    });
    tamper_test!(test_tampered_protocol, |t| {
        t.protocol = PROTOCOL_RDP.to_string();
    });
    tamper_test!(test_tampered_host, |t| {
        t.host = "evil.example.test".to_string();
    });
    tamper_test!(test_tampered_port, |t| {
        t.port = 23;
    });
    tamper_test!(test_tampered_target_service, |t| {
        t.target_service = t.target_service.wrapping_add(1);
    });
    tamper_test!(test_tampered_issued_at, |t| {
        t.issued_at = t.issued_at.wrapping_add(1);
    });
    tamper_test!(test_tampered_expires_at, |t| {
        t.expires_at = t.expires_at.wrapping_add(1);
    });
    tamper_test!(test_tampered_nonce, |t| {
        t.nonce[0] = t.nonce[0].wrapping_add(1);
    });
    tamper_test!(test_tampered_mac, |t| {
        t.mac[0] = t.mac[0].wrapping_add(1);
    });

    // ── version, expiry, skew ─────────────────────────────────────

    #[test]
    fn test_unknown_version_fails_closed() {
        let key = fresh_key();
        let mut token = sample_token(&key, 1_700_000_000);
        token.version = 99;
        // Re-MAC with the bogus version so the version error wins
        // over the MAC error (we want to prove the version check
        // fires).
        token.mac = compute_mac(&key, &token);
        let result = token.verify(&key, 1_700_000_000, &supervisor_view(&token));
        assert_eq!(result, Err(TokenError::UnknownVersion(99)));
    }

    #[test]
    fn test_expired_token_rejected() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let later = 1_700_000_000 + TOKEN_TTL_SECONDS + 1;
        let result = token.verify(&key, later, &supervisor_view(&token));
        assert_eq!(result, Err(TokenError::Expired));
    }

    #[test]
    fn test_token_at_exact_expiry_still_valid() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let at_expiry = 1_700_000_000 + TOKEN_TTL_SECONDS;
        token
            .verify(&key, at_expiry, &supervisor_view(&token))
            .expect("token MUST still verify at the exact expiry boundary (now == expires_at)");
    }

    #[test]
    fn test_future_token_beyond_skew_rejected() {
        let key = fresh_key();
        let issued = 1_700_000_000;
        let token = sample_token(&key, issued);
        let earlier = issued - CLOCK_SKEW_TOLERANCE_SECONDS - 1;
        let result = token.verify(&key, earlier, &supervisor_view(&token));
        assert_eq!(result, Err(TokenError::NotYetValid));
    }

    #[test]
    fn test_future_token_within_skew_accepted() {
        let key = fresh_key();
        let issued = 1_700_000_000;
        let token = sample_token(&key, issued);
        let just_within = issued - CLOCK_SKEW_TOLERANCE_SECONDS;
        token
            .verify(&key, just_within, &supervisor_view(&token))
            .expect("clock skew tolerance must accept tokens minted slightly in the future");
    }

    // ── verifier-role binding ─────────────────────────────────────

    #[test]
    fn test_supervisor_verifier_rejects_wrong_host() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = supervisor_view(&token);
        if let Verifier::Supervisor { host, .. } = &mut view {
            *host = "other.example.test".to_string();
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("host"))
        );
    }

    #[test]
    fn test_supervisor_verifier_rejects_wrong_port() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = supervisor_view(&token);
        if let Verifier::Supervisor { port, .. } = &mut view {
            *port = 2222;
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("port"))
        );
    }

    #[test]
    fn test_supervisor_verifier_rejects_wrong_target_service() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = supervisor_view(&token);
        if let Verifier::Supervisor { target_service, .. } = &mut view {
            *target_service = target_service.wrapping_add(1);
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("target_service"))
        );
    }

    #[test]
    fn test_supervisor_verifier_rejects_wrong_session_id() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = supervisor_view(&token);
        if let Verifier::Supervisor { session_id, .. } = &mut view {
            *session_id = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("session_id"))
        );
    }

    #[test]
    fn test_proxy_verifier_rejects_wrong_user_uuid() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = proxy_view(&token);
        if let Verifier::Proxy { user_uuid, .. } = &mut view {
            *user_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("user_uuid"))
        );
    }

    #[test]
    fn test_proxy_verifier_rejects_wrong_asset_uuid() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = proxy_view(&token);
        if let Verifier::Proxy { asset_uuid, .. } = &mut view {
            *asset_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("asset_uuid"))
        );
    }

    #[test]
    fn test_proxy_verifier_rejects_wrong_protocol() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let mut view = proxy_view(&token);
        if let Verifier::Proxy { protocol, .. } = &mut view {
            *protocol = PROTOCOL_RDP.to_string();
        }
        assert_eq!(
            token.verify(&key, 1_700_000_000, &view),
            Err(TokenError::FieldMismatch("protocol"))
        );
    }

    // ── key isolation ─────────────────────────────────────────────

    #[test]
    fn test_token_minted_with_one_key_rejected_by_another() {
        let key_a = fresh_key();
        let key_b = fresh_key();
        let token = sample_token(&key_a, 1_700_000_000);
        let result = token.verify(&key_b, 1_700_000_000, &supervisor_view(&token));
        assert_eq!(result, Err(TokenError::MacMismatch));
    }

    #[test]
    fn test_two_mints_produce_distinct_nonces() {
        let key = fresh_key();
        let now = 1_700_000_000;
        let t1 = sample_token(&key, now);
        let t2 = sample_token(&key, now);
        assert_ne!(t1.nonce, t2.nonce, "nonces must differ across mints");
        assert_ne!(t1.mac, t2.mac, "MAC must differ when nonce differs");
    }

    #[test]
    fn test_constant_time_mac_comparison_used() {
        // Smoke test: subtle::ConstantTimeEq is in the verify() path.
        // We can't truly observe constant-time behaviour from a unit
        // test, but we can pin the call site via a regression test on
        // the source so that a future refactor that switches to
        // PartialEq fails this test.
        let source = include_str!("mod.rs");
        assert!(
            source.contains("ct_eq"),
            "MAC comparison MUST go through subtle::ConstantTimeEq::ct_eq"
        );
    }

    // ── from_bytes / verify_bytes ─────────────────────────────────

    #[test]
    fn test_empty_bytes_rejected() {
        let result = SessionToken::from_bytes(&[]);
        assert_eq!(result, Err(TokenError::Empty));
    }

    #[test]
    fn test_truncated_bytes_rejected() {
        let key = fresh_key();
        let token = sample_token(&key, 1_700_000_000);
        let bytes = token.to_bytes().unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        let result = SessionToken::from_bytes(truncated);
        assert_eq!(result, Err(TokenError::Malformed));
    }

    #[test]
    fn test_verify_bytes_round_trip() {
        let key = fresh_key();
        let now = 1_700_000_000;
        let token = sample_token(&key, now);
        let bytes = token.to_bytes().unwrap();
        let recovered =
            SessionToken::verify_bytes(&bytes, &key, now, &supervisor_view(&token)).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    fn test_verify_bytes_strict_order_unknown_version_before_mac() {
        // A token with an unknown version should fail with
        // UnknownVersion BEFORE MacMismatch is reported, even if the
        // MAC also happens to be wrong. We assert this by minting a
        // token, bumping the version, and NOT re-MACing it: both
        // version and MAC are wrong, but the verifier must report
        // UnknownVersion first.
        let key = fresh_key();
        let mut token = sample_token(&key, 1_700_000_000);
        token.version = 99;
        let bytes = token.to_bytes().unwrap();
        let result =
            SessionToken::verify_bytes(&bytes, &key, 1_700_000_000, &supervisor_view(&token));
        assert_eq!(result, Err(TokenError::UnknownVersion(99)));
    }

    // ── TokenKey ──────────────────────────────────────────────────

    #[test]
    fn test_token_key_generate_produces_random_keys() {
        let k1 = TokenKey::generate();
        let k2 = TokenKey::generate();
        assert_ne!(
            k1.as_bytes(),
            k2.as_bytes(),
            "OsRng must not produce identical 32-byte keys back to back"
        );
    }

    #[test]
    fn test_token_key_base64_roundtrip() {
        let key = TokenKey::generate();
        let encoded = key.to_base64();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .unwrap();
        assert_eq!(decoded.len(), KEY_LENGTH);
        assert_eq!(decoded.as_slice(), key.as_bytes().as_slice());
    }

    #[test]
    fn test_token_key_debug_redacts() {
        let key = TokenKey::generate();
        let dbg = format!("{:?}", key);
        assert!(
            dbg.contains("[REDACTED]"),
            "TokenKey Debug must redact the inner bytes, got: {dbg}"
        );
        assert!(
            !dbg.contains(&key.to_base64()),
            "TokenKey Debug must not leak the base64 form"
        );
    }
}
