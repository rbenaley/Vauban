//! Cryptographic session-token verification at a protocol-proxy
//! boundary.
//!
//! This module is the **single, factorized, fail-closed gate** every
//! Vauban protocol proxy (`vauban-proxy-ssh`, `vauban-proxy-rdp`,
//! future VNC and industrial proxies) runs against the cryptographic
//! session token before invoking [`crate::access_guard::AccessGuard`]
//! and before opening an upstream session.
//!
//! Why a shared module: every proxy must enforce the exact same crypto
//! contract (same key loader, same MAC verification, same anti-replay
//! window, same fail-closed semantics). A copy per proxy is a security
//! liability — see the equivalent rationale for [`crate::access_guard`].
//!
//! Lifecycle (mirrors `AccessGuard::from_env`):
//!
//! 1. Each proxy calls [`init_from_env`] **before** Capsicum sealing,
//!    because [`super::TokenKey::from_env`] reads then removes the
//!    env var from the process environment, which is impossible once
//!    in capability mode.
//! 2. The proxy's session-open handler calls [`verify_proxy`] inline,
//!    BEFORE the existing `AccessGuard::authorize` round-trip; failure
//!    collapses to a fail-closed deny.
//!
//! See `docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md` §6.

use super::replay_cache::ReplayCache;
use super::{SessionToken, TokenKey, Verifier};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

static TOKEN_KEY: OnceLock<TokenKey> = OnceLock::new();
static REPLAY_CACHE: OnceLock<Mutex<ReplayCache>> = OnceLock::new();

/// Construction-time failure for [`init_from_env`].
#[derive(Debug, thiserror::Error)]
pub enum ProxyGateError {
    #[error("Failed to load VAUBAN_SESSION_TOKEN_KEY: {0}")]
    TokenKey(#[from] super::TokenKeyError),
    #[error("session-token key already initialized")]
    AlreadyInitialized,
}

/// Load `VAUBAN_SESSION_TOKEN_KEY` (set by `vauban-supervisor`) into
/// the process-global [`TokenKey`] and prepare the per-proxy
/// anti-replay cache. MUST be called from the main thread, before any
/// other thread is spawned, because [`super::TokenKey::from_env`]
/// removes the env var from the process environment.
///
/// Returns an error if the variable is missing, malformed, or the key
/// is already initialized — every error path is a hard boot failure
/// for the proxy.
pub fn init_from_env() -> Result<(), ProxyGateError> {
    let key = TokenKey::from_env()?;
    TOKEN_KEY
        .set(key)
        .map_err(|_| ProxyGateError::AlreadyInitialized)?;
    let _ = REPLAY_CACHE.set(Mutex::new(ReplayCache::new()));
    Ok(())
}

/// Verify a session token at the proxy boundary. Returns `true` if
/// the token is fresh, MAC-valid, binds the expected
/// `(user_uuid, asset_uuid, protocol, session_id)`, and is not a
/// replay. Returns `false` on any failure.
///
/// Fail-closed: if the key was never initialized (operator forgot the
/// env var, dev mode), this returns `false` so no session can open.
pub fn verify_proxy(
    token_bytes: &[u8],
    user_uuid: &str,
    asset_uuid: &str,
    protocol: &str,
    session_id: &str,
) -> bool {
    let key = match TOKEN_KEY.get() {
        Some(k) => k,
        None => {
            warn!(
                "session-token key not initialized; fail-closed deny \
                 (vauban-supervisor must set VAUBAN_SESSION_TOKEN_KEY)"
            );
            return false;
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verifier = Verifier::Proxy {
        user_uuid: user_uuid.to_string(),
        asset_uuid: asset_uuid.to_string(),
        protocol: protocol.to_string(),
        session_id: session_id.to_string(),
    };
    let token = match SessionToken::verify_bytes(token_bytes, key, now, &verifier) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                session_id,
                protocol, "session token rejected at proxy: {e}; fail-closed deny"
            );
            return false;
        }
    };
    // Anti-replay (post-MAC, post-expiry checks: the cache only sees
    // tokens that were otherwise valid, so we can't be DoS'd by junk).
    match REPLAY_CACHE.get().and_then(|m| {
        m.lock()
            .ok()
            .map(|mut c| c.record(&token.session_id, &token.nonce))
    }) {
        Some(true) => true,
        Some(false) => {
            warn!(
                session_id,
                "session token replay detected at proxy; fail-closed deny"
            );
            false
        }
        None => {
            warn!("replay cache lock failed; fail-closed deny");
            false
        }
    }
}
