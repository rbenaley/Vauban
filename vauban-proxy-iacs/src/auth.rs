//! Public-key authentication for IACS tunnel sessions, DB-less
//! flavour.
//!
//! Unlike the legacy in-process flavour that lived inside `vauban-web`
//! (which queried `proxy_sessions`/`ews` rows in the russh handler),
//! `vauban-proxy-iacs` runs under Capsicum and has no DB connection.
//! The pre-flight authorization is fully done by `vauban-web` BEFORE
//! sending the `IacsTunnelOpen` IPC message:
//!
//!   * `vauban-web` validates the asset, the EWS ownership, the
//!     access-rule (via `vauban-access::IssueSessionToken`), the
//!     quotas, and snapshots `(user_uuid, asset_uuid, ews_uuid,
//!     ews_pubkey_fp, asset_host, asset_port, session_token, ttl)`
//!     into the `IacsTunnelOpen` payload.
//!   * `vauban-proxy-iacs` cryptographically verifies the
//!     `session_token` against its proxy MAC key
//!     ([`shared::session_token::proxy_gate::verify_proxy`]) before
//!     storing the tuple in [`PendingSessions`].
//!   * In `auth_publickey`, the russh handler ONLY checks that the
//!     offered public key fingerprints to the value pinned in the
//!     pending entry. No DB hit.
//!
//! This collapses the previous 7-way `RejectReason` enum to 3 reasons
//! visible to the proxy: invalid UUID, no pending entry, fingerprint
//! mismatch. Every other rejection is handled at the
//! `IacsTunnelOpen` boundary and surfaced as a fail-closed
//! `IacsTunnelOpened { success: false }`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use russh::keys::PublicKey;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Pre-authorized tunnel state, materialized from
/// `Message::IacsTunnelOpen` and consumed by the russh handler.
#[derive(Debug, Clone)]
pub struct PendingTunnel {
    pub session_uuid: Uuid,
    pub user_uuid: Uuid,
    pub asset_uuid: Uuid,
    pub ews_uuid: Uuid,
    /// SHA-256 hex (lower-case, 64 chars) of the EWS public key wire
    /// encoding. Used as the SOLE authentication criterion in
    /// `auth_publickey`.
    pub ews_pubkey_fp: String,
    /// Per-asset upstream target. Compared verbatim against the
    /// `direct-tcpip` request via [`crate::relay::validate_target`].
    pub asset_host: String,
    pub asset_port: u16,
    /// Industrial protocol label (`"modbus"`, `"opcua"`, `"tcp"`,
    /// ...). Currently used only for forensic logs / future audit
    /// payloads. Kept in the pending tuple so a watchdog snapshot
    /// can attribute the closure to the right protocol bucket.
    #[allow(dead_code)]
    pub industrial_protocol: String,
    /// Opaque BLAKE3-keyed token bytes. The proxy verifies them
    /// LOCALLY in `Verifier::Proxy` role (no IPC) on receive, and
    /// re-presents them on `TcpConnectRequest` so the supervisor
    /// re-verifies them in `Verifier::Supervisor` role before
    /// connecting.
    pub session_token: Vec<u8>,
    /// Wall-clock instant after which `auth_publickey` rejects even
    /// a fingerprint match. Mirrors `waiting_client_ttl_seconds`.
    pub deadline: Instant,
}

/// Outcome of a public-key auth attempt. `PartialEq`/`Eq` are not
/// derived because `PendingTunnel` carries opaque token bytes; the
/// adversarial tests pattern-match on the variant explicitly.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Accept(PendingTunnel),
    Reject(RejectReason),
}

impl AuthOutcome {
    /// Convenience predicate used by the per-handler tests.
    #[allow(dead_code)]
    pub fn is_accept(&self) -> bool {
        matches!(self, AuthOutcome::Accept(_))
    }
    /// Convenience predicate used by the per-handler tests.
    #[allow(dead_code)]
    pub fn rejected_with(&self, expected: RejectReason) -> bool {
        matches!(self, AuthOutcome::Reject(r) if *r == expected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `user` field of the SSH handshake is not a valid UUID.
    InvalidSessionUuidFormat,
    /// No pending tunnel entry: either the EWS connected before
    /// `IacsTunnelOpen` arrived, or after the deadline expired, or
    /// for a session we never knew about.
    PendingNotFound,
    /// Pending entry expired (deadline elapsed before the EWS
    /// completed its handshake).
    PendingExpired,
    /// EWS public-key fingerprint does not match the pinned value.
    FingerprintMismatch,
}

/// Compute the SHA-256 hex fingerprint of an OpenSSH public key,
/// matching the format `vauban_web::services::iacs::compute_fp`
/// stores in `ews.public_key_fingerprint`. Identical implementation
/// to the legacy in-process module so a fingerprint computed by
/// vauban-web is byte-for-byte the same as the one we compute here.
pub fn fingerprint_sha256_hex(key: &PublicKey) -> Option<String> {
    use russh::keys::PublicKeyBase64;
    let blob = key.public_key_base64();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob.as_bytes())
        .ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Process-wide concurrent map of pending tunnels.
#[derive(Debug, Default, Clone)]
pub struct PendingSessions {
    inner: Arc<Mutex<HashMap<Uuid, PendingTunnel>>>,
}

#[allow(dead_code)] // `snapshot` surfaces in Lot 5 (revocation watchdog kill)
impl PendingSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new pending entry. Returns the previously-pinned
    /// entry for the same session UUID (should always be `None` --
    /// vauban-web never re-issues the same UUID).
    pub async fn insert(&self, entry: PendingTunnel) -> Option<PendingTunnel> {
        let mut g = self.inner.lock().await;
        g.insert(entry.session_uuid, entry)
    }

    /// Remove and return the entry. Used by the handler exactly
    /// once per session: the entry is consumed when the
    /// `direct-tcpip` channel opens, so a second reuse attempt of
    /// the session UUID has nothing to take.
    pub async fn take(&self, session_uuid: &Uuid) -> Option<PendingTunnel> {
        let mut g = self.inner.lock().await;
        g.remove(session_uuid)
    }

    /// Snapshot used by the watchdog to terminate stale entries.
    pub async fn snapshot(&self) -> Vec<PendingTunnel> {
        self.inner.lock().await.values().cloned().collect()
    }

    /// Sweep entries whose deadline has elapsed. Returns the
    /// removed entries so the caller can emit `IacsTunnelClosed`
    /// to the web side.
    pub async fn drop_expired(&self, now: Instant) -> Vec<PendingTunnel> {
        let mut g = self.inner.lock().await;
        let to_remove: Vec<Uuid> = g
            .iter()
            .filter_map(|(k, v)| if v.deadline <= now { Some(*k) } else { None })
            .collect();
        let mut out = Vec::with_capacity(to_remove.len());
        for uuid in to_remove {
            if let Some(v) = g.remove(&uuid) {
                out.push(v);
            }
        }
        out
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }
}

/// Verify an offered (user, public_key) pair against the pending
/// table. Single source of truth for `auth_publickey`.
pub async fn verify_publickey(
    pending: &PendingSessions,
    session_uuid_str: &str,
    public_key: &PublicKey,
    now: Instant,
) -> AuthOutcome {
    let session_uuid = match Uuid::parse_str(session_uuid_str) {
        Ok(u) => u,
        Err(_) => return AuthOutcome::Reject(RejectReason::InvalidSessionUuidFormat),
    };
    let entry = match pending.take(&session_uuid).await {
        Some(e) => e,
        None => return AuthOutcome::Reject(RejectReason::PendingNotFound),
    };
    if entry.deadline <= now {
        return AuthOutcome::Reject(RejectReason::PendingExpired);
    }
    let fp_hex = match fingerprint_sha256_hex(public_key) {
        Some(s) => s,
        None => return AuthOutcome::Reject(RejectReason::FingerprintMismatch),
    };
    if !constant_time_eq(fp_hex.as_bytes(), entry.ews_pubkey_fp.as_bytes()) {
        return AuthOutcome::Reject(RejectReason::FingerprintMismatch);
    }
    AuthOutcome::Accept(entry)
}

/// Constant-time equality. The SSH protocol has its own constant-
/// time auth-rejection delay, but the upstream comparison should
/// not leak via a timing side-channel either. 64-char hex strings
/// keep this branch-free at zero overhead.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::Algorithm;
    use russh::keys::ssh_key::rand_core::OsRng;
    use std::time::Duration;

    fn fresh_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("ed25519 keygen")
    }

    fn pending_for(key: &PrivateKey, session: Uuid, deadline: Instant) -> PendingTunnel {
        let fp = fingerprint_sha256_hex(key.public_key()).expect("fp");
        PendingTunnel {
            session_uuid: session,
            user_uuid: Uuid::new_v4(),
            asset_uuid: Uuid::new_v4(),
            ews_uuid: Uuid::new_v4(),
            ews_pubkey_fp: fp,
            asset_host: "127.0.0.1".to_string(),
            asset_port: 4321,
            industrial_protocol: "modbus".to_string(),
            session_token: vec![],
            deadline,
        }
    }

    #[test]
    fn fingerprint_is_deterministic_per_key() {
        let key = fresh_key();
        let pk = key.public_key();
        let a = fingerprint_sha256_hex(pk).expect("a");
        let b = fingerprint_sha256_hex(pk).expect("b");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "sha256 hex must be 64 chars");
    }

    #[test]
    fn fingerprint_differs_per_key() {
        let a = fingerprint_sha256_hex(fresh_key().public_key()).expect("a");
        let b = fingerprint_sha256_hex(fresh_key().public_key()).expect("b");
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn verify_publickey_accept_happy_path() {
        let pending = PendingSessions::new();
        let session = Uuid::new_v4();
        let key = fresh_key();
        let deadline = Instant::now() + Duration::from_secs(60);
        pending.insert(pending_for(&key, session, deadline)).await;
        let outcome = verify_publickey(
            &pending,
            &session.to_string(),
            key.public_key(),
            Instant::now(),
        )
        .await;
        assert!(outcome.is_accept());
        // Pending entry is consumed.
        assert_eq!(pending.len().await, 0);
    }

    #[tokio::test]
    async fn verify_publickey_reject_on_invalid_uuid() {
        let pending = PendingSessions::new();
        let key = fresh_key();
        let outcome =
            verify_publickey(&pending, "not-a-uuid", key.public_key(), Instant::now()).await;
        assert!(outcome.rejected_with(RejectReason::InvalidSessionUuidFormat));
    }

    #[tokio::test]
    async fn verify_publickey_reject_on_unknown_session() {
        let pending = PendingSessions::new();
        let key = fresh_key();
        let outcome = verify_publickey(
            &pending,
            &Uuid::new_v4().to_string(),
            key.public_key(),
            Instant::now(),
        )
        .await;
        assert!(outcome.rejected_with(RejectReason::PendingNotFound));
    }

    #[tokio::test]
    async fn verify_publickey_reject_on_expired_pending() {
        let pending = PendingSessions::new();
        let session = Uuid::new_v4();
        let key = fresh_key();
        let past = Instant::now() - Duration::from_secs(1);
        pending.insert(pending_for(&key, session, past)).await;
        let outcome = verify_publickey(
            &pending,
            &session.to_string(),
            key.public_key(),
            Instant::now(),
        )
        .await;
        assert!(outcome.rejected_with(RejectReason::PendingExpired));
        // Even on rejection, the entry is consumed -- a second
        // attempt will see "not found" instead of "expired".
        assert_eq!(pending.len().await, 0);
    }

    #[tokio::test]
    async fn verify_publickey_reject_on_fingerprint_mismatch() {
        let pending = PendingSessions::new();
        let session = Uuid::new_v4();
        let key_a = fresh_key();
        let key_b = fresh_key();
        pending
            .insert(pending_for(
                &key_a,
                session,
                Instant::now() + Duration::from_secs(60),
            ))
            .await;
        let outcome = verify_publickey(
            &pending,
            &session.to_string(),
            key_b.public_key(),
            Instant::now(),
        )
        .await;
        assert!(outcome.rejected_with(RejectReason::FingerprintMismatch));
    }

    #[tokio::test]
    async fn drop_expired_collects_only_past_deadlines() {
        let pending = PendingSessions::new();
        let key = fresh_key();
        let now = Instant::now();
        pending
            .insert(pending_for(
                &key,
                Uuid::new_v4(),
                now - Duration::from_secs(1),
            ))
            .await;
        pending
            .insert(pending_for(
                &key,
                Uuid::new_v4(),
                now + Duration::from_secs(60),
            ))
            .await;
        let dropped = pending.drop_expired(now).await;
        assert_eq!(dropped.len(), 1);
        assert_eq!(pending.len().await, 1);
    }
}
