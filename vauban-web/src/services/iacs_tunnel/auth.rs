//! Public-key authentication for IACS tunnel sessions.
//!
//! The russh server hands us a `(user, public_key)` pair. The
//! contract is:
//!
//!   * `user` is the session UUID (one-shot, issued by the
//!     `connect-iacs` route in lot L4).
//!   * `public_key` is the EWS's public key (the operator generated
//!     it once with `ssh-keygen` during the iacs onboarding flow).
//!
//! We accept iff:
//!
//!   1. There is a `proxy_sessions` row with `uuid = user` whose
//!      `session_type = 'iacs_tunnel'` and `status = 'waiting_client'`.
//!   2. There is an active `ews` row whose `public_key_fingerprint`
//!      matches the SHA-256 of the offered key AND whose `user_id`
//!      matches the row's `user_id` (no impersonating someone else's
//!      session UUID with your own EWS key).
//!   3. The session row's `ews_uuid` (pinned at L4) matches the
//!      EWS row we found.
//!
//! On any deny path we return `AuthOutcome::Reject`. The russh
//! server takes care of the constant-time rejection delay
//! (`config.auth_rejection_time`).

use base64::Engine;
use diesel_async::AsyncPgConnection;
use russh::keys::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Outcome of a public-key auth attempt. The structured form makes
/// the russh `Handler::auth_publickey` glue trivial AND lets the
/// adversarial test suite inspect the deny reason without scraping
/// log output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Auth accepted. Carries the resolved EWS UUID + user UUID
    /// so the caller can stash them on the `IacsTunnelHandler`
    /// for the relay phase (peer_ip, audit, watchdog mapping).
    Accept { ews_uuid: Uuid, user_uuid: Uuid },
    /// Auth refused with a structured reason. The reason is
    /// **never** propagated to the SSH client (russh will simply
    /// say "publickey rejected") -- it lives only in our logs and
    /// adversarial tests.
    Reject(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// `user` field of the SSH handshake is not a valid UUID.
    InvalidSessionUuidFormat,
    /// No `proxy_sessions` row matches the offered `user` UUID.
    SessionNotFound,
    /// The session row exists but is not in `waiting_client`
    /// (already claimed, expired, terminated).
    SessionWrongStatus,
    /// The session row exists but is not an IACS tunnel.
    SessionWrongType,
    /// No active EWS row matches the offered public key
    /// fingerprint.
    EwsNotFound,
    /// EWS exists but belongs to a different user than the one
    /// who created the session row.
    EwsOwnershipMismatch,
    /// The session row pins a specific `ews_uuid` and the offered
    /// key resolves to a different EWS.
    EwsSessionMismatch,
}

/// Compute the SHA-256 hex fingerprint of an OpenSSH public key,
/// matching the format `vauban_web::services::iacs::compute_fp`
/// stores in `ews.public_key_fingerprint`. The fingerprint is
/// taken over the SSH wire encoding of the key (i.e. the bytes
/// after the algorithm string in `ssh-ed25519 BASE64 comment`).
pub fn fingerprint_sha256_hex(key: &PublicKey) -> Option<String> {
    use russh::keys::PublicKeyBase64;
    let blob = key.public_key_base64();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob.as_bytes())
        .ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Database-backed verification. Pure async over the Diesel
/// connection -- the russh handler clones a `DbPool` from the
/// `AppState` and calls into this module. Kept separate so the
/// adversarial tests can construct a known-state DB and reuse
/// the same code path the production server runs.
pub async fn verify_pubkey(
    conn: &mut AsyncPgConnection,
    session_uuid_str: &str,
    public_key: &PublicKey,
) -> AuthOutcome {
    use crate::schema::{ews, proxy_sessions, users};
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    let session_uuid = match Uuid::parse_str(session_uuid_str) {
        Ok(u) => u,
        Err(_) => return AuthOutcome::Reject(RejectReason::InvalidSessionUuidFormat),
    };

    let fp_hex = match fingerprint_sha256_hex(public_key) {
        Some(s) => s,
        None => return AuthOutcome::Reject(RejectReason::EwsNotFound),
    };

    // 1) Locate the session row. Filter on session_type so a
    //    legacy SSH session UUID cannot be reused as an IACS
    //    handshake username.
    #[allow(clippy::type_complexity)]
    let session_row: Option<(i32, String, String, Option<Uuid>, Uuid)> =
        proxy_sessions::table
            .inner_join(users::table.on(users::id.eq(proxy_sessions::user_id)))
            .filter(proxy_sessions::uuid.eq(session_uuid))
            .select((
                proxy_sessions::user_id,
                proxy_sessions::session_type,
                proxy_sessions::status,
                proxy_sessions::ews_uuid,
                users::uuid,
            ))
            .first(conn)
            .await
            .optional()
            .ok()
            .flatten();

    let (session_user_id, session_type, status, pinned_ews_uuid, owner_user_uuid) =
        match session_row {
            Some(r) => r,
            None => return AuthOutcome::Reject(RejectReason::SessionNotFound),
        };

    if session_type != "iacs_tunnel" {
        return AuthOutcome::Reject(RejectReason::SessionWrongType);
    }
    if status != "waiting_client" {
        return AuthOutcome::Reject(RejectReason::SessionWrongStatus);
    }

    // 2) Locate the active EWS by fingerprint. The partial unique
    //    index `ews_active_fingerprint_uniq` guarantees there is
    //    at most one match here.
    #[allow(clippy::type_complexity)]
    let ews_row: Option<(i32, Uuid)> = ews::table
        .filter(ews::public_key_fingerprint.eq(&fp_hex))
        .filter(ews::disabled_at.is_null())
        .filter(ews::offboarded_at.is_null())
        .select((ews::user_id, ews::uuid))
        .first(conn)
        .await
        .optional()
        .ok()
        .flatten();

    let (ews_user_id, ews_uuid) = match ews_row {
        Some(r) => r,
        None => return AuthOutcome::Reject(RejectReason::EwsNotFound),
    };

    // 3) Cross-checks. Both must succeed.
    if ews_user_id != session_user_id {
        return AuthOutcome::Reject(RejectReason::EwsOwnershipMismatch);
    }
    if let Some(pinned) = pinned_ews_uuid
        && pinned != ews_uuid
    {
        return AuthOutcome::Reject(RejectReason::EwsSessionMismatch);
    }

    AuthOutcome::Accept {
        ews_uuid,
        user_uuid: owner_user_uuid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::Algorithm;
    use russh::keys::ssh_key::rand_core::OsRng;

    fn fresh_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("ed25519 keygen")
    }

    #[test]
    fn fingerprint_is_deterministic_per_key() {
        let key = fresh_key();
        let pk = key.public_key();
        let a = fingerprint_sha256_hex(pk).expect("fingerprint");
        let b = fingerprint_sha256_hex(pk).expect("fingerprint");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "sha256 hex must be 64 chars");
    }

    #[test]
    fn fingerprint_differs_per_key() {
        let a = fingerprint_sha256_hex(fresh_key().public_key()).expect("fp a");
        let b = fingerprint_sha256_hex(fresh_key().public_key()).expect("fp b");
        assert_ne!(a, b);
    }

    #[test]
    fn reject_reasons_are_distinct() {
        // Sanity: the enum has not been silently collapsed by a
        // refactor (which would let an adversarial test pass for
        // the wrong reason).
        let reasons = [
            RejectReason::InvalidSessionUuidFormat,
            RejectReason::SessionNotFound,
            RejectReason::SessionWrongStatus,
            RejectReason::SessionWrongType,
            RejectReason::EwsNotFound,
            RejectReason::EwsOwnershipMismatch,
            RejectReason::EwsSessionMismatch,
        ];
        let mut s = std::collections::HashSet::new();
        for r in reasons {
            assert!(s.insert(format!("{:?}", r)));
        }
    }
}
