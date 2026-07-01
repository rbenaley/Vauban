//! VAUBAN Web - Login-session revocation service.
//!
//! Central seam for revoking `auth_sessions` rows when a privilege- or
//! credential-affecting mutation lands on a user:
//!
//! - role change (`is_superuser` / `is_staff`) via the admin edit form,
//! - password change (admin-forced or self-service rotation),
//! - account deactivation (SEC-07, which layers proxy-session termination
//!   and API-key disabling on top of this seam).
//!
//! This is the *event-driven* half of the privilege-revocation contract.
//! The *invariant* half lives in
//! [`crate::middleware::auth`]::`verify_session_with_timeouts`, which
//! denies any session whose JWT role claims diverge from the `users` row
//! (fail-closed, zero extra queries). The two layers are independent:
//! even if a future write path forgets to call this service, the
//! per-request invariant caps the exposure window at a single request
//! for role changes. Password changes are NOT covered by the invariant
//! (the hash is not a claim), so every `password_hash` write site MUST
//! call into this module -- pinned by
//! `tests/security/privilege_revocation_test.rs`.

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use uuid::Uuid;

use crate::AppState;
use crate::schema::auth_sessions;

/// Delete the login sessions of `user_id` and force-logout the matching
/// browser tabs over WebSocket (best-effort side channel).
///
/// When `keep` carries the `auth_sessions.uuid` of the caller's own
/// session, that row survives (self-service password rotation must not
/// log out the browser that performed it) and the WebSocket force-logout
/// is narrowed to connections positively attributed to a *deleted*
/// session via its `token_hash`. Connections whose registry hash went
/// stale (cookie rotation) are cleaned up by the next authenticated
/// request instead: the row is gone, so the auth middleware denies it.
///
/// When `keep` is `None`, every session dies and every connection of the
/// user receives the force-logout redirect -- the exact SEC-07
/// deactivation behavior.
///
/// Returns the number of deleted sessions. The DB delete is the
/// authoritative act; WebSocket delivery failures are logged and ignored.
pub async fn revoke_auth_sessions(
    state: &AppState,
    user_id: i32,
    user_uuid: &str,
    keep: Option<Uuid>,
    reason: &str,
) -> usize {
    let Ok(mut conn) = state.db_pool.get().await else {
        tracing::error!(
            user_uuid = %user_uuid,
            reason = %reason,
            "revoke_auth_sessions: database unavailable, sessions NOT revoked"
        );
        return 0;
    };

    let deleted: usize;
    match keep {
        None => {
            deleted =
                diesel::delete(auth_sessions::table.filter(auth_sessions::user_id.eq(user_id)))
                    .execute(&mut conn)
                    .await
                    .unwrap_or(0);

            let force_logout_html = crate::services::session_activity::force_logout_oob(reason);
            state
                .user_connections
                .send_personalized(user_uuid, |_token_hash| force_logout_html.clone())
                .await;
        }
        Some(kept_session_uuid) => {
            // Capture the token hashes of the doomed sessions BEFORE the
            // delete so the WebSocket force-logout can be targeted at
            // exactly those browsers.
            let doomed_hashes: Vec<String> = auth_sessions::table
                .filter(auth_sessions::user_id.eq(user_id))
                .filter(auth_sessions::uuid.ne(kept_session_uuid))
                .select(auth_sessions::token_hash)
                .load(&mut conn)
                .await
                .unwrap_or_default();

            deleted = diesel::delete(
                auth_sessions::table
                    .filter(auth_sessions::user_id.eq(user_id))
                    .filter(auth_sessions::uuid.ne(kept_session_uuid)),
            )
            .execute(&mut conn)
            .await
            .unwrap_or(0);

            let force_logout_html = crate::services::session_activity::force_logout_oob(reason);
            for hash in &doomed_hashes {
                state
                    .user_connections
                    .send_to_matching(user_uuid, hash, &force_logout_html)
                    .await;
            }
        }
    }

    tracing::info!(
        user_id = user_id,
        user_uuid = %user_uuid,
        reason = %reason,
        deleted = deleted,
        kept_current = keep.is_some(),
        "Revoked login sessions"
    );
    deleted
}
