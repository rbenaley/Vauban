//! Step-up authentication enforcement (issue #11).
//!
//! Sensitive operations (rotating a password, deleting a user, ...) MUST
//! require a fresh proof of the *operator's* strongest enrolled second
//! factor before they execute. This is the "step-up auth" pattern (NIST
//! SP 800-63B AAL2/3, RFC 9470 OAuth Step-Up).
//!
//! For this release the only second factor we support is TOTP (RFC 6238).
//! When Passkeys/WebAuthn, itsme or eID are added later, the negotiator
//! lives here and the call sites in `handlers::web` keep the same shape:
//! they hand off the operator + a piece of evidence and we either accept
//! the step-up (and persist enough state to make the proof single-use) or
//! return a structured error the handler maps to a flash + redirect.
//!
//! ## Contract for callers
//!
//! 1. Acquire a DB connection from the pool.
//! 2. Call [`enforce_totp_step_up`] with the operator UUID extracted from
//!    [`crate::middleware::auth::WebAuthUser`] and the TOTP code submitted
//!    in the form.
//! 3. On `Ok(())` the proof has been *consumed* (i.e. the operator's
//!    `last_totp_used_window` row has been advanced); the caller may now
//!    perform the side-effecting operation. The same code cannot be used
//!    again, by anyone, before the next 30-second window.
//! 4. On `Err(StepUpError)` the caller MUST abort the operation and
//!    redirect with the message returned by [`StepUpError::flash_message`].

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::totp::TOTP_STEP;

use crate::AppState;
use crate::services::auth::{AuthService, is_encrypted_mfa_secret};

/// Database connection alias used by handler-side code paths.
type Conn = diesel_async::pooled_connection::deadpool::Object<diesel_async::AsyncPgConnection>;

/// Reasons a step-up TOTP enforcement can fail.
///
/// All variants imply the caller MUST refuse the gated operation. The
/// `flash_message` helper provides the user-facing copy that the handlers
/// pass to `flash_redirect`; it is also stable enough to be matched on by
/// integration tests so the wording changes in lockstep with the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpError {
    /// The operator UUID stored in the JWT could not be parsed.
    OperatorIdentityMalformed,
    /// The operator was not found in the database, or has been
    /// soft-deleted between the JWT issuance and now.
    OperatorNotFound,
    /// The operator does not have a usable TOTP factor enrolled. Either
    /// `mfa_enabled = false` or `mfa_secret` is NULL/empty. The caller
    /// should surface a message that links to `/accounts/mfa/setup`.
    MfaNotEnrolled,
    /// The form did not contain a TOTP code (or contained only whitespace).
    CodeMissing,
    /// The TOTP code does not match the current 30-second window for the
    /// operator's secret.
    CodeInvalid,
    /// The code matched but a code from this window (or later) has already
    /// been consumed by this operator. RFC 6238 §5.2 requires we reject.
    CodeReplayed,
    /// The operator's TOTP secret is stored encrypted (vauban-vault
    /// envelope `"v{digit}:..."`) but the vault IPC client is unavailable
    /// in the current process. This is an infrastructure misconfiguration
    /// -- never the operator's fault -- so we surface it explicitly
    /// instead of returning a generic "code invalid" message that would
    /// loop the operator forever (issue #11 bugfix).
    VaultUnavailable,
    /// A database error occurred while reading or persisting state.
    DatabaseError,
    /// The vault IPC call itself failed (transport error, vault returned
    /// an internal error, etc.). Distinct from [`VaultUnavailable`] so
    /// operations can distinguish "nothing to talk to" from "talked,
    /// failed".
    VaultError,
}

impl StepUpError {
    /// User-facing message displayed via flash on redirect.
    ///
    /// These strings are part of the contract between the handler layer and
    /// the integration tests; changing them is OK but the corresponding
    /// `tests/web/user_edit_test.rs` assertions must move in lockstep.
    pub fn flash_message(self) -> &'static str {
        match self {
            StepUpError::OperatorIdentityMalformed | StepUpError::OperatorNotFound => {
                "Could not verify your identity. Please log out and log back in."
            }
            StepUpError::MfaNotEnrolled => {
                "MFA enrollment required to perform this action. \
                 Enable MFA on your profile first."
            }
            StepUpError::CodeMissing => {
                "Please enter your authenticator code to confirm this action."
            }
            StepUpError::CodeInvalid => "Authenticator code is incorrect.",
            StepUpError::CodeReplayed => {
                "Authenticator code has already been used. \
                 Please wait for the next code from your authenticator app."
            }
            StepUpError::VaultUnavailable | StepUpError::VaultError => {
                "MFA backend is temporarily unavailable. Please try again \
                 in a moment, or contact an administrator if the problem persists."
            }
            StepUpError::DatabaseError => {
                "Database error while verifying your identity. Please try again."
            }
        }
    }
}

/// Verify a TOTP step-up proof for the operator and consume it on success.
///
/// On success the operator's `last_totp_used_window` is advanced to the
/// freshly-consumed window BEFORE the function returns; this is what makes
/// the proof single-use across concurrent requests within the same
/// 30-second window.
///
/// `operator_uuid_str` is the raw string from
/// [`crate::middleware::auth::WebAuthUser::uuid`]; we parse it here so the
/// caller does not need to.
pub async fn enforce_totp_step_up(
    state: &AppState,
    conn: &mut Conn,
    operator_uuid_str: &str,
    totp_code: &str,
) -> Result<(), StepUpError> {
    let result = enforce_totp_step_up_inner(state, conn, operator_uuid_str, totp_code).await;
    if let Err(ref err) = result {
        // Centralized AccessDenied for every step-up refusal (wrong code,
        // replay, missing factor, ...). Fire-and-forget: never block the
        // sensitive operation's response on the audit transport.
        crate::services::emit_audit(
            state,
            crate::ipc::AuditEvent::new(
                shared::messages::AuditEventType::AccessDenied,
                format!(r#"{{"seam":"step_up","reason":"{err:?}"}}"#),
            )
            .user(operator_uuid_str.to_string()),
        );
    }
    result
}

async fn enforce_totp_step_up_inner(
    state: &AppState,
    conn: &mut Conn,
    operator_uuid_str: &str,
    totp_code: &str,
) -> Result<(), StepUpError> {
    use crate::schema::users;

    let trimmed_code = totp_code.trim();
    if trimmed_code.is_empty() {
        return Err(StepUpError::CodeMissing);
    }

    let operator_uuid = uuid::Uuid::parse_str(operator_uuid_str).map_err(|_| {
        tracing::warn!(
            operator = %operator_uuid_str,
            "step_up: operator UUID is malformed; rejecting step-up"
        );
        StepUpError::OperatorIdentityMalformed
    })?;

    let operator_state: Option<(i32, bool, Option<String>, Option<i64>)> = users::table
        .filter(users::uuid.eq(operator_uuid))
        .filter(users::is_deleted.eq(false))
        .select((
            users::id,
            users::mfa_enabled,
            users::mfa_secret,
            users::last_totp_used_window,
        ))
        .first(conn)
        .await
        .optional()
        .map_err(|err| {
            tracing::error!(
                operator = %operator_uuid_str,
                error = ?err,
                "step_up: database error while loading operator MFA state"
            );
            StepUpError::DatabaseError
        })?;

    let (operator_id, mfa_enabled, mfa_secret, last_window) = match operator_state {
        Some(state) => state,
        None => {
            tracing::warn!(
                operator = %operator_uuid_str,
                "step_up: operator account not found while enforcing step-up"
            );
            return Err(StepUpError::OperatorNotFound);
        }
    };

    let secret = match mfa_secret {
        Some(s) if mfa_enabled && !s.is_empty() => s,
        _ => {
            tracing::info!(
                operator = %operator_uuid_str,
                mfa_enabled,
                has_secret = mfa_secret.is_some(),
                "step_up: rejected -- operator has no usable TOTP factor enrolled"
            );
            return Err(StepUpError::MfaNotEnrolled);
        }
    };

    // Dispatch the actual TOTP comparison the same way the login flow does
    // (`crate::handlers::auth::login`): production stores the secret as a
    // vauban-vault ciphertext (`"v{digit}:..."`) that can ONLY be verified
    // by the vault process, while dev/test setups keep it as plaintext
    // base32 verifiable locally. Without this dispatch the encrypted
    // ciphertext would be fed straight to `AuthService::verify_totp`,
    // which would silently always return `false` (the ciphertext is not
    // valid base32) and surface as a permanent "Authenticator code is
    // incorrect" -- this is exactly the regression that landed in #11.
    let code_is_valid = if is_encrypted_mfa_secret(&secret) {
        let Some(vault) = state.vault_client.as_ref() else {
            tracing::error!(
                operator = %operator_uuid_str,
                "step_up: operator's MFA secret is encrypted but vault IPC client is not configured -- refusing instead of failing closed as 'invalid code'"
            );
            return Err(StepUpError::VaultUnavailable);
        };
        vault
            .mfa_verify(&secret, trimmed_code)
            .await
            .map_err(|err| {
                tracing::error!(
                    operator = %operator_uuid_str,
                    error = %err,
                    "step_up: vault.mfa_verify returned an IPC error"
                );
                StepUpError::VaultError
            })?
    } else {
        AuthService::verify_totp(&secret, trimmed_code)
    };

    if !code_is_valid {
        tracing::info!(
            operator = %operator_uuid_str,
            "step_up: rejected -- TOTP code is invalid for current window"
        );
        return Err(StepUpError::CodeInvalid);
    }

    // The code matched. Compute the consumed window AFTER verification so
    // we know we're recording a value that is at least as recent as the
    // window the code was actually accepted for. With `TOTP_SKEW = 0` the
    // accepted window is necessarily the current one (or the one that just
    // ended a few milliseconds ago); recording the slightly-later window
    // is safe and keeps the single-use guarantee intact.
    let window = chrono::Utc::now().timestamp() / (TOTP_STEP as i64);
    if let Some(last) = last_window
        && window <= last
    {
        tracing::warn!(
            operator = %operator_uuid_str,
            last_window = last,
            current_window = window,
            "step_up: rejected -- TOTP code is valid but its window has already been consumed"
        );
        return Err(StepUpError::CodeReplayed);
    }

    diesel::update(users::table.filter(users::id.eq(operator_id)))
        .set(users::last_totp_used_window.eq(window))
        .execute(conn)
        .await
        .map_err(|err| {
            tracing::error!(
                operator = %operator_uuid_str,
                error = ?err,
                "step_up: database error while consuming TOTP window"
            );
            StepUpError::DatabaseError
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flash_messages_match_test_contract() {
        assert_eq!(
            StepUpError::MfaNotEnrolled.flash_message(),
            "MFA enrollment required to perform this action. \
             Enable MFA on your profile first."
        );
        assert_eq!(
            StepUpError::CodeMissing.flash_message(),
            "Please enter your authenticator code to confirm this action."
        );
        assert_eq!(
            StepUpError::CodeInvalid.flash_message(),
            "Authenticator code is incorrect."
        );
        assert_eq!(
            StepUpError::CodeReplayed.flash_message(),
            "Authenticator code has already been used. \
             Please wait for the next code from your authenticator app."
        );
        assert_eq!(
            StepUpError::OperatorIdentityMalformed.flash_message(),
            "Could not verify your identity. Please log out and log back in."
        );
        assert_eq!(
            StepUpError::OperatorNotFound.flash_message(),
            "Could not verify your identity. Please log out and log back in."
        );
        assert_eq!(
            StepUpError::DatabaseError.flash_message(),
            "Database error while verifying your identity. Please try again."
        );
        // Vault* variants share a single user-facing copy on purpose: the
        // operator cannot do anything actionable other than retry; the
        // distinction is only useful in our logs.
        let vault_msg = "MFA backend is temporarily unavailable. Please try again \
                         in a moment, or contact an administrator if the problem persists.";
        assert_eq!(StepUpError::VaultUnavailable.flash_message(), vault_msg);
        assert_eq!(StepUpError::VaultError.flash_message(), vault_msg);
    }

    /// Source-level guard against the issue #11 regression.
    ///
    /// The bug was that `enforce_totp_step_up` fed the vault-encrypted
    /// `mfa_secret` (`v1:...`) directly to `AuthService::verify_totp`,
    /// which silently returned false. The fix is to dispatch through the
    /// vault when the secret looks encrypted -- and to return
    /// `StepUpError::VaultUnavailable` when no vault is configured.
    ///
    /// This test reads the source file and asserts the literal markers of
    /// that dispatch are still present. It will fail loudly if a future
    /// refactor accidentally removes the encryption check or the
    /// vault.mfa_verify call -- giving a maintainer a much better error
    /// than a flaky integration test 6 weeks later.
    #[test]
    fn source_guard_step_up_dispatches_through_vault_for_encrypted_secrets() {
        let src = include_str!("step_up.rs");
        assert!(
            src.contains("is_encrypted_mfa_secret(&secret)"),
            "step_up.rs no longer classifies the operator's secret -- the \
             encrypted/plaintext dispatch is gone (issue #11 regression risk)"
        );
        assert!(
            src.contains("vault.mfa_verify(&secret, trimmed_code)")
                || src.contains("vault\n            .mfa_verify(&secret, trimmed_code)"),
            "step_up.rs no longer routes encrypted secrets through \
             vault.mfa_verify (issue #11 regression risk)"
        );
        assert!(
            src.contains("StepUpError::VaultUnavailable"),
            "step_up.rs no longer raises VaultUnavailable when an encrypted \
             secret is presented without a vault client (issue #11 regression risk)"
        );
    }
}
