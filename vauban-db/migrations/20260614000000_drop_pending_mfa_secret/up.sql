-- VAU-008 (ephemeral variant): drop the per-user pending MFA columns.
--
-- The candidate TOTP secret is no longer persisted in `users`. It now lives in
-- a process-local, per-session in-memory store (see
-- vauban-web/src/services/pending_mfa.rs) so that:
--   * it is never written to the database before enrolment confirmation, and
--   * two distinct login sessions of the same account get distinct candidates
--     (the previous column was shared across all sessions of a user).
ALTER TABLE users
    DROP COLUMN IF EXISTS pending_mfa_generated_at,
    DROP COLUMN IF EXISTS pending_mfa_secret;
