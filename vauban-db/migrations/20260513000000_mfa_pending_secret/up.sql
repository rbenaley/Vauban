-- VAU-008: split GET/POST /mfa/setup with a pending TOTP secret.
--
-- The candidate TOTP secret generated during the (CSRF + password step-up
-- gated) `POST /mfa/setup/init` step lives in `pending_mfa_secret` until the
-- user confirms a valid code via `POST /mfa/setup`; only then is it promoted
-- to `users.mfa_secret`. Keeping the candidate OUT of `mfa_secret` guarantees:
--   * a GET can never (re)bind a second factor (no side effect), and
--   * a generation never overwrites an already-enrolled `mfa_secret`.
-- `pending_mfa_generated_at` lets the confirm step expire a stale candidate.
ALTER TABLE users
    ADD COLUMN pending_mfa_secret VARCHAR(255) NULL,
    ADD COLUMN pending_mfa_generated_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN users.pending_mfa_secret IS
    'Candidate TOTP secret (vault envelope vN:...) awaiting confirmation via '
    'POST /mfa/setup. Promoted to mfa_secret only after a valid TOTP code. '
    'See VAU-008 / vauban-web/src/handlers/auth.rs::mfa_setup_init.';

COMMENT ON COLUMN users.pending_mfa_generated_at IS
    'UTC timestamp when pending_mfa_secret was generated; used to expire a '
    'stale candidate at confirmation time (TTL).';
