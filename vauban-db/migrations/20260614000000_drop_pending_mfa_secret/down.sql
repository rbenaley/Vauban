-- Revert: re-add the per-user pending MFA columns (symmetric with
-- 20260513000000_mfa_pending_secret).
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
