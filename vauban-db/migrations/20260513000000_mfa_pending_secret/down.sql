-- Revert VAU-008 pending TOTP secret columns.
ALTER TABLE users
    DROP COLUMN IF EXISTS pending_mfa_generated_at,
    DROP COLUMN IF EXISTS pending_mfa_secret;
