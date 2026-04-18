-- Step-up TOTP replay protection (issue #11 follow-up).
--
-- The Edit User flow now requires the OPERATOR (the person making the
-- request) to confirm any password rotation with a fresh TOTP code from
-- their own authenticator app. Because TOTP_SKEW = 0 (see shared/totp.rs)
-- a code is valid for exactly ONE 30-second window. To prevent an attacker
-- who intercepts a valid code from replaying it within that window on
-- another sensitive operation (RFC 6238 §5.2), we persist the last window
-- consumed by each user and refuse any code whose window has already been
-- recorded as used.
--
-- The value stored is `unix_timestamp_seconds / TOTP_STEP` (i.e. an integer
-- counter that increments once per 30 seconds). NULL means no TOTP code has
-- ever been consumed via the step-up flow yet.
ALTER TABLE users
    ADD COLUMN last_totp_used_window BIGINT NULL;

COMMENT ON COLUMN users.last_totp_used_window IS
    'Last TOTP time-step (unix_seconds / TOTP_STEP) consumed by this user '
    'via the step-up flow. Used to refuse replay of a valid code within its '
    '30-second window. See vauban-web/src/services/auth.rs::verify_and_consume_totp.';
