-- Rename require_justification to require_approval on access_rules.
-- The flag controls the JIT approval workflow, not just justification text.
ALTER TABLE access_rules RENAME COLUMN require_justification TO require_approval;

-- Remove security constraint columns from assets.
-- These belong on access_rules only (PAM best practice: constraints at rule level).
ALTER TABLE assets DROP COLUMN require_mfa;
ALTER TABLE assets DROP COLUMN require_justification;
ALTER TABLE assets DROP COLUMN max_session_duration;
