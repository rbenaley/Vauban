-- Restore security constraint columns on assets with original defaults.
ALTER TABLE assets ADD COLUMN require_mfa BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE assets ADD COLUMN require_justification BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE assets ADD COLUMN max_session_duration INTEGER NOT NULL DEFAULT 28800;

-- Revert rename on access_rules.
ALTER TABLE access_rules RENAME COLUMN require_approval TO require_justification;
