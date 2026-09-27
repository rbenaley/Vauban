-- TRUSTED R1: contestation queue hanging off R0 decision_id.
-- Overturn restores group eligibility only (no vbw_ resurrection).

CREATE TABLE access_contestations (
    id              BIGSERIAL PRIMARY KEY,
    uuid            UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    decision_id     VARCHAR(64) NOT NULL,
    session_uuid    UUID NOT NULL,
    subject_user_id INTEGER NOT NULL REFERENCES users(id),
    status          VARCHAR(16) NOT NULL
        CHECK (status IN ('open', 'under_review', 'upheld', 'overturned')),
    opened_by_id    INTEGER NOT NULL REFERENCES users(id),
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    open_reason     TEXT NOT NULL,
    claimed_by_id   INTEGER REFERENCES users(id),
    claimed_at      TIMESTAMPTZ,
    resolved_by_id  INTEGER REFERENCES users(id),
    resolved_at     TIMESTAMPTZ,
    resolution_note TEXT,
    restore_group_id INTEGER REFERENCES vauban_groups(id),
    restore_applied_at TIMESTAMPTZ,
    CONSTRAINT contestation_sod_claim
        CHECK (claimed_by_id IS NULL OR claimed_by_id <> opened_by_id),
    CONSTRAINT contestation_sod_resolve
        CHECK (resolved_by_id IS NULL OR resolved_by_id <> opened_by_id),
    CONSTRAINT contestation_overturn_has_group
        CHECK (status <> 'overturned' OR restore_group_id IS NOT NULL)
);

CREATE UNIQUE INDEX uq_contestation_open_per_decision
    ON access_contestations (decision_id)
    WHERE status IN ('open', 'under_review');

CREATE INDEX idx_contestations_status_opened
    ON access_contestations (status, opened_at DESC);

CREATE INDEX idx_contestations_decision
    ON access_contestations (decision_id);

CREATE INDEX idx_contestations_session
    ON access_contestations (session_uuid);

COMMENT ON TABLE access_contestations IS
  'TRUSTED R1: contestation of an R0 access decision (MCP session cut)';
