DROP INDEX IF EXISTS uq_contestation_per_decision;

CREATE UNIQUE INDEX uq_contestation_open_per_decision
    ON access_contestations (decision_id)
    WHERE status IN ('open', 'under_review');

CREATE INDEX idx_contestations_decision
    ON access_contestations (decision_id);
