-- One contestation per R0 decision, whatever its status: uphold and
-- overturn are final. Fails on a database that already holds two
-- contestations of one decision; resolve those by hand first.

DROP INDEX IF EXISTS uq_contestation_open_per_decision;
DROP INDEX IF EXISTS idx_contestations_decision;

CREATE UNIQUE INDEX uq_contestation_per_decision
    ON access_contestations (decision_id);
