-- Closed status vocabulary for proxy_sessions (July 2026 status audit).
--
-- The column carried no constraint, which let two phantom statuses
-- accumulate: 'completed' (written only by the demo seeder) and
-- 'consumed' (never written by any code path). Both are folded into
-- 'disconnected', then the vocabulary is sealed by a CHECK kept in
-- lock-step with `SessionStatus::ALL` (vauban-web/src/models/session.rs)
-- by tests/web/status_vocab_drift_test.rs.
--
-- Any OTHER out-of-vocabulary value makes the ALTER fail loudly
-- (fail-closed on purpose): an operator must look at the rows instead
-- of this migration silently laundering them.

UPDATE proxy_sessions
    SET status = 'disconnected'
    WHERE status IN ('completed', 'consumed');

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_status_chk;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_status_chk
    CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired', 'orphaned', 'connecting', 'active', 'disconnected', 'terminated', 'failed', 'waiting_client', 'tunnel_active'));
