-- Drop in reverse order of creation. Triggers/functions before tables,
-- audit log before its referenced tables (no FK but conceptually downstream).

DROP TRIGGER IF EXISTS block_ews_audit_log_delete ON ews_audit_log;
DROP TRIGGER IF EXISTS block_ews_audit_log_update ON ews_audit_log;
DROP FUNCTION IF EXISTS block_ews_audit_log_mutation();

DROP INDEX IF EXISTS idx_ews_audit_log_target;
DROP INDEX IF EXISTS idx_ews_audit_log_actor;
DROP INDEX IF EXISTS idx_ews_audit_log_request_uuid;
DROP INDEX IF EXISTS idx_ews_audit_log_ews_uuid;
DROP TABLE IF EXISTS ews_audit_log;

DROP INDEX IF EXISTS idx_ews_user;
DROP INDEX IF EXISTS ews_active_fingerprint_uniq;
DROP TABLE IF EXISTS ews;

DROP INDEX IF EXISTS idx_ews_onboarding_requests_fingerprint_pending;
DROP INDEX IF EXISTS idx_ews_onboarding_requests_user;
DROP INDEX IF EXISTS idx_ews_onboarding_requests_status;
DROP TABLE IF EXISTS ews_onboarding_requests;
