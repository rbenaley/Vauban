-- IACS / Engineering Workstation (EWS) onboarding -- preliminary scaffolding.
--
-- This migration introduces the data model for the IACS section: industrial
-- operators ("EWS owners") submit onboarding requests for their workstations
-- (laptop / desktop running an SSH client used to reach future IACS assets);
-- administrators then approve, reject, disable, re-enable, or offboard them.
--
-- The schema mirrors the JIT access pattern shipped in
-- 20260425000000_approval_audit_and_sod (deux tables + audit append-only):
--
--   1. ews_onboarding_requests -- pending / approved / rejected / cancelled
--      lifecycle. A row stays for the entire request history (a request can
--      be edited while pending, cancelled by the requester, or decided by an
--      admin). Once approved, the matching `ews` row is created in the same
--      transaction (vauban-access enforces atomicity).
--
--   2. ews -- the approved EWS. Holds the active SSH public key, plus
--      disable / offboard soft-delete columns. Offboarded rows are kept for
--      audit (FK target of `ews_audit_log`) but never become active again
--      (offboarding is irreversible by design).
--
--   3. ews_audit_log -- append-only trail of every state transition (submit,
--      edit, cancel, approve, reject, disable, enable, offboard). Same
--      `block_*_mutation` trigger pattern as `approval_audit_log` so a
--      compromised app or a non-superuser DBA cannot rewrite history.
--
-- Snapshots: actor / target usernames and EWS name are denormalised at write
-- time so the trail survives later user soft-deletes (FKs use ON DELETE SET
-- NULL on the user-id columns; snapshots stay).
--
-- Defense-in-depth: an additional partial unique index on `ews` enforces
-- "one active fingerprint at a time" at the DB layer. The advisory check at
-- form-submit time exists in vauban-web for UX (immediate 400 with a clear
-- message), but the DB index is the authoritative gate.

-- 1) Onboarding requests. Status transitions:
--    pending -> approved  (admin RecordEwsDecision Approve)
--    pending -> rejected  (admin RecordEwsDecision Reject; reason required)
--    pending -> cancelled (requester CancelEwsRequest)
--    The row is never deleted, never UPDATEd back to pending after a final
--    decision (CHECK below). Re-submissions create a NEW request row with a
--    fresh uuid; the original row stays for audit.
CREATE TABLE ews_onboarding_requests (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_algo VARCHAR(40) NOT NULL,
    justification VARCHAR(250) NOT NULL,
    status VARCHAR(10) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    decision_reason TEXT NULL,
    decided_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    decided_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_request_decision_consistency CHECK (
        (status = 'pending' AND decided_by_id IS NULL AND decided_at IS NULL)
        OR
        (status IN ('approved', 'cancelled') AND decided_at IS NOT NULL)
        OR
        (status = 'rejected' AND decided_at IS NOT NULL AND decision_reason IS NOT NULL)
    )
);

CREATE INDEX idx_ews_onboarding_requests_status
    ON ews_onboarding_requests (status);

CREATE INDEX idx_ews_onboarding_requests_user
    ON ews_onboarding_requests (user_id, status, created_at DESC);

CREATE INDEX idx_ews_onboarding_requests_fingerprint_pending
    ON ews_onboarding_requests (public_key_fingerprint)
    WHERE status = 'pending';

-- 2) Approved EWS. State derived from disabled_at / offboarded_at:
--      both NULL                       -> active
--      disabled_at IS NOT NULL, ...    -> disabled (reversible by enable)
--      offboarded_at IS NOT NULL       -> offboarded (irreversible soft-delete)
--    A disabled EWS keeps the fingerprint locked (an admin may re-enable
--    later and we don't want a stranger to grab the key meanwhile). Only
--    offboarding releases the fingerprint -- enforced by the partial unique
--    index below.
CREATE TABLE ews (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    request_uuid UUID NOT NULL UNIQUE
        REFERENCES ews_onboarding_requests(uuid) ON DELETE RESTRICT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    key_algo VARCHAR(40) NOT NULL,
    disabled_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    disabled_at TIMESTAMPTZ NULL,
    offboarded_by_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    offboarded_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_disabled_consistency CHECK (
        (disabled_at IS NULL AND disabled_by_id IS NULL)
        OR
        (disabled_at IS NOT NULL)
    ),
    CONSTRAINT ews_offboarded_consistency CHECK (
        (offboarded_at IS NULL AND offboarded_by_id IS NULL)
        OR
        (offboarded_at IS NOT NULL)
    )
);

-- One active fingerprint at a time. Covers active + disabled rows; only
-- offboarded rows release the fingerprint, which matches the spec:
--   - the user can re-submit the same key after offboarding,
--   - but two simultaneous active EWS cannot share a key.
CREATE UNIQUE INDEX ews_active_fingerprint_uniq
    ON ews (public_key_fingerprint)
    WHERE offboarded_at IS NULL;

CREATE INDEX idx_ews_user
    ON ews (user_id, created_at DESC);

-- 3) Append-only audit log. One row per state transition.
--    Snapshot fields denormalise the actor / target usernames and the EWS
--    name at decision time so the trail survives later user soft-delete.
CREATE TABLE ews_audit_log (
    id BIGSERIAL PRIMARY KEY,
    ews_uuid UUID NULL,
    request_uuid UUID NULL,
    event VARCHAR(20) NOT NULL CHECK (event IN (
        'submitted', 'edited', 'cancelled',
        'approved', 'rejected',
        'disabled', 'enabled',
        'offboarded'
    )),
    actor_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(150) NOT NULL,
    target_user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
    target_username VARCHAR(150) NOT NULL,
    ews_name VARCHAR(128) NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    decision_reason TEXT NULL,
    actor_ip INET NULL,
    request_id VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ews_audit_log_event_targets_at_least_one CHECK (
        ews_uuid IS NOT NULL OR request_uuid IS NOT NULL
    )
);

-- 4) Append-only invariant -- same pattern as `block_approval_audit_log_mutation`.
--    UPDATE / DELETE are rejected, except for the FK cascaded SET NULL on
--    actor_user_id / target_user_id (snapshot usernames are preserved).
CREATE OR REPLACE FUNCTION block_ews_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'ews_audit_log is append-only (DELETE on id=% rejected)',
            OLD.id
            USING ERRCODE = 'check_violation';
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id, NEW.ews_uuid, NEW.request_uuid, NEW.event,
               NEW.actor_username, NEW.target_username,
               NEW.ews_name, NEW.public_key_fingerprint,
               NEW.decision_reason, NEW.actor_ip,
               NEW.request_id, NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id, OLD.ews_uuid, OLD.request_uuid, OLD.event,
               OLD.actor_username, OLD.target_username,
               OLD.ews_name, OLD.public_key_fingerprint,
               OLD.decision_reason, OLD.actor_ip,
               OLD.request_id, OLD.created_at)
        THEN
            RAISE EXCEPTION
                'ews_audit_log is append-only (UPDATE on id=% rejected)',
                OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER block_ews_audit_log_update
    BEFORE UPDATE ON ews_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_ews_audit_log_mutation();

CREATE TRIGGER block_ews_audit_log_delete
    BEFORE DELETE ON ews_audit_log
    FOR EACH ROW EXECUTE FUNCTION block_ews_audit_log_mutation();

CREATE INDEX idx_ews_audit_log_ews_uuid
    ON ews_audit_log (ews_uuid)
    WHERE ews_uuid IS NOT NULL;

CREATE INDEX idx_ews_audit_log_request_uuid
    ON ews_audit_log (request_uuid)
    WHERE request_uuid IS NOT NULL;

CREATE INDEX idx_ews_audit_log_actor
    ON ews_audit_log (actor_user_id, created_at DESC);

CREATE INDEX idx_ews_audit_log_target
    ON ews_audit_log (target_user_id, created_at DESC);
