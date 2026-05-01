-- Email outbox for the Vauban notification system (Issue #10).
--
-- Pattern: transactional outbox. The application writes one row per
-- notification event in the SAME database transaction as the business
-- mutation that triggers it (e.g. UPDATE proxy_sessions SET status='approved'
-- and INSERT email_outbox in the same BEGIN/COMMIT). This guarantees:
--
--   * At-least-once delivery: if the business commit succeeds, the email
--     row is durable and will eventually be picked up by the dispatcher.
--   * Atomicity: a rollback of the business mutation cancels the email.
--   * Idempotence: each event has a UUID `event_id` enforced UNIQUE; a
--     replay by a buggy handler is rejected at INSERT time.
--
-- The dispatcher (vauban-web/src/tasks/mailer.rs) polls this table with
-- `SELECT ... FOR UPDATE SKIP LOCKED LIMIT N` so multiple workers (today
-- one, tomorrow several) can drain in parallel without double-sends.
--
-- Defense-in-depth header sanitization: the application MUST refuse any
-- recipient/subject containing CR or LF (anti-injection), but we also
-- pin a CHECK at the DB layer as a hard floor. Even a buggy or
-- compromised application cannot persist a header-injection payload.
CREATE TABLE email_outbox (
    id BIGSERIAL PRIMARY KEY,
    -- Idempotence key: caller-generated UUIDv4. INSERT collides on
    -- duplicate event_id so a retried handler does not enqueue twice.
    event_id UUID NOT NULL,
    -- Event taxonomy (e.g. "access_request.submitted", "user.created").
    -- Used for filtering, rate-limiting per kind, and template lookup.
    event_kind VARCHAR(64) NOT NULL,
    -- RFC 5321 maximum is 254 (local-part 64 + "@" + domain 253). We
    -- store up to 320 chars for safety with comments.
    recipient VARCHAR(320) NOT NULL,
    -- Display name for the recipient (rendered as "Name <email>").
    -- Optional (empty string == bare address).
    recipient_name VARCHAR(255) NOT NULL DEFAULT '',
    -- Subject line. RFC 2822 limits "unfolded" lines to 998 chars; we
    -- clamp to 200 for sanity. The CHECK below forbids CR/LF.
    subject VARCHAR(200) NOT NULL,
    -- text/plain body (mandatory). text/html body (optional, multipart).
    body_text TEXT NOT NULL,
    body_html TEXT,
    -- Lifecycle: pending -> (sent | failed | cancelled).
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    -- Retry bookkeeping. A pending row is eligible when
    -- next_retry_at <= NOW() (or NULL = ready immediately).
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    -- Status whitelist enforced at the DB layer.
    CONSTRAINT email_outbox_status_valid
        CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
    -- Idempotence enforced at the DB layer.
    CONSTRAINT email_outbox_event_id_unique
        UNIQUE (event_id),
    -- Anti-CRLF injection (defense-in-depth, the application MUST also
    -- sanitize before INSERT). strpos returns >0 if the substring exists.
    CONSTRAINT email_outbox_no_crlf_recipient
        CHECK (strpos(recipient, E'\r') = 0 AND strpos(recipient, E'\n') = 0),
    CONSTRAINT email_outbox_no_crlf_recipient_name
        CHECK (strpos(recipient_name, E'\r') = 0 AND strpos(recipient_name, E'\n') = 0),
    CONSTRAINT email_outbox_no_crlf_subject
        CHECK (strpos(subject, E'\r') = 0 AND strpos(subject, E'\n') = 0),
    -- Sanity bounds.
    CONSTRAINT email_outbox_attempts_nonneg
        CHECK (attempts >= 0 AND max_attempts > 0),
    CONSTRAINT email_outbox_recipient_nonempty
        CHECK (length(recipient) > 0),
    CONSTRAINT email_outbox_subject_nonempty
        CHECK (length(subject) > 0)
);

-- Hot-path index for the dispatcher's "pick the next batch" query.
-- Partial index keeps it small (only pending rows are interesting).
CREATE INDEX idx_email_outbox_pending_due
    ON email_outbox (next_retry_at NULLS FIRST, id)
    WHERE status = 'pending';

-- Index for operator queries on the admin status page (future PR).
CREATE INDEX idx_email_outbox_status_created
    ON email_outbox (status, created_at DESC);

-- Index for retry/audit queries by event kind (e.g. "show me the last
-- 50 access_request.approved emails").
CREATE INDEX idx_email_outbox_event_kind_created
    ON email_outbox (event_kind, created_at DESC);
