CREATE TABLE "issue_mail_outbox" (
    "id" BIGSERIAL NOT NULL,
    "issue_id" BIGINT NOT NULL,
    "event" TEXT NOT NULL,
    "source_id" BIGINT NOT NULL,
    "actor_user_id" BIGINT NOT NULL,
    "recipient_user_id" BIGINT NOT NULL,
    "created_at" BIGINT NOT NULL,
    "sent_at" BIGINT NOT NULL,
    "attempts" BIGINT NOT NULL,
    "last_error" TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "index_issue_mail_outbox_by_issue_id_event_source_id_recipient_user_id"
    ON "issue_mail_outbox" ("issue_id", "event", "source_id", "recipient_user_id");
CREATE INDEX "index_issue_mail_outbox_by_issue_id" ON "issue_mail_outbox" ("issue_id");
CREATE INDEX "index_issue_mail_outbox_by_sent_at" ON "issue_mail_outbox" ("sent_at");
