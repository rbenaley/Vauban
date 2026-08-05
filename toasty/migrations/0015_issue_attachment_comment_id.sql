ALTER TABLE "issue_attachments" ADD COLUMN "issue_comment_id" BIGINT NOT NULL DEFAULT 0;
CREATE INDEX "index_issue_attachments_by_issue_comment_id" ON "issue_attachments" ("issue_comment_id");
CREATE INDEX "index_issue_attachments_by_issue_id_and_issue_comment_id" ON "issue_attachments" ("issue_id", "issue_comment_id");
