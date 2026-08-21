ALTER TABLE "issue_comments" ADD COLUMN "edited_at" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "issue_comments" ALTER COLUMN "edited_at" DROP DEFAULT;
