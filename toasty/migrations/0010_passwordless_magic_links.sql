ALTER TABLE "users" DROP COLUMN "password_hash";
ALTER TABLE "users" ADD COLUMN "deleted_at" BIGINT NOT NULL DEFAULT 0;
