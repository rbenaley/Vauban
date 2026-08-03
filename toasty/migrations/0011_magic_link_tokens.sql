CREATE TABLE "magic_link_tokens" (
    "token_hash" TEXT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "expires_at" BIGINT NOT NULL,
    "consumed_at" BIGINT NOT NULL,
    "created_at" BIGINT NOT NULL,
    PRIMARY KEY ("token_hash")
);
CREATE INDEX "index_magic_link_tokens_by_user_id" ON "magic_link_tokens" ("user_id");
