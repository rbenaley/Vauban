-- Materialize semver sort components for SQL ORDER BY (see release_pkg::version_sort_fields).
-- Backfill is applied in Rust via db::resync_release_sort_keys after migrations.
ALTER TABLE "releases" ADD COLUMN "v_major" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "releases" ADD COLUMN "v_minor" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "releases" ADD COLUMN "v_patch" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "releases" ADD COLUMN "has_client_suffix" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "releases" ADD COLUMN "client_suffix" TEXT NOT NULL DEFAULT '';
ALTER TABLE "releases" ALTER COLUMN "v_major" DROP DEFAULT;
ALTER TABLE "releases" ALTER COLUMN "v_minor" DROP DEFAULT;
ALTER TABLE "releases" ALTER COLUMN "v_patch" DROP DEFAULT;
ALTER TABLE "releases" ALTER COLUMN "has_client_suffix" DROP DEFAULT;
ALTER TABLE "releases" ALTER COLUMN "client_suffix" DROP DEFAULT;
