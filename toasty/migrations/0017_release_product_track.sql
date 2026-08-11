-- Product-track entitlement + industrial sort tie-break (see release_pkg).
-- Backfill is applied in Rust via db::resync_release_sort_keys after migrations.
ALTER TABLE "releases" ADD COLUMN "is_industrial" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "releases" ADD COLUMN "product_track" TEXT NOT NULL DEFAULT 'Stable';
ALTER TABLE "releases" ALTER COLUMN "is_industrial" DROP DEFAULT;
ALTER TABLE "releases" ALTER COLUMN "product_track" DROP DEFAULT;
