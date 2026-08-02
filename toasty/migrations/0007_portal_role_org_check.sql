-- Closed User.portal_role catalogue: admin (Vauban Support) | org (client).
UPDATE "users" SET "portal_role" = 'org' WHERE "portal_role" = '';
ALTER TABLE "users" ALTER COLUMN "portal_role" SET DEFAULT 'org';
ALTER TABLE "users" ADD CONSTRAINT "users_portal_role_check"
  CHECK ("portal_role" IN ('admin', 'org'));
