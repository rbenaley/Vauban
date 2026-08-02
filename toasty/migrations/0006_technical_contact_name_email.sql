-- Preserve free-form contact text as the full-name field; email starts empty
-- (operators can split name/email on the next company edit).
ALTER TABLE "organizations" RENAME COLUMN "technical_contact" TO "technical_contact_name";
ALTER TABLE "organizations" ADD COLUMN "technical_contact_email" TEXT NOT NULL DEFAULT '';
ALTER TABLE "organizations" ALTER COLUMN "technical_contact_email" DROP DEFAULT;
