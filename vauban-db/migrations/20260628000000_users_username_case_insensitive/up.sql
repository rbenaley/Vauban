-- Vauban login identifiers are case-insensitive: `Alice`, `alice` and
-- `ALICE` denote the same account. Until now the `username` column was a
-- plain case-sensitive VARCHAR UNIQUE and the login lookup did an exact
-- (byte-for-byte) match, so an account created as `Admin` could not log
-- in by typing `admin`, and the LDAP just-in-time path could even mint a
-- second shadow row for a different-cased spelling of the same identity.
--
-- This migration canonicalises the stored identity and pins the
-- case-insensitive uniqueness at the database layer (defence in depth:
-- even a future code path that forgets to normalise the identifier cannot
-- create a case-variant duplicate).

-- 1) Canonicalise every existing username to its lower-cased form.
--    This fails loudly (unique_violation on the existing UNIQUE(username)
--    constraint) if two rows differ only by case: silently merging two
--    distinct identities would be a security defect, so an operator must
--    resolve such a collision by hand before re-running the migration.
UPDATE users
SET username = lower(username)
WHERE username <> lower(username);

-- 2) Enforce case-insensitive uniqueness going forward. The index is
--    non-partial to mirror the existing column-level UNIQUE semantics:
--    soft-deleted rows retire their username with a `_deleted_<ts>`
--    suffix (all lower-case), which keeps the lower(username) value
--    unique as well, so deleted spellings remain reusable.
CREATE UNIQUE INDEX idx_users_username_lower ON users (lower(username));
