-- Drop the UNIQUE constraint on users.email: several accounts may
-- legitimately belong to the same person (e.g. a nominal account plus
-- an admin/break-glass account) and share one e-mail address.
--
-- New contract:
--   * `username` remains the sole login identifier and stays UNIQUE
--     (case-insensitively, via idx_users_username_lower). Login is
--     never resolved by e-mail, so duplicates cannot make
--     authentication ambiguous (pinned by
--     vauban-web/tests/web/users_email_shared_e2e_test.rs).
--   * `email` stays NOT NULL and format-validated, but any number of
--     ACTIVE accounts may carry the same address.
--   * The non-unique search index idx_users_email is kept as-is.
--
-- The constraint is looked up by shape (single-column unique on
-- `email`) instead of hardcoding the default name `users_email_key`,
-- so dump-restored databases with a renamed constraint are handled
-- too. Idempotent: re-running on a database without the constraint is
-- a no-op.
DO $$
DECLARE
    con text;
BEGIN
    FOR con IN
        SELECT c.conname
        FROM pg_constraint c
        WHERE c.conrelid = 'users'::regclass
          AND c.contype = 'u'
          AND c.conkey = ARRAY[
              (SELECT attnum FROM pg_attribute
               WHERE attrelid = 'users'::regclass AND attname = 'email')
          ]::smallint[]
    LOOP
        EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', con);
    END LOOP;
END $$;
