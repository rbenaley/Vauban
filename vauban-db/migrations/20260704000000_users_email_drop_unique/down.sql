-- Re-add the original single-column UNIQUE constraint on users.email.
--
-- WARNING: this down migration can FAIL if, while the relaxed model
-- was in effect, several accounts were created with the same e-mail --
-- which is exactly what the up migration set out to allow. Re-adding
-- the constraint will then raise a unique_violation (23505). That is
-- the intended, loud behaviour: rolling back is only safe once the
-- operator has manually reconciled the duplicate addresses. There is
-- no lossless automatic down path.
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
