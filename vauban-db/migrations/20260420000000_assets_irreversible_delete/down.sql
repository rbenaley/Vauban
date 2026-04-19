-- Reverse of 20260420000000_assets_irreversible_delete.
--
-- WARNING: this rollback is NOT semantically symmetric.
--
--   * It removes the structural enforcement of the irreversible-delete
--     policy (CHECK constraint + trigger). Any downstream environment
--     that relied on those guarantees will lose them at the instant
--     this script runs.
--   * It does NOT restore secrets that were scrubbed from existing
--     tombstones in step 2 of up.sql -- those are gone by design.
--     There is no recovery path; the scrub is intentionally
--     destructive.
--   * The partial unique index `idx_assets_hostname_port_username_active`
--     created by the earlier migration 20260330000000_add_connection_username
--     remains in place: it is OUT OF SCOPE for this rollback, because
--     it predates this migration and rolling it back here would
--     silently re-open the I1 invariant ("two active rows for the same
--     triplet").
--
-- Use this rollback only for local dev / test cleanup or for an
-- emergency hotfix deploy. Production rollbacks should be paired with
-- an explicit incident review.

DROP VIEW IF EXISTS assets_active;

DROP TRIGGER IF EXISTS assets_no_resurrection_trg ON assets;
DROP FUNCTION IF EXISTS assets_no_resurrection();

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_tombstone_no_secrets;
