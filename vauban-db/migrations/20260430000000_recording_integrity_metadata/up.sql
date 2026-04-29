-- Recording integrity metadata persisted on `proxy_sessions`.
--
-- Until now the BLAKE3 hash, file size, duration, terminal/screen geometry
-- and segment count of every recording lived only on disk in `meta.json`,
-- written by `vauban-audit` at session end. The new "Recording Details"
-- page surfaces this data on every render, and we want to avoid an
-- I/O round-trip + JSON parse on every GET. We therefore precompute the
-- bundle once into `proxy_sessions` via a lazy background hydrator
-- (vauban-web/src/services/recording_hydrator.rs) and the page becomes a
-- pure SELECT.
--
-- Format unification: SSH stores a single hash of the `.cast` file, but
-- RDP records one hash per fragmented-MP4 segment. The hydrator computes
-- BLAKE3(concat(segment_hashes_hex)) for RDP so this column has uniform
-- semantics regardless of protocol.
--
-- The columns are all NULL-able because:
--   1. Pre-existing rows from before this migration must remain valid.
--   2. The hydrator runs asynchronously after session disconnect; rows
--      sit unfinalized for a few seconds. The detail page handles the
--      `None` state by showing "Integrity metadata pending finalization".
--
-- A partial index on the unfinalized subset keeps the hydrator's
-- batch-scan cheap as the recordings table grows.

ALTER TABLE proxy_sessions
    ADD COLUMN recording_blake3 VARCHAR(64),
    ADD COLUMN recording_size_bytes BIGINT,
    ADD COLUMN recording_duration_ms BIGINT,
    ADD COLUMN recording_event_count INTEGER,
    ADD COLUMN recording_format VARCHAR(32),
    ADD COLUMN recording_width SMALLINT,
    ADD COLUMN recording_height SMALLINT,
    ADD COLUMN recording_segment_count INTEGER,
    ADD COLUMN recording_codec VARCHAR(64),
    ADD COLUMN recording_finalized_at TIMESTAMPTZ;

-- BLAKE3 hex format invariant: the column is either NULL or exactly 64
-- lowercase hex characters. This rules out partial writes and uppercase
-- variants (BLAKE3.to_hex() is lowercase) at the DB layer.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_blake3_format
        CHECK (recording_blake3 IS NULL OR recording_blake3 ~ '^[0-9a-f]{64}$');

-- Recording format enum: pinned to the three formats the hydrator knows
-- how to produce. Adding a new format requires bumping this constraint
-- AND the hydrator's parser.
ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_format_enum
        CHECK (recording_format IS NULL
               OR recording_format IN ('asciicast-v2', 'fmp4-dash', 'fmp4-flat'));

-- Partial index for the hydrator's batch-scan query. Only rows that are
-- recorded, have a path on disk, and have NOT been finalized yet are
-- candidates. The index stays small because finalized rows leave it
-- (PostgreSQL prunes them automatically thanks to the WHERE clause).
CREATE INDEX idx_proxy_sessions_pending_finalization
    ON proxy_sessions (created_at)
    WHERE is_recorded = TRUE
      AND recording_path IS NOT NULL
      AND recording_finalized_at IS NULL;
