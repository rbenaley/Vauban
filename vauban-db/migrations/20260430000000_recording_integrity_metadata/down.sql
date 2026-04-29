DROP INDEX IF EXISTS idx_proxy_sessions_pending_finalization;

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS recording_format_enum;
ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS recording_blake3_format;

ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_finalized_at;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_codec;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_segment_count;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_height;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_width;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_format;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_event_count;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_duration_ms;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_size_bytes;
ALTER TABLE proxy_sessions DROP COLUMN IF EXISTS recording_blake3;
