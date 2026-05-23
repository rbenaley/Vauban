CREATE INDEX idx_proxy_sessions_recording_retention
    ON proxy_sessions (disconnected_at ASC)
    WHERE is_recorded = TRUE
      AND recording_path IS NOT NULL
      AND disconnected_at IS NOT NULL;
