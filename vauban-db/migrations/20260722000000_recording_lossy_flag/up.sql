-- Sticky latch: SSH/RDP audit try_send dropped >=1 frame for this session.
-- Set by vauban-web on Message::RecordingLossObserved (proxy detects drop).
-- Monotone (false -> true only). IACS sessions stay false (ack-block semantics).
ALTER TABLE proxy_sessions
    ADD COLUMN recording_lossy BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN proxy_sessions.recording_lossy IS
    'Sticky latch: true if SSH/RDP audit try_send dropped >=1 frame for this session';
