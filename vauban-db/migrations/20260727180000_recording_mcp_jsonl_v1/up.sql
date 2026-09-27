-- Allow mcp-jsonl-v1 as a persisted recording_format (MCP JSONL audit trail).
-- Spec: docs/specs/vauban-mcp/06-audit-recording.md
ALTER TABLE proxy_sessions
    DROP CONSTRAINT IF EXISTS recording_format_enum;

ALTER TABLE proxy_sessions
    ADD CONSTRAINT recording_format_enum
        CHECK (recording_format IS NULL
               OR recording_format IN (
                   'asciicast-v2',
                   'fmp4-dash',
                   'fmp4-flat',
                   'pcap-bundle',
                   'mcp-jsonl-v1'
               ));
