-- Revert MCP asset / session type (fails if mcp rows still exist).

DELETE FROM proxy_sessions WHERE session_type = 'mcp';
DELETE FROM assets WHERE asset_type = 'mcp';

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_chk;
ALTER TABLE assets ADD CONSTRAINT assets_asset_type_chk CHECK (asset_type IN (
    'ssh', 'rdp',
    'iacs_modbus', 'iacs_opcua', 'iacs_profinet',
    'iacs_iec104', 'iacs_tcp'
));

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'proxy_sessions_session_type_chk'
    ) THEN
        ALTER TABLE proxy_sessions DROP CONSTRAINT proxy_sessions_session_type_chk;
        ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_session_type_chk
            CHECK (session_type IN ('ssh', 'rdp', 'iacs_tunnel'));
    END IF;
END $$;

ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_iacs_consistency;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_iacs_consistency CHECK (
    (session_type = 'iacs_tunnel'
        AND industrial_protocol IS NOT NULL
        AND ews_uuid IS NOT NULL)
    OR
    (session_type IN ('ssh', 'rdp')
        AND industrial_protocol IS NULL
        AND ews_uuid IS NULL
        AND tunnel_target_addr IS NULL)
);
