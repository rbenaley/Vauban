-- Lot 1a: MCP as a first-class asset / session type (docs/specs/vauban-mcp).

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_chk;
ALTER TABLE assets ADD CONSTRAINT assets_asset_type_chk CHECK (asset_type IN (
    'ssh', 'rdp',
    'iacs_modbus', 'iacs_opcua', 'iacs_profinet',
    'iacs_iec104', 'iacs_enip', 'iacs_bacnet_sc',
    'iacs_dnp3', 'iacs_iec61850', 'iacs_tcp',
    'mcp'
));
-- 20260817000000_iacs_protocol_profiles rewrites this CHECK after this
-- migration and must keep 'mcp' (see that file).

-- proxy_sessions.session_type may be constrained by name; widen if present.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'proxy_sessions_session_type_chk'
    ) THEN
        ALTER TABLE proxy_sessions DROP CONSTRAINT proxy_sessions_session_type_chk;
        ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_session_type_chk
            CHECK (session_type IN ('ssh', 'rdp', 'iacs_tunnel', 'mcp'));
    END IF;
END $$;

-- `proxy_sessions_iacs_consistency` (20260508000000_iacs_tunnel) only
-- allowed the "no IACS columns" branch for `ssh`/`rdp`. MCP sessions
-- carry no `industrial_protocol` / `ews_uuid` / `tunnel_target_addr`
-- either -- widen the branch to admit `mcp` so a session INSERT does
-- not violate the CHECK.
ALTER TABLE proxy_sessions DROP CONSTRAINT IF EXISTS proxy_sessions_iacs_consistency;
ALTER TABLE proxy_sessions ADD CONSTRAINT proxy_sessions_iacs_consistency CHECK (
    (session_type = 'iacs_tunnel'
        AND industrial_protocol IS NOT NULL
        AND ews_uuid IS NOT NULL)
    OR
    (session_type IN ('ssh', 'rdp', 'mcp')
        AND industrial_protocol IS NULL
        AND ews_uuid IS NULL
        AND tunnel_target_addr IS NULL)
);
