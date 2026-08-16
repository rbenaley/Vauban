ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_chk;

ALTER TABLE assets ADD CONSTRAINT assets_asset_type_chk CHECK (asset_type IN (
    'ssh',
    'rdp',
    'iacs_modbus',
    'iacs_opcua',
    'iacs_profinet',
    'iacs_iec104',
    'iacs_tcp'
));
