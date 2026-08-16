-- Widen assets.asset_type CHECK for ADR 006 profiles
-- (EtherNet/IP explicit, BACnet/SC, DNP3, IEC 61850 MMS).
-- Do not rewrite 20260508000000_iacs_tunnel.

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_chk;

ALTER TABLE assets ADD CONSTRAINT assets_asset_type_chk CHECK (asset_type IN (
    'ssh',
    'rdp',
    'iacs_modbus',
    'iacs_opcua',
    'iacs_profinet',
    'iacs_iec104',
    'iacs_enip',
    'iacs_bacnet_sc',
    'iacs_dnp3',
    'iacs_iec61850',
    'iacs_tcp'
));
