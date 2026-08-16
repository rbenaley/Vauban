-- Reverse of the ADR 006 access-rule upgrade: drop the four new
-- tokens from rows that still look like a full current IACS grant
-- (legacy five + the four ADR 006 profiles). Does not touch partial
-- rules that listed only one of the new tokens.

UPDATE access_rules
SET allowed_protocols = ARRAY(
    SELECT u
    FROM unnest(allowed_protocols) AS u
    WHERE u IS NULL
       OR u NOT IN (
           'iacs_enip',
           'iacs_bacnet_sc',
           'iacs_dnp3',
           'iacs_iec61850'
       )
)
WHERE allowed_protocols @> ARRAY[
        'iacs_modbus',
        'iacs_opcua',
        'iacs_profinet',
        'iacs_iec104',
        'iacs_tcp',
        'iacs_enip',
        'iacs_bacnet_sc',
        'iacs_dnp3',
        'iacs_iec61850'
    ]::text[];
