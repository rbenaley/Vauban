-- ADR 006: persist the four new IACS tokens on access rules that
-- already carry the pre-ADR-006 "IACS (all industrial protocols)"
-- snapshot (the five tokens the web form wrote at save time).
-- Partial IPC rules (Modbus only, etc.) are left unchanged.
-- Idempotent: rows that already contain the four tokens are skipped.

UPDATE access_rules
SET allowed_protocols = (
    SELECT ARRAY(
        SELECT DISTINCT e
        FROM unnest(
            allowed_protocols
            || ARRAY[
                'iacs_enip',
                'iacs_bacnet_sc',
                'iacs_dnp3',
                'iacs_iec61850'
            ]::text[]
        ) AS e
        WHERE e IS NOT NULL
    )
)
WHERE allowed_protocols @> ARRAY[
        'iacs_modbus',
        'iacs_opcua',
        'iacs_profinet',
        'iacs_iec104',
        'iacs_tcp'
    ]::text[]
  AND NOT (
      allowed_protocols @> ARRAY[
          'iacs_enip',
          'iacs_bacnet_sc',
          'iacs_dnp3',
          'iacs_iec61850'
      ]::text[]
  );
