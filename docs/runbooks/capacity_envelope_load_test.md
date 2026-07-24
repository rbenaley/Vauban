# Runbook: Capacity envelope load-test (staging)

**Purpose:** Amend
[ADR 005 -- Capacity envelope](../adr/005-capacity-envelope.md)
from **estimated** to **measured**.

**Scope:** Single FreeBSD staging appliance ([ADR 002](../adr/002-single-appliance-ha-posture.md)).
Do not use production. Do not expect live multi-node HA.

## Preconditions

- Build / package matching the release under test (record git SHA).
- Hardware SKU noted (CPU model, core count, RAM, disk type).
- Metrics visible: Bastion Watch / `ServiceStats` (IACS ack fields),
  proxy `recording_lossy` / write errors, PostgreSQL and disk I/O.
- Synthetic users + assets for SSH, RDP, and IACS as needed.

## Scenarios

| ID | Name | Ramp | Success / break signals |
|----|------|------|-------------------------|
| A | SSH open storm | connects/s until cliff | access timeouts, 5xx, latency spike |
| B | RDP open storm | same | same + encoder spawn failures |
| C | RDP hold | N concurrent 720p for fixed window | CPU/session, thermal, dropouts |
| D | Login storm | concurrent login+MFA | logins/s, audit ack timeouts |
| E | IACS flood | sustained tunnel bytes | `recording_ack_timeouts`, `ack_wait_ms_max` |

Record for each: sustained plateau, break point, and first wall hit
(access / audit / auth / CPU / disk / DB).

## After the campaign

1. Amend [ADR 005](../adr/005-capacity-envelope.md): Status
   `Accepted (measured <date>)`, hardware SKU, build SHA, replace
   **(E)** cells with sustained/break tables.
2. Close scorecard "measured capacity" remainder.

## Non-goals

- Tuning production mid-test.
- Validating S3 primary writes ([ADR 003](../adr/003-local-first-recording-storage.md)).
- Proving cluster failover.
- Linking this ADR from the repository root README.
