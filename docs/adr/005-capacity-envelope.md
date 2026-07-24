# ADR 005: Single-appliance capacity envelope (estimated)

**Status:** Accepted (estimated; not load-tested)  
**Date:** 2026-07-24  
**Related:**
[ADR 002 -- Single-appliance HA](002-single-appliance-ha-posture.md),
[ADR 001 -- Recording durability](001-recording-durability-per-protocol.md),
[ADR 003 -- Local-first storage](003-local-first-recording-storage.md),
[Privilege Separation Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md),
[Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md),
[IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md),
[capacity_envelope_load_test runbook](../runbooks/capacity_envelope_load_test.md)

## Context

The architecture review (§7) identified clear single-appliance failure
walls (audit IACS/WORM, access opens, auth Argon2, RDP encoder cores,
web DB pool) but left sizing as tribal knowledge. Operators and
integrators need published order-of-magnitude guidance without
implying SLAs or a live cluster ([ADR 002](002-single-appliance-ha-posture.md)).

A FreeBSD staging load-test campaign is still required before claiming
measured numbers. Until then, engineering estimates from the review
and repayment through crate **0.9.31** are the accepted interim
envelope.

## Decision

1. **Publish capacity as an ADR, not a README architecture-table
   doc.** Sizing doctrine belongs with HA / storage decisions; the
   root README stays limited to versioned technical architecture
   families (no `docs/adr/` links).

2. **Unit of capacity = one appliance.** Cold/warm standby does not
   add live capacity ([ADR 002](002-single-appliance-ha-posture.md)).
   Object store is not on the write path ([ADR 003](003-local-first-recording-storage.md)).

3. **Accepted interim estimates (E = estimate only):**

| Metric | Estimate (E) | Notes |
|--------|--------------|-------|
| Concurrent SSH sessions | tens–low hundreds (E) | PTY + FD + local asciicast write |
| Concurrent RDP @ 720p | ~**50** ≈ **20–25 cores** (E) | Dominant hardware driver |
| Concurrent IACS tunnels | low tens before ack pressure (E) | Watch ack metrics |
| SSH/RDP **opens**/s | ~**50**/s saturates access (E) | Two access trips per open (0.9.27) |
| Interactive logins/s | ~**2–10**/s (E) | Argon2id in `vauban-auth` |
| Recording write throughput | disk-bound (E) | Local FD writers ([ADR 001](001-recording-durability-per-protocol.md)) |
| Web `max_connections` | **10** default | First ops knob under dashboard fan-out |

4. **Failure-wall order (architectural, not measured ranking):**
   (1) `vauban-audit` IACS/WORM, (2) `vauban-access`, (3) `vauban-auth`,
   (4) RDP encoder cores, (5) web DB pool, (6) supervisor `send_fd`
   path. SSH/RDP media no longer floods audit IPC (0.9.29).

5. **Operational smoke before measured numbers:** sustained IACS
   `recording_ack_timeouts > 0`, `ack_wait_ms_max` near 5 s,
   rising `recording_lossy` / write errors, login 500s with audit
   ack timeout (should be rare post-0.9.24–0.9.26).

6. **Measured amendment path.** After the staging campaign in
   [`capacity_envelope_load_test.md`](../runbooks/capacity_envelope_load_test.md),
   amend this ADR (Status: Accepted (measured …)) with hardware SKU,
   build SHA, and sustained/break tables — still one appliance.

## Consequences

- Sizing RFCs and sales guidance cite this ADR; invented SLAs without
  a measured amend are out of scope.
- Load-test work updates **this** file (or a dated amend block), not
  a parallel `docs/technical/Vauban_Capacity_Envelope_*` family.
- README must not link this ADR (hygiene pin).
- Hardware sketch (E): size CPU for peak concurrent RDP
  (0.4–0.5 core/720p) + headroom; local NVMe (or equivalent) for
  recordings/WORM; standby same class, no extra live capacity.
