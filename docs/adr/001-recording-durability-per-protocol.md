# ADR 001: Recording durability per protocol

**Status:** Accepted  
**Date:** 2026-07-21  
**Related:** [Recording Architecture 1.7](../technical/Vauban_Recording_Architecture_EN(1.7).md)

## Context

IACS tunnel recording is ack-blocked and fail-closed: the proxy waits
for audit `fdatasync` (5 s ceiling) before forwarding bytes. SSH and
RDP interactive sessions use non-blocking `try_send` into a bounded
audit channel so a slow disk does not stall the terminal UX.

That asymmetry was an accidental product of evolution, not a written
decision. Operators need a clear evidence guarantee per protocol.

## Decision

1. **IACS** remains ack-block + fail-closed. An ack timeout closes the
   channel and increments `recording_ack_timeouts` (exported via
   `ServiceStats` / `IacsProxyHealth` / Bastion Watch). Silent loss is
   not acceptable for industrial capture.
2. **SSH / RDP** remain best-effort for interactive latency. Drops on
   a full audit channel MUST be **detectable**: bump
   `recording_try_send_full` and rate-limited `warn!`. Full ack-blocking
   for SSH/RDP is rejected (unacceptable UX).
3. Before sharding `vauban-audit`, treat `rate(ack_timeouts) > 0` or
   sustained high `ack_wait_ms_max` as capacity alerts.

## Consequences

- Protocol-dependent durability is intentional and documented.
- Observability (Lot F) converts SSH/RDP silent loss into recorded loss
  without changing the data-plane latency model.
- Capacity work (shards / async fsync pools) is gated on these metrics,
  not on speculation.
