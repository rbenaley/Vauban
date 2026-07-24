# ADR 001: Recording durability per protocol

**Status:** Accepted (amended 2026-07-24)  
**Date:** 2026-07-21  
**Amended:** 2026-07-24 (proxy-owned SSH/RDP FDs)  
**Related:** [Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md)

## Context

IACS tunnel recording is ack-blocked and fail-closed: the proxy waits
for audit `fdatasync` (5 s ceiling) before forwarding bytes. SSH and
RDP originally used non-blocking `try_send` into a bounded audit
channel so a slow disk would not stall interactive UX — but under
output floods (`du /`, busy RDP) that channel dropped **real session
bytes** from the forensic artefact while the live UI kept working.

Operators need a clear evidence guarantee per protocol without
ack-blocking the PTY / RDP stream.

## Decision

1. **IACS** remains ack-block + fail-closed. An ack timeout closes the
   channel and increments `recording_ack_timeouts` (exported via
   `ServiceStats` / `IacsProxyHealth` / Bastion Watch). Silent loss is
   not acceptable for industrial capture. Audit continues to hold
   write FDs for PCAP/gzip.

2. **SSH / RDP** write recording **media on supervisor-brokered FDs**
   owned by the proxy (`shared::recording_fd` / `RecordingFileRequest`).
   Interactive paths stay non-blocking w.r.t. audit IPC. Full
   ack-blocking for SSH/RDP remains rejected (unacceptable UX).

3. **Detectable loss (SSH/RDP):** a failed local write, flush/fsync, or
   FD lease emits `Message::RecordingLossObserved` and latches
   `proxy_sessions.recording_lossy` (Incomplete capture). This replaces
   the former `try_send` full signal for media. BLAKE3 covers bytes
   successfully written.

4. **Audit role (SSH/RDP):** receive lifecycle + seal stats on
   enriched `*RecordingEnd`; write `meta.json` only. Legacy
   `SshRecordingData` / `RdpVideoFrame` recording firehose is ignored.

5. Before sharding `vauban-audit`, treat IACS `rate(ack_timeouts) > 0`
   or sustained high `ack_wait_ms_max` as capacity alerts.

## Consequences

- Protocol-dependent durability remains intentional: IACS ack-block vs
  SSH/RDP local FD write.
- Forensic completeness for SSH/RDP no longer depends on audit IPC
  queue depth; loss requires real I/O or broker failure.
- Shared plumbing: `shared::recording_fd` (also used by audit for
  meta/IACS leases). Format writers stay protocol-specific.
- Sticky `recording_lossy` UI badge retained; wording updated for I/O
  failure semantics (0.9.29).
