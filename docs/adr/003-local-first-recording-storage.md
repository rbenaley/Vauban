# ADR 003: Local-first recording storage

**Status:** Accepted  
**Date:** 2026-07-24  
**Related:**
[ADR 001 -- Recording durability per protocol](001-recording-durability-per-protocol.md),
[ADR 002 -- Single-appliance HA posture](002-single-appliance-ha-posture.md),
[Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md),
[Privilege Separation Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md)

## Context

Recording durability depends on supervisor-canonicalized local paths,
Capsicum-limited writers, and `fdatasync`-style integrity on the
appliance disk. IACS ack-block (ADR 001) waits on audit completing
durable local writes before forwarding tunnel bytes. SSH/RDP write
media on proxy-owned brokered FDs to the same local tree.

Object storage (S3/MinIO) is a recurring request for capacity and
offsite retention. Replacing the primary write path with remote PUTs
would put object-store latency inside the IACS ack window, break
Capsicum FD rights as the integrity boundary, and couple forensic
completeness to network availability.

## Decision

1. **Local is the integrity plane.** All recording and WORM write
   paths remain on local filesystem artefacts opened via the
   supervisor FD broker (`RecordingFileRequest` / related leases).
   Proxies (SSH/RDP media) and audit (IACS PCAP, WORM segments,
   SSH/RDP `meta.json`) write only to those local FDs.

2. **Remote is async replication only.** Any object-store or NAS
   offload happens **after** session finalisation (for example after
   `recording_finalized_at` / equivalent seal). A future sealed
   uploader service may mirror finalized artefacts and record a
   remote URL on the session row. Mirroring must not gate interactive
   paths or IACS acks.

3. **Local remains source of truth for forensics.** Playback,
   Inspect, integrity hashes, and retention reapers read the local
   tree first. Remote copies are capacity / offsite; they do not
   replace local verification.

4. **Rejected: object store as primary store.** Designs that open
   recording writers directly against S3/MinIO APIs, or that require
   a successful remote PUT inside an IACS durability ack, are out of
   scope unless a future ADR explicitly supersedes this one.

## Consequences

- ADR 001 protocol durability rules stay unchanged; this ADR only
  constrains *where* bytes may be written on the hot path.
- Implementing offsite retention is a new service (or task) with its
  own Capsicum surface -- not a flag that redirects the FD broker.
- Standby HA ([ADR 002](002-single-appliance-ha-posture.md)) replicates
  the local artefact tree; object mirrors are optional extras.
- No code change is required to accept this ADR; it freezes the
  existing architecture against premature S3 primary-store work.
