# ADR 002: Single-appliance scope and HA posture

**Status:** Accepted  
**Date:** 2026-07-24  
**Related:**
[Privilege Separation Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md),
[Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md),
[Vault Architecture 1.2](../technical/Vauban_Vault_Architecture_EN(1.2).md),
[ADR 003 -- Local-first recording storage](003-local-first-recording-storage.md)

## Context

Vauban is built as a privilege-separated FreeBSD appliance: one root
supervisor, Capsicum-sealed children, anonymous-pipe IPC, and
supervisor-brokered `SCM_RIGHTS` for every network and recording file
descriptor. That model assumes co-location on a single host. Operators
and integrators still ask "what about HA?" -- usually meaning live
multi-node clustering, sticky sessions across hosts, or sharded
`vauban-access` / `vauban-audit`.

Anonymous pipes and the FD broker do not span hosts. Treating
horizontal clustering as an implied roadmap would force a different
IPC fabric, a different sandbox story, and a different recording
integrity plane. The product needs an explicit posture so capacity
work and standby ops stay honest.

## Decision

1. **Single-appliance doctrine.** The supported deployment is one
   FreeBSD appliance (or equivalent single-machine topology) running
   the full supervisor + child mesh against local PostgreSQL and a
   local recording tree. Multi-host live clustering is out of product
   scope.

2. **Supported HA = cold / warm standby.** Continuity is achieved by
   a second appliance that can take over after failover procedures:
   - PostgreSQL physical or logical replication to the standby,
   - replication or rsync of the local recording / WORM artefact tree,
   - vault / TLS material handled by the existing key and cert
     procedures for that host.
   Live session failover (preserving an in-flight SSH/RDP/IACS
   proxy session across hosts) is not offered.

3. **Explicitly out of scope.** Live sharding of `vauban-access` or
   `vauban-audit`, cross-host anonymous-pipe meshes, sticky session
   routing across appliances, and "transparent" HA that hides
   appliance identity from operators.

4. **Capacity envelope is separate.** Scaling limits of the sync
   control plane (audit, access, auth, supervisor) are sizing
   constants for a single appliance. Publishing numeric envelopes
   after a load-test campaign does not change this ADR and is not a
   prerequisite for accepting it.

## Consequences

- Roadmaps and RFCs must not assume a live cluster; design reviews
  reject "just add another access node" without a new ADR that
  overturns this one.
- Ops runbooks for HA describe standby promotion (DB + artefacts),
  not session migration.
- Sizing and load-tests treat one appliance as the unit under test.
- Object-storage offload, if any, must obey [ADR 003](003-local-first-recording-storage.md)
  (local write path retained on the active appliance).
