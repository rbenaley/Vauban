# ADR 004: Retain flat IPC Message enum

**Status:** Accepted  
**Date:** 2026-07-24  
**Related:**
[Privilege Separation Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md),
[AccessGuard Architecture 1.0](../technical/Vauban_AccessGuard_Architecture_EN(1.0).md),
[Vault Architecture 1.2](../technical/Vauban_Vault_Architecture_EN(1.2).md)

## Context

Inter-process traffic uses a single flat `Message` enum in `shared`
(on the order of ninety variants). Every service binary links the
full enum. Peer legality ("may proxy-ssh send `AdminCommand`?") is
enforced at runtime by per-service authorization matrices (vault's
`is_authorized` with `_ => false` is the reference pattern) and by
supervisor routing, not by distinct Rust types per pipe.

Bincode discriminants are append-only and pinned by structural tests.
A recurring refactor proposal is to split into per-edge enums so the
type system prevents naming illegal variants. That would multiply
enum definitions roughly by the number of TOPOLOGY edges, fragment
the single-dispatch loops every service uses, and enlarge coordinated
wire changes without removing the need for runtime matrices on
SCM_RIGHTS and policy edges.

## Decision

1. **Keep one flat `Message` enum** shared across the mesh. Services
   continue to match on the variants they understand and ignore or
   reject the rest per their matrices.

2. **Wire stability rules stay:** new variants are append-only;
   discriminant ordinals remain frozen and covered by pin tests;
   renumbering or inserting in the middle is forbidden.

3. **Authorization stays runtime.** Each privileged peer keeps an
   explicit allow matrix (fail-closed default). Compile-time
   "cannot name this variant" is not a substitute for those
   matrices.

4. **Per-edge enum split is rejected for now.** Revisit only if the
   product adds a plugin model or a tenth (or later) service where
   recompile fan-out or accidental cross-peer construction becomes a
   demonstrated incident class -- and then only with a superseding
   ADR.

## Consequences

- Refactors that "just split `messages.rs` by pipe" are out of
  scope; reviews cite this ADR.
- Adding a protocol or service still means appending variants and
  updating matrices / pins / TOPOLOGY -- the linear cost already
  documented in Privsep extensibility notes.
- Correlated IPC clients (`shared::correlated_ipc`) and AccessGuard
  continue to speak the same wire enum; no dual stacks.
- Accepted recompile fan-out across the workspace when `Message`
  grows is an explicit trade for one dispatch shape and one pin
  surface.
