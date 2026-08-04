# VCP Capsicum and artifact storage sandboxing

**Date:** 2026-08-02 (status updated 2026-08-04)  
**Scope:** Whether Capsicum is useful for VCP (customer portal), and specifically
whether a dedicated **thread** that reads/writes a future `storage/` tree for
release artifacts adds security value versus ordinary in-process I/O.  
**Audience:** engineers designing FreeBSD deploy hardening for uploads
(admin) and downloads (org / client).  
**Status:** **implemented** — Option C helper process shipped as `vcp-store`
(`src/bin/vcp_store.rs`, `src/storage/*`). Portable I/O + SEQPACKET IPC;
**digest SoT = SQLite** in the helper (`blob_path/meta.sqlite`); Postgres
`storage_objects` is a **mirror** for portal UI / publish gates (SQLite SoT
migration in progress per architecture 1.0, design updated 2026-08-04);
FreeBSD attempts real `cap_enter`; soft WARN elsewhere.
**Related:** architecture
[`docs/technical/VCP_Storage_Helper_Architecture_EN(1.0).md`](../../docs/technical/VCP_Storage_Helper_Architecture_EN(1.0).md);
ops [`docs/runbooks/storage_helper_ops.md`](../../docs/runbooks/storage_helper_ops.md);
smoke [`docs/runbooks/storage_helper_smoke_test.md`](../../docs/runbooks/storage_helper_smoke_test.md);
bastion patterns in `../Vauban` (`Vauban_Privsep_Architecture`);
VCP TLS code already notes some paths must run before `cap_enter()`
(`src/tls/resolver.rs`).

---

## 1. Executive summary

| Question | Answer |
|----------|--------|
| Does VCP need OpenSSH-style **privsep** (root → unprivileged children)? | **No.** VCP should run as a dedicated non-root user from the start. |
| Is Capsicum still useful without privsep? | **Yes**, as an optional FreeBSD hardening layer — not as a PAM-grade mandate. |
| Does a Capsicum-capable **thread** isolate `storage/`? | **No.** Capability mode is **process-wide**. A thread shares the process credential flag and address space. |
| First high-value focus for artifacts | Harden `storage/` with **directory FD + `openat`**, path policy, and OS permissions; add Capsicum later as process-wide sandbox **or** a small **helper process**. |
| Highest Capsicum ROI for VCP long term | Either sandbox **all of `vcp`** after pre-opening listen / DB / storage FDs, or run a **storage-only helper process** under Capsicum. |

**Verdict:** Do not plan a “Capsicum storage thread.” Plan soft filesystem controls now; reserve Capsicum for a **process** boundary when artifact I/O and FreeBSD deploy are real.

---

## 2. Threat model and bar (VCP vs Vauban)

### 2.1 Why the bastion is different

Vauban (PAM / bastion) terminates privileged protocols, brokers upstream
connections, and mixes high-value secrets with untrusted session traffic. Its
architecture therefore combines:

- **Privilege separation** (supervisor + leaf services, often with distinct
  UIDs and IPC);
- **Capsicum** after pre-opening FDs (`cap_enter`, `cap_rights_limit`);
- Strict boot ordering so bind, DB pool, TLS material, and IPC never need
  global namespaces post-sandbox.

That bar is appropriate for a bastion. Copying the full topology into VCP
would be over-engineering unless product risk demands it.

### 2.2 VCP bar (secure, not lax)

VCP is an authenticated customer portal: SSR, sessions, entitlements, admin
release management, and (planned) binary artifact store. Risks that matter:

| Risk | Example | Capsicum relevance |
|------|---------|-------------------|
| Path traversal / symlink escape in upload or download | `../../etc/passwd` via crafted name | Soft controls + dirfd stop this; Capsicum limits blast radius after RCE |
| RCE in the web process | Unsafe parse, dependency bug | Capsicum on **whole process** or helper limits FS/network namespaces |
| Cross-tenant blob leak | Wrong object key served to another org | App authz + opaque keys; Capsicum does not replace tenant checks |
| Stolen session / IDOR | Download without entitlement | App layer; out of Capsicum scope |
| Host compromise as `vcp` UID | Attacker already has process rights | Capsicum still bounds *what that UID can open by name* after `cap_enter` |

**Design stance:** boring app controls first; Capsicum as defense-in-depth on
FreeBSD production hosts — without importing bastion privsep, mTLS IPC, or
Casbin models from `../Vauban` by default.

---

## 3. Capsicum mechanics that decide the design

### 3.1 Process-wide capability mode

On FreeBSD, `cap_enter(2)` sets a credential flag on the **process**. Effects:

- Applies to **all threads** in that process;
- Inherited by children created with `fork` / `pdfork`;
- **Cannot be cleared** once set;
- Global namespaces (filesystem open-by-path, arbitrary `bind`, named IPC,
  etc.) become unavailable except through delegated FDs and constrained APIs
  such as `openat` relative to a directory capability.

There is **no** supported “enter Capsicum for this thread only” API. A
dedicated Tokio worker or `std::thread` that calls `cap_enter` would sandbox
the **entire** `vcp` process — usually by accident and at the wrong time.

### 3.2 Capability rights on FDs

The useful companion to capability mode is `cap_rights_limit(2)`: even with
an open FD, the process may only perform allowed operations (read, write,
lookup, accept, …). Bastion docs stress that rights on a **listening** socket
must include rights needed by **accepted** sockets (`accept` inherits rights).
The same discipline applies if VCP ever sandboxes its HTTPS listener.

### 3.3 Directory FDs and `openat` (valuable with or without Capsicum)

Even before `cap_enter`, the Capsicum-friendly I/O style is the right storage
API:

1. At boot, `open("…/storage", O_DIRECTORY | O_CLOEXEC)` → `storage_dirfd`.
2. All artifact create/read/unlink goes through `openat(storage_dirfd, …)`.
3. Reject absolute paths, `..` components, and unsafe symlink following
   (`O_NOFOLLOW` where appropriate).
4. Optionally `cap_rights_limit` the dirfd once Capsicum is enabled.

This pattern is the main **portable** win; Capsicum then turns “we promise to
use the dirfd” into “the kernel refuses other opens.”

### 3.4 Cross-platform reality

Capsicum is FreeBSD-native. Vauban treats non-FreeBSD as no-op with a warning.
VCP should assume the same: **macOS/Linux CI and local dev run without
capability mode**; production FreeBSD can enable it. Soft controls
(dirfd, path policy, UID, permissions) must work everywhere Capsicum does not.

---

## 4. The thread idea — why it fails as a sandbox

### 4.1 Shared fate with the web process

| Property | Capsicum “storage thread” in `vcp` | In-process storage I/O in `vcp` |
|----------|-------------------------------------|----------------------------------|
| Address space | Shared | Shared |
| UID / credential | Shared | Shared |
| Capability mode flag | Shared if entered | Shared if entered |
| Can open global paths before `cap_enter` | Yes (same as siblings) | Yes |
| Kernel isolation of blob code from HTTP handlers | **None** | **None** |

An RCE or logic bug in a Topcoat handler can call the same filesystem APIs as
the storage thread, read the same env, and use the same open FDs. Thread
boundaries are **not** a FreeBSD security boundary for Capsicum.

### 4.2 What a dedicated thread *can* still buy (non-security)

Worth considering for product/engineering reasons only:

- Keep large sequential disk I/O off the async runtime (blocking pool);
- Serialize writers / apply backpressure on uploads;
- Centralize “only this module touches blobs” for reviewability.

Treat those as **concurrency and structure**, not sandboxing. Do not brand
them Capsicum.

### 4.3 Confusion with “worker thread” mental models

Linux Landlock and some userspace sandboxes are also typically
process-scoped. Seccomp-bpf is process/thread-filter nuanced but still not a
substitute for “this thread alone may touch `/storage`.” For VCP on FreeBSD,
stick to the Capsicum model: **process + FDs**, or **helper process**.

---

## 5. Options that actually move the needle

### 5.1 Option A — Soft storage hardening (recommended first)

**Shape:** Single `vcp` process; no Capsicum yet.

| Control | Intent |
|---------|--------|
| Dedicated FreeBSD user/group for `vcp` | Least privilege vs host |
| `storage/` owned by that user, mode `0700` (or group-tight) | Other UIDs cannot read blobs |
| Boot-time directory FD | Contain all relative opens |
| Opaque object keys (UUID / content hash), never client path segments | Kill traversal |
| Quotas: max size, content-type allowlist, virus/scan hook later | Abuse resistance |
| Authz on every download (org + entitlement) | Tenant isolation |
| Digest SoT in helper SQLite (`meta.sqlite`); Postgres `storage_objects` mirror; blobs under `storage/` | Clear trust boundary (UIDs separate) |

**Value:** High relative to cost; works on all platforms; prerequisite for any
later Capsicum design.

### 5.2 Option B — Capsicum on the whole `vcp` process

**Shape:** Like a simplified `vauban-web`: pre-acquire everything, then
`cap_enter`.

Typical pre-sandbox checklist for VCP:

1. Bind HTTPS listen socket (or inherit a pre-bound FD);
2. Open Postgres pool connections (fixed size; no reconnect-by-hostname after
   enter unless a broker exists);
3. Open `storage` directory FD (+ any staging dir);
4. Load TLS material / ACME state FDs as required (note: ACME renewal that
   writes new cert files is a **hard** Capsicum problem — may need a
   non-sandboxed helper or FD passing);
5. Open log / metrics sinks if they need path opens;
6. `cap_rights_limit` on each FD;
7. `cap_enter()`.

**Pros:** Strong host containment; one binary; matches “no privsep” preference.  
**Cons:** Touches every subsystem (TLS/ACME already documents pre-`cap_enter`
file I/O); pool death may require process restart; higher ops and test cost.

**Fit:** Best when VCP is deploy-stable on FreeBSD and ACME/cert rotation is
designed for sealed mode.

### 5.3 Option C — Capsicum **helper process** for `storage` only

**Shape:** Non-root sibling process (not a root privsep parent). Parent or
supervisor starts:

1. Helper opens `storage` dirfd, limits rights, `cap_enter`;
2. Speaks a small IPC protocol (Unix socket / seqpacket) for
   `put` / `get` / `delete` / `stat`;
3. `vcp` never opens blob paths by name — only talks to the helper.

**Pros:** Localizes Capsicum complexity to blob I/O; web RCE cannot
`openat` arbitrary host paths *through the helper* if the protocol is strict;
ACME/DB in `vcp` remain unconstrained by capability mode (until Option B).  
**Cons:** Streaming large releases over IPC; auth of the IPC channel (socket
permissions, `LOCAL_PEERCRED`); failure domains; more moving parts than Option A.

**Fit:** Best answer if the goal is “Capsicum where storage matters most”
without freezing the whole portal into capability mode on day one.

### 5.4 Option D — Capsicum thread (rejected)

No kernel isolation beyond Option A/B. Risk of calling `cap_enter` too early
and breaking the rest of the app. **Do not pursue.**

---

## 6. Mapping Capsicum to other VCP resources (later)

The original discussion also mentioned TCP bind and the DB pool. Those matter
for Option B, not for a storage thread.

| Resource | Pre-`cap_enter` | Post-`cap_enter` |
|----------|-----------------|------------------|
| Listen socket | `bind` / inherit FD; rights must cover accept + I/O | `accept` only on that FD |
| DB pool | Connect all sockets; size fixed | Use existing FDs; reconnect policy is the hard part |
| `storage/` dirfd | Open directory; rights for create/read/write/unlink as needed | `openat` only under that FD |
| ACME / cert files | Load or keep FDs; renewals need a design | Cannot freely rewrite paths unless planned |
| Random host paths (plugins, ad-hoc `std::fs`) | Must be eliminated or pre-opened | Denied |

For **storage-first** work, do not block artifact delivery on listen/DB
sandboxing. Keep those as a separate “full process Capsicum” milestone.

---

## 7. Recommended roadmap

### Phase 0 — Policy (now)

- Document that Capsicum, if used, is **process-scoped**.
- Explicitly reject “sandbox thread” designs in plans and reviews.
- Keep bastion privsep / IPC out of VCP unless a future threat model changes.

### Phase 1 — Artifact storage without Capsicum

Ship `storage/` with Option A controls. Wire admin upload and org download to
dirfd-based I/O. Add tests for traversal, symlink, oversized body, and
cross-tenant denial.

### Phase 2 — Decide Capsicum shape

| If… | Choose… |
|-----|---------|
| Want kernel fence on blobs only, keep ACME/DB flexible | **Option C** (helper process) |
| Want one sealed FreeBSD service and can freeze boot resources | **Option B** (whole `vcp`) |
| Deploy is multi-OS / early product | Stay on **Option A** |

### Phase 3 — Production FreeBSD enablement

- Feature-flag or `cfg(target_os = "freebsd")` enter path;
- Integration tests on FreeBSD CI or a staging jail (`gisco` or similar);
- Runbooks for “pool exhausted → restart process” and cert rotation under
  the chosen option.

---

## 8. Security properties comparison

| Property | A Soft | B Whole process | C Storage helper | Capsicum thread |
|----------|--------|-----------------|------------------|-----------------|
| Stops path traversal if app is correct | Yes | Yes | Yes | Yes (app only) |
| Limits FS after web RCE | No | **Yes** (host-wide) | **Partial** (blobs + helper surface) | No |
| Limits new TCP connects after RCE | No | **Yes** (if no spare sockets) | No (web still open) | No |
| Complexity | Low | High | Medium–high | Misleadingly “medium” |
| Fits “no root privsep” | Yes | Yes | Yes | N/A |

---

## 9. Practical guidance for release artifacts

When `storage/` lands, prefer this object layout and API shape:

```text
storage/
  releases/
    <release_id>/
      <artifact_id>.bin          # or content-addressed <sha256>
  tmp/
    <upload_id>.partial          # rename into place after hash verify
```

Rules of thumb:

- Never interpolate org slugs or filenames from the client into path
  components without a strict allowlist;
- Verify digest after upload before publish;
- Serve downloads via controlled streaming (helper or `File` from dirfd), not
  by returning a host-absolute path to a static file server outside the
  entitlement gate;
- Log artifact IDs and byte counts, never full signing keys or session tokens.

Capsicum does not replace any of the above; it only bounds how badly a
compromised process can touch the rest of the host.

---

## 10. Method and confidence

| Input | Source |
|-------|--------|
| Capsicum process scope | FreeBSD `cap_enter(2)` / Capsicum design; Vauban privsep doc §5 |
| Bastion pre-sandbox sequence | `../Vauban` Capsicum + `vauban-web` notes |
| VCP current stance | Portal rules (no bastion Capsicum by default); TLS comment on pre-`cap_enter` I/O |
| Storage product intent | Admin upload + org download for releases (planned) |

**Confidence:** High on “thread ≠ Capsicum isolation.” Medium on exact Phase 2
choice (B vs C) until ACME renewal and artifact size/streaming requirements are
fixed.

---

## 11. Bottom line

Capsicum remains a **useful FreeBSD hardening tool** for VCP even without
bastion-style privsep, because the portal need not run as root. Its unit of
isolation is the **process**, not the thread.

For the planned `storage/` tree, a Capsicum-dedicated thread adds **no**
meaningful sandbox value over ordinary in-process I/O. Invest first in
directory-FD storage hygiene and tenant-safe keys; when you want Capsicum,
either seal **all of `vcp`** after boot or add a **storage helper process** —
not a storage thread.

## 12. Implementation status (2026-08-04)

| Item | State |
|------|-------|
| Helper binary `vcp-store` | Shipped (`[[bin]]`, spawn + named socket) |
| Engine (cap-std dirfd, digest, sniff, quotas) | `src/storage/engine.rs` |
| IPC + SCM_RIGHTS + peercred | `src/storage/ipc.rs`, socket mode in bin |
| Digest SoT (SQLite in helper) | `blob_path/meta.sqlite` (`objects`); migration in progress |
| Postgres `storage_objects` mirror | Migration `0013_storage_objects.sql`; digests off `Release` |
| HTTP releases + images | Admin upload / org download / `/{org}/images` |
| Prod boot guards | Refuse `ipc=spawn` / writable `blob_path` |
| Capsicum | FreeBSD `cap_enter` attempt; WARN soft path elsewhere |
| Ops / smoke | `docs/runbooks/storage_helper_ops.md`, `storage_helper_smoke_test.md` |
| Pyramid | `tests/integration_tests/storage_*` + `scripts/check_storage.sh` |

Jail / gisco validation remains a **manual FreeBSD** checklist in the ops
runbook (not exercised on macOS CI).
