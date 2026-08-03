# VCP `storage/` — Sandboxed helper process (design & architecture)

**Date:** 2026-08-03
**Status:** design proposal (to be validated before implementation)
**Scope:** on-disk storage under a configurable root `storage.blob_path`
(`vcp.conf`) for two artifact families — **release artifacts** (admin upload,
org download) and **tenant images** (uploaded by organization users working on
their org tenant) — served by a dedicated **helper process** (`vcp-store`)
sandboxed with **Capsicum on FreeBSD**, with **controlled degradation** (WARN
log line) and **maximum portable hardening** (syscalls + POSIX rights) on
platforms without Capsicum.
**Reference:** audit `vcp_capsicum_storage_sandbox_2026-08-02.md` (Option C
selected, Option A folded in as the baseline); `../Vauban` for the
“no-op + warning” pattern outside FreeBSD.

---

## 1. Structural decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Helper process** `vcp-store`; no thread, no Capsicum on `vcp` itself | `cap_enter(2)` is process-wide; ACME/cert rotation inside `vcp` stays unconstrained (`src/tls/resolver.rs` already mandates pre-`cap_enter` file I/O) |
| D2 | **Dedicated UID** `vcp-store` in production; `storage/` owned by it, mode `0700` | Without a separate UID, a compromised `vcp` opens blobs by path and bypasses the helper — the sandbox would be decorative |
| D3 | **Separate control plane / data plane**: IPC for commands, `SCM_RIGHTS` for bytes | Native disk throughput, helper out of the data path; every transferred FD is a single-file capability with minimal rights |
| D4 | **Best-effort Capsicum**: `cap_enter` + `cap_rights_limit` on FreeBSD; elsewhere no-op + `WARN` | macOS/Linux dev and CI behave identically; FreeBSD production gains the kernel fence |
| D5 | **Mandatory portable baseline**: dirfd + `openat`, `O_NOFOLLOW`, `O_RESOLVE_BENEATH`/`openat2(RESOLVE_BENEATH)`, opaque IDs, umask 077 | Security never depends on Capsicum alone; Capsicum turns “we promise” into “the kernel refuses” |
| D6 | **Synchronous, minimal helper** (no tokio) | Smallest attack and audit surface; disk I/O is sequential by nature |
| D7 | **Application authz stays in `vcp`** (org + entitlement via Casbin); the helper only sees opaque IDs plus an org scope for images | Capsicum replaces neither authz nor anti-IDOR; the helper has no notion of sessions or entitlements |
| D8 | **Two storage families, one mechanism**: `releases/` and `images/` share the same dirfd, IPC protocol, tmp+rename pipeline, and rights tables; they differ only in scope (`org_id` for images), quotas, and content validation | One audited code path instead of two; per-family rules are data, not new machinery |

---

## 2. Architecture

```text
                 ┌─────────────────────────────────────────────┐
                 │  vcp (UID vcp)                              │
                 │  HTTPS · sessions · authz · ACME · DB       │
                 │                                             │
   HTTP body ───▶│  admin release upload / org download        │
                 │  org-user image upload / image serving      │
                 │        │ control (SOCK_SEQPACKET)           │
                 │        │ + FDs (SCM_RIGHTS)                 │
                 └────────┼────────────────────────────────────┘
                          │  IPC (inherited socketpair in dev,
                          │       named socket + LOCAL_PEERCRED in prod)
                 ┌────────▼────────────────────────────────────┐
                 │  vcp-store (UID vcp-store)                  │
                 │  1. open(blob_path, O_DIRECTORY) → dirfd    │
                 │  2. cap_rights_limit(dirfd, …)   [FreeBSD]  │
                 │  3. cap_enter()                  [FreeBSD]  │
                 │     otherwise: WARN + soft containment      │
                 │  validate · openat · limit · renameat       │
                 └────────┬────────────────────────────────────┘
                          │ openat(dirfd, …) only
                 ┌────────▼────────────────────────────────────┐
                 │  storage/  (vcp-store:vcp-store, 0700)      │
                 │    releases/<release_id>.pkg                │
                 │    images/<org_id>/<image_id>.<ext>         │
                 │    tmp/<upload_id>.partial                  │
                 └─────────────────────────────────────────────┘
```

Key property: after boot, `vcp-store` can no longer open anything by absolute
path (Capsicum); `vcp` can never open `storage/` at all (UID permissions). The
only bytes that move are carried by individually restricted FDs.

---

## 3. Configuration (`vcp.conf`)

```toml
[storage]
# Blob root. Must exist and be owned by the helper's user.
blob_path = "/var/db/vcp/storage"

# IPC mode: "spawn"  (vcp fork/execs the helper, socketpair, same UID — dev)
#           "socket" (helper started by rc.d under its own UID, named socket — prod)
ipc = "socket"

# "socket" mode only:
socket_path = "/var/run/vcp/store.sock"

# "spawn" mode only (default: vcp-store binary next to the executable):
# helper_path = "/usr/local/libexec/vcp-store"

# Abuse guards (enforced by the helper, re-checked by vcp):
max_artifact_bytes = 2147483648        # 2 GiB — release artifacts
max_image_bytes = 10485760             # 10 MiB — tenant images
allowed_image_types = ["png", "jpeg", "webp"]  # no SVG (stored-XSS vector)
max_concurrent_uploads = 4
max_images_per_org = 1000              # per-tenant cap, enforced at put_begin
upload_ttl_secs = 3600                 # purge orphaned .partial files
```

Boot-time validation rules (`config.rs`, struct `StorageConfig`):
`blob_path` absolute, existing, a directory; in production `ipc = "socket"` is
required, and `vcp` **refuses to start** if `blob_path` is writable by the
`vcp` UID (effective check via `access(2)`), so that a bad install silently
voiding D2 is caught immediately.

---

## 4. Helper lifecycle and boot sequence

### 4.1 Production (`ipc = "socket"`, FreeBSD)

`rc.d/vcp_store` starts `vcp-store` as user `vcp-store` **before** `vcp`.
Strict sequence inside the helper:

1. `umask(077)`; close stdin; `setrlimit` (bounded NOFILE, CORE=0).
2. `open(blob_path, O_DIRECTORY | O_CLOEXEC)` → `storage_dirfd`; create
   `releases/`, `images/`, and `tmp/` via `mkdirat` if missing; purge expired
   `tmp/*.partial`.
3. Create the `SOCK_SEQPACKET` listening socket at `socket_path`
   (directory `/var/run/vcp`: `vcp-store:vcp`, `0750`; socket `0660`).
4. **FreeBSD:** `cap_rights_limit` on `storage_dirfd` and on the listening
   socket (§7), then `cap_enter()`. Verify with `cap_getmode` and log
   `INFO capsicum: capability mode entered`.
5. **Non-FreeBSD or failure:**
   `WARN capsicum unavailable on <os>; storage helper running with soft containment only (dirfd + RESOLVE_BENEATH + uid/permissions)` —
   once at boot, level `warn`, never fatal. If `environment = production`
   **and** OS ≠ FreeBSD, add a second
   `WARN production deployment without kernel sandbox`.
6. `accept` loop; on each connection, check `LOCAL_PEERCRED` (peer UID ==
   configured `vcp` UID), otherwise close immediately.

The 2→3→4 ordering is mandatory: everything that needs the global namespace
(open-by-path, bind) happens before `cap_enter`; afterwards only
`openat(dirfd, …)` and `accept` on the pre-opened FD remain possible — which
is the point.

### 4.2 Development (`ipc = "spawn"`)

`vcp` creates a `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)`, then
fork/execs `vcp-store` with one end inherited (FD 3), same UID. No filesystem
endpoint, no auth needed. The helper runs the same sequence (the step-5 `WARN`
shows up on macOS/Linux). An extra
`WARN storage helper shares vcp uid (dev mode)` reminds that D2 is not in
effect.

### 4.3 Supervision and failure domains

- Helper is **stateless** (all durable state lives on disk + Postgres); a
  crash means an rc.d/spawn restart, in-flight uploads are lost (`.partial`
  files get purged), no impact on the rest of the portal.
- In `vcp`: dead IPC ⇒ **503** on artifact/image routes only, reconnect with
  backoff; the portal (docs, issues, accounts) keeps serving.
- Per-request IPC timeout (e.g. 10 s excluding data transfer — data does not
  cross the IPC channel, so no oversized timeout is needed).

---

## 5. Storage layout and identifier validation

```text
storage/
  releases/
    <release_id>.pkg         # u64 decimal — Release primary key; ONE package per release
  images/
    <org_id>/                # u64 decimal from the Organization model
      <image_id>.<ext>       # UUID v4 + extension from the validated type
  tmp/
    <upload_id>.partial      # UUID v4, generated by the helper
```

**DB alignment.** The layout mirrors the VCP schema exactly: a `Release` row
carries a single full-package `sha256` and a single `size_mb` (migrations
`0005_release_sha256`, `0008_release_version_sort`) — there is no artifact
table and no 1-N relation, so storage holds **one flat blob per release**,
keyed by the **primary key** `Release.id`. The version string is deliberately
not used as the disk key: `Release.version` is not globally unique (GA rows
plus org-private `X.Y.Z-client` hotfixes; routes resolve via
`find_visible_release_by_version(version, org_id)`), and a rename/typo fix in
the version must not orphan a blob. The user-visible filename
(`vauban-{ver}.pkg` / `vauban-{ver}+LTS.pkg`, from
`release_pkg::package_file_name`) is applied by `vcp` at serving time via
`Content-Disposition` — it never appears on disk. `EphemeralDownload` tokens
(scoped by `release_version` + org) are likewise resolved to a `Release.id`
by `vcp` before any IPC call; the helper never sees versions or tokens.

Rules (enforced by the helper, independently of Capsicum):

- IDs are **server-generated**, never derived from a client filename; display
  names (release package names via `release_pkg::package_file_name`, original
  image filenames) live in the DB, not on disk.
- Strict regex validation before any `openat`:
  `release_id | org_id = ^[0-9]{1,20}$`,
  `image_id | upload_id = ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`,
  `ext = ^(png|jpe?g|webp)$` (must also match the sniffed content type, §6.3).
  Anything else ⇒ reject, **never** interpreted as a path.
- No client-supplied path segment is ever concatenated; `..`, leading `/`, and
  NUL are structurally impossible (guaranteed by the regexes, re-guaranteed by
  `RESOLVE_BENEATH`, re-guaranteed by Capsicum).
- Release digest: `Release.sha256` (already in the DB) is the source of truth;
  the helper verifies SHA-256 **before** publication (§6.2).
- Tenant scoping on disk (`images/<org_id>/`) is an operational convenience
  (per-org quota, deletion, audit) — **not** the isolation mechanism. The
  isolation mechanism is `vcp`'s authz: an org user may only reference
  `image_id`s that the DB maps to their own `org_id`, and `vcp` passes that
  DB-derived `org_id` (never a client-supplied one) into the IPC call.

---

## 6. IPC protocol

### 6.1 Control plane

`SOCK_SEQPACKET`: message boundaries preserved, natural “1 message ↔ 0..1
ancillary FD” alignment. Each message is a short JSON document (< 4 KiB,
maximum size enforced at `recvmsg`). Every request carries a `scope` whose
addressing matches the DB schema:

- `{"scope":"release","release_id":…}` — the release **is** the blob
  (1 release = 1 package, per the `Release` model); no secondary ID exists;
- `{"scope":"image","org_id":…,"image_id":"…"}` — tenant images are
  UUID-keyed under their organization.

| Request (`vcp` → helper) | Response (helper → `vcp`) | FD attached |
|---|---|---|
| `{"op":"get","scope":…}` | `{"ok":true,"size":…,"sha256":"…"}` | ✔ read-only (response) |
| `{"op":"put_begin","scope":…,"declared_size":…,"ext":"png"}`¹ | `{"ok":true,"upload_id":"…"}` | ✔ write-only (response) |
| `{"op":"put_commit","upload_id":"…","scope":…,"sha256":"…"}` | `{"ok":true}` or `{"ok":false,"err":"digest_mismatch"}` | — |
| `{"op":"put_abort","upload_id":"…"}` | `{"ok":true}` | — |
| `{"op":"stat","scope":…}` | `{"ok":true,"size":…}` | — |
| `{"op":"delete","scope":…}` | `{"ok":true}` | — |
| `{"op":"delete_org","org_id":…}`² | `{"ok":true,"deleted":…}` | — |

¹ `ext` only for `scope = image`. At `put_begin`, the scope omits the final
identifier; the target is named at `put_commit`: for images, `vcp` supplies a
fresh `image_id` UUID it has already recorded in the DB (DB stays the source
of truth); for releases, the target is simply `releases/<release_id>.pkg`.
Committing over an existing package is an **atomic replace** (`renameat` over
the target), which is the intended re-upload path for a pending or corrected
release.
² Bulk removal of `images/<org_id>/` when an organization is deleted
(admin-only route in `vcp`).

Errors: `{"ok":false,"err":"<code>"}` with a closed set of codes
(`not_found`, `invalid_id`, `quota`, `org_quota`, `bad_image`,
`digest_mismatch`, `io`, `busy`). Responses never contain paths or filesystem
details.

### 6.2 Data plane (SCM_RIGHTS)

**Download (`get`)** — identical for both scopes:
1. Helper: regex → `openat(storage_dirfd, "<family>/<parent_id>/<id>.<sfx>",
   O_RDONLY | O_NOFOLLOW | O_CLOEXEC [ | O_RESOLVE_BENEATH ])`.
2. FreeBSD: `cap_rights_limit(fd, CAP_READ | CAP_SEEK | CAP_FSTAT)`.
3. `sendmsg` response + FD; helper closes its copy.
4. `vcp`: `recvmsg(MSG_CMSG_CLOEXEC)`; authz was checked **before** the call
   (entitlement for releases, org membership for images); streams to the HTTP
   client from the FD (tokio blocking pool), `Content-Length` = returned
   `size`. Images are served with the exact `Content-Type` recorded at upload
   and `X-Content-Type-Options: nosniff`.

**Upload (`put_begin` → write → `put_commit`)** — identical mechanism, per-scope
limits:
1. Helper: quota checks (`max_concurrent_uploads`; for images also
   `max_images_per_org` via a directory entry count on
   `images/<org_id>/`), then
   `openat(storage_dirfd, "tmp/<uid>.partial", O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600)`;
   **helper keeps a `dup` of the FD**.
2. FreeBSD: on the copy being sent,
   `cap_rights_limit(fd, CAP_WRITE | CAP_SEEK | CAP_FSTAT)` — no `CAP_READ`:
   `vcp` has no need to read back what it writes.
3. `vcp` streams the HTTP body into the FD (bounded by
   `max_artifact_bytes` / `max_image_bytes`, re-bounded by the helper at
   commit via `fstat`), closes the FD, sends `put_commit` with the expected
   sha256 (admin-provided for releases; computed by `vcp` while streaming for
   images).
4. Helper, from **its own** FD (the only trusted one): `fstat` (size ≤ the
   scope's max), full re-read + SHA-256, comparison; for images, content
   sniffing (§6.3); `fsync(fd)`;
   `mkdirat` of `images/<org_id>/` if needed (releases are flat — no
   per-release directory);
   `renameat(dirfd, tmp/…, dirfd, "releases/<release_id>.pkg" | "images/<org_id>/<image_id>.<ext>")`;
   `fsync` of the directory. Mismatch/abort/TTL ⇒ `unlinkat`.
5. On a successful release commit, `vcp` updates the `Release` row from the
   helper's response: `sha256` (verified value), `size_mb` via
   `release_pkg::size_mb_from_bytes(fstat size)`, and flips `status` from
   pending to published — so the DB never advertises a package the disk does
   not hold, and the `/{org}/builds/{version}/download` route (currently 501
   `DOWNLOAD_NOT_CONFIGURED`) can switch to the `get` flow above.

Atomicity: `tmp/`, `releases/`, and `images/` all live under the same
`blob_path` (same filesystem) ⇒ `renameat` is atomic; a partial file is never
visible to downloads.

### 6.3 Image content validation (helper-side)

Because tenant images are user-supplied and later served back to browsers,
`put_commit` with `scope = image` additionally requires, on the helper's own
FD:

- **Magic-byte sniffing**: the first bytes must match the declared `ext`
  (PNG `89 50 4E 47…`, JPEG `FF D8 FF`, WebP `RIFF…WEBP`); mismatch ⇒
  `bad_image`. The stored `.<ext>` and the DB `content_type` are derived from
  the **sniffed** type, never from the client's filename or `Content-Type`
  header.
- **SVG is rejected by construction** (not in `allowed_image_types`): SVG is a
  stored-XSS vector when served same-origin.
- Optional later hardening (flagged, not blocking v1): dimension/pixel-count
  cap via a decode-free header parse, and a re-encode (“image laundering”)
  pipeline — if ever added, the decoder belongs **in the helper or a further
  sandboxed child**, never in `vcp`, since image parsers are a classic RCE
  surface and the helper is exactly the process built to contain one.

---

## 7. Capsicum (FreeBSD) — exact rights

| FD | Rights (`cap_rights_limit`) |
|----|------------------------------|
| `storage_dirfd` | `CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_CREATE, CAP_FSTAT, CAP_FSTATAT, CAP_FSYNC, CAP_MKDIRAT, CAP_UNLINKAT, CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET` |
| Listening socket | `CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_GETPEERNAME` — the listening socket's rights must cover those needed by **accepted** sockets (rights are inherited) |
| Transferred `get` FD | `CAP_READ, CAP_SEEK, CAP_FSTAT` |
| Transferred `put` FD | `CAP_WRITE, CAP_SEEK, CAP_FSTAT` |
| stderr/log FD | `CAP_WRITE, CAP_FSTAT` (opened before `cap_enter`) |

Notes:

- `openat` under capability mode requires `CAP_LOOKUP` on the dirfd plus the
  rights of the operation; the table above covers the entire §6 protocol —
  including `delete_org`'s directory iteration (`CAP_READ` +
  `CAP_FSTATAT`/`CAP_UNLINKAT` via `openat(O_DIRECTORY)` on
  `images/<org_id>` under the same dirfd) — and **nothing more** (no
  `CAP_FCHMOD`, no broad `CAP_FCNTL`).
- Rights are **monotonically decreasing**: the `get`/`put` copy sent to `vcp`
  stays restricted even though `vcp` (unsandboxed) receives it — rights travel
  with the FD, not with the process.
- Forbidden after `cap_enter` (by design): open by absolute path, new
  `connect`/`bind`, `exec` of external tools. The helper must never need any
  of these; any feature that would require one is a design smell.

---

## 8. Hardening without Capsicum (mandatory everywhere)

These controls also apply **on** FreeBSD (defense in depth); outside FreeBSD
they are the entire fence, hence the `WARN`.

| Layer | Mechanism | Platforms |
|-------|-----------|-----------|
| Identity | Dedicated `vcp-store` UID; `storage/` `0700`; `vcp` has no access | FreeBSD/Linux prod (dev: shared-UID WARN) |
| Path resolution | `openat` relative to the dirfd **exclusively**; zero path-based `std::fs` in the helper (CI lint: `std::fs::` forbidden in `vcp-store` outside the boot module) | all |
| Kernel anti-escape | FreeBSD: `O_RESOLVE_BENEATH`; Linux: `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)`; macOS: emulation (regex validation + `O_NOFOLLOW`, sufficient since names are server-side UUIDs) | per OS |
| Symlinks | `O_NOFOLLOW` everywhere; creation with `O_CREAT\|O_EXCL` | all |
| Process hygiene | `umask 077`, `O_CLOEXEC`/`SOCK_CLOEXEC` everywhere, `MSG_CMSG_CLOEXEC` when receiving FDs, `setrlimit`, stdin closed | all |
| IPC | `SOCK_SEQPACKET`, bounded message size, ancillary FD count bounded to 1, `LOCAL_PEERCRED` (FreeBSD) / `SO_PEERCRED` (Linux) in socket mode | all |
| Abuse | `max_artifact_bytes` / `max_image_bytes` (`fstat` at commit, never trusting the client), `max_concurrent_uploads`, `max_images_per_org`, TTL + `tmp/` purge | all |
| Content | Helper-side SHA-256 before `renameat`; image magic-byte sniffing; SVG banned; `nosniff` on serving | all |
| Logging | IDs + sizes + durations only; never full host paths, org names, or tokens | all |
| Ops (outside code) | FreeBSD: a dedicated jail around `vcp-store` is possible (stacks with Capsicum); eventual Linux: systemd unit with `ProtectSystem=strict`, `ReadWritePaths=blob_path`, `NoNewPrivileges` | deployment |

Recommended abstraction: the **`cap-std`** crate provides a `Dir` type with
portable “beneath” semantics (openat2 on Linux, `O_RESOLVE_BENEATH` /
emulation elsewhere) — it implements D5 behind a single API and serves as the
helper's baseline on every platform; the **`capsicum`** crate adds
`cap_enter`/`CapRights` behind `#[cfg(target_os = "freebsd")]`, and `nix`
covers `sendmsg`/`recvmsg` + `ScmRights` + peer credentials.
`unsafe_code = "deny"` (Cargo.toml) remains tenable: the unsafe lives in those
dependencies, not in `vcp`.

---

## 9. Resulting security properties

| Property | FreeBSD prod (Capsicum + UID) | Linux/macOS (soft only) |
|----------|-------------------------------|--------------------------|
| Traversal / symlink escape via IDs | Impossible (regex + RESOLVE_BENEATH + Capsicum) | Impossible (regex + RESOLVE_BENEATH/emulation) |
| RCE in `vcp` → reading blobs by path | **Blocked** (UID + 0700) | **Blocked** (UID + 0700, if multi-user prod) |
| RCE in `vcp` → abusing the helper | Limited to the strict protocol (valid IDs only, no arbitrary listing) | Same |
| RCE in `vcp-store` (e.g. via a malicious image) → host filesystem | **Blocked** (capability mode: no open by path) | Limited by UID + permissions only ⇒ **WARN** |
| RCE in `vcp-store` → outbound network | **Blocked** (no pre-opened outbound socket) | Not blocked by code (⇒ systemd/jail at the ops layer) |
| Partial file served | Impossible (tmp + fsync + atomic renameat) | Same |
| Cross-tenant image access | Out of helper scope by design — `vcp` authz maps `image_id` → owning `org_id` from the DB and enforces membership; opaque UUIDs prevent enumeration | Same |
| Stored XSS via uploaded image | Blocked (sniffed type, SVG banned, `nosniff`) | Same |

---

## 10. Tests

- **Unit (all platforms):** ID regexes (fuzz/proptest — reject `..`, `/`,
  NUL, unicode), commit with a wrong digest, `max_artifact_bytes` /
  `max_image_bytes` overrun, double `put_commit`, `put_abort`, TTL purge,
  release re-upload (commit over an existing `releases/<id>.pkg` atomically
  replaces it; a concurrent `get` FD keeps reading the old inode to EOF),
  magic-byte sniffing (PNG header with `ext=jpeg` ⇒ `bad_image`, SVG payload
  ⇒ `bad_image`), `max_images_per_org` boundary.
- **Integration (all platforms):** full upload→commit→download cycle for both
  scopes over a real socketpair + `tempfile`; a `put` FD received by the test
  must not allow reads (verifiable only on FreeBSD; elsewhere assert
  `O_WRONLY`); helper crash mid-upload ⇒ `.partial` purged, `vcp` returns 503
  then recovers; image download for an org the session does not belong to ⇒
  denied in `vcp` before any IPC call (assert no helper traffic).
- **FreeBSD CI / staging jail (`gisco`):** `cap_getmode` == 1 after boot;
  `open("/etc/passwd")` from the helper fails with `ECAPMODE`;
  `openat(dirfd, "../x")` fails; a transferred `get` FD refuses `write`
  (`ENOTCAPABLE`); accepted-socket rights correctly inherited.
- **Config anti-regression:** production boot refuses a `blob_path` writable
  by the `vcp` UID; production boot refuses `ipc = "spawn"`.

---

## 11. Implementation plan

| Phase | Content | Deliverable |
|-------|---------|-------------|
| 1 | `StorageConfig` + portable I/O module (`cap-std::Dir`, IDs, tmp+rename, digest, sniffing) **in the crate**, tested without the helper | `src/storage/` + tests |
| 2 | `vcp-store` binary (`[[bin]]`, like `vcp-cli`): IPC loop, `spawn` mode, WARN outside FreeBSD | Working dev helper |
| 3 | Handlers wired to the IPC client — admin release upload / org download, org-user image upload / image serving; degraded 503; removal of any direct `storage/` access from `vcp` (CI lint) | Feature complete |
| 4 | `socket` mode + `LOCAL_PEERCRED` + rc.d + `vcp-store` UID; `access(2)` check at `vcp` boot | Prod-ready soft |
| 5 | `#[cfg(freebsd)]`: `cap_rights_limit` + `cap_enter` + jail tests | Prod-ready Capsicum |
| 6 | Runbooks: helper restart, `blob_path` rotation, digest-mismatch procedure, org deletion (`delete_org`) | Ops |

Each phase ships on its own; security increases monotonically (1–4 = full
soft fence everywhere, 5 = FreeBSD kernel fence).

---

## 12. Bottom line

A single I/O code path (dirfd + `openat`, opaque IDs, tmp+rename, digest and
content sniffing on the sandboxed side) runs everywhere and serves both
storage families — release artifacts and per-tenant images — as data-driven
variants of the same mechanism. On FreeBSD, `vcp-store` seals that path with
`cap_enter` after pre-opening the dirfd and the socket, and every byte
exchanged with `vcp` rides an FD restricted by `cap_rights_limit` and passed
via `SCM_RIGHTS`. Outside FreeBSD nothing breaks: the helper logs an explicit
`WARN` and the same soft fence (dedicated UID, `0700`, `RESOLVE_BENEATH`,
`O_NOFOLLOW`, quotas, digest, image sniffing) remains fully in force. Capsicum
is a **kernel bonus**, never a functional dependency — and never an excuse to
relax application-level controls.
