# VCP privsep visualization — Capsicum, IPC socket, WebAuthn E2E

**Audience:** engineers and operators who need a picture of the trust
boundaries.  
**Normative design:**
[`VCP_Storage_Helper_Architecture_EN(1.2).md`](VCP_Storage_Helper_Architecture_EN(1.2).md).  
**ADRs:** [002](../adr/002-storage-webauthn-ceremony-channel-c1.md) (C1
ceremony), [003](../adr/003-ctap2-enrol-revoke-asymmetry.md) (E1/E2 KEY),
[004](../adr/004-webauthn-sign-count-policy.md) (`sign_count`).

This note is a **visualization** of three layers that work together:

1. Process privilege separation (`vcp` vs `vcp-store`) and Capsicum.
2. The Unix SEQPACKET socket (control plane + `SCM_RIGHTS` data plane).
3. End-to-end WebAuthn: browser assertion verified **inside** `vcp-store`
   (portal `vcp` is only a C1 relay for gated mutations).

---

## 1. Trust map (who may do what)

```mermaid
flowchart TB
  subgraph Browser["Browser (admin)"]
    UI["Portal HTML / confirm UI"]
    WA["WebAuthn authenticator<br/>credentials.get / create"]
  end

  subgraph Portal["vcp — UID 800"]
    HTTPS["HTTPS · TLS 1.3"]
    CAS["Casbin · sessions · org tenancy"]
    PG[("Postgres<br/>mirror + KEY pending UX")]
    RELAY["WebAuthn ceremony relay C1<br/>display helper summary"]
  end

  subgraph Helper["vcp-store — UID 801 / vcp-storage"]
    IPC["SEQPACKET accept<br/>peercred expected_peer_uid=800"]
    RP["WebAuthn RP verify<br/>challenges · ACTIVE keys"]
    SQL[("meta.sqlite SoT<br/>objects + webauthn_*")]
    CAP["Capsicum cap_enter<br/>FreeBSD / soft fence elsewhere"]
    AUDIT["audit/webauthn.log<br/>not writable by UID 800"]
  end

  subgraph Disk["blob_path 0700 — vcp-storage only"]
    BLOBS["releases/ · images/ · tmp/"]
  end

  UI --> HTTPS
  HTTPS --> CAS
  CAS --> RELAY
  CAS --> PG
  WA -.->|assertion / attestation| RELAY
  RELAY <-->|SOCK_SEQPACKET + SCM_RIGHTS<br/>+ assertion on gated ops| IPC
  IPC --> RP
  RP --> SQL
  CAP -.-> IPC
  CAP -.-> SQL
  CAP --> BLOBS
  RP --> AUDIT
  AUDIT --> Disk
  SQL --> Disk
```

| Principal | Trust for sensitive storage mutations |
|-----------|----------------------------------------|
| Browser admin | Human presence + UV (PIN/biometric) via authenticator |
| `vcp` (800) | **Untrusted** for finalize/delete (D10); Casbin/session only |
| `vcp-store` (801) | **TCB** for digests, rename, WebAuthn verify, audit |
| Capsicum | Kernel fence on FreeBSD after bind/connect; not the only control |

---

## 2. Privilege separation and Capsicum

`cap_enter(2)` is **process-wide**. Capsicum therefore lives on
`vcp-store` only: the portal keeps ACME, TLS, and Postgres (D1).

```mermaid
flowchart LR
  subgraph Before["Before capability mode"]
    B1["Open blob_path dirfd"]
    B2["Bind / connect Unix socket"]
    B3["cap_enter — FreeBSD"]
  end

  subgraph After["After capability mode"]
    A1["openat(dirfd) only"]
    A2["Accept + peercred"]
    A3["No ambient path walk"]
  end

  B1 --> B2 --> B3 --> A1
  B3 --> A2
  B3 --> A3
```

Portable baseline (always on, Capsicum or not):

- Distinct UIDs **800** / **801**; `blob_path` mode **0700**.
- Helper I/O via `dirfd` + `openat`; opaque object IDs.
- `expected_peer_uid` on the listen socket (required with `--production`).

Non-FreeBSD builds: same IPC and WebAuthn behavior; Capsicum is a WARN /
soft fence (D4).

---

## 3. Socket between `vcp` and `vcp-store`

Production layout:

| Item | Typical value |
|------|----------------|
| Portal `[storage]` | `ipc = "socket"`, `socket_path = "/var/run/vcp/store.sock"` |
| Helper | `listen` same path; `blob_path = "/var/db/vcp/storage"` |
| Socket type | `SOCK_SEQPACKET` (message boundaries) |
| AuthN of peer | `getpeereid` / `SO_PEERCRED` → UID **800** |
| Data plane | `SCM_RIGHTS` file descriptors for upload/download streams |

```mermaid
sequenceDiagram
  participant V as vcp UID 800
  participant S as store.sock
  participant H as vcp-store UID 801

  Note over H: bind listen, then Capsicum
  V->>S: connect SEQPACKET
  S->>H: accept
  H->>H: peercred == expected_peer_uid?
  alt foreign UID
    H-->>V: reject / close
  else UID 800
    V->>H: control message put_begin / get / ...
    opt data plane
      H-->>V: SCM_RIGHTS FD rights-limited
      V->>H: write/read bytes on FD
    end
    V->>H: put_prepare / put_commit + assertion / ...
    H-->>V: ok / typed error
  end
```

**Control plane** carries JSON-ish protocol messages (prepare, commit,
challenge, delete, key ops).  
**Data plane** moves artifact bytes on FDs; finalize still requires a
control message (and WebAuthn when gated).

Dev/test may use `ipc = "spawn"` (parent passes `--blob-path` /
`--listen`); production portal config must stay on **socket** mode.

---

## 4. WebAuthn E2E — browser to helper verify (C1)

Ceremony channel **C1**: the browser never talks to `vcp-store` directly.
`vcp` relays challenges and assertions. Verification of the assertion
runs **only** in the helper (D10, D11).

### 4.1 Gated release publish (happy path)

```mermaid
sequenceDiagram
  actor Admin as Admin browser
  participant V as vcp UID 800
  participant H as vcp-store UID 801
  participant Auth as Authenticator

  Admin->>V: upload bytes (admin UI)
  V->>H: put_begin
  H-->>V: SCM_RIGHTS write FD
  V->>H: write package on FD
  V->>H: put_prepare release_id + expected sha256
  H->>H: hash FD, bind challenge<br/>{op, release_id, upload_id, digest}
  H-->>V: challenge + summary + rp_id + allowCredentials
  V-->>Admin: confirm page shows helper summary
  Admin->>Auth: credentials.get(challenge)
  Auth-->>Admin: assertion UV
  Admin->>V: POST assertion
  V->>H: put_commit + assertion
  H->>H: COSE · ACTIVE · UV · binding · sign_count<br/>consume challenge · audit
  H->>H: renameat + meta.sqlite upsert
  H-->>V: ok digest/size
  V->>V: Postgres mirror upsert
  V-->>Admin: published
```

Cross-check on the helper host (ops): `vcp-store pending-ops` shows the
same canonical `summary` while the challenge is in flight.

### 4.2 What the helper checks on every gated assertion

```text
ACTIVE credential  →  COSE signature OK  →  UV required
       →  challenge unconsumed + unexpired  →  binding match (incl. digest)
       →  sign_count policy  →  consume + audit  →  mutate disk/SQLite
```

Without a valid assertion, `put_commit` (release) / `delete*` do not
materialize.

### 4.3 Deletes (same E2E shape)

```text
challenge_begin → C1 ceremony (summary in UI) → delete|delete_org + assertion
```

When an object exists at challenge time, the binding includes its SoT
`sha256`. If content changed before execute → `object_modified` (retry).

---

## 5. KEY enrolment (E1 web / E2 CLI) — why the browser alone is not enough

```mermaid
flowchart LR
  E1["E1 — /admin/key<br/>credentials.create<br/>PENDING + fingerprint"]
  OOB["Operator records fingerprint<br/>out of band"]
  E2["E2 — helper host CLI<br/>vcp-store approve-key<br/>--fingerprint"]
  ACT["ACTIVE in meta.sqlite<br/>usable for verify"]

  E1 --> OOB --> E2 --> ACT
```

A compromised `vcp` can create PENDING artefacts in the portal UX; it
**cannot** write ACTIVE rows without helper-host CLI approve (ADR 003).
Revocation stays dashboard-driven (accept revoke-DoS residual).

---

## 6. One-page mental model

```text
  Browser ──HTTPS──► vcp (800) ──SEQPACKET──► vcp-store (801) ──openat──► blobs
     │                  │                         │
     │                  │ Casbin / session        │ Capsicum + peercred
     │                  │ relay only (C1)         │ WebAuthn RP + SoT
     └── authenticator ─┘                         └── audit under blob_path
```

| Question | Answer |
|----------|--------|
| Who verifies WebAuthn for release finalize? | `vcp-store` |
| Who sees the human? | Browser authenticator (+ UV) |
| Who may open `blob_path` by path? | UID **801** only |
| Who invents the op summary? | Helper (`summary`); UI must display it |
| Separate ceremony HTTPS (C2)? | Deferred — ADR 002 |

---

## Related docs

| Doc | Role |
|-----|------|
| [Architecture 1.2](VCP_Storage_Helper_Architecture_EN(1.2).md) | Normative design |
| [Ops runbook](../runbooks/storage_helper_ops.md) | Socket ownership, restart, KEY CLI |
| [Smoke](../runbooks/storage_helper_smoke_test.md) | Staging Pass / Fail |
| Capsicum audit | `.cursor/audits/vcp_capsicum_storage_sandbox_2026-08-02.md` |
