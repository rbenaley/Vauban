# Vauban LDAPS Authentication and Group Aggregation Architecture

**Version:** 1.1  
**Date:** 21 August 2026  
**Author:** Richard Ben Aleya  
**Status:** Bind path implemented (v1); group aggregation and mapping file
are the accepted design for the next implementation lot

> Supersedes
> [Vauban_LDAPS_Auth_Architecture_EN(1.0).md](Vauban_LDAPS_Auth_Architecture_EN(1.0).md)
> for everything after the bind-only snapshot. Keep 1.0 as the historical
> "authentication only -- no group synchronization" contract.
>
> **1.1 additions:** directory group resolution after a successful user
> bind; operator mapping file `ldaps_mapping.conf` (`static` / `match`);
> replace-set of Vauban User Groups on LDAP shadow accounts; three-way
> search outcome (found / not found / unreachable). Product decisions
> live in [ADR 007](../adr/007-ldap-group-aggregation-phase-1.md) and
> [ADR 008](../adr/008-ldaps-mapping-file-dsl.md).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Bind inside the sandboxed service](#2-bind-inside-the-sandboxed-service)
3. [End-to-end flow](#3-end-to-end-flow)
4. [Web-side authentication routing](#4-web-side-authentication-routing)
5. [User Group aggregation](#5-user-group-aggregation)
6. [Mapping file DSL](#6-mapping-file-dsl)
7. [Directory group resolution](#7-directory-group-resolution)
8. [Three outcomes of LDAP resolution](#8-three-outcomes-of-ldap-resolution)
9. [IPC message protocol](#9-ipc-message-protocol)
10. [Supervisor broker gating](#10-supervisor-broker-gating)
11. [Sandbox integration](#11-sandbox-integration)
12. [Configuration](#12-configuration)
13. [Threat inventory](#13-threat-inventory)
14. [Security analysis](#14-security-analysis)
15. [Testing strategy](#15-testing-strategy)
16. [Limitations and roadmap](#16-limitations-and-roadmap)
17. [Related documents](#17-related-documents)
18. [Appendix A -- Changelog](#appendix-a----changelog)

---

## 1. Introduction

Vauban authenticates users against an LDAPS directory in addition to
local Argon2id accounts, and (from 1.1) derives Vauban User Group
membership from the directory groups returned after a successful bind.

The design goal is unchanged: the user's plaintext password and all
LDAP/BER + TLS parsing stay inside sandboxed `vauban-auth`. The
supervisor only brokers a TCP socket. `vauban-web` never opens an
LDAPS connection and never builds a bind DN or a search filter.

### 1.1 Decisions frozen (bind -- from 1.0)

- **Direct bind** via `dn_template` (UPN or DN). `{username}` is
  substituted only through
  [`shared::ldap_dn::substitute_bind_dn`](../../shared/src/ldap_dn.rs).
- **Synchronous, dependency-light codec**: hand-rolled BER. No
  `tokio`, no `ldap3` inside `vauban-auth`.
- **Single attempt, tight timeout** (~5 s), fail-closed.
- **Anti-enumeration (login UI)**: every bind failure mode collapses
  to the same generic "invalid credentials" response presented to the
  client.

### 1.2 Decisions frozen (aggregation -- 1.1)

- **Login is the LDAP I/O point.** Bind and group search share the
  same brokered FD and the same user bind. Phase 1 does not introduce
  a directory service account and does not re-query LDAP on
  `auth_sessions` idle refresh or WebSocket revalidation (see
  [ADR 007](../adr/007-ldap-group-aggregation-phase-1.md)).
- **Auth returns directory keys; web maps them.** `vauban-auth`
  returns a bounded list of group keys (DNs, and later mail / CN).
  `vauban-web` applies the compiled mapping AST and writes
  `user_groups`.
- **Replace-set.** Each successful resolution fully replaces the
  LDAP shadow account's User Group membership. Removals on the
  directory side become removals in Vauban at the next successful
  login resolution.
- **Direct membership only.** No nested / transitive groups in
  Phase 1.
- **Strict LDAPS.** No `ldap://`, no StartTLS on 389, no certificate
  validation opt-out.
- **Mapping file, not `dn_template`.** Bind identity stays
  `dn_template` in `[auth.ldaps]`. Group mapping lives in
  `mapping_path` (Casbin-style external file). See
  [ADR 008](../adr/008-ldaps-mapping-file-dsl.md).
- **User Groups are not Casbin roles.** A mapped name such as
  `Administrators` is an Access Rules principal. It does not set
  `is_superuser` / `is_staff` and does not grant `role:superuser`.

### 1.3 What aggregation produces

A pure function in `shared`:

```text
(directory group keys, compiled mapping AST) -> set of User Group UUIDs
```

The function is deterministic, order-independent, and has no I/O.
Persistence (replace `user_groups` for that user) stays in
`vauban-web`.

---

## 2. Bind inside the sandboxed service

Two integration approaches were considered for the bind (unchanged
from 1.0):

| | Chosen design | Rejected alternative |
|---|---|---|
| TLS + bind + search | inside `vauban-auth` (sandboxed) | inside the supervisor (root) |
| Supervisor sees password | **never** | yes |
| New attack surface in TCB | DNS + connect only (already present) | full TLS + LDAP/BER parsing |

The supervisor does what it already does for every other upstream
socket: DNS resolution, `connect()`, and an `SCM_RIGHTS` hand-off of
the connected file descriptor, gated by an `(host, port)` whitelist.
Sandboxed `vauban-auth` terminates TLS (rustls, chain validated
against a CA delivered pre-seal) and runs the LDAP simple bind, then
the group search, on that pre-connected FD.

---

## 3. End-to-end flow

```mermaid
sequenceDiagram
    participant Web as vauban-web (login)
    participant Auth as vauban-auth (sandboxed)
    participant Sup as vauban-supervisor
    participant DS as LDAPS directory
    participant DB as PostgreSQL

    Web->>Auth: AuthLdapBindAndSearch { username, password }
    Note over Auth: DN = substitute_bind_dn(dn_template, username)
    Auth->>Sup: TcpConnectRequest { target_service: Auth, host, port }
    Note over Sup: ldap.allows(host, port) ? else fail-closed
    Sup->>Sup: DNS + connect_timeout
    Sup-->>Auth: send_fd(connected TCP FD) via SCM_RIGHTS
    Sup->>Auth: TcpConnectResponse { success }
    Note over Auth: rustls (CA pre-seal, SNI=host) + simple bind
    alt bind fails
        Auth->>Web: outcome InvalidCredentials / Unreachable / TlsError
        Note over Web: generic invalid-credentials to the client
    else bind succeeds
        Note over Auth: SearchRequest on the same TLS session
        Auth->>Web: outcome + group_keys (may be empty)
        Note over Web: JIT provision if unknown; MFA unchanged
        Web->>Web: apply mapping AST (static then match)
        Web->>DB: replace user_groups for this LDAP user
    end
```

`AuthLdapBind` remains on the wire for bind-only callers and tests.
The login path that enables aggregation uses the appended
bind-and-search variant so the password is presented once and the
search rides the already-authenticated LDAP session.

---

## 4. Web-side authentication routing

Routing stays in `vauban-web/src/handlers/auth.rs` (`login` /
`login_web`):

- **Existing user**: `user.auth_source` is authoritative.
  - `Ldap` -> directory bind (and search when aggregation is enabled);
    **never** a local password fallback (anti-downgrade); local
    `failed_login_attempts` / `locked_until` are **not** incremented.
  - `Local` -> existing Argon2id path, including progressive lockout.
    Aggregation is not invoked.
- **Unknown username**: if `[auth.ldaps].enabled` and `order`
  contains `"ldap"`, a bind is attempted; on success the user is
  **JIT-provisioned** (`auth_source = Ldap`, `external_id = username`,
  sentinel password hash, `is_active = true`) and then proceeds to MFA
  enrollment. Aggregation runs after provision (usually an empty
  prior set).
- **Local accounts always work** (break-glass), independent of
  directory availability.
- **MFA**: Vauban's TOTP is always enforced on top of a successful
  bind; an LDAP user with no MFA is routed to `/mfa/setup` on first
  login.

Aggregation never writes `user_groups` for `auth_source = Local`.

---

## 5. User Group aggregation

### 5.1 Scope

In scope for Phase 1:

- Resolve the user's **direct** directory groups after a successful
  bind.
- Map those keys to existing Vauban User Groups via
  `ldaps_mapping.conf`.
- Replace the shadow account's membership on every successful
  resolution (case A), including replacing it with the empty set.
- Distinguish search outcomes from transport outcomes (Section 8).

Out of scope (Phase 2 or elsewhere):

- Directory service account and a periodic job independent of login.
- Forced termination of an open SSH / RDP / IACS session when
  membership shrinks (existing sessions keep AccessGuard /
  `expires_at` / admin terminate).
- Nested (transitive) groups.
- Union / priority among Access Rules (already implemented).
- Creating Vauban User Groups from directory names.
- Promoting `is_superuser` / Casbin roles from the mapping file.

### 5.2 Cardinalities

- **1 User Group <- N mapping lines** (OR: any matching key joins
  the group, subject to `static` target reservation).
- **1 user -> N User Groups** (Access Rules already union rights).

### 5.3 Replace-set

On case A, `user_groups` rows for that user are replaced by the
computed set. Incremental add-only is rejected: a directory
removal would otherwise never disappear.

Phase 1 treats an LDAP shadow account's User Groups as
**directory-derived only**. A manual extra membership on that
account is overwritten at the next successful resolution. Local
accounts are untouched. If mixed membership is required later, a
provenance column on `user_groups` needs its own ADR.

`vauban_groups.source` / `external_id` / `last_synced` already exist
and may record that a group is referenced by the mapping file; they
do not auto-create groups.

### 5.4 When LDAP I/O runs

| Event | Bind + search? | Why |
|---|---|---|
| Interactive login (web / API) | Yes | Password is present; one FD |
| JIT provision (first bind) | Yes | Same path |
| `auth_sessions` idle / `last_activity` | No | Password is gone; no service account |
| WebSocket login revalidation | No | Same |
| Mid-session AccessGuard re-check | No | Access Rules use the last written `user_groups` |

The draft "every HTTPS token renewal, delay <= 15 minutes" is
**not** Phase 1. Vauban has no OAuth refresh that re-presents the
directory password. Promising a 15-minute bound without a read
identity would require storing the password or opening an
unauthenticated search -- both rejected. Phase 2 introduces a
vault-held read identity and a periodic job if that bound is
required. See ADR 007.

---

## 6. Mapping file DSL

### 6.1 Path and ownership

Production path (same tree as Casbin, no extra `config/` infix):

```text
/usr/local/etc/vauban/access/ldaps_mapping.conf
```

Repository default:

```text
config/access/ldaps_mapping.conf
```

`vauban.conf`:

```toml
[auth.ldaps]
dn_template = "{username}@example.com"
mapping_path = "/usr/local/etc/vauban/access/ldaps_mapping.conf"
```

`dn_template` remains the bind identity. It is **not** overloaded
as a path. `mapping_path` is the Casbin-style pointer.

The package installs the file `0644` `root:wheel`, next to
`policy.csv` (`pkg/build-pkg.sh`). Whoever can write this file
controls which User Groups an LDAP user may gain. The supervisor
reads and parses it **pre-seal**, fail-closed, and provisions the
compiled AST to `vauban-web`. `vauban-auth` never sees the file.
No hot-reload in Phase 1: change the file, restart the supervisor.

When `[auth.ldaps].enabled = true` and aggregation is enabled, a
missing, unreadable, or illegal mapping file refuses boot.

### 6.2 Grammar

Line-oriented, Casbin-adjacent. Not Python, not evaluated.

```text
# kind   ldap-key                                              vauban-user-group
static   CN=Domain Admins,CN=Users,DC=netris,DC=local          Administrators

match    CN={name},OU=UserGroup,OU=Vauban,DC=netris,DC=local   {name}
```

| Token | Meaning |
|---|---|
| `static` | Exact directory key (after normalization) maps to one existing User Group name |
| `match` | One `{name}` capture in the key; the same `{name}` is the User Group name |
| `#` | Comment to end of line |
| empty line | Ignored |

Rules:

- Fields are separated by ASCII whitespace. The LDAP key may contain
  spaces (AD CNs). The last field is the User Group token (`{name}`
  or a literal). Implementation: kind = first token, target = last
  token, key = trim(middle).
- The only placeholder is `{name}`. `{username}` is bind-only and
  is illegal in this file.
- A `match` line must contain `{name}` in the key **and** the
  target must be exactly `{name}`.
- A `static` line must not contain `{name}`.
- Unknown kind, unknown placeholder, or a `match` without `{name}`
  on both sides refuses boot.
- Duplicate `static` keys with different targets: OR (user gains
  both groups) -- allowed. Duplicate identical lines: ignored.
- File order does not affect evaluation.

`{name}` is a **capture against keys already returned** by the
directory. It is never interpolated into a bind DN or a search
filter (R1).

### 6.3 Evaluation and `static` target reservation

1. Build `reserved` = the set of User Group names that appear as
   `static` targets.
2. For each directory key (normalized for comparison):
   - apply every matching `static` line (OR);
   - then apply every `match` line; if the captured `{name}` is in
     `reserved`, skip that hit and emit a structured `warn!`
     (`ldap_mapping_match_skipped_reserved_target`).
3. Look up remaining names as existing `vauban_groups.name`. Missing
   groups are skipped (no implicit create).
4. Result is a set of UUIDs.

Example:

| Directory key | Result |
|---|---|
| `CN=Domain Admins,CN=Users,DC=netris,DC=local` | User Group `Administrators` |
| `CN=Administrators,OU=UserGroup,OU=Vauban,DC=netris,DC=local` | **none** for `Administrators` (`static` reserved that target) |
| `CN=Developers,OU=UserGroup,OU=Vauban,DC=netris,DC=local` | User Group `Developers` if it exists |

### 6.4 Normalization and captured `{name}`

- DN comparison: lowercase, strip whitespace around commas, collapse
  repeated spaces inside RDN values. Comparison is string-based after
  that pass (not a full RFC 4514 rewrite).
- `{name}` charset (skip the key if the capture fails): ASCII
  alphanumeric, space, `.`, `_`, `-`; first character alphanumeric;
  length 1..=100; no RFC 4514 specials (`, = + " \ < > # ;`).
- User Group lookup uses the captured string after trim. Case
  folding against `vauban_groups.name` is case-insensitive for the
  lookup, then the stored name is kept.

### 6.5 Later key kinds (not Phase 1 syntax)

Google Secure LDAP often exposes group **mail** rather than a DN.
Phase 1 lines are DN-shaped keys. A later `static mail …` kind can
be added without changing `static` / `match` semantics. Do not invent
a second file.

---

## 7. Directory group resolution

Directories do not all expose membership the same way.

| Model | Mechanism | Typical vendors |
|---|---|---|
| Attribute on the user | Multivalued `memberOf` | Active Directory, Entra ID DS, FreeIPA, 389 with `memberOf` plugin |
| Attribute on the group | `member` / `uniqueMember`; search groups | OpenLDAP default, Google Secure LDAP, JumpCloud, Authentik LDAP Outpost |

Phase 1 strategy, decided **from the search result**, not from a
vendor enum:

1. After bind, search the bound user entry (base = bind DN when it
   is a DN; otherwise a filter on `sAMAccountName` / `uid` built
   with the LDAP filter encoder, never `format!`).
2. If `memberOf` is present and non-empty, those values are the
   keys (**direct** strategy).
3. If `memberOf` is absent or empty, search candidate keys referenced
   by compiled `static` lines (and, when cheap enough, a single
   filter `(|(member=encoded_dn)(uniqueMember=encoded_dn))` under a
   configured `groups_base_dn` if we add that knob). Phase 1 minimum:
   one search per `static` DN **or** one OR-filter of those DNs, plus
   no automatic walk of every group in the tree.
4. `match` lines do not expand into extra searches. They only score
   keys already returned. A directory that has neither `memberOf` nor
   hits on `static` DNs yields an empty key list (case A with zero
   groups), not a tree-wide search.

Nested groups (AD `LDAP_MATCHING_RULE_IN_CHAIN`, FreeIPA nesting)
are Phase 2 and vendor-specific. Operators must map User Groups to
groups assigned **directly** to users.

Every filter value (username, user DN, group DN) goes through a
dedicated RFC 4515 encoder in `shared` (sibling of
`substitute_bind_dn`). Concatenating into `(sAMAccountName=…)` or
`(member=…)` is forbidden (R1). Lint:
`shared/scripts/check_untrusted_interpolation.sh`.

---

## 8. Three outcomes of LDAP resolution

The bind UI still collapses failures for anti-enumeration. The
**search** step after a successful bind must not collapse "no such
object" with "directory unreachable."

```text
After successful bind
      |
      |-- (A) Entry read, groups parsed (zero or more keys)
      |       -> replace user_groups with mapping(keys)
      |       -> reset the consecutive search-failure counter
      |
      |-- (B) Entry explicitly not found
      |       (LDAP noSuchObject / empty search after a successful
      |        bind -- not a TCP/TLS error)
      |       -> deactivate the shadow account
      |       -> purge user_groups
      |
      +-- (C) Search timeout / truncated / malformed / TLS drop
              after bind
              -> do not change user_groups
              -> increment consecutive-failure counter
              -> at threshold: purge user_groups, do NOT deactivate
              -> raise one ops signal (Notifications / Bastion Watch
                 tile -- radar stays read-only)
```

Case (C) must not take the case (B) path. A down directory is not
"this user was deleted."

Bind-level `Unreachable` / `TlsError` / `InvalidCredentials` still
deny login and do **not** deactivate the account (1.0). They are
not case (B).

### 8.1 Threshold (case C)

| Parameter | Default | Notes |
|---|---|---|
| Consecutive search failures before purge | 3 | Reset on any case A |
| Granularity | Per LDAP source for the counter and the alert; purge applied to the user whose login just failed the search | Phase 1 has one directory |
| Configurable | `[auth.ldaps].aggregation_fail_closed_threshold` | `0` disables purge (keep last groups forever on search errors) -- allowed for break-glass labs; production default is 3 |

Because Phase 1 search runs at login only, three failures means
three logins that bound successfully but could not read groups, not
a 45-minute clock.

---

## 9. IPC message protocol

Bincode encodes enum variants by ordinal. New variants are
**appended**. Existing `AuthLdapBind` / `AuthLdapBindResponse` /
`AuthLdapProvision` layouts stay unchanged ([ADR 004](../adr/004-flat-message-enum.md)).

Append (names are design-level; implementation may bike-shed
identifiers as long as ordinals stay append-only):

- `AuthLdapBindAndSearch { request_id, username, password }` --
  web -> auth. Same allowlist on `username` as bind.
- `AuthLdapBindAndSearchResponse { request_id, outcome, group_keys }`
  -- auth -> web. `group_keys` is empty unless `outcome` is the
  success-with-entry variant.
- `WebLdapMappingProvision { rules_blob or compiled records }` --
  supervisor -> web, **pre-seal**. Trust material (operator file),
  not a secret.

`LdapBindOutcome` stays `{ Success, InvalidCredentials, Unreachable,
TlsError }` for bind-only. Bind-and-search uses a wider outcome
that can express EntryNotFound vs Unreachable **after** bind
success, for web's A/B/C switch. The login HTML/JSON response for
a failed **bind** remains generic.

Bounds (fail-closed in the codec):

- `MAX_LDAP_MESSAGE` stays the per-PDU cap (64 KiB today).
- At most **256** group keys per response; excess is truncated,
  latched as incomplete, treated as case (C) (do not silently drop
  keys and call it a full set).
- Each key max **512** bytes.

Google Secure LDAP client-certificate TLS is a provision extension
(`client_cert_pem` / `client_key` from vault or `0700` files) when
that vendor is onboarded. It is not required for AD / Authentik
simple bind. Do not ship a "disable server cert check" flag with
it.

---

## 10. Supervisor broker gating

Unchanged from 1.0: `handle_tcp_connect_request` `Service::Auth`
arm gated by `config.auth.ldaps.allows(host, port)` derived from
the `ldaps://` URL. Fail-closed when LDAP is disabled or the
target is not whitelisted. Empty session token on this arm (auth
is key-less).

The mapping file is **not** consulted by the broker. Search does
not add a second host.

---

## 11. Sandbox integration

`vauban-auth` already has `ResourceKind::FdReceiver`. Search uses
the same received FD; no new kind.

`AuthLdapProvision` still arrives pre-seal (URL, `dn_template`, CA
PEM, timeout). After seal, auth can only `recvmsg` the brokered FD
and speak TLS+LDAP on it.

`vauban-web` receives the compiled mapping AST pre-seal
(`WebLdapMappingProvision` or an equivalent). After seal it must
not need to reopen `ldaps_mapping.conf`.

No new `Service` variant. `Service::Auth` already exists. Mailer
(uid 909) is unrelated.

---

## 12. Configuration

Supervisor (`config/vauban.conf`, `[auth.ldaps]`):

```toml
[auth.ldaps]
enabled = false
url = "ldaps://dc.example.com:636"
dn_template = "{username}@example.com"
mapping_path = "/usr/local/etc/vauban/access/ldaps_mapping.conf"
ca_cert_file = "/usr/local/etc/vauban/certs/ldap_ca.pem"
timeout_secs = 5
order = ["ldap", "local"]
login_username_min_length = 3
login_password_min_length = 12
aggregation_enabled = false
aggregation_fail_closed_threshold = 3
```

Only `ldaps://` is accepted; a plaintext `ldap://` URL is rejected
at config load. The CA file stays under `0700 root:wheel` `certs/`.

`login_username_min_length` / `login_password_min_length` are
login-form floors applied **before** any LDAPS bind. They do **not**
enforce directory password policy (AD / Authentik still owns that)
and are independent of `security.password_min_length` (local
password create / change only). Absolute floors are username >= 3
and password >= 12; values below those refuse to start (fail-closed
at config load on both supervisor and web). Operators may raise
them to skip useless binds when typed credentials are obviously too
short. When a login is rejected for this reason, vauban-web emits a
`warn!` (`login credentials below configured minimums; LDAPS bind
not attempted`) and returns the same generic invalid-credentials
response as every other bind failure mode.

`aggregation_enabled = false` keeps today's bind-only login (1.0
behavior) even if `mapping_path` is set. Turning aggregation on
with an empty or illegal mapping file refuses boot.

Web (`config/default.toml`, `[auth.ldaps]`) keeps routing knobs and
floors. It does not need the directory URL or CA. It needs
`aggregation_enabled` (and the provisioned AST at runtime).

---

## 13. Threat inventory

Required by R4 before the SearchRequest codec and the mapping file
are implemented. Trust anchors are **out of band**: the operator CA
PEM, `dn_template`, `mapping_path` contents, and the `(host, port)`
whitelist -- never a key or DN taken from the LDAP entry being
verified.

| Attacker | Entry | Language joined | Trust anchor | If file / packet rewritten |
|---|---|---|---|---|
| Login form (username) | Bind name | LDAP DN / UPN | `substitute_bind_dn` allowlist + operator `dn_template` | Extra RDN / filter meta in username is rejected before the directory sees it |
| Login form (username) | Search filter | LDAP filter (RFC 4515) | Filter encoder + allowlisted identifier | `*)(uid=*` / `)(\|` does not close the filter early |
| Directory (hostile or MITM after a stolen CA) | `memberOf` / `member` values | Mapping matcher (string), then SQL via Diesel | Operator mapping AST; Diesel parameters | Extra keys only join User Groups the AST allows; reserved `static` targets stay reserved |
| Operator file writer | `ldaps_mapping.conf` | Mapping DSL | Filesystem ACL (`root:wheel`); parse fail-closed | A rewritten file can map any key to any existing User Group after restart -- this is intended privilege, same class as editing `policy.csv` |
| Network (on-path, no CA) | TLS | TLS records | Provisioned CA only (no webpki) | Handshake fails; case is bind/search `TlsError`, not case B |
| Compromised `vauban-web` | IPC username / password | LDAP (via auth) | Auth still allowlists username; supervisor still whitelists host | Web cannot point the broker at an arbitrary LDAP host |
| Compromised `vauban-auth` | BER on the FD | LDAP | Capsicum: no new sockets, no filesystem | Can speak freely to the one brokered directory; cannot reach the DB or mint session tokens |
| LDAP admin creating `CN=Administrators,OU=UserGroup,…` | `match {name}` | Mapping AST | `static` target reservation | Capture `Administrators` does not join the reserved User Group |

Implementation must ship `attack_*` / `forged_*` / `*_is_rejected`
tests for every row that the rustdoc or a runbook later phrases as
a refusal. Do not write "an attacker cannot X" until that test
exists (`shared/scripts/check_security_claims.sh`).

---

## 14. Security analysis

- **Privilege separation**: plaintext password and LDAP/BER + TLS
  parsing stay in `vauban-auth`; supervisor brokers a socket;
  mapping AST is applied in `vauban-web` with Diesel.
- **SSRF**: broker arm remains the configured directory endpoint.
- **TLS**: rustls validates the directory chain against the
  provisioned CA only; SNI/hostname uses the configured host.
- **Anti-enumeration (bind)**: invalid credentials, unreachable
  directory, and TLS errors stay indistinguishable to the client.
- **Anti-collapse (search)**: after a successful bind, unreachable
  search is not treated as a deleted entry.
- **Anti-downgrade**: an `Ldap` user never falls back to local
  password verification.
- **Lockout**: LDAP bind failures do not touch local lockout
  counters.
- **R1**: bind DN and search filters use dedicated encoders. The
  mapping `{name}` capture is match-only.
- **R2**: CA, `dn_template`, and mapping file are operator input,
  not fields of the LDAP object under evaluation.
- **Fail-closed BER**: malformed / truncated / oversized PDUs are
  `io::Error`; oversized group lists are case (C), not a silent
  subset.
- **Casbin isolation**: mapping cannot flip `is_superuser`.
  `role_invariants` stay the last-superuser fence.

---

## 15. Testing strategy

Behavioral surface (auth / LDAP / membership): full Vauban pyramid.

| Layer | Artifact |
|---|---|
| Unit | Filter encoder; mapping parser; reserved-target evaluation; A/B/C state machine; `{name}` charset |
| Invariants | `include_str!` pins on `static` / `match` grammar; `dn_template` is not a path; no `ldap://` fallback; `check_untrusted_interpolation.sh`; Casbin `policy.csv` install path sibling |
| Proptest | Random usernames and filter metacharacters never break out of the encoded filter; mapping files with shuffled line order yield the same AST effect |
| Battle | Parallel logins against a stub directory; counter increments do not race two users into the wrong case B |
| E2E | Extend `vauban-auth/tests/ldap_bind_e2e_test.rs` with SearchRequest on the in-process rustls directory; extend `vauban-web/tests/security/ldap_login_test.rs` for replace-set, reserved target, local account isolation, case C purge without deactivate |
| Smoke | New runbook next to [`ldaps_bind_dn_smoke_test.md`](../runbooks/ldaps_bind_dn_smoke_test.md): live AD (or Authentik) bind + `memberOf` / reverse search + mapping file |

Refusal tests (names required if prose claims a refusal):

- `attack_filter_metacharacters_are_rejected` (or encoded so the
  directory sees a literal, never a second clause)
- `attack_mapping_match_cannot_claim_static_target`
- `forged_ldap_ca_is_rejected` (already on the bind path; keep)
- `search_unreachable_is_not_treated_as_entry_not_found`

---

## 16. Limitations and roadmap

Phase 1 limitations:

1. **No coverage without a login.** A directory change applies at
   the next successful bind-and-search. An idle `auth_session` keeps
   the last `user_groups` until logout, expiry, or a later login.
2. **No nested groups.** Map to groups assigned directly to users.
3. **No 15-minute mid-session bound.** See ADR 007 / Phase 2.
4. **Open SSH / RDP / IACS sessions** are not killed when groups
   shrink. The next `IssueSessionToken` / AccessGuard uses the new
   `user_groups`.
5. **Direct bind only** for authentication (1.0). Search-then-bind
   with a service account remains Phase 2.
6. **No e-mail from the directory** (1.0 placeholder unchanged).
7. **Google mTLS client cert** and group-mail keys are designed for
   but not required in the first vendor cut (AD / Authentik).
8. **Single-threaded auth**: bind+search still blocks the auth loop
   for the bounded timeout; web IP rate limit remains the backstop.

Phase 2:

- Vault-held directory read identity; periodic sync; case (C) on
  that job (possibly a different threshold).
- Evaluate forced terminate of proxy sessions when membership
  shrinks.
- Nested groups where the vendor has a single, documented query
  (AD in-chain, FreeIPA); explicit per-vendor "unsupported" where
  it does not.
- Optional condition types beyond group membership (OU, org
  attribute) if the mapping grammar grows a third kind -- new ADR.
- Search-then-bind for directories that refuse direct UPN/DN bind.

---

## 17. Related documents

- [ADR 007 -- LDAP group aggregation Phase 1](../adr/007-ldap-group-aggregation-phase-1.md)
- [ADR 008 -- LDAPS mapping file DSL](../adr/008-ldaps-mapping-file-dsl.md)
- [ADR 004 -- Flat `Message` enum](../adr/004-flat-message-enum.md)
- [IAM Architecture 1.1](Vauban_IAM_Architecture_EN(1.1).md)
- [Privilege Separation Architecture 1.3](Vauban_Privsep_Architecture_EN(1.3).md)
- [AccessGuard Architecture 1.0](Vauban_AccessGuard_Architecture_EN(1.0).md)
- [Vault Architecture 1.2](Vauban_Vault_Architecture_EN(1.2).md)
- [LDAPS bind-DN smoke runbook](../runbooks/ldaps_bind_dn_smoke_test.md)

---

## Appendix A -- Changelog

| Version | Date | Notes |
|---|---|---|
| 1.0 | 1 June 2026 | Direct bind, JIT provision, anti-downgrade, no group sync |
| 1.1 | 21 August 2026 | Bind-and-search on the same FD; mapping file `static` / `match`; replace-set; A/B/C; threat inventory; login-only LDAP I/O in Phase 1 |
