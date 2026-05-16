# Runbook -- IACS / EWS onboarding lifecycle

> Operator playbook for the **IACS / Engineering Workstation (EWS)**
> module: configuration kill-switch, onboarding-request lifecycle,
> EWS state transitions (disable / enable / offboard), audit queries
> against the append-only `ews_audit_log`, and recovery paths.
>
> Audience: on-call operators, IACS administrators, compliance
> reviewers.
> Severity: LOW for routine reads; MEDIUM when the kill-switch is
> toggled in production or when bulk-disabling EWS rows; HIGH if
> append-only invariants are reported violated.

## Background

IACS is the preliminary scaffolding for managing **Engineering
Workstations** -- operator laptops / desktops running the SSH client
that will reach future IACS assets through Vauban. The data model is
intentionally separated from the core `assets` table:

- `ews_onboarding_requests` -- the request lifecycle
  (`pending -> approved | rejected | cancelled`).
- `ews` -- approved workstations holding the active SSH public key,
  with reversible `disabled_at` and irreversible `offboarded_at`
  soft-delete columns.
- `ews_audit_log` -- append-only trail of every state transition.

Migration: [`20260506000000_iacs_ews_onboarding`](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql).

## URL surface

| URL | Verb | Casbin gate | Purpose |
|-----|------|-------------|---------|
| `/iacs/onboard` | GET | `iacs:request` | Render the onboarding form (key generation help + request form) |
| `/iacs/onboard` | POST | `iacs:request` | Submit a new request -> `pending` row, redirects to `/sessions/my-requests` |
| `/iacs/onboard/{uuid}/edit-form` | GET | `iacs:request` | Edit form (only while pending and only the requester) |
| `/iacs/onboard/{uuid}/edit` | POST | `iacs:request` | Save edits |
| `/iacs/onboard/{uuid}/cancel` | POST | `iacs:request` | Cancel a pending request |
| `/iacs/{uuid}/offboard-self` | POST | `iacs:request` | User-initiated offboarding of one of their approved EWS |
| `/iacs/admin` | GET | `iacs:manage` | Admin landing: pending requests + EWS list |
| `/iacs/admin/request/{uuid}` | GET | `iacs:manage` | Request detail page |
| `/iacs/admin/request/{uuid}/approve` | POST | `iacs:manage` | Approve a pending request -> creates the matching `ews` row |
| `/iacs/admin/request/{uuid}/reject` | POST | `iacs:manage` | Reject a pending request (reason >= 5 chars required) |
| `/iacs/admin/ews/{uuid}` | GET | `iacs:manage` | EWS detail page |
| `/iacs/admin/ews/{uuid}/disable` | POST | `iacs:manage` | Disable an active EWS (reversible) |
| `/iacs/admin/ews/{uuid}/enable` | POST | `iacs:manage` | Re-enable a disabled EWS |
| `/iacs/admin/ews/{uuid}/offboard` | POST | `iacs:manage` | Offboard an EWS (irreversible) |

The `/iacs/admin/*` sub-tree carries
`route_layer(require_iacs_manage)` so a non-admin gets **403 BEFORE
the handler runs** (anti-enumeration: a random UUID under the
sub-tree is rejected without a DB lookup). Each handler ALSO
re-checks `perms.iacs_manage` in its body for defence-in-depth.

## Kill-switch -- `[industrial].enabled`

The whole IACS surface is gated by a single config flag in
`vauban.conf`:

```toml
[industrial]
enabled = true            # set to false to fully hide the IACS surface
max_ews_per_user = 0      # 0 = no cap; otherwise a per-user EWS quota
```

Enforcement is centralised in
[`PermissionContext::load`](../../vauban-web/src/auth/permissions.rs)
(folded into every `iacs_*` flag). When `enabled = false`:

- the sidebar entry disappears,
- the IACS button on `/assets` is hidden,
- every `/iacs/*` URL collapses to 404 (user zone) or 403 (admin
  zone),
- already-issued JWTs see the new flag on the next request -- no
  cache, no warm-up window.

Source-level invariant pinned by
[`scripts/check_iacs_kill_switch.sh`](../../vauban-web/scripts/check_iacs_kill_switch.sh):
the `industrial.enabled` flag MUST NOT be read from anywhere except
the canonical loader and `main.rs` boot. Any handler / template
introducing a parallel decision path is flagged in CI.

Runtime invariant pinned by
[`tests/web/iacs_kill_switch_test.rs`](../../vauban-web/tests/web/iacs_kill_switch_test.rs).

### Toggling in production

1. Edit `vauban.conf` -> set `[industrial].enabled = false` (or
   `true`).
2. Reload the service:

   ```bash
   sudo systemctl reload vauban-web vauban-access
   ```

3. Verify from a browser logged in as a regular user: the **IACS**
   sidebar entry should be gone and `/iacs/onboard` should return
   404.
4. Existing `ews` and `ews_onboarding_requests` rows are NOT
   modified -- the kill-switch only hides the surface. Re-enabling
   restores access to the same data.

> Severity bump to MEDIUM: announce the toggle on the operator
> channel BEFORE flipping the switch. Active EWS owners will lose
> the "My Requests" UI for their EWS rows for the duration of the
> outage. The keys themselves remain valid (the proxy enforcement
> happens elsewhere); a flip is only a UI hide.

## Standard operator queries

> Run from the `vauban-web` PostgreSQL role (read-only on
> `ews_audit_log`). Replace placeholders in `{...}`.

### All onboarding events for a given EWS

```sql
SELECT created_at, event, actor_username, target_username,
       ews_name, public_key_fingerprint, decision_reason, actor_ip
FROM ews_audit_log
WHERE ews_uuid = '{ews_uuid}'
   OR request_uuid = (
       SELECT request_uuid FROM ews WHERE uuid = '{ews_uuid}'
   )
ORDER BY created_at ASC;
```

### All decisions made by a given admin over the last 30 days

```sql
SELECT created_at, event, target_username, ews_name,
       public_key_fingerprint, decision_reason, actor_ip
FROM ews_audit_log
WHERE actor_user_id = {admin_id}
  AND event IN ('approved', 'rejected', 'disabled', 'enabled', 'offboarded')
  AND created_at >= NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;
```

### Currently active EWS rows (for a snapshot inventory)

```sql
SELECT e.uuid AS ews_uuid, u.username AS owner,
       e.name, e.key_algo, e.public_key_fingerprint,
       e.created_at
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.offboarded_at IS NULL
  AND e.disabled_at IS NULL
ORDER BY u.username, e.name;
```

### Pending requests older than 7 days (SLA breach detection)

```sql
SELECT r.uuid AS request_uuid, u.username AS requester,
       r.name AS ews_name, r.created_at,
       NOW() - r.created_at AS age
FROM ews_onboarding_requests r
INNER JOIN users u ON u.id = r.user_id
WHERE r.status = 'pending'
  AND r.created_at < NOW() - INTERVAL '7 days'
ORDER BY r.created_at ASC;
```

### Fingerprint provenance check

```sql
SELECT 'ews' AS source, e.uuid::text, e.name, u.username,
       e.created_at, e.disabled_at, e.offboarded_at
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.public_key_fingerprint = '{fingerprint_hex}'
UNION ALL
SELECT 'request' AS source, r.uuid::text, r.name, u.username,
       r.created_at, NULL, NULL
FROM ews_onboarding_requests r
INNER JOIN users u ON u.id = r.user_id
WHERE r.public_key_fingerprint = '{fingerprint_hex}'
ORDER BY created_at ASC;
```

The DB-level invariant
`ews_active_fingerprint_uniq` (partial unique index, see
[migration up.sql §2](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql))
guarantees that at most ONE non-offboarded `ews` row holds any given
fingerprint. The query above exists for forensic audits, not for
runtime checks.

## Lifecycle troubleshooting

### A user reports "EWS onboarding submitted" but no admin notification

1. Check `ews_audit_log` for the `submitted` event:

   ```sql
   SELECT * FROM ews_audit_log
   WHERE event = 'submitted'
     AND target_username = '{username}'
   ORDER BY created_at DESC LIMIT 5;
   ```

2. If the event is present, the request reached the DB. Inspect the
   mailer queue:

   ```sql
   SELECT * FROM email_events
   WHERE event_kind LIKE 'IacsOnboard%'
     AND created_at >= NOW() - INTERVAL '1 hour'
   ORDER BY created_at DESC;
   ```

3. If the event is absent, the request never reached `vauban-access`
   -- inspect `vauban-web` logs for the user's session at submit
   time, looking for `IacsError::Internal` or CSRF rejections.

### A user cannot self-offboard their EWS

The user must own the EWS. The handler maps `EwsDenyReason::NotOwner`
to a 404 to prevent enumeration -- so a 404 from
`/iacs/{uuid}/offboard-self` means either:

- the UUID does not exist, OR
- the UUID exists but the caller is not the owner.

Verify ownership with:

```sql
SELECT u.username AS owner
FROM ews e
INNER JOIN users u ON u.id = e.user_id
WHERE e.uuid = '{ews_uuid}';
```

Self-offboarding is also blocked when the EWS is already offboarded
(`EwsDenyReason::EwsAlreadyOffboarded`, surfaced as a flash message,
not a 404).

### "This SSH public key is already registered"

Surfaced as a flash message on the form (`EwsDenyReason::KeyAlreadyUsed`).

The conflict can come from:

- another active or disabled `ews` row carrying the same fingerprint,
- another pending request the requester does not own.

Run the **Fingerprint provenance check** query above. The user MUST
rotate their key (`ssh-keygen -t ed25519 -C VAUBAN -N ""`) and resubmit;
the form does not expose a way to "force" a conflicting key.

## Append-only invariant

`ews_audit_log` is append-only. The trigger
`block_ews_audit_log_mutation` raises on every `UPDATE` and `DELETE`
(except FK-cascaded `SET NULL` on `actor_user_id` /
`target_user_id`, which keeps the snapshot usernames intact).

Verify the invariant on a fresh database:

```sql
-- Both should raise check_violation:
UPDATE ews_audit_log SET event = 'edited' WHERE id = 1;
DELETE FROM ews_audit_log WHERE id = 1;
```

If either succeeds, the trigger has been dropped or the table has
been re-created without the trigger -- this is a HIGH-severity
incident. Restore the trigger from
[migration up.sql §4](../../vauban-db/migrations/20260506000000_iacs_ews_onboarding/up.sql)
and freeze IACS writes until a forensic review of recent rows.

## Recovery paths

### Cancelled-by-mistake request

A cancelled request stays in `ews_onboarding_requests` with
`status = 'cancelled'` and is NOT editable (the CHECK constraint
`ews_request_decision_consistency` forbids transitioning back to
`pending`). The user MUST submit a new request -- there is no
"un-cancel" button.

### Erroneous approval

There is no "un-approve" verb. If an admin approved a request that
should have been rejected:

1. **Disable** the EWS row immediately
   (`POST /iacs/admin/ews/{uuid}/disable`). This is reversible and
   keeps the fingerprint locked, preventing the user from
   re-submitting the same key.
2. Once the case is reviewed, **offboard** the EWS row
   (`POST /iacs/admin/ews/{uuid}/offboard`). This is irreversible
   and releases the fingerprint.
3. The audit trail now shows `submitted -> approved -> disabled
   -> offboarded`, with the actor / reason / IP for each
   transition.

### Erroneous rejection

A rejected request is final. The user must submit a new request
(with the same key + new justification). The original `rejected`
row stays for audit; the partial unique index does not block a
re-submission because rejected rows are not in the
`pending`-filtered index.

## `vauban-proxy-iacs` -- per-asset target tunnel runtime

Starting with v0.7.8, the IACS tunnel runtime moved from a thread
inside `vauban-web` to a dedicated, sandboxed service called
`vauban-proxy-iacs`. The runbook impact is localised; the user-facing
URLs and the `ews_audit_log` invariants documented above are
unchanged. What follows is the operator playbook for the new
service.

### Process layout

```
vauban-supervisor (root, un-sandboxed)
  | bind() 127.0.0.1:<bind_addr>            <-- pre-fork, before drop_priv
  | bind() upstream PerAssetTcp <-- on demand, gated by anti-SSRF
  | SCM_RIGHTS over `pipe:web<->access<->audit<->proxy_iacs`
  v
vauban-proxy-iacs (vauban_iacs:vauban_iacs, Capsicum cap_enter)
   - inherits the listening FD via VAUBAN_IACS_LISTENER_FD
   - never calls bind() / connect() / socket()
   - russh sshd, EWS-facing
   - `direct-tcpip` -> SupervisorBrokerOpener -> SCM_RIGHTS upstream FD
```

The supervisor pre-binds the listening socket (so the proxy can stay
fully sandboxed) and brokers every upstream TCP connection on behalf
of the proxy via `Message::TcpConnectRequest` / `Message::TcpConnectResponse`
with the connected file descriptor passed via `SCM_RIGHTS`.

### Anti-SSRF guards (supervisor side)

The supervisor enforces two guards on every TCP broker request that
targets `Service::ProxyIacs`:

1. **Anti-self-listener**. A request whose `(target_host, target_port)`
   equals the IACS sshd's own listening address is rejected. This
   prevents an attacker who owns an EWS key from looping the SSH
   server back into itself (which would create an infinite ssh-in-ssh
   tunnel and exhaust file descriptors).
2. **Anti-loopback (default deny)**. A request that resolves to a
   loopback IP (`127.0.0.0/8`, `::1`) is rejected unless
   `industrial.iacs_tunnel.allow_loopback_targets = true` (set this
   ONLY for the integration test harness, never in production --
   loopback assets give an EWS oracular access to colocated
   services).

Both guards log a structured `target_resolved_ip` field so an
operator can pivot on `journalctl -u vauban-supervisor -g
target_resolved_ip` to triage a denied tunnel.

### `vauban.conf` knobs

```toml
[industrial.iacs_tunnel]
enabled = true
bind_addr = "127.0.0.1:2225"
advertise_hostname = "vauban.example.org"
host_key_path = "/var/lib/vauban/iacs_host_key"
allow_loopback_targets = false   # NEVER set true outside of CI
waiting_client_ttl_seconds = 60
revocation_poll_interval_seconds = 5
max_concurrent_per_user = 8
max_concurrent_per_ews = 4
max_concurrent_channels_per_session = 16  # default, see below

[services.proxy_iacs]
enabled = true
binary_path = "/usr/local/bin/vauban-proxy-iacs"
log_level = "info"
```

#### Per-login concurrent SSH channels (`max_concurrent_channels_per_session`)

Every TCP `accept()` on the EWS-side `ssh -L LP:asset:AP` listener
spawns a NEW `direct-tcpip` channel over the existing SSH login
(this is normal OpenSSH behaviour: the bastion does NOT "reuse" a
single channel for multiple TCP clients). A bastion that capped
the per-login channel count to `1` would therefore break every
multi-client industrial workflow -- e.g. a SCADA HMI keeping a
polling channel open while an engineer attaches a Modbus
diagnostic tool, or simply an operator running `nc localhost 7022`
twice in a row.

The cap protects against fan-out exfil while preserving the
multi-client workflow. Operationally:

- Default `16`: leaves room for an HMI + a couple of diagnostic
  tools per asset without ever surfacing
  `administratively prohibited` to legitimate operators.
- `0`: disables the cap entirely (unlimited concurrent channels
  per login). NOT recommended in production -- the supervisor
  broker has its own quotas but the per-login cap is the only
  bound that scales with the in-flight SSH channel count.
- `1`: re-introduces the pre-v0.7.9 single-shot bug where a
  closed `nc` made every subsequent connection fail. NEVER use.

Forwarded to `vauban-proxy-iacs` via the
`VAUBAN_IACS_MAX_CHANNELS_PER_SESSION` env var (set automatically
by the supervisor; do not export it manually).

If an operator reports `channel N: open failed: administratively
prohibited` after a clean `nc`/Ctrl-C cycle, the most likely
cause is a misconfigured `max_concurrent_channels_per_session = 1`
or `max_concurrent_channels_per_session = 0` on a build older
than v0.7.9 where the runtime ignored this field. Bumping to the
default `16` and restarting `vauban-proxy-iacs` clears it.

The pre-v0.7.8 field `target_addr` is no longer read. The persisted
`proxy_sessions.tunnel_target_addr` is now derived per-session from
`asset.hostname:asset.port` at session creation time, not from a
process-wide constant. A residual `target_addr` line in
`vauban.conf` is silently ignored (it has a `default_target_addr`
in code purely for backwards-compatible test deserialization).

### Status of an active tunnel

```sql
-- All sessions opened in the last hour with their resolved target
SELECT ps.uuid, u.username, a.name AS asset, ps.tunnel_target_addr,
       ps.status, ps.created_at, ps.industrial_protocol
FROM proxy_sessions ps
INNER JOIN users u ON u.id = ps.user_id
INNER JOIN assets a ON a.id = ps.asset_id
WHERE ps.session_type = 'iacs_tunnel'
  AND ps.created_at >= NOW() - INTERVAL '1 hour'
ORDER BY ps.created_at DESC;
```

A `tunnel_target_addr` that does NOT match the current
`asset.hostname:asset.port` indicates either (a) the asset was edited
after the session was created (legitimate, the session keeps the
pinned target until termination) or (b) data drift (HIGH severity
incident, file a forensic ticket).

### Live tunnel status (WebSocket fan-out)

`vauban-proxy-iacs` emits `IacsTunnelStatusUpdate` and
`IacsTunnelClosed` IPC messages on every state change; `vauban-web`
forwards them as WebSocket frames on the `notifications` channel.
The supervisor dashboard (`/admin`) and the user "My Requests" page
both subscribe and update without a page refresh. If you observe
"My tunnel is stuck on `waiting_client`" in production:

1. Check `vauban-proxy-iacs` logs for the matching `session_id` --
   look for `WebSocket connected` / `WebSocket closed` lifecycle
   lines and a `cause = ...` field on the closed line.
2. If the tunnel was opened on the proxy but never broadcast as
   `IacsTunnelStatusUpdate`, the IPC pipe between proxy-iacs and
   web is wedged: bounce `vauban-web` (the watchdog inside
   proxy-iacs will re-emit on the next heartbeat).

### Revocation watchdog (DB-driven, IPC-dispatched)

The watchdog still lives inside `vauban-web` (DB-resident logic) but
no longer manipulates an in-process registry. When it decides a
tunnel must die (EWS disabled / offboarded / user deactivated /
access-rule revoked / waiting_client TTL exceeded), it sends an
`IacsTunnelTerminate` IPC message to `vauban-proxy-iacs`. The
proxy answers asynchronously with an `IacsTunnelClosed` event that
fans out on the WebSocket channel.

Operator triage when "an offboarded EWS still has an open tunnel":

1. `journalctl -u vauban-web -g 'iacs_tunnel.*revocation'` -- the
   watchdog logs every dispatched terminate.
2. `journalctl -u vauban-proxy-iacs -g 'IacsTunnelTerminate'` -- the
   proxy logs every received terminate.
3. Mismatch (web dispatched, proxy never received) -> the IPC pipe
   is wedged; restart `vauban-proxy-iacs` (the supervisor will
   respawn it and the watchdog will redispatch on the next tick).

### Privileged-port unprivilegisation on the EWS (`-L LP:asset:AP`)

Most industrial protocols listen on TCP ports below 1024 (Modbus
502, MMS / IEC-61850 102, FTP 21). Binding such a port via
`bind(2)` requires elevated privileges on every Unix kernel
(`CAP_NET_BIND_SERVICE` on Linux, root on FreeBSD/macOS) and on
Windows (the "increased priority" right). Forcing operators to run
`ssh -L 502:...` as root every time they need to reach a Modbus
PLC is unacceptable from a security and a UX standpoint.

Vauban therefore decouples the local-bind port (LHS of `ssh -L`)
from the asset's upstream port (RHS):

| Asset upstream port | EWS local-bind port (LHS) |
|---|---|
| 502 (Modbus / Modbus-TCP) | 50502 |
| 102 (IEC-61850 / MMS) | 50102 |
| 21 (FTP) | 50021 |
| 22 (SSH) | 50022 |
| 4840 (OPC-UA) | 4840 (no rewrite -- already user-range) |
| 34962 (Profinet) | 34962 (no rewrite) |
| 2404 (IEC-60870-5-104) | 2404 (no rewrite) |
| 1023 | 51023 (last privileged port) |
| 1024 | 1024 (first user port; no rewrite) |

The mapping is `local = asset_port if asset_port >= 1024 else
50000 + asset_port` -- deterministic, reversible, collision-free
on the privileged range, stable across releases (pinned by
[`port_mapping::derive_local_forward_port_is_stable_across_releases`](mdc:vauban-web/src/services/iacs_tunnel/port_mapping.rs)).
The status page renders the mapped port AND a yellow hint
explaining the rewrite for any asset whose upstream port is `< 1024`,
including a copy-pasteable example for `mbpoll` / similar tools
(test pin
[`lot_a_modbus_502_renders_local_50502`](mdc:vauban-web/tests/web/iacs_local_forward_port_test.rs)).

Operator workflow:

1. Open the IACS tunnel from `/assets`. The status page renders
   `ssh -i ~/.ssh/id_VAUBAN -L 50502:plc.factory.example:502
   <session>@bastion -p 22322 -N`.
2. Run the command verbatim on the EWS -- no `sudo`, no
   `setcap`, no Windows admin elevation.
3. Configure the IACS client to connect to **`127.0.0.1:50502`**
   (NOT 502). The client speaks the protocol normally; the
   bastion tunnels every byte to the asset on port 502.

Edge cases:

- **IPv6 asset hostname** (`fd00::cafe:beef`): the literal is
  preserved verbatim in the rendered command. OpenSSH parses
  `-L LP:fd00::cafe:beef:AP` correctly because the LHS port +
  separator are unambiguous; the operator does NOT need to
  bracket the IPv6 host. Pinned by
  [`lot_a_ipv6_asset_host_preserved_verbatim`](mdc:vauban-web/tests/web/iacs_local_forward_port_test.rs).
- **Already-bound `127.0.0.1:50502`**: the EWS-side `ssh` will
  fail with `bind: Address already in use`. Pick another port via
  `ssh -L 60502:...` overriding the rendered command. The
  bastion's `validate_target` only enforces the RHS triplet
  `<asset_host>:<asset_port>`; the LHS is purely an EWS-side label.
- **Custom port `< 1024` not in the canonical IACS list**: still
  rewritten by `derive_local_forward_port`. Example: an asset on
  port 23 (Telnet) renders as `-L 50023:host:23`.

### Capsicum / FreeBSD-only sandbox notes

`vauban-proxy-iacs` runs under Capsicum on FreeBSD (production). On
Linux/macOS dev hosts the sandbox is a no-op (the process still
inherits the FD and behaves identically, but cap_enter is skipped).
Concretely:

- Production (FreeBSD): `cap_enter` after the listener FD is
  granted the `cap_listen | cap_accept` rights. Any subsequent
  `socket()`, `bind()`, `connect()`, or open of an unallowed FD
  returns `ECAPMODE`. This is why the supervisor brokers every
  upstream TCP.
- Development (Linux/macOS): the proxy still goes through the
  supervisor broker (so the per-asset target contract is
  exercised in tests), but a misbehaving build that called
  `connect()` directly would NOT fail-close. CI exercises both
  paths; do not rely on the dev path for security claims.

## Change log

| Version | Date | Notes |
|---------|------|-------|
| 0.7.4 | 2026-05-06 | Initial release: data model + user / admin handlers + kill-switch + audit log. |
| 0.7.8 | 2026-05-15 | IACS tunnel runtime split into `vauban-proxy-iacs` (Capsicum-sandboxed). Per-asset target resolution: `tunnel_target_addr` is now derived from `asset.hostname:asset.port`. Anti-SSRF guards (anti-self-listener, anti-loopback) added on the supervisor TCP broker. Watchdog dispatches `IacsTunnelTerminate` IPC instead of touching an in-process registry. |
| 0.7.8 | 2026-05-16 | Privileged-port unprivilegisation: the EWS local-bind port (LHS of `ssh -L`) is now decoupled from the asset port. Privileged asset ports (`< 1024`, e.g. Modbus 502, MMS 102) are shifted into the user range (50502, 50102) so operators never need root on their EWS. The rendered status page surfaces a yellow hint with a copy-pasteable client example whenever the rewrite kicks in. The RHS of `-L` now carries the asset's actual hostname (was hardcoded `127.0.0.1`), so production assets on routable IPs validate correctly against the bastion's `validate_target`. |
| 0.7.8 | 2026-05-16 | Fix: IACS access denied despite an explicit access rule. `CheckAccessByUuid(protocol="iacs_tunnel")` now matches any access_rule whose `allowed_protocols` array intersects the applicative IACS set (`iacs_modbus`, `iacs_opcua`, `iacs_profinet`, `iacs_iec104`, `iacs_tcp`). The bridging seam lives in `shared::access_guard::expand_protocol_for_access_match` and `vauban-access::handlers::protocol_match_filter`. No DB migration required; existing access rules created via the "IACS (all industrial protocols)" master checkbox keep working unchanged. |
| 0.7.9 | 2026-05-16 | Fix: `channel N: open failed: administratively prohibited: Rejected` after a clean `nc localhost <LP>`/Ctrl-C cycle. The pre-fix `channel_open_direct_tcpip` used `AtomicBool::swap(true)` to enforce "at most one direct-tcpip per SSH login", which made every TCP `accept()` past the first one fail -- breaking the multi-client `ssh -L` workflow on every IACS asset (each `accept()` spawns a new SSH channel by OpenSSH design). Replaced with a bounded `live_channels: AtomicUsize` counter capped by the new `industrial.iacs_tunnel.max_concurrent_channels_per_session` (default 16, `0` = unlimited). Closed channels return their slot to the pool. E2E tested: sequential reuse, concurrent reuse, cap enforcement. |
| 0.7.10 | 2026-05-16 | Fix (continuation of 0.7.9): the same workflow still failed at the supervisor layer with `session token rejected: token expired; fail-closed deny` after the first 30 s, OR with a silent `Access denied` on the second channel-open within the TTL. Root cause: the cryptographic `SessionToken` used a single 30 s TTL plus a `(session_id, nonce)` replay cache -- both designed for the SSH/RDP single-shot model in which one upstream TCP per session is opened. IACS multiplexes many `direct-tcpip` channels over its lifetime, all carrying the SAME token bytes. Fix: `Service::ProxyIacs` tokens now get a 12 h TTL (`TOKEN_TTL_SECONDS_IACS_TUNNEL`), and the supervisor's replay cache is bypassed for `Service::ProxyIacs`. Compensating controls unchanged: per-asset crypto binding, anti-SSRF guards, revocation watchdog. No config knob -- the TTL and bypass live in the code (see `shared::session_token::token_ttl_for` and `vauban-supervisor::handle_tcp_connect_request`). Pinned by `iacs_token_ttl_is_long_lived`, `iacs_token_eventually_expires`, `non_iacs_tokens_keep_short_single_shot_ttl`, `test_supervisor_tcp_broker_bypasses_replay_cache_for_iacs`. |
