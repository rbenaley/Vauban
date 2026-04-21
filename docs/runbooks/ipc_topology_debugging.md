# Runbook: Debugging the IPC Pipe Topology

**Audience:** on-call SRE / platform engineers
**Trigger:** SSH or RDP sessions silently fail with `Access denied`,
`vauban-supervisor` logs `<service> is unresponsive, forcing restart`,
or `vauban-proxy-ssh` / `vauban-proxy-rdp` logs `RBAC re-check timed
out - denying fail-closed`.

This document captures the post-incident knowledge from the
`CheckAccessByUuid` regression: a single missing TOPOLOGY edge in
`vauban-access` made every SSH session open time out at the RBAC
re-check, which in turn made `vauban-proxy-ssh` unresponsive to
supervisor pings, which in turn triggered a restart loop.

---

## 1. Mental model

`vauban-supervisor` declares the IPC topology in
`vauban-supervisor/src/main.rs::TOPOLOGY`. Each entry is a directed
edge `from: Service -> to: Service`. At boot, the supervisor:

1. Creates a `pipe(2)` pair per edge,
2. Keeps **both** sides open for the supervisor's lifetime (they
   live in the original `pipes: HashMap<...>` allocation that is
   never dropped),
3. Forks each child and passes the relevant raw FDs through env
   vars `VAUBAN_<PEER>_IPC_READ` / `VAUBAN_<PEER>_IPC_WRITE`.

Each child must:

- **Parse** every env var the supervisor exports for it,
- **Bind** each parsed FD into an `IpcChannel`,
- **Poll** every channel's `read_fd` in its main loop.

A child that exports the env var but forgets to poll the channel
will accept writes silently (they pile up in the kernel pipe
buffer until it fills, then the writer blocks / times out).
This is the failure mode the runbook below addresses.

---

## 2. Symptoms

| Symptom                                                              | Likely cause                                                  |
| -------------------------------------------------------------------- | ------------------------------------------------------------- |
| `RBAC re-check timed out - denying fail-closed` (proxy_ssh / proxy_rdp) | `vauban-access` not polling its `proxy_<x> -> access` edge    |
| `<svc> is unresponsive, forcing restart` (supervisor watchdog)       | Child's main loop blocked on a synchronous IPC call           |
| `rbac_recheck_timeouts` keeps climbing in proxy_ssh / proxy_rdp logs | Access tier is wedged or saturated (DB / runtime)             |
| `vauban-access TOPOLOGY mismatch` panic at boot                      | A peer env var was not exported by the supervisor             |
| `Access denied` for **every** user in the web UI, no DB writes       | Same as #1 above (look one layer up in the relevant proxy)    |

---

## 3. Triage in <2 minutes

```bash
# 1. Verify each service is up and the supervisor is not in restart loop
journalctl -u vauban-supervisor -n 100 --no-pager | grep -E 'unresponsive|Restarting|TOPOLOGY|peers='

# 2. Look at the access tier's boot line to confirm peer wiring
journalctl -u vauban-supervisor -n 200 --no-pager | grep -E 'vauban-access.*peers='
# Expected:  peers=["web", "auth", "proxy_ssh", "proxy_rdp"]  peer_count=4

# 3. Look at the proxy_ssh AND proxy_rdp RBAC timeout counters.
# Both proxies share the same shared::access_guard module, so the
# log shape is identical -- just the prefix differs.
journalctl -u vauban-supervisor -n 200 --no-pager \
    | grep -E 'rbac_recheck_timeouts|RBAC re-check'
```

If `peers=` is missing one of the 4 entries OR `peer_count != 4`,
**that is the bug**. `vauban-access` should now refuse to start in
this state and emit `TOPOLOGY mismatch: expected 4 incoming peers ...`
-- if you see it actually running with fewer peers, you are on a
build older than the post-incident hardening; re-deploy.

---

## 4. Common root causes

### 4.1 New TOPOLOGY edge added to supervisor, peer side not updated

When you add a new `from -> Service::Access` edge to `TOPOLOGY` in
`vauban-supervisor`, you MUST also:

1. Bump `EXPECTED_PEER_COUNT` in `vauban-access/src/main.rs`,
2. Add a `parse_topology_channel("<NEW_PEER>")` call,
3. Push it into `peer_channels`,
4. Update the structural test
   `test_access_main_binds_all_topology_incoming_peers` to include
   the new peer.

The boot-time `TOPOLOGY mismatch` bail will catch (1)+(2) if you
forget; the structural test catches (3)+(4) at CI time.

### 4.2 Channel parsed into an underscore-prefixed binding

```rust
let _proxy_ssh_channel = parse_topology_channel("PROXY_SSH"); // BUG
```

Rust drops this binding at the end of the statement -- the FDs
are closed, the supervisor's writes go to a half-broken pipe, and
the symptom is a `RBAC re-check timed out`. The structural test
explicitly rejects this pattern.

### 4.3 vauban-access overloaded (genuine saturation)

If `rbac_recheck_timeouts` rises in proxy_ssh / proxy_rdp logs but
the TOPOLOGY is correct, the access tier itself is too slow:

- Check DB pool exhaustion: `vauban-access` uses a deadpool with
  a small max_size. Look for `Pool exhausted` warnings.
- Check that the access runtime is not stuck on a long query
  (any `WHERE` over `events` without a covering index, e.g.).
- If sustained, consider promoting `vauban-access` to a
  multi-thread tokio runtime OR adding a small in-memory TTL
  cache (~1s) of `(user_uuid, asset_uuid, protocol) -> bool`
  inside `shared::access_guard::AccessGuard` (single change, both
  proxies benefit).

The hard timeout (`shared::access_guard::RBAC_RECHECK_TIMEOUT =
Duration::from_secs(10)`) is the safety net, not the remediation.
Adjusting it upward is a last resort -- the supervisor's heartbeat
threshold is roughly 20s, so going beyond ~15s starts cascading
restarts again.

---

## 5. Reproducing locally

```bash
# Spawn a deliberately-broken vauban-access (drop one peer):
#   1. Comment out the parse_topology_channel("PROXY_SSH") line,
#   2. cargo build, run under supervisor,
#   3. attempt an SSH session in the web UI.
# Expected: vauban-access bails at boot with TOPOLOGY mismatch.
# If it does NOT bail, the boot-time check is broken and you have
# a regression in `vauban-access/src/main.rs`.
```

The integration test
`test_check_access_by_uuid_full_wire_roundtrip` in
`vauban-access/src/handlers.rs` exercises the wire format on a
real Unix pipe with a real PostgreSQL pool. If it passes, the
proxy_ssh <-> access bincode contract is intact; the bug is
elsewhere (likely the topology wiring above).

---

## 6. Bootstrap policy: every user needs an access_rule

Since the RBAC defense-in-depth re-check landed (commit
`fix(access,proxy-ssh): RBAC re-check by UUID`), the historical
"superuser / staff bypass" in `vauban-web` is gone. Both layers
(`vauban-web::handlers::web::ssh::connect_ssh` and
`vauban-proxy-ssh::SshSessionOpen` -> `vauban-access::CheckAccessByUuid`)
require **the same** access_rule lookup. Same policy, two layers.

This means:

- A freshly-deployed system where only the bootstrap superuser exists
  CANNOT open any SSH/RDP session until that superuser creates an
  access_rule for themselves.
- The error users see when they forget is `Access denied` (proxy)
  preceded by `No access rule grants you access to this asset`
  (vauban-web).

### Bootstrap procedure

1. Sign in as the bootstrap superuser via the web UI.
2. Create or reuse a vauban-group containing the superuser
   (`/groups`).
3. Create or reuse an asset-group containing the assets the
   superuser must reach (`/asset-groups`).
4. Create an access_rule binding (vauban-group, asset-group,
   protocols=[ssh, rdp], require_approval=false, is_active=true)
   at `/access-rules`.
5. Retry the connection. The proxy logs should now show
   `CheckAccessByUuid granted` instead of `denied: no granting
   access_rule`.

A common shortcut for one-superuser deployments is a single
"admin-bypass" rule:
- vauban-group = "admins" (members: bootstrap superuser),
- asset-group = "all-assets" (every asset auto-membered via the
  asset-group's slug pattern, or simply via /asset-groups bulk add),
- protocols = ["ssh", "rdp"],
- require_mfa, require_approval = depending on org policy.

If you have an existing deployment that was working pre-commit and
suddenly returns `Access denied` for every superuser, this section
is the cause: update your seed data / migrations to insert the
bootstrap rule, or do it manually as above.

---

## 7. Related code

- `vauban-supervisor/src/main.rs::TOPOLOGY`           - edge declarations
- `vauban-supervisor/src/main.rs::respawn_linked_group` - linked-restart pipe handling
- `vauban-access/src/main.rs::run_service`            - peer binding + boot check
- `vauban-access/src/handlers.rs::handle_check_access_by_uuid` - server-side authoritative RBAC (no superuser bypass)
- `vauban-web/src/handlers/web/ssh.rs::connect_ssh`   - web-side gate (no superuser bypass either)
- `vauban-web/src/handlers/web/rdp.rs::connect_rdp`   - same for RDP
- `shared/src/access_guard.rs`                        - **the** defense-in-depth
  RBAC re-check module shared by every proxy (SSH, RDP, future VNC / industrial)
- `shared/src/access_guard.rs::RBAC_RECHECK_TIMEOUT`  - shared 10s hard timeout
- `shared/src/access_guard.rs::AccessGuard::authorize` - single fail-closed entry point
- `vauban-proxy-ssh/src/main.rs` (PROTOCOL_SSH wiring) - SSH consumer of AccessGuard
- `vauban-proxy-rdp/src/main.rs` (PROTOCOL_RDP wiring) - RDP consumer of AccessGuard

If you are wiring a new proxy (VNC, Modbus, ...): add it to TOPOLOGY,
bump `EXPECTED_PEER_COUNT` in `vauban-access`, then in the new proxy
crate enable the `shared = { features = ["access-guard"] }` flag and
call `AccessGuard::from_env(PROTOCOL_<X>, state)` at boot. That is the
**only** supported path; do NOT re-implement an in-crate RBAC client.
