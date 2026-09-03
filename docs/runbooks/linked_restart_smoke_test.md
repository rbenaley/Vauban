# Runbook -- Linked restart pipe ownership smoke test

> Manual validation after shipping **PipeStore + transitive linked
> restart** (crates **0.9.43+**). A first-match linked group plus a
> dropped local pipe map left stale fd numbers in `service_pipes`; the
> second restart of `web` then broke SSH and RDP together. CI covers
> store / closure / EOF / pump layers; staging proves two successive
> kills leave sessions and host-key / cert checks working.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for production supervisor respawn.

Related:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md) §7.5
- [IPC topology debugging](ipc_topology_debugging.md)
- Lint: `shared/scripts/check_ipc_eof_handling.sh`

## Automated prerequisites

```bash
bash shared/scripts/check_ipc_eof_handling.sh
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-supervisor -p vauban-web -p vauban-proxy-ssh --all-targets -- -D warnings
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target --all-targets -- -D warnings
rtk cargo test -p shared -p vauban-supervisor -p vauban-web -p vauban-proxy-ssh -- pipe_store linked pump_exit web_eof recv_after_eof classify_web -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- classify_web recv_delivers battle_recv e2e_select -- --test-threads=1
```

## Lab prerequisites

- Packaged binaries **0.9.43+** with production `vauban.conf`.
- One SSH asset and one RDP asset the operator can open.
- Ability to `kill -9` / `kill -STOP` children and read `/var/log/vauban.log`.
- `fstat -p <supervisor-pid>` (or `procstat -f`) for fd-count stability.

## A -- Kill web once

1. Confirm SSH and RDP sessions open; asset host-key and RDP cert
   checks succeed.
2. `kill -9` the `vauban-web` pid.
3. Expect supervisor log `Restarting linked group` listing `web`,
   `proxy_ssh`, and `proxy_rdp` (not SSH alone).
4. After the group is back, open SSH and RDP again; host-key / cert
   checks still succeed.

Pass: full closure restarted; both protocols work.

## B -- Kill web a second time (the production incident)

1. Wait ~1 minute after A.
2. `kill -9` `vauban-web` again.
3. Expect the same linked closure, **no** burst of
   `Web connection closed`, at most one
   `Web IPC pipe closed, exiting for linked respawn` per proxy.
4. `fstat -p <supervisor-pid>` fd count is stable versus the count
   after A (no leak, no recycled collision).
5. SSH + RDP + host-key + cert checks succeed.

Pass: second restart does not poison topology fds.

## C -- Unresponsive web after proxy_rdp kill

1. `kill -9` `vauban-proxy-rdp`; wait for the linked group to return.
2. `kill -STOP` `vauban-web` for 20 s (3 missed heartbeats at 5 s).
3. Expect `is unresponsive` then the same `{web, proxy_ssh, proxy_rdp}`
   restart (not SSH-only).
4. `kill -CONT` is unnecessary after SIGKILL/respawn; confirm SSH and
   RDP open.

Pass: unresponsive path uses the same transitive closure.

## Rollback notes

Revert to 0.9.42 only if 0.9.43 cannot boot; 0.9.42 still has the
stale-fd class of bug. Prefer staying on 0.9.43 and collecting
`linked` / `unresponsive` / `pipe closed` log lines.
