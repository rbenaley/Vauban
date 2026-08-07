# Runbook -- `vcp` PID-file singleton (fail-closed)

> Manual validation that a second portal launch fails via the **PID file**
> (`server.pid_file`) before DB connect / listen bind — not merely because
> the TCP port is busy (another app may own the port).
>
> Audience: local / staging operators.
> Severity: **BLOCKING** for singleton-guard changes.

Related:

- `src/process_guard.rs`
- `server.pid_file` in `config/vcp.conf` (`/var/run/vcp/vcp.pid`) and
  `config/development.toml` (`/tmp/vcp.pid`)
- `Justfile` recipe `run`
- Pyramid: `.cursor/rules/vcp-test-pyramid.mdc`
- Filter: `cargo test -p vcp process_guard -- --test-threads=1`

## Automated prerequisites

```bash
just fmt-check
rtk cargo clippy --all-targets -- -D warnings
rtk cargo test -p vcp process_guard -- --test-threads=1
rtk cargo test -p vcp loads_development_layering loads_production_vcp_conf -- --test-threads=1
```

## Lab prerequisites

- One terminal already serving the portal (`just run` or `target/debug/vcp`).
- Confirm the PID file:
  ```bash
  # development
  cat /tmp/vcp.pid
  # production-shaped
  # cat /var/run/vcp/vcp.pid
  ```

## A -- `just run` fails before rebuild when PID file is held

With an existing live `vcp` and `/tmp/vcp.pid` present:

```bash
just run
```

Pass: exits immediately with
`error: another vcp process is already running (pid …, pid_file …)` and does
**not** reach `Address already in use` after DB seed / magic-link scheduler
lines.

Fail: compiles and boots until `TcpListener::bind` (or starts a second
instance).

## B -- Bare binary also fail-closes

```bash
./target/debug/vcp
```

Pass: same early error from `process_guard::acquire`, before heavy
`toasty` / `db::connect` work dominates the log.

## C -- Stale PID file is replaced

1. Stop the portal (or `kill` it) so the process exits.
2. If Drop cleanup did not remove the file, leave a dead PID in
   `/tmp/vcp.pid` (or write a known-dead PID).
3. `just run` again.

Pass: starts successfully; PID file rewritten with the new PID.

## D -- Unrelated port holder is not reported as `vcp`

If some other process binds the listen port but `server.pid_file` is absent
(or names a non-`vcp` / dead PID), starting `vcp` must **not** print the
singleton message. Bind may still fail later with `Address already in use`.

Pass: no `another vcp process is already running` unless the PID file names
a live process whose name is exactly `vcp`.
