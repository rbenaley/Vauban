# Runbook -- sealed mailer graceful Shutdown smoke test

> Manual validation after shipping the **mailer idle-wait IPC wake**
> (crates **0.9.38+**): `vauban-mailer` must honor supervisor
> `ControlMessage::Shutdown` during the outbox poll sleep and during an
> SMTP broker wait, instead of waiting out `poll_interval_secs` and
> being `SIGTERM`/`SIGKILL`'d.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for any change to the mailer dispatcher or
> `answer_control` path. Do not ship without A–C.

Related:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md) -- leaf Mailer, no `TOPOLOGY` edges
- [evidence_mailer_extract_smoke_test.md](evidence_mailer_extract_smoke_test.md)
- Lint: `vauban-web/scripts/check_mailer_sealed.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-mailer -p vauban-supervisor -p shared --all-targets -- -D warnings
bash vauban-web/scripts/check_mailer_sealed.sh
rtk cargo test -p vauban-mailer -- shutdown -- --test-threads=1
rtk cargo test -p vauban-web -- inv_mailer_shutdown -- --test-threads=1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

## Lab prerequisites

- Coordinated binaries with `[mailer] enabled = true` (mailer spawned).
- Ability to read **vauban-supervisor** and **vauban-mailer** logs.
- A quiet window (no pending outbox drain required for A).

## A -- Idle Ctrl+C

1. Start the stack; wait until mailer logs `Mailer SMTP runtime provisioned`
   and `Database pool ready`.
2. Confirm mailer is between drain ticks (no SMTP dialogue in the last
   few seconds).
3. Send SIGINT to the supervisor (Ctrl+C in the console).
4. Expect mailer to log `Shutdown requested, setting graceful shutdown flag`
   then `Mailer dispatcher shutting down` / `vauban-mailer exiting normally`
   in the same ~100–500 ms window as `auth` / `vault` / `web`.
5. Supervisor must log `mailer: Exited with code 0`.
6. Supervisor must **not** log `mailer: Still running after timeout, sending SIGTERM`
   nor `mailer: Still running, sending SIGKILL`.

Pass: mailer exits 0 with the other leaves; no 5 s + 1 s SIGKILL path.

## B -- Shutdown during a broker wait

1. Point `[mailer]` at a sink that accepts TCP slowly (or drop the
   relay after connect so `TcpConnectRequest` hangs toward
   `broker_timeout_secs`).
2. Queue one notification so mailer enters `request_smtp_connect`.
3. Ctrl+C the supervisor while the broker wait is outstanding.
4. Expect the same clean Shutdown logs as A, **not** a wait of
   `broker_timeout_secs` (often 30 s) followed by SIGKILL.

Pass: broker wait aborts on `Shutdown`; process exits 0.

## C -- Heartbeat still answered

1. Leave the stack idle for at least two supervisor heartbeat
   intervals with mailer up.
2. Confirm supervisor does **not** mark mailer unresponsive / respawn
   it (`Respawning mailer`).
3. Ctrl+C; same Pass criteria as A.

Pass: Ping during the idle `select!` still gets a Pong; Shutdown still
wakes immediately.

## Rollback notes

- Reverting to a `sleep_until(poll_interval)` without `select!` brings
  back the 5 s supervisor timeout + SIGKILL on Ctrl+C.
- Swallowing `ControlMessage::Shutdown` in `answer_control` makes a
  mid-broker Ctrl+C wait out `broker_timeout_secs`.
