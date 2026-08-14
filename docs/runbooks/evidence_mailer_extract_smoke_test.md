# Runbook -- Evidence sub-crate + sealed mailer extract smoke test

> Manual validation checklist after shipping **Lots A+B** in crates
> **0.9.28+** (`vauban-web-evidence` + Capsicum `vauban-mailer`,
> architecture §3.2 / §10.13), and the **0.9.36+** Capsicum FD-kind
> fix (mailer `ipc_fds` must not include `fd_passing_socket`). CI covers
> structural lints, discriminant pins, and queue/analyzer wiring; staging
> / production pkg deploy proves Inspect / hydrate / SMTP fail-closed
> end-to-end, including seal without `ConflictingFdRights`.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the **0.9.28** release (new leaf
> `vb-mailer` uid/gid 909, `Service::Mailer=9`, coordinated
> supervisor + web + mailer pkg), **BLOCKING** for **0.9.36+** mailer
> sandbox wiring (staging FreeBSD 2026-08-14 crash-loop), and any later
> change that moves the analyzer, hydrator pipeline, or SMTP drain across
> process boundaries.
> Do not ship without a full pass of sections A–E.

Related architecture:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md) -- leaf Mailer, FD broker, discriminant 9
- [IACS Inspect Capture 1.1](../technical/Vauban_IACS_Inspect_Capture_EN(1.1).md) -- analyzer in `vauban-web-evidence`
- [Recording Architecture 1.8](../technical/Vauban_Recording_Architecture_EN(1.8).md) -- hydrator traits + web adapters
- Architecture analysis §10.13 / §16.6
- Lints: `vauban-web/scripts/check_web_evidence_crate.sh`,
  `vauban-web/scripts/check_mailer_sealed.sh`

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-web-evidence -p vauban-mailer -p vauban-web -p vauban-supervisor -p shared --all-targets -- -D warnings
bash vauban-web/scripts/check_web_evidence_crate.sh
bash vauban-web/scripts/check_mailer_sealed.sh
rtk cargo test -p shared -- sandbox -- --test-threads=1
rtk cargo test -p vauban-web-evidence -p vauban-mailer -p vauban-web -p vauban-supervisor -- evidence_mailer -- --test-threads=1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

Suite highlights that must stay green:

| Layer | Examples |
|-------|----------|
| Invariants + lint | `evidence_mailer_extract_invariants_test`, both `check_*.sh`, `MAILER_KINDS`, `inv_mailer_db_warmup_before_sandbox` |
| Proptest | `evidence_mailer_extract_proptest`, sandbox `mailer_fd_kinds_disjoint_ok_overlap_rejected`, mailer `force_create_count_is_total_on_dead_url` |
| Battle | `evidence_mailer_extract_battle_test`, `battle_mailer_validate_under_contention`, `battle_force_create_dead_url_under_contention` |
| E2E | `evidence_mailer_extract_e2e_test`, `e2e_mailer_sandbox_wiring_staging_regression`, `e2e_mailer_db_warmup_order_staging_regression` |
| Wire | `Service::Mailer.as_token_discriminant() == 9` |

## Lab prerequisites

- Deployed binaries at **0.9.36+** with **coordinated** supervisor +
  web + mailer (`Service::Mailer` discriminant 9, `MailerSmtpProvision`,
  mailer seal with `ipc_fds` = read/write only and `fd_receiver` =
  `fd_passing_socket`).
- Production pkg: `pw usershow vb-mailer` shows UID/GID **909**;
  `[services.mailer]` in `/usr/local/etc/vauban/vauban.conf` has
  `uid = 909` / `gid = 909`; binary at
  `/usr/local/libexec/vauban/vauban-mailer`.
- `[mailer]` enabled with allowlisted `smtp_host` / `smtp_port` and
  `VAUBAN_SMTP_PASSWORD` injected (cleared from environ after read).
- IACS (or SSH/RDP) asset with recording enabled; JIT rule for mail
  approve/reject path.
- Ability to read **vauban-mailer** logs (not web) for STARTTLS/DATA.

## A -- Inspect (evidence analyzer)

1. Open a recorded IACS session that has at least one channel PCAP.
2. As admin, open **Inspect Capture** list then packet detail.
3. Confirm packets/dissection render; process tree shows analysis
   via `vauban-web-evidence` (web has no `etherparse` / no local
   `services/iacs_packet_analyzer/` tree).

Pass: Inspect UI works; no regression vs pre-extract analyzer.

## B -- Hydrate (evidence pipeline + web adapters)

1. End a recorded session (SSH/RDP/IACS) so `meta.json` is available.
2. Wait for bootstrap/cron hydrator (or trigger via lab hook).
3. Confirm integrity columns populated and Recording Details shows
   hydrated state (retry WS/poll if first paint races).

Pass: hydrate completes; WS `recording_hydrated` still updates UI.

## C -- Mail (sealed mailer drain)

1. Approve or reject a JIT access request that queues email.
2. Confirm `email_outbox` row moves `pending` -> `sent` (or retrying
   then sent).
3. In **vauban-mailer** logs, expect SMTP dialogue (EHLO / STARTTLS /
   AUTH / DATA). Web must **not** log SMTP session open.

Pass: mail delivered (or accepted by lab relay); drain is mailer-only.

## C' -- Capsicum seal (0.9.36+ / staging FreeBSD regression)

Regression: before 0.9.36, mailer listed `fd_passing_socket` in both
`ipc_fds` and `fd_receiver_fds`, so `enter_sandbox` failed with
`ConflictingFdRights` / `declared under two sandbox resource kinds
(IpcPipe and FdReceiver)` and the supervisor respawn-stormed.

1. Start (or restart) the coordinated stack with `[mailer] enabled = true`.
2. In **vauban-mailer** logs, confirm provision then seal / main-loop
   progress (no immediate exit 1).
3. Confirm logs do **not** contain `ConflictingFdRights`,
   `declared under two sandbox resource kinds`, or a tight respawn
   loop (`Respawning mailer` every ~100 ms).
4. Confirm supervisor does not warn `mailer exited with code 1` in a
   burst after boot.

Pass: mailer stays up after `Mailer SMTP runtime provisioned`; SMTP
drain (section C) can proceed.

## C'' -- DB pool pre-open (0.9.36 second mailer lot)

Regression: after the FD-kind seal fix, mailer built the deadpool
*after* `cap_enter()`, so every 10 s tick logged
`DB pool error: error connecting to server` while Postgres was up.

1. With Postgres reachable, restart the stack (`[mailer] enabled = true`).
2. In **vauban-mailer** logs, after `Mailer SMTP runtime provisioned`,
   expect `Database pool ready (2 connections pre-established)` **before**
   any drain line.
3. Confirm there is **no** burst of `error connecting to server` on
   every poll tick.
4. Optional: stop Postgres and restart mailer -- expect **exit 1 /
   supervisor respawn** at boot (warm-up fail), not a live process
   looping drain errors every 10 s.

Pass: warm-up precedes seal; drain can talk to the pre-opened sockets.

## D -- Fail-closed

1. Point `[mailer].smtp_host` at a host **not** in the supervisor
   whitelist (or use a non-allowlisted port) and restart mailer /
   supervisor as required.
2. Queue another notification; expect supervisor deny on
   `TcpConnectRequest` with `target_service: Mailer`; outbox stays
   pending/retrying.
3. Stop `vauban-mailer`; queue again -- row remains pending; web
   cannot call `request_smtp_connect` (symbol absent).

Pass: whitelist deny + mailer-down leave outbox durable; web has no
SMTP FD path.

## E -- Full pass gate

Sections A–D, C' and C'' must all Pass before declaring the deploy good.

## Rollback notes

- Mixed versions without `Service::Mailer=9` / `MailerSmtpProvision`
  fail mailer boot or SMTP broker.
- Pre-0.9.36 mailer binaries reintroduce the Capsicum FD double-declare
  crash-loop on FreeBSD; do not mix with a supervisor that keeps
  respawning forever.
- Re-enabling an in-web SMTP dispatcher is forbidden by
  `check_mailer_sealed.sh`.
