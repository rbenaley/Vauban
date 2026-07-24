# Runbook -- Correlated IPC align (RbacClient / SupervisorClient) smoke test

> Manual validation checklist after shipping **CorrelatedIpc alignment** in
> crates **0.9.31+**: `CorrelatedIpcCore` lives in `shared::correlated_ipc`;
> proxy `AccessGuard::RbacClient` drains via AsyncFd `try_io` /
> `PendingGuard`; `SupervisorClient` keeps its sync `poll` + SCM_RIGHTS
> thread but RAII-GCs its three pending maps. CI covers invariants,
> proptest, battle, and E2E source pins, but cannot prove live FreeBSD
> supervisor / AccessGuard behaviour under real Capsicum.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the **0.9.31** release and any later change
> that reintroduces `clear_ready` in `access_guard` or drops
> `PendingGuard` / `insert_pending` from SupervisorClient request paths.
> Do not ship without a full pass of sections A–D.

Related architecture:

- Architecture analysis §13 / remaining-open (CorrelatedIpc client alignment)
- Lint: `vauban-web/scripts/check_ipc_correlated_core.sh`
- Lint: `vauban-web/scripts/check_supervisor_ipc_pending_guard.sh`
- Core: `shared/src/correlated_ipc.rs`

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-web --all-targets -- -D warnings
bash vauban-web/scripts/check_ipc_correlated_core.sh
bash vauban-web/scripts/check_supervisor_ipc_pending_guard.sh
rtk cargo test -p shared -p vauban-web -- correlated -- --test-threads=1
rtk cargo test -p shared --features access-guard -- access_guard -- --test-threads=1
# before hand-off / merge:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

Suite highlights that must stay green:

| Layer | Examples |
|-------|----------|
| Invariants + lint | `correlated_ipc_align_invariants_test`, both `check_*.sh` |
| Proptest | `correlated_ipc_align_proptest`, `correlated_proptest` |
| Battle | `correlated_ipc_align_battle_test`, `battle_*_send_fail_clears_pending` (supervisor unit) |
| E2E | `correlated_ipc_align_e2e_test`, existing connect / access suites |

## Lab prerequisites

- Deployed binaries at **0.9.31+** (web + access + supervisor + proxies
  coordinated; no mixed CorrelatedIpc / AccessGuard layouts).
- Staging user with matching SSH and RDP access rules; pinned SSH host
  key and RDP server cert assets.
- Ability to read **vauban-web** logs (`supervisor-ipc`, AccessGuard /
  `CheckAccessByUuid`) and **vauban-access** logs.

## A -- Happy path AccessGuard

1. As a user with an active rule **without** `require_approval`, open
   an SSH session until the terminal loads (or until proxy open succeeds).
2. Repeat for RDP.
3. In access / proxy logs for each open, expect **one**
   `CheckAccessByUuid` (AccessGuard) after SessionOpen; no panic; no
   unexplained ~10 s hang on authorize.
4. Session remains usable (keystrokes / RDP input).

Pass: session opens (or fails only for unrelated proxy/target reasons)
and AccessGuard completes without pending-map growth symptoms.

## B -- Supervisor TCP connect

1. Perform a connect that exercises `request_tcp_connect` (normal SSH/RDP
   open path through the supervisor broker).
2. Expect success or a clear business error (DNS / refused), not a web
   deadlock.
3. After idle, confirm logs do not show unbounded growth of orphan
   pending TCP request_ids (no repeated "No pending request for TCP
   connect response" storms after a quiet period).

Pass: connect path healthy; no pending leak signal in steady state.

## C -- Recording hydrate / delete

1. Open a session that was recorded; open the recording viewer (hydrator
   `request_recording_file` + SCM_RIGHTS FD).
2. If admin delete is available, delete a recording (`request_recording_delete`).
3. Briefly stop / block supervisor IPC (or restart supervisor), trigger a
   hydrate or delete, expect a **clean UI/API error** (timeout / IPC),
   **not** a wedged `vauban-web` process.
4. Restart supervisor; next hydrate/delete succeeds.

Pass: FD path works when supervisor is up; fail-closed when down; recovery OK.

## D -- Adjacent regressions

1. MFA login still fail-closed (WORM Ack / HOL budget unchanged).
2. Supervisor Ping / heartbeat still healthy after the smoke.
3. No regression of Kerberos KDC FD-pass or proxy-owned SSH/RDP FD
   recording (already shipped 0.9.29 / 0.9.30).

## What not to re-litigate

- Do not rewrite `SupervisorClient` onto AsyncFd `process_loop`.
- Do not remove AccessGuard to "save" a policy eval.
- Do not merge the three supervisor pending maps into one generic map
  (SCM_RIGHTS / response types differ).
- Do not reintroduce `clear_ready` in `shared::access_guard`.
