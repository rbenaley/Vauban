# Runbook -- Rust 1.93 hygiene smoke test

> Manual staging validation after shipping **MSRV 1.93** and the
> std-API hygiene lot (`Path::with_added_extension` for legacy RDP
> BLAKE3 sidecars, `Duration::from_hours`, `VecDeque::pop_front_if` on
> the session-token replay cache, DashMap collect-then-remove GC for
> rate-limit / pending MFA).
>
> Audience: release / staging operators.
> Severity: **LOW--MEDIUM**. Not release-blocking unless retention
> delete, session-token replay, or rate-limit / MFA enrolment regress.

Related:

- [Recording Architecture 1.9](../technical/Vauban_Recording_Architecture_EN(1.9).md)
  (legacy flat `.mp4.blake3` layout + `with_added_extension`)
- [Recording retention runbook](recording_retention.md)
- [IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md)
  (session-token / replay)
- Plan: `.cursor/plans/hygiène_rust_1.93_d43b9011.plan.md`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-web -p vauban-mailer -p vauban-supervisor \
  --all-targets -- -D warnings
# session-token unit / proptest / battle (feature-gated on shared)
rtk cargo test -p shared --features session-token -- replay_cache -- --test-threads=1
rtk cargo test -p shared -- recording_blake3 -- --test-threads=1
rtk cargo test -p shared -- recording_paths -- --test-threads=1
rtk cargo test -p vauban-web -- \
  cleanup_expired|pending_mfa|rate_limit|recording_retention|legacy_flat_rdp \
  -- --test-threads=1
rtk cargo test -p vauban-mailer -- backoff_cap -- --test-threads=1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target \
  -- --test-threads=1
```

## Lab prerequisites

- Binaries built with Rust **>= 1.93** (MSRV).
- Staging appliance with recording enabled and an aged / reaped path
  available (or ability to plant files under `recordings/`).
- Ability to open SSH or RDP and read proxy / supervisor logs.

## A -- Legacy RDP sidecar delete

1. Under the configured recording `storage_path`, plant a legacy flat
   pair (use a disposable UUID):

   ```text
   recordings/YYYY/MM/<uuid>.mp4
   recordings/YYYY/MM/<uuid>.mp4.blake3
   ```

2. Trigger retention delete for that session (bootstrap reaper, or
   supervisor `RecordingDeleteRequest` via the same relative path the
   DB would store: `YYYY/MM/<uuid>.mp4`).
3. Confirm **both** files are gone and bytes-freed logging (if enabled)
   accounts for the sidecar.
4. Confirm a media-only plant (no sidecar) still deletes cleanly.

Pass: sidecar resolved via `with_added_extension("blake3")`; no leftover
`.mp4.blake3`.

## B -- Session token replay

1. Open a short SSH or RDP session (nominal connect OK).
2. Capture / re-present the same session token on a second
   `TcpConnectRequest` within the 30 s TTL (lab tooling or proxy
   harness). Expect **reject** (anti-replay).
3. After the TTL window (or lab backdate), a fresh mint must succeed.

Pass: replay rejected in-window; IACS multi-channel bypass unchanged
(see supervisor pin tests). Automated coverage:
`test_supervisor_tcp_broker_records_replay` + shared `replay_cache`
TTL / battle tests.

## C -- Rate limit + MFA pending sweep

1. Burst session-open (or login) until the in-memory limiter returns
   **429** / deny for the scoped key.
2. Start MFA enrollment, abandon mid-flow (candidate left in
   `PendingMfaStore`), wait past TTL (15 min) or force a sweep in lab.
3. Confirm the stale candidate cannot confirm enrollment and memory
   does not grow unbounded across repeated abandons.

Pass: limiter still in-process only (no Redis); abandoned MFA
candidates do not linger after sweep. Automated:
`session_creation_limits_test`, `mfa_setup_vau008_test`, unit/battle
in `rate_limit.rs` / `pending_mfa.rs`.

## Rollback notes

- Reverting only the sidecar path to `with_extension("mp4.blake3")` +
  `format!("{}.blake3")` reintroduces the dual-path workaround and
  fails the source-pin invariant.
- Do not lower `rust-version` below **1.93** without removing
  `with_added_extension` / `pop_front_if` / `Duration::from_hours`
  call sites.
