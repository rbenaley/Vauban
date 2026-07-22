# Runbook -- Eager WORM boot open manual smoke test

> Manual validation checklist after shipping **eager WORM segment open at
> audit boot** in `vauban-audit` (crate **0.9.26+**). Signing-key unseal and
> initial WORM open are **mandatory** (no `VAUBAN_AUDIT_REQUIRED` toggle).
> CI covers the helper and source invariants, but cannot prove that the
> first fail-closed MFA critical on a live FreeBSD deploy no longer waits
> on a supervisor broker open for segment 0.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the 0.9.26 release (and any later change to
> `open_initial_worm_segment`, WORM boot order, or MFA audit HOL budget).
> Do not ship without a full pass of sections A–C; section D is a short
> adjacent regression sweep.

Related architecture:

- Architecture analysis §16.2 (MFA HOL) / §16.3 (gzip off-thread) /
  §16.4 (eager WORM boot)
- Companion runbook:
  [iacs_gzip_offthread_smoke_test.md](iacs_gzip_offthread_smoke_test.md)

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-audit --all-targets -- -D warnings
bash vauban-audit/scripts/check_audit_worm_eager_boot.sh
bash vauban-audit/scripts/check_audit_mfa_hol.sh
bash vauban-audit/scripts/check_audit_worm.sh
rtk cargo test -p vauban-audit -- --test-threads=1
# before hand-off / merge:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

Audit suite highlights that must stay green:

| Layer | Examples |
|-------|----------|
| Invariants + lint | `worm_eager_boot_invariants_test`, `check_audit_worm_eager_boot.sh` |
| Proptest | `worm_eager_boot_proptest` (append without broker) |
| Battle | `worm_eager_boot_battle_test` (silent broker timeout, concurrent drain) |
| E2E (unit) | `test_boot_opens_worm_before_first_event`, `test_boot_open_fails_when_broker_silent` |
| MFA HOL | `mfa_hol_*`, `check_audit_mfa_hol.sh` (Ack before rotate unchanged) |

## Lab prerequisites

- Deployed binaries at **0.9.26+** (at least `vauban-audit`,
  `vauban-supervisor`, `vauban-web`).
- Staging with a provisioned audit signing key
  (`vauban-vault seal-audit-key` / sealed file under `[audit] log_path`)
  and a working vault unseal path.
- A user with MFA enrolled (TOTP).
- Ability to read audit + web logs (filter on `WORM segment`,
  `AuditAck`, `audit ack`, `MfaChallengePassed`).
- Optional: ability to briefly stop / break the supervisor audit-file
  broker only in a **lab** (for fail-closed boot -- section C).

### Boot needles (do this first)

After a clean audit start, logs MUST contain (in order of interest):

```text
Audit signing key unsealed; WORM segments will be Ed25519-sealed
WORM segment opened at boot
```

Then the main loop starts. On disk under the supervisor audit tree,
expect a new append-only segment shaped like
`YYYY/MM/audit-<n>.jsonl` **before** any MFA attempt.

If instead you see either of:

```text
audit signing key could not be unsealed; refusing to start without Ed25519 WORM seals
initial WORM segment could not be opened; refusing to start without durable audit log
```

the audit process must **exit** (fail-closed). Do not ship a build that
continues into `main_loop` without a signing key and WORM FD.

---

## Manual checklist

### A. First MFA after cold boot (primary 0.9.26 proof)

Cold-start the stack (or at least restart `vauban-audit` so segment 0 is
opened on this process lifetime), confirm the boot needles above, then:

| # | Action | Pass | Fail |
|---|--------|------|------|
| A1 | Logout → login → submit **valid** TOTP (first critical after boot) | Dashboard / JWT within ~2–3 s; **no** web `audit emit failed: audit ack timed out` | 500 / timeout ~5 s on first MFA only |
| A2 | Grep audit around A1 | Append + `AuditAck` for MFA; **no** `AuditLogFileRequest` / "failed to open WORM segment" on that event | Broker open still on the first critical path |
| A3 | Repeat MFA login twice more | Same latency as A1 | First OK, later slow (unrelated; still fail if timeout) |

The point of A1 is specifically the **first** critical after audit boot:
that used to pay the broker open; after 0.9.26 it should only pay append
+ fsync + Ack.

### B. Fail-closed MFA contract (0.9.24 still holds)

| # | Action | Pass | Fail |
|---|--------|------|------|
| B1 | Submit a **wrong** TOTP | Domain MFA error (not an audit timeout) | `audit ack timed out` / 500 |
| B2 | Three consecutive valid MFA cycles | All succeed under the web critical budget | Intermittent ACK timeouts |

### C. Fail-closed boot when broker / key cannot open (lab only)

Only on a disposable staging lab:

1. Arrange for the supervisor audit-log broker to refuse / never answer
   **or** remove / break the sealed signing key path.
2. Restart `vauban-audit`.
3. **Pass:** process exits; log contains
   `refusing to start without durable audit log` and/or
   `refusing to start without Ed25519 WORM seals`.
4. **Fail:** process enters `main_loop` without WORM / without seals.

Restore the lab before continuing.

### D. Adjacent regression sweep (~10 min)

| Surface | Quick check |
|---------|-------------|
| IACS ChannelEnd + MFA concurrent | Still OK per [gzip off-thread runbook](iacs_gzip_offthread_smoke_test.md) section C (gzip worker must still start) |
| SSH or RDP session | Connect / disconnect; no audit ACK storms |
| Bastion Watch / sessions list | No 5xx after MFA + session tests |
| WORM segment file | Grows after MFA events; `vauban-audit verify <segment>` OK if you run it |

---

## Stop-ship signals

Abort the release if any of the following appear during the manual pass:

- Missing `WORM segment opened at boot` / signing-key unseal line
- Audit continues running after key or WORM boot failure
- First MFA after cold boot hits `audit ack timed out` (~5 s)
- First MFA audit path still logs WORM segment open failure / broker
  open for segment 0 (eager path skipped)
- Reintroduction of `VAUBAN_AUDIT_REQUIRED` / BestEffort boot continue
- Softening of fail-closed MFA (`emit_audit_critical` fire-and-forget)

---

## Suggested timing (~15–20 min)

| Step | Section | Budget |
|------|---------|--------|
| 1 | Boot needles + segment on disk | ~1 min |
| 2 | A -- first MFA after cold boot | ~5 min |
| 3 | B -- MFA contract | ~3 min |
| 4 | C -- fail-closed boot (lab) | ~5 min (optional if lab allows) |
| 5 | D -- adjacent | ~5 min |

---

## Known-good reference

| Crate / change | Validated on | By |
|----------------|--------------|----|
| 0.9.26 -- eager WORM open + mandatory fail-closed boot | _pending first manual pass_ | _--_ |
