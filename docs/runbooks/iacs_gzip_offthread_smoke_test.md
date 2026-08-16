# Runbook -- IACS gzip off-thread manual smoke test

> Manual validation checklist after shipping **off-thread IACS ChannelEnd
> gzip** in `vauban-audit` (crate **0.9.25+**). CI covers the CPU kernel,
> pending barrier, wakeup pipe, and source invariants, but cannot prove
> that MFA fail-closed WORM acks stay responsive while a large PCAP is
> compressed on a live FreeBSD deploy.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the 0.9.25 release (and any later change to
> `iacs_gzip_worker`, ChannelEnd orchestration, or MFA audit HOL budget).
> Do not ship without a full pass of sections A–D; section E is a short
> adjacent regression sweep.

Related architecture:

- [Recording Architecture 1.8](../technical/Vauban_Recording_Architecture_EN(1.8).md) §5.4
- Architecture analysis §16.2 (MFA HOL) / §16.3 (gzip off-thread)
- [IACS protocol profiles smoke](iacs_protocol_profiles_smoke_test.md)

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-audit --all-targets -- -D warnings
bash vauban-audit/scripts/check_iacs_gzip_offthread.sh
bash vauban-audit/scripts/check_audit_mfa_hol.sh
rtk cargo test -p vauban-audit -- --test-threads=1
# before hand-off / merge:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

Audit suite highlights that must stay green:

| Layer | Examples |
|-------|----------|
| Invariants + lint | `iacs_gzip_offthread_invariants_test`, `check_iacs_gzip_offthread.sh` |
| Proptest | `iacs_gzip_offthread_proptest` (round-trip + pending barrier) |
| Battle | `iacs_gzip_offthread_battle_test` (concurrent drain, wake coalesce) |
| E2E / IPC | `iacs_ipc_test::gzip_roundtrip_*`, `e2e_session_end_waits_for_inflight_gzip` |
| MFA HOL | `mfa_hol_*`, `check_audit_mfa_hol.sh` |

## Lab prerequisites

- Deployed binaries at **0.9.25+** (at least `vauban-audit`,
  `vauban-supervisor`, `vauban-web`, `vauban-proxy-iacs`).
- A user with MFA enrolled and an active IACS access rule.
- An EWS / tunnel client that can open **one** and **two or more**
  `direct-tcpip` channels with real payload.
- Ability to read audit logs (filter on `IACS gzip`, `SessionEnd`,
  `meta.json`, `audit ack`).
- Optional but recommended: a second browser profile for MFA while an
  IACS session is closing.

### Boot needle (do this first)

After audit starts, logs MUST contain:

```text
IACS gzip worker started (CPU off main poll loop)
```

If the worker fails to start, ChannelEnd will drop gzip jobs
(`IACS gzip worker unavailable`) -- abort the release until fixed.

---

## Manual checklist

### A. MFA fail-closed (HOL regression -- 0.9.24 contract)

| # | Action | Pass | Fail |
|---|--------|------|------|
| A1 | Logout → login → submit valid TOTP | Dashboard / JWT within ~2–3 s of submit | HTTP 500, or web log `audit emit failed: audit ack timed out` (~5 s) |
| A2 | Repeat A1 three times in a row | All three succeed | Intermittent timeout |
| A3 | Submit a **wrong** TOTP | Domain MFA error (not an audit timeout) | `audit ack timed out` / 500 |

### B. IACS session + recording (happy-path gzip)

| # | Action | Pass | Fail |
|---|--------|------|------|
| B1 | Open an IACS session; send a short burst of traffic | Tunnel stays up; no premature channel close | Relay / ack timeout closing the channel |
| B2 | Close channels, then end the session | Session terminates cleanly | Session stuck open |
| B3 | Open the recording detail page | Hydrates (`meta.json` / blake3); not stuck on « Awaiting hydration » | Infinite hydrate wait |
| B4 | Download the IACS ZIP | ZIP contains `meta.json` + `channels/NNN.pcap.gz` with Unix mode `0600` (`-rw-------`); gunzip / Wireshark opens the PCAP | Empty ZIP, missing gz, blake3 absent, or extract mode `----------` (0) |
| B5 | Inspect `recording.storage_path` for the session | Only `.pcap.gz` remains (raw `.pcap` unlinked) | Orphan raw `.pcap` after SessionEnd |

Expected audit log shape (logical order): ChannelEnd → broker dst →
enqueue → (main returns to poll) → wakeup → unlink →
`finalize_channel_gzip` → (possibly deferred) `IACS meta.json written successfully`.

Optional needle when SessionEnd races inflight gzip:

```text
Deferring IACS SessionEnd until inflight gzip completes
```

`meta.json` MUST still appear after the deferred barrier clears.

### C. Concurrent MFA during gzip (primary 0.9.25 proof)

This is the scenario sync ChannelEnd gzip could still starve after
0.9.24's timed broker waits.

1. Open an IACS session and transfer enough data to produce a **large**
   raw PCAP (gzip should take multiple seconds on the worker).
2. While channels are closing (or immediately after ChannelEnd), in a
   **second** browser: perform MFA login / `/mfa/verify`.
3. **Pass:** MFA completes inside the web critical budget (&lt; 5 s;
   typically &lt; 2–3 s) **while** gzip is still running.
4. **Fail:** MFA hits `audit ack timed out` / 500 during ChannelEnd.

Also confirm audit keeps draining web AuditEvents (no multi-second
silence on the MFA path while the worker compresses).

### D. Multi-channel SessionEnd barrier

1. Open a session that creates **two or more** `direct-tcpip` channels
   with payload on each.
2. Close both channels, then end the session.
3. **Pass:** one coherent `meta.json` with two `channels` entries; two
   `.pcap.gz` files; ZIP download lists both.
4. If `Deferring IACS SessionEnd…` appears, that is expected; meta MUST
   arrive only after both gzip completions.

### E. Adjacent regression sweep (~5 min)

| Surface | Quick check |
|---------|-------------|
| SSH session + recording | Connect / disconnect; cast hydrates |
| RDP (if a target is available) | Viewer opens; segment finalizes |
| Bastion Watch / sessions list | No 5xx after the IACS runs |
| Notifications WebSocket | No ERROR flood from audit |

---

## Stop-ship signals

Abort the release if any of the following appear during the manual pass:

- `IACS gzip worker unavailable; ChannelEnd dropped`
- `Failed to enqueue IACS gzip CPU job`
- Recurrent `IACS gzip CPU failed; leaving raw PCAP` (isolate disk-full
  once; otherwise fail the build)
- Raw `.pcap` left on disk after SessionEnd with no finalized `.pcap.gz`
- MFA `audit ack timed out`, especially **during** IACS ChannelEnd
- Deferred SessionEnd that never produces `meta.json`

---

## Suggested timing (~20–30 min)

| Step | Section | Budget |
|------|---------|--------|
| 1 | Boot + worker needle | ~30 s |
| 2 | A — MFA ×3 | ~3 min |
| 3 | B — small IACS + download | ~5–8 min |
| 4 | C — large IACS + concurrent MFA | ~8–10 min (**critical**) |
| 5 | D — multi-channel | ~5 min |
| 6 | E — SSH/RDP adjacent | ~5 min |

---

## Known-good reference

| Crate / change | Validated on | By |
|----------------|--------------|----|
| 0.9.25 — IACS gzip off-thread (`iacs_gzip_worker` + SessionEnd barrier) | _pending first manual pass_ | _--_ |
