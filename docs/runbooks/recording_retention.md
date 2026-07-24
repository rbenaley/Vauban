# Runbook -- Recording retention reaper

> Daily background task in `vauban-web` that deletes aged or
> quota-exceeded session recordings (RDP + SSH) from disk via supervisor
> IPC and clears recording metadata in `proxy_sessions`.
>
> Configuration is **TOML-only** (`[recording].retention_*` in
> `vauban.conf`). There is no web UI or API to change retention knobs.
>
> Audience: on-call operators, storage owners.
> Severity: LOW for routine daily passes with `age_reaped=0`;
> MEDIUM when disk usage grows despite `retention_max_size_gib`;
> HIGH if DB/disque diverge (recordings listed but files missing, or vice versa).

## Model at a glance

```
BOOTSTRAP: vauban-web boot -> one-shot scan -> delete aged / quota backlog   (immediate)
SAFETY:    daily cron at configured local hour -> bootstrap re-run             (24h max)
```

Each bootstrap run loops in batches of `retention_batch_size` until no
candidates remain. Two independent triggers per tick:

1. **Age** -- delete when `disconnected_at < now - retention_days` (default 365).
2. **Quota** -- when `retention_max_size_gib > 0` and total finalized
   `recording_size_bytes` exceeds the cap, delete oldest recordings
   (FIFO by `disconnected_at`) even if younger than `retention_days`.

Live sessions (`active`, `connecting`, `approved`, `pending`) are never
candidates.

### BOOTSTRAP path (one-shot at boot)

`tasks::recording_reaper::run_bootstrap_retention` runs once at
`vauban-web` boot (when `retention_enabled` and a supervisor is
available). It loops until the candidate index is empty, then emits a
`bootstrap_complete { passes, age_reaped, quota_reaped, ... }` log line.

In nominal operation (nothing to delete) this completes in milliseconds.

### SAFETY path (daily cron)

`start_recording_retention` schedules a once-a-day re-run of
`run_bootstrap_retention` via `shared::tasks::spawn_periodic` at
`retention_daily_cron_hour` (default 05:00 in
`recording_daily_cron_timezone`, one hour after the hydrator safety
cron). Mops up backlog if the boot bootstrap was missed or new
candidates appeared since the last pass.

## Configuration (`[recording]`)

| Key | Default | Meaning |
|-----|---------|---------|
| `recording_daily_cron_timezone` | `Europe/Brussels` | IANA timezone for hydrator + reaper SAFETY crons |
| `hydration_daily_cron_hour` | `4` | Local hour for hydrator SAFETY cron |
| `retention_daily_cron_hour` | `5` | Local hour for retention SAFETY cron (must be > hydrator hour) |
| `retention_enabled` | `true` | Kill-switch |
| `retention_days` | `365` | Max age in days |
| `retention_max_size_gib` | `0` | `0` = unlimited quota |
| `retention_batch_size` | `50` | Max deletions per tick (bootstrap loops until empty) |

Requires a live supervisor (`SupervisorClient`) for disk delete. Without
supervisor (some dev setups), retention is skipped at boot with an info log.

## Logs to grep

```text
task=recording_reaper bootstrap_started
task=recording_reaper bootstrap_complete age_reaped=... quota_reaped=... bytes_freed=...
task=recording_reaper recording reaped pass=age|quota session_uuid=...
Recording deleted from storage   # supervisor
```

Failures:

```text
task=recording_reaper bootstrap tick failed
task=recording_reaper reap_one failed
Failed to delete recording from storage
```

## DB / disk consistency

Post-reap, the `proxy_sessions` row remains (session audit trail) but:

- `is_recorded = false`
- `recording_path = NULL`
- all `recording_*` integrity columns = NULL

Recording list/detail/download endpoints filter on `is_recorded AND recording_path IS NOT NULL`, so reaped sessions disappear from the UI (404 anti-enumeration on detail).

### Manual recovery

**Disk gone, DB stale (orphan metadata):**

1. Confirm file missing under `storage_path`.
2. Either wait for the next bootstrap or daily pass (supervisor returns success with `bytes_freed=0` on ENOENT) or manually UPDATE the row to clear recording columns **exactly like the reaper** -- including `is_recorded = false`. Omitting that flag leaves rows counted as HYDRATING on the Bastion Watch dashboard (`is_recorded = true`, `recording_path IS NULL`, `recording_finalized_at IS NULL`) even though nothing remains to hydrate or reap.

   ```sql
   UPDATE proxy_sessions
   SET is_recorded = false,
       recording_path = NULL,
       recording_blake3 = NULL,
       recording_size_bytes = NULL,
       recording_duration_ms = NULL,
       recording_event_count = NULL,
       recording_format = NULL,
       recording_width = NULL,
       recording_height = NULL,
       recording_segment_count = NULL,
       recording_codec = NULL,
       recording_finalized_at = NULL
   WHERE uuid = '<session-uuid>';
   ```

**Disk remains, DB cleared:**

1. Safe to delete the orphan directory/file manually as root under `storage_path`.
2. No UI reference remains.

## Related documents

- [Recording Architecture v1.7 -- Retention (§11) + Appendix B](../technical/Vauban_Recording_Architecture_EN(1.8).md#11-retention)
- [Recording hydrator runbook](recording_hydrator.md) (runs one hour earlier by default)
- [Rust 1.93 hygiene smoke test](rust_193_hygiene_smoke_test.md) (legacy `.mp4.blake3` sidecar delete)
