# Runbook -- Recording integrity hydrator

> Event-driven background pipeline introduced in v1.3 of the recording
> architecture. Hydrates `proxy_sessions.recording_blake3` and the
> nine sibling integrity columns from on-disk `meta.json` files via
> the supervisor's existing SCM_RIGHTS plumbing.
>
> Audience: on-call operators, recording-pipeline owners.
> Severity: LOW for routine "pending finalization" toasts on the
> Recording Details page (transient, < `hydration_enqueue_delay_secs`);
> MEDIUM if a single session stays unfinalized for more than 5 minutes;
> HIGH if the table-wide pending count grows monotonically.

## Hydration model at a glance

```
PRIMARY:   session ends -> enqueue_hydration -> sleep 5s -> finalize  (~5s latency)
BOOTSTRAP: vauban-web boot -> one-shot scan -> finalize all backlog   (one-time)
SAFETY:    daily cron at 04:00 UTC -> bootstrap re-run                (24h max)
```

In nominal operation the **PRIMARY** path is the one that finalizes
every recording. **BOOTSTRAP** rattrape any backlog left over by a
downtime or by legacy recordings produced before the integrity columns
existed. The **SAFETY** cron is a 24h fallback that only does real
work when the PRIMARY path was bypassed (vauban-web crash, missing
call-site, audit flush race past `hydration_missing_meta_grace_secs`).

## Background

The Recording Details page (`/sessions/recordings/{uuid}`) reads
ten integrity columns directly from `proxy_sessions`. Those columns
are populated by the recording hydrator pipeline in `vauban-web`,
not by `vauban-audit` or the supervisor.

### PRIMARY path (per session end, ~5 s latency)

`services::recording_hydrator::enqueue_hydration(state, session_id, grace)`
is called immediately after every UPDATE that sets `disconnected_at`
on a `proxy_sessions` row. The helper:

1. Short-circuits if `state.supervisor` is `None` (development mode)
   or if `recording.hydration_enabled = false`.
2. `tokio::spawn`s a detached task that `sleep(grace)` then
   `RecordingHydrator::hydrate_session_id(id)`.
3. `hydrate_session_id` SELECTs the row by id (gated by `is_recorded
   = true AND recording_path IS NOT NULL AND recording_finalized_at
   IS NULL`), requests `meta.json` from the supervisor, parses, and
   UPDATEs the integrity columns -- all idempotent under concurrent
   enqueues.

Call-sites instrumented (issue #29, source-level pinned):

- `handlers/websocket.rs` -- 4 sites (SSH/RDP, recording on/off)
- `handlers/api/sessions.rs::terminate` -- 2 sites
- `handlers/web/assets.rs` -- 1 site (asset deletion cascades to active sessions)
- `handlers/web/users.rs::delete_user` -- 2 sites
- `tasks/cleanup.rs` -- 2 sites (`terminate_expired_proxy_sessions`,
  `disconnect_stale_active_sessions`). NOT instrumented:
  `expire_stale_connecting_sessions` (sessions that never connected
  have no recording on disk to hydrate).

### BOOTSTRAP path (one-shot at boot)

`tasks::recording_hydrator::run_bootstrap_hydration` runs once at
`vauban-web` boot. It loops over the partial index
`idx_proxy_sessions_pending_finalization` in batches of
`hydration_batch_size` until the candidate set is empty (only
`skipped_missing_meta` rows remain), then exits with a single
`bootstrap_complete { passes, finalized, ..., elapsed_ms }` log line.

### SAFETY path (daily cron, 04:00 UTC)

`tasks::recording_hydrator::start_daily_reconciliation` schedules a
once-a-day re-run of `run_bootstrap_hydration` via
`shared::tasks::spawn_periodic` (period = 86 400 s). The first
firing window is the next `hydration_daily_cron_hour_utc:00` UTC.

In nominal operation this logs `bootstrap_complete { hydrated=0 }`
and exits in milliseconds. See "Verifier qu'une session vient d'etre
hydratee" below for the observable signature of a healthy run.

## Verifier qu'une session vient d'etre hydratee

The PRIMARY path leaves a deterministic log signature within
`hydration_enqueue_delay_secs + few_seconds` of the session ending:

```text
DEBUG enqueue_hydration: scheduled session_id=42 grace_secs=5
INFO  hydration_finalized: integrity bundle persisted session_uuid=...
```

To verify a specific session was hydrated, search the last few
minutes of the `vauban-web` logs for the session UUID, looking for
the `enqueue_hydration` line followed by `hydration_finalized`. If
only `enqueue_hydration` shows up, either the grace has not yet
elapsed or the bundle hit `MissingMeta` (the next bootstrap or daily
cron will retry). If neither shows up, the call-site for that
endpoint is missing the enqueue -- this should never happen because
the source-level CI pin would have failed the build.

## Forcer une hydratation manuelle

Two options, depending on urgency:

### Option 1 -- via SQL + bootstrap or cron

Reset the row so it becomes a candidate again:

```sql
UPDATE proxy_sessions
   SET recording_finalized_at = NULL,
       recording_blake3       = NULL,
       recording_size_bytes   = NULL,
       recording_duration_ms  = NULL,
       recording_event_count  = NULL,
       recording_format       = NULL,
       recording_width        = NULL,
       recording_height       = NULL,
       recording_segment_count = NULL,
       recording_codec        = NULL
 WHERE uuid = '<uuid>';
```

Then either:
- restart `vauban-web` to trigger the BOOTSTRAP path (immediate);
- or wait for the next 04:00 UTC cron (up to 24h).

### Option 2 -- via API terminate (idempotent)

If the session is still in `active`/`connecting` state, the
`POST /api/v1/sessions/<uuid>/terminate` endpoint will both
transition it AND issue a fresh `enqueue_hydration` (latency = 5s).

## Le cron quotidien n'a pas tourne

Diagnostic procedure:

1. Search the logs for the most recent
   `daily_reconciliation scheduled at next ...` line. There MUST be
   one within the last 24 h plus the boot delay.
2. Search for `bootstrap_complete` lines emitted by the cron.
   Expected: exactly one per 24 h period after boot.
3. If neither line appears for > 25 h, suspect a tokio runtime
   stall or a `vauban-web` restart that never re-armed the cron
   (this should be impossible -- the cron is spawned during the
   normal boot sequence -- but worth confirming with `pgrep
   vauban-web` and the boot timestamp).
4. As a workaround, restart `vauban-web` to force the BOOTSTRAP
   path which will rattrape whatever the cron should have caught.

## Symptomes d'un enqueue rate

If a session ended hours ago but its integrity bundle is still
NULL, the PRIMARY path was bypassed. Find the offenders:

```sql
SELECT uuid, disconnected_at, recording_path, session_type
  FROM proxy_sessions
 WHERE is_recorded = TRUE
   AND recording_path IS NOT NULL
   AND recording_finalized_at IS NULL
   AND disconnected_at IS NOT NULL
   AND disconnected_at < now() - INTERVAL '1 hour'
 ORDER BY disconnected_at ASC;
```

If this query returns rows, the SAFETY cron will eventually
reconcile them (up to 24h delay). If it returns the same rows for
multiple consecutive days, the PRIMARY path is broken for one or
more call-sites and the source-level CI pin in
`vauban-web/tests/services/recording_hydrator_test.rs` should be
re-run on the offending file.

## Symptomes / triggers (legacy table preserved)

| Symptom | Likely cause | Severity |
|---|---|---|
| Recording Details page shows "Integrity metadata pending finalization" briefly after a session ends | Normal: PRIMARY enqueue's grace period (~5s) | LOW |
| Same session stuck on "pending finalization" > 5 min | `meta.json` missing on disk OR supervisor down OR enqueue lost | MEDIUM |
| Page shows "Integrity metadata unavailable for this recording" | Hydrator parsed and finalized but JSON was malformed (or marked-lost past grace) | MEDIUM |
| Pending count grows monotonically across many recordings | Supervisor unreachable, disk pressure on the recordings volume, or PRIMARY enqueue silently broken across many call-sites | HIGH |
| Boot log contains "recording hydrator disabled by config" but operator expected it enabled | Config typo or env override | LOW |
| Logs show "skipped: no supervisor" repeatedly | Development mode without `vauban-supervisor`; expected outside production | LOW |

## Useful queries

### Count of unfinalized recordings (relies on the partial index)

```sql
SELECT COUNT(*)
  FROM proxy_sessions
 WHERE is_recorded = TRUE
   AND recording_path IS NOT NULL
   AND recording_finalized_at IS NULL;
```

`EXPLAIN` should show
`Index Scan using idx_proxy_sessions_pending_finalization`. If it
falls back to a sequential scan, the index has been dropped or the
predicate has drifted -- compare against migration
`20260430000000_recording_integrity_metadata`.

### Oldest unfinalized recording

```sql
SELECT uuid, created_at, disconnected_at, recording_path, session_type
  FROM proxy_sessions
 WHERE is_recorded = TRUE
   AND recording_path IS NOT NULL
   AND recording_finalized_at IS NULL
 ORDER BY created_at ASC
 LIMIT 20;
```

If `created_at` is older than a few hours, suspect a missing or
unreadable `meta.json`. Cross-check with
`SELECT recording_path FROM proxy_sessions WHERE uuid = '<uuid>';`
then verify the file exists on disk under the supervisor's recording
root.

### Recordings with corrupt or lost meta (parsed but no integrity)

```sql
SELECT uuid, recording_path, recording_finalized_at
  FROM proxy_sessions
 WHERE recording_finalized_at IS NOT NULL
   AND recording_blake3 IS NULL
   AND is_recorded = TRUE
   AND recording_path IS NOT NULL;
```

Each row here is a recording the hydrator gave up on (corrupt JSON,
or missing-meta-past-grace). Inspect the on-disk `meta.json` and
re-run hydration manually after fixing it (see "Forcer une
hydratation manuelle" above).

### Distribution per format

```sql
SELECT recording_format, COUNT(*)
  FROM proxy_sessions
 WHERE recording_finalized_at IS NOT NULL
 GROUP BY recording_format;
```

Anything outside (`asciicast-v2`, `fmp4-dash`, `fmp4-flat`) would have
been rejected by the `recording_format_enum` CHECK constraint, so a
non-empty NULL bucket here is corrupt-meta or lost-recording
territory.

## Configuration knobs

All under the `recording.*` prefix:

| Key | Default | Effect |
|---|---|---|
| `hydration_enabled` | `true` | Spawn the bootstrap + per-call-site enqueue + daily cron at boot |
| `hydration_batch_size` | `50` | Max rows per bootstrap/cron pass |
| `hydration_missing_meta_grace_secs` | `300` | After this delay, missing `meta.json` flips from "retry" to "marked lost" |
| `hydration_enqueue_delay_secs` | `5` | PRIMARY grace between `UPDATE disconnected_at` and the actual hydrate call |
| `hydration_daily_cron_hour_utc` | `4` | UTC hour (0..=23) at which the SAFETY reconciliation runs |

## Related references

- [Recording Architecture v1.3 -- "Hydration model"](../technical/Vauban_Recording_Architecture_EN(1.3).md)
- Migration: `vauban-db/migrations/20260430000000_recording_integrity_metadata`
- Source (pipeline): `vauban-web/src/services/recording_hydrator.rs`
- Source (scheduler): `vauban-web/src/tasks/recording_hydrator.rs`
- Tests: `vauban-web/tests/services/recording_hydrator_test.rs`
