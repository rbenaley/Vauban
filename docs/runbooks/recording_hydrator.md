# Runbook -- Recording integrity hydrator

> Lazy background tokio task introduced in v1.3 of the recording
> architecture. Hydrates `proxy_sessions.recording_blake3` and the
> nine sibling integrity columns from on-disk `meta.json` files via
> the supervisor's existing SCM_RIGHTS plumbing.
>
> Audience: on-call operators, recording-pipeline owners.
> Severity: LOW for routine "pending finalization" toasts on the
> Recording Details page (transient, < 1 tick); MEDIUM if a single
> session stays unfinalized for more than 5 minutes; HIGH if the
> table-wide pending count grows monotonically.

## Background

The Recording Details page (`/sessions/recordings/{uuid}`) reads
ten integrity columns directly from `proxy_sessions`. Those columns
are populated by the `recording_hydrator` background task in
`vauban-web`, not by `vauban-audit` or the supervisor. The hydrator:

1. Selects up to `recording.hydration_batch_size` rows (default 50)
   matching the partial index
   `idx_proxy_sessions_pending_finalization`:

   ```sql
   WHERE is_recorded = TRUE
     AND recording_path IS NOT NULL
     AND recording_finalized_at IS NULL
   ```

2. For each row, requests `meta.json` from the supervisor over the
   pre-existing `RecordingFileRequest` IPC verb (FD passing). No
   special privilege beyond what `serve_manifest` already needs.
3. Parses the JSON into an `IntegrityBundle`. RDP additionally
   aggregates per-segment hashes to expose a single
   `recording_blake3` column with the same semantics as SSH.
4. UPDATEs the row inside a `WHERE recording_finalized_at IS NULL`
   guard (idempotent under concurrent ticks).

Tick interval is `recording.hydration_interval_secs` (default 30 s).
Hydration can be disabled at boot via `recording.hydration_enabled =
false`; the task is then never spawned.

## Symptoms / triggers

| Symptom | Likely cause | Severity |
|---|---|---|
| Recording Details page shows "Integrity metadata pending finalization" briefly after a session ends | Normal: row landed before next tick | LOW |
| Same session stuck on "pending finalization" > 5 min | `meta.json` missing on disk OR supervisor down OR hydrator panicked | MEDIUM |
| Page shows "Integrity metadata unavailable for this recording" | Hydrator parsed and finalized but JSON was malformed | MEDIUM |
| Pending count grows monotonically across many recordings | Hydrator loop crashed; or supervisor is unreachable; or disk pressure on the recordings volume | HIGH |
| Boot log contains "recording hydrator disabled by configuration" but operator expected it enabled | Config typo or env override | LOW |

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
SELECT uuid, created_at, ended_at, recording_path, session_type
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

### Recordings with corrupt meta (parsed but no integrity)

```sql
SELECT uuid, recording_path, recording_finalized_at
  FROM proxy_sessions
 WHERE recording_finalized_at IS NOT NULL
   AND recording_blake3 IS NULL
   AND is_recorded = TRUE
   AND recording_path IS NOT NULL;
```

Each row here is a recording the hydrator gave up on. Inspect the
on-disk `meta.json` and re-run hydration manually after fixing it
(see *Recovery* below).

### Distribution per format

```sql
SELECT recording_format, COUNT(*)
  FROM proxy_sessions
 WHERE recording_finalized_at IS NOT NULL
 GROUP BY recording_format;
```

Anything outside (`asciicast-v2`, `fmp4-dash`, `fmp4-flat`) would have
been rejected by the `recording_format_enum` CHECK constraint, so a
non-empty NULL bucket here is corrupt-meta territory.

## Recovery procedures

### A. Re-run hydration on a single row

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

The next hydrator tick will pick the row up again. Safe to run
during business hours -- the partial index makes the rescan O(rows
returned), not O(table).

### B. Force-finalize a hopelessly broken row

If `meta.json` cannot be reconstructed, mark the row finalized so
the page stops showing the "pending" toast and instead shows
"Integrity metadata unavailable":

```sql
UPDATE proxy_sessions
   SET recording_finalized_at = NOW()
 WHERE uuid = '<uuid>'
   AND recording_finalized_at IS NULL;
```

This is irreversible from the page's point of view (it cannot tell
"meta corrupt" from "meta force-marked"). Document the manual
intervention in the change log.

### C. Hydrator stuck (no progress between ticks)

1. Check the logs for `recording_hydrator` `ERROR` entries.
2. Check the supervisor IPC endpoint is up
   (`vauban-supervisor` healthcheck).
3. Restart `vauban-web`. The hydrator is just a `tokio::spawn`d
   loop: a clean restart re-arms it.
4. If the loop crashes on boot, set
   `recording.hydration_enabled = false` to keep the rest of the
   web tier serving while you investigate. The Recording Details
   page degrades gracefully ("pending finalization") rather than
   500-ing.

## Configuration knobs

All under the `recording.*` prefix:

| Key | Default | Effect |
|---|---|---|
| `hydration_enabled` | `true` | Spawn the background task at boot |
| `hydration_interval_secs` | `30` | Sleep between batches |
| `hydration_batch_size` | `50` | Max rows per batch |

Lowering `hydration_interval_secs` to 5 s during a backfill is safe
(the partial index keeps the SELECT cheap) and recommended after
restoring a large number of corrupt-meta recordings via procedure A.

## Related references

- [Recording Architecture v1.3 §"Integrity Persistence"](../technical/Vauban_Recording_Architecture_EN(1.3).md)
- Migration: `vauban-db/migrations/20260430000000_recording_integrity_metadata`
- Source: `vauban-web/src/services/recording_hydrator.rs`
- Tests: `vauban-web/tests/services/recording_hydrator_test.rs`
