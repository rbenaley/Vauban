# Runbook — Virtual "All assets" group

> Recovery procedure for the singleton `asset_groups` row that powers
> the **virtual "All assets" group** introduced in migration
> `20260424000000_virtual_asset_group_all`.
>
> Audience: on-call operators. Severity: HIGH if both vauban-access and
> vauban-web refuse to start; MEDIUM if only access-rule resolution is
> degraded.

## Background

The virtual "All assets" group is a single, system-managed row in the
`asset_groups` table that:

- carries `kind = 'all'` (vs. `kind = 'static'` for ordinary,
  user-managed groups);
- has the reserved UUID `00000000-0000-0000-0000-000000000a11`
  (mnemonic: `…0a11` ≈ "all");
- never has any rows in `asset_asset_groups` pointing at it (a Postgres
  `BEFORE INSERT` trigger raises if you try);
- cannot be updated, deleted, or soft-deleted via ordinary SQL (a
  separate `BEFORE UPDATE/DELETE` trigger raises);
- is exposed exclusively through the **access-rule editor** dropdown
  with a "Virtual — N assets" badge.

`vauban-access` and `vauban-web` resolve the row's internal `id` once
at boot, cache it in a process-wide `OnceLock`, and refuse to serve
traffic if the lookup fails. The recovery procedure below restores the
singleton row.

## Symptoms

- `vauban-access` exits at startup with:

  ```
  virtual_group: the seeded 'All assets' row (uuid=00000000-0000-0000-0000-000000000a11)
  is missing. Re-run migration 20260424000000_virtual_asset_group_all to recover.
  ```

- `vauban-web` exits at startup with the equivalent message.
- Or: both binaries are running but every access-rule that targets the
  virtual group silently grants nothing — the resolver never matched.
  This is rare in practice because both binaries fail loud at boot, but
  it can happen if the row was deleted **after** boot via a manual
  `ALTER TABLE … DISABLE TRIGGER` + `DELETE` sequence.

## Causes (root-cause catalogue)

1. The migration was rolled back manually (`down.sql` was applied).
2. The DB was restored from a backup taken **before** migration
   `20260424000000_virtual_asset_group_all` was applied.
3. An operator disabled the `block_mutation_on_virtual_groups` trigger
   and deleted the row — accidentally or as part of an incident
   response.
4. The DB was scrubbed with `session_replication_role = replica` and
   the singleton row was caught in the scrub.

## Recovery — re-running the migration

The seed `INSERT` is `ON CONFLICT DO NOTHING`, so re-applying the
migration is safe and self-healing.

```bash
cd vauban-db
DATABASE_URL=postgresql://vauban:vauban@localhost/vauban diesel migration run
```

This re-applies any pending migrations (no-op for already-applied ones)
and re-seeds the singleton row. Restart `vauban-access` and
`vauban-web`; both binaries will resolve the row at boot and proceed.

## Manual recovery — direct SQL

If the migration tooling is unavailable, you can re-seed the row by
hand:

```sql
INSERT INTO asset_groups (uuid, name, slug, kind, color, icon, description)
VALUES (
  '00000000-0000-0000-0000-000000000a11',
  'All assets',
  '__all-assets__',
  'all',
  '#6366f1',
  'globe',
  'System-managed virtual group: dynamically resolves to every non-deleted asset'
)
ON CONFLICT (uuid) DO NOTHING;
```

The partial `UNIQUE` index `uniq_asset_groups_kind_singleton` will
reject any attempt to insert a second `kind='all'` row, so this is
inherently safe to run.

## Verification

After recovery, verify the singleton invariant:

```sql
SELECT id, uuid, name, kind, is_deleted FROM asset_groups WHERE kind = 'all';
```

Expected:

| id | uuid                                   | name        | kind | is_deleted |
| -- | -------------------------------------- | ----------- | ---- | ---------- |
| _N_ | 00000000-0000-0000-0000-000000000a11   | All assets  | all  | false      |

If the row is present and `is_deleted = false`, restart both binaries.
The boot-time resolver will succeed and emit:

```
INFO Virtual 'All assets' group resolved at boot virtual_group_id=N uuid=00000000-…
```

## Hardening — preventing recurrence

- Never disable `block_mutation_on_virtual_groups` or
  `block_membership_on_virtual_groups` outside of the recovery
  procedure documented above.
- Backup-restore drills MUST verify the singleton row exists
  post-restore (the boot-time resolver enforces this on the next
  service start, but the operator can sanity-check ahead of time).
- Audit-log alerts should fire if either trigger ever raises in
  production — the only legitimate path that touches the virtual row
  is migration `20260424000000_virtual_asset_group_all`.

## Related documentation

- [`docs/technical/Vauban_AccessGuard_Architecture_EN(1.0).md`](../technical/Vauban_AccessGuard_Architecture_EN(1.0).md)
  — RBAC re-check semantics and the OR-aggregation rule.
- [`docs/technical/Vauban_IAM_Architecture_EN(1.1).md`](../technical/Vauban_IAM_Architecture_EN(1.1).md)
  — IAM model, asset groups, and the virtual-group sub-section.
- Migration source:
  [`vauban-db/migrations/20260424000000_virtual_asset_group_all/`](../../vauban-db/migrations/20260424000000_virtual_asset_group_all/).
