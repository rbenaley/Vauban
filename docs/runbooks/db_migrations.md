# Runbook -- Database schema migrations

> Embedded, baseline-aware migration runner: `vauban-supervisor migrate`.
> Every migration under `vauban-db/migrations/` is compiled into the
> binary (`diesel_migrations::embed_migrations!`) and tracked in the
> `__diesel_schema_migrations` table, one transaction per migration.
> The FreeBSD package (`pkg/+POST_INSTALL`) invokes the runner for both
> fresh installs and upgrades; any failure aborts the package
> installation loudly.
>
> Audience: on-call operators, release engineers.
> Severity: HIGH whenever `migrate` fails or the supervisor refuses to
> boot on pending migrations -- the services will not start until the
> schema is complete.

## Model at a glance

- **Single mechanism, four states.** On every run the runner classifies
  the database before writing anything:

  | State | Detection | Action |
  |---|---|---|
  | Nominal | `__diesel_schema_migrations` exists | apply the pending delta |
  | Fresh | no tracking table, no `asset_groups` table | apply the full embedded chain |
  | Baseline | no tracking table, schema present, sentinels OK | stamp the baseline versions (no SQL re-executed), then apply the delta |
  | Unknown / partial | schema present, sentinels FAIL | refuse loudly, zero writes |

- **Baseline.** Installations provisioned before the runner existed
  received the consolidated schema (every migration up to
  `20260628000000`) without a tracking table. The runner adopts them by
  *stamping* those versions as applied -- but only after sentinel probes
  prove the schema really is the frozen baseline: the
  `idx_users_username_lower` unique index (artifact of the last baseline
  migration) and the `__all-assets__` / `__all-iacs-assets__` virtual
  group seeds. A partial schema fails the probes and is refused.

- **Transactions.** Each migration runs in its own transaction. A
  failure leaves the database at the boundary of the last successful
  migration with a consistent tracking table: fix the cause and re-run,
  already-applied migrations are skipped.

- **Boot invariant.** At boot the supervisor performs a read-only check:
  pending migrations abort the boot with a clear error (it never
  auto-migrates); an unreachable database only warns (PostgreSQL may
  still be starting; the services are fail-closed on DB access anyway).

- **History is append-only.** Never edit a shipped `up.sql`; add a new
  migration instead. The baseline history is frozen by tests
  (`vauban-db/tests/migrate_runner_test.rs`), including a byte-exact
  fixture of the consolidated baseline schema
  (`vauban-db/tests/fixtures/vauban_schema.sql`).
- New migrations must stay transaction-safe: no `CREATE INDEX
  CONCURRENTLY`, no `metadata.toml` with `run_in_transaction = false`
  (pinned by the same test suite).

## Commands

```sh
# Apply pending migrations (config-file connection, run as root):
vauban-supervisor migrate

# Same, as the postgres OS user over the local socket (what the
# package post-install runs; works without access to vauban.conf):
su -m postgres -c "/usr/local/libexec/vauban/vauban-supervisor migrate --database-url postgresql:///vauban"

# Read-only check: exit 0 when up to date, non-zero (with the list)
# when migrations are pending. No writes, safe for monitoring.
vauban-supervisor migrate --check
```

URL resolution order: `--database-url` flag, then the `DATABASE_URL`
environment variable, then `[database].url` from `vauban.conf`.

## Release / upgrade procedure (FreeBSD package)

1. `pkg upgrade vauban` (or `pkg add` the new package). The package
   scripts handle the rest:
   - `+PRE_INSTALL` stops a running Vauban service, so migrations never
     run under the previous version's binaries;
   - `+POST_INSTALL` runs `vauban-supervisor migrate` (fresh installs
     create the database and role first) and re-asserts the `vauban`
     role GRANTs;
   - any migration failure fails the package installation with a
     visible error banner (`DB_SETUP_FAILED`, exit 1).
2. `service vauban start`.
3. Optional sanity check: `vauban-supervisor migrate --check`.

## Failure recovery

- **`migrate` failed mid-chain.** The error banner contains the failing
  SQL. The database sits at the last successful migration; nothing is
  half-applied. Fix the cause (e.g. install a missing PostgreSQL
  extension package) and re-run the migrate command from the banner.
- **`refusing to migrate: ... does NOT match the expected baseline`.**
  The database has a schema but no tracking table AND the sentinel
  probes failed: this is a partial or hand-modified schema. Do NOT
  force anything. Diagnose with the missing artifacts listed in the
  error, restore the schema to the baseline state (or restore from
  backup), then re-run. The runner wrote nothing.
- **Supervisor refuses to boot with pending migrations.** Run
  `vauban-supervisor migrate`, then `service vauban start`.
- **PostgreSQL was not running at install time.** The post-install
  printed a warning and skipped database provisioning. Start
  PostgreSQL, then run the `su -m postgres -c "... migrate ..."`
  command shown above.
