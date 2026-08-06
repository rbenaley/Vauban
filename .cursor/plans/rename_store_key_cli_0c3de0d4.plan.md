---
name: Rename store key CLI
overview: Renommer les sous-commandes `vcp-store key …` en commandes top-level (`pending-keys` / `list-keys` / `approve-key`), et retirer des textes CLI tout message qui parle de development / VCP_ENVIRONMENT — sans toucher aux smoke runbooks génériques ni au mécanisme de config.
todos:
  - id: cli-rename
    content: Top-level pending-keys / list-keys / approve-key; strip CLI dev usage/hints/eprintln
    status: completed
  - id: ui-pins-docs
    content: Update UI copy, check_storage, invariants/E2E, storage ops/smoke KEY + ADRs/arch quotes
    status: completed
  - id: validate
    content: fmt, clippy, check_storage, focused bin/lib/integration tests
    status: completed
isProject: false
---

# Rename vcp-store KEY CLI + strip CLI dev copy

## Scope (locked)

- **In:** CLI surface of [`src/bin/vcp_store.rs`](src/bin/vcp_store.rs) (usage, error hints, `eprintln`, module docs that describe the ops CLI), plus every **string that must match the CLI** (UI copy, invariants, `check_storage`, storage ops/smoke KEY sections, ADRs/arch that quote the commands).
- **Out:** Smoke prerequisites like `VCP_ENVIRONMENT=development + just run`, Justfile, README, `config.rs` loader, and the internal `load_key_cfg_with_env` resolution (still may read `VCP_ENVIRONMENT` — just no operator-facing CLI text about it).

## CLI rename

| Old | New |
|-----|-----|
| `vcp-store key pending` | `vcp-store pending-keys` |
| `vcp-store key list` | `vcp-store list-keys` |
| `vcp-store key approve --fingerprint` | `vcp-store approve-key --fingerprint` |

In [`src/bin/vcp_store.rs`](src/bin/vcp_store.rs):

- Drop nested `key` dispatch (`args.first() == "key"` → `run_key`).
- Top-level match on `pending-keys` | `list-keys` | `approve-key` (shared option parser for `--config` / `--blob-path` / `--fingerprint`).
- Replace `key_usage()` with a short ops usage listing the three commands only — **no** “Development (spawn)…” block.
- On engine open failure: hint only production-safe guidance (`--config` / `--blob-path` / default `vcp-store.conf`), **no** `VCP_ENVIRONMENT=development` / `./target/debug/vcp-store` / “Local spawn”.
- Remove `eprintln!("vcp-store key: using {} blob_path=…")` (announces env name to the operator).
- Neutralize other CLI strings that say `key approve` (e.g. pending header → `approve-key --fingerprint …`).
- Module crate docs: document the new commands; drop the `VCP_ENVIRONMENT=development|testing` bullet from the ops-CLI config blurb (keep `--blob-path` / `--config` / production conf).

Keep `load_key_cfg` / `load_key_cfg_with_env` behavior and unit tests that exercise Development/Testing resolution — that is code, not CLI messaging.

## Call-site string updates (must match CLI)

- UI: [`src/app/admin/key.rs`](src/app/admin/key.rs) `approve_command` + callout chip → `vcp-store approve-key`.
- Confirm surfaces: [`src/app/admin/releases/confirm.rs`](src/app/admin/releases/confirm.rs), [`delete_confirm.rs`](src/app/admin/releases/delete_confirm.rs) → `vcp-store pending-keys`.
- Pins: [`scripts/check_storage.sh`](scripts/check_storage.sh), [`tests/integration_tests/storage_invariants_test.rs`](tests/integration_tests/storage_invariants_test.rs), [`storage_e2e_test.rs`](tests/integration_tests/storage_e2e_test.rs).
- Docs that quote the commands: [`docs/runbooks/storage_helper_ops.md`](docs/runbooks/storage_helper_ops.md), [`storage_helper_smoke_test.md`](docs/runbooks/storage_helper_smoke_test.md) §F/§G (command names only; drop the “Local spawn: `VCP_ENVIRONMENT=development ./target/debug/…`” **CLI recipe** in §G — replace with bare `vcp-store approve-key --fingerprint <hex>` / `--blob-path` if needed), ADRs 002–004 + architecture 1.2 command tables, brief comments in `engine.rs` / `meta_db.rs`.

Do **not** mass-edit unrelated smoke runbooks’ `VCP_ENVIRONMENT=development + just run` prerequisites.

## Validation

```bash
just fmt
rtk cargo clippy -p vcp --all-targets -- -D warnings
bash scripts/check_storage.sh
rtk cargo test -p vcp --bin vcp-store -- --test-threads=1
rtk cargo test -p vcp --lib admin::key -- --test-threads=1
rtk cargo test --test integration_tests -- storage_invariants_ inv_key_ -- --test-threads=1
```
