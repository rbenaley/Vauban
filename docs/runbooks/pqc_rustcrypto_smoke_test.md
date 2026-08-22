# Runbook -- hybrid PQC RustCrypto (`ml-kem` / `ml-dsa`) smoke test

> Manual validation after shipping **Lot A** (crates **0.9.39+**):
> `vauban-web` hybrid KEM / signatures use RustCrypto `ml-kem` 0.3 and
> `ml-dsa` 0.1. Vault AES-256-GCM, hydrator BLAKE3, and WORM Ed25519
> are out of scope and must keep behaving as before.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for any change to `vauban-web/src/crypto.rs`
> or the `ml-kem` / `ml-dsa` pins. Do not ship without A–C.

Related:

- Production module: `vauban-web/src/crypto.rs`
- Skill: `.cursor/skills/rust-best-practices/SKILL.md` §4.7
- Lint: `shared/scripts/check_security_claims.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-web --all-targets -- -D warnings
rtk cargo test -p vauban-web -- crypto hybrid_pqc zeroize -- --test-threads=1
just deny
# workspace lock must not retain PQClean:
rg -n 'name = "pqcrypto' Cargo.lock; test $? -eq 1
# hand-off:
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

## Lab prerequisites

- Coordinated binaries **0.9.39+**.
- Ability to run `just deny` and `rg` on a checkout that matches the
  deployed revision.
- No change to vault / hydrator / WORM config is required.

## A -- Deny and lockfile

1. From the repo root, run `just deny`.
2. Confirm the report does **not** list `RUSTSEC-2024-0436` (paste via
   pqcrypto-mldsa) or `RUSTSEC-2026-0163` / `0166` / `0161` / `0162`
   (PQClean archive).
3. `rg -n 'name = "pqcrypto' Cargo.lock` must print nothing.

Pass: `just deny` exits 0; no `pqcrypto*` in the workspace lock.

## B -- Hybrid unit / E2E on the host

1. Run `rtk cargo test -p vauban-web -- crypto hybrid_pqc -- --test-threads=1`.
2. Expect `test_hybrid_kem_encapsulate_decapsulate_same_secret`,
   `forged_hybrid_signature_is_rejected`,
   `e2e_hybrid_kem_round_trip_via_public_api`, and
   `battle_hybrid_pqc_generate_encap_sign_under_barrier` to pass.

Pass: the focused filter is green on the staging builder.

## C -- Rest-at-rest unchanged

1. Open an existing vault secret and an existing recording (hydrator
   BLAKE3) created **before** the upgrade.
2. Confirm decrypt / playback still succeed.
3. Confirm `vauban-audit verify --pubkey <signing_key.pub> <segment>`
   still accepts a WORM segment sealed before the upgrade.

Pass: no re-encrypt / re-hydrate / re-seal is required; at-rest
formats are untouched.

## Rollback notes

- Reverting `vauban-web` to `pqcrypto-*` brings back the PQClean
  advisories and the unused-ignore set in `deny.toml`.
- Do not mix a 0.9.39 web binary with an older `Cargo.lock` that still
  vendors `pqcrypto-mlkem`.
