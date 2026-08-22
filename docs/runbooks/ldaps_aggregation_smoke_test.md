# Runbook -- LDAPS group aggregation Phase 1 smoke test

> Manual validation after shipping **login-time group aggregation**
> (crates **0.9.40+**; `shared::ldap_mapping` + `AuthLdapBindAndSearch`
> + web replace-set).
> CI covers parse, RFC 4515 filters, BER search, A/B/C, and the in-process
> stub; staging proves a live directory (AD `memberOf` **or** Authentik
> `group-attr`) updates `user_groups` without a service account.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** when `[auth.ldaps] aggregation_enabled = true`.

Related:

- [LDAPS Auth Architecture 1.1](../technical/Vauban_LDAPS_Auth_Architecture_EN(1.1).md)
- [ADR 007](../adr/007-ldap-group-aggregation-phase-1.md)
- [ADR 008](../adr/008-ldaps-mapping-file-dsl.md)
- [LDAPS bind-DN smoke](ldaps_bind_dn_smoke_test.md)
- Mapping catalogue: `config/access/ldaps_mapping.conf`

## Automated prerequisites

```bash
bash shared/scripts/check_untrusted_interpolation.sh
bash shared/scripts/check_security_claims.sh
rtk cargo test -p shared -- ldap_mapping ldap_filter -- --test-threads=1
rtk cargo test -p vauban-auth -- ldap_bind ldap_search -- --test-threads=1
rtk cargo test -p vauban-web -- ldap_aggregation ldap_login -- --test-threads=1
# hand-off:
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target --all-targets -- -D warnings
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
```

## Lab prerequisites

- `[auth.ldaps] enabled = true` and `aggregation_enabled = true`.
- `mapping_path` points at a readable file with at least one `resolve`
  line uncommented (shipped catalogue is comments-only and **refuses boot**
  when aggregation is on).
- Existing Vauban User Groups whose **names** match `static` / `match`
  targets (no implicit create).
- A known good directory user and password. MFA still applies after bind.
- Ability to read `vauban-auth` / `vauban-web` logs and inspect
  `user_groups` (or the Groups UI).

## A -- Complete keys (AD `memberOf` or Authentik reverse `member`)

1. Uncomment the vendor `resolve` block:
   - AD / 389ds: `resolve user-attr memberOf`
   - Authentik (or any directory without `memberOf`):  
     `resolve group-attr member base ou=groups,dc=example,dc=com`
2. Add `static` / `match` lines so a real directory key maps to an
   **existing** User Group name.
3. Log in as the known good user (web or API). Expect the usual MFA path.
4. Confirm `user_groups` equals the mapped set (replace-set). Local
   accounts on the same host are unchanged.
5. Audit / logs show `ldap_aggregation_replaced` (and
   `ldap_aggregation_emptied` only if the mapped set is empty).

Pass: login succeeds; LDAP shadow membership matches the mapping; no
`is_superuser` / `is_staff` change; MFA unchanged.

## B -- Search entry not found (hold)

1. Bind still succeeds (correct password) but the user entry is missing
   or unreadable (`noSuchObject` / `insufficientAccessRights`).
2. Log in. Expect a normal session (MFA if configured).
3. Previous `user_groups` stay as they were. The account stays **active**.
4. `vauban-web` increments the in-memory incomplete streak (no purge yet
   if below `aggregation_fail_closed_threshold`).

Pass: hold, not deactivate; bind anti-enumeration still collapses a
**failed bind** to the generic invalid-credentials page.

## C -- Incomplete / overflow (range, size) then restore

1. Force an incomplete search: AD `memberOf;range=`, payload over 192 KiB,
   or more than 1024 keys. Expect case C (`IncompleteUnreachable`).
2. Repeat until `aggregation_fail_closed_threshold` (default 3). Membership
   is **purged**; the account stays active. Logs:
   `ldap_aggregation_purged_failsafe`.
3. Restore a complete directory response. Next successful login is case A:
   streak resets, groups restore (auto-heal).

Pass: B and C never deactivate; threshold purge is membership-only;
case A heals.

## Rollback notes

Set `aggregation_enabled = false` and restart. Login falls back to
bind-only 1.0. Existing `user_groups` rows are left as-is until the
next case-A login after re-enable.
