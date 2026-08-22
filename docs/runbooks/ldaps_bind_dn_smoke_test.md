# Runbook -- LDAPS bind-DN allowlist smoke test

> Manual check after shipping **fail-closed bind-DN construction**
> (`shared::ldap_dn::substitute_bind_dn`). CI covers the allowlist,
> lint, and in-process E2E; staging proves a live directory never sees
> a steered DN.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** when `[auth.ldaps] enabled = true`.

Related:

- [LDAPS Auth Architecture 1.1](../technical/Vauban_LDAPS_Auth_Architecture_EN(1.1).md)
  (Appendix B -- directory coverage)
- [ADR 007](../adr/007-ldap-group-aggregation-phase-1.md) -- aggregation
- [ADR 008](../adr/008-ldaps-mapping-file-dsl.md) -- mapping file
  (`resolve` / `static` / `match`; uncomment a vendor block in
  `config/access/ldaps_mapping.conf`)
- Lint: `vauban-auth/scripts/check_ldap_dn_escaping.sh`

## Automated prerequisites

```bash
bash vauban-auth/scripts/check_ldap_dn_escaping.sh
rtk cargo test -p shared -p vauban-auth -- ldap_dn -- --test-threads=1
rtk cargo test -p vauban-auth -- comma_in_username -- --test-threads=1
```

## Lab prerequisites

- `[auth.ldaps] enabled = true` with a full-DN `dn_template`
  (`uid={username},ou=...`).
- A known good directory user (e.g. `alice`) and password.
- Ability to read `vauban-auth` logs and directory bind logs.

## A -- Happy path

1. Log in as the known good user with the correct password.
2. Expect a normal session (MFA if configured).
3. Directory bind log shows the templated DN, not a raw interpolation.

Pass: login succeeds; DN matches the template.

## B -- Comma does not steer

1. Attempt login as `alice,ou=admins` (or any comma-bearing identifier)
   with the known-good password.
2. Expect the generic "Incorrect username or password" response.
3. `vauban-auth` logs `LDAP bind DN rejected`; the directory **must not**
   record a bind for a steered DN.

Pass: reject locally; no directory bind.

## C -- UPN-style template

1. If the lab uses `{username}@realm`, log in with the sAMAccountName
   only (no `@`).
2. A typed UPN (`user@realm`) is rejected by the allowlist (the `@`
   lives in the template, not the username).

Pass: local-part bind works; `@` in the typed username fails closed.

## Related links

- [LDAPS aggregation Phase 1 smoke](ldaps_aggregation_smoke_test.md)
- [WORM eager-boot smoke](worm_eager_boot_smoke_test.md)
- [Adversarial review](adversarial_review.md)
