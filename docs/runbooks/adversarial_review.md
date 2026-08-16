# Runbook -- Adversarial review (auth / crypto / IPC)

> Independent pass after shipping a security-sensitive surface. CI and
> `just lint` catch known classes; this pass assumes the rustdoc is
> lying.
>
> Audience: reviewer (human or `security-review` subagent), not the
> author of the change.
> Severity: **BLOCKING** for auth / crypto / IPC lots.

Related:

- [Untrusted input rule](../../.cursor/rules/untrusted-input-and-trust-anchors.mdc)
- [Adversarial-review skill](../../.cursor/skills/adversarial-review/SKILL.md)
- [Local lint tools](local_lint_tools.md)

## Automated prerequisites

```bash
just lint
rtk cargo test -p shared -p vauban-auth -p vauban-audit -- ldap_dn -- --test-threads=1
rtk cargo test -p vauban-audit -- forged_seal -- --test-threads=1
```

## When to run

After any change that touches bind DN, WORM verify, session tokens,
vault unseal, Casbin / BAC, or a new protocol integration (R4 table
in the plan).

## A -- Claims vs tests

1. Grep `vauban-*/src` and `shared/src` for `attacker who` / `cannot forge`.
2. For each hit, name the test that performs that attack.
3. If none, the lot is not done.

Pass: every claim has an `attack_*` / `forged_*` / `*_is_rejected` test
or an explicit `// allow-untested-claim:`.

## B -- Interpolation

1. Search for `.replace("{username}"`, `format!` into DN/SQL/shell.
2. Confirm the only LDAP substitution is `shared::ldap_dn`.

Pass: no raw interpolation on a production path.

## C -- Trust anchors

1. Confirm `verify_reader` takes `expected: &VerifyingKey`.
2. Confirm `vauban-audit verify` without `--pubkey` exits 2.

Pass: in-band pubkey is never the sole verifier.

## Related links

- [LDAPS bind-DN smoke](ldaps_bind_dn_smoke_test.md)
- [WORM eager-boot smoke](worm_eager_boot_smoke_test.md)
