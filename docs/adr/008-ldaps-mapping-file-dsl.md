# ADR 008: LDAPS mapping file (`static` / `match`)

**Status:** Accepted  
**Date:** 2026-08-21  
**Related:**
[LDAPS Auth Architecture 1.1](../technical/Vauban_LDAPS_Auth_Architecture_EN(1.1).md),
[ADR 007 -- Group aggregation Phase 1](007-ldap-group-aggregation-phase-1.md)

## Context

Casbin already lives in operator-editable files under
`/usr/local/etc/vauban/access/` (`model.conf`, `policy.csv`). Group
mapping must be equally reviewable and must not sit inline in
`vauban.conf`.

Conceptual probes used a Python list of `(dn, vauban_name)` tuples
and a `{Name}` shortcut so every `CN=X,OU=UserGroup,…` could map to
User Group `X` without repeating the OU suffix. Evaluating that
file as Python, or interpolating `{Name}` into an LDAP filter, is
incompatible with R1 and with a Capsicum appliance.

`dn_template` already means the **bind** identity
(`{username}@realm`). Overloading it as a path would break
`AuthLdapProvision` and `substitute_bind_dn`.

A dynamic rule that maps `CN={name},…` to User Group `{name}` can
collide with a privileged User Group (`Administrators`) if someone
creates that CN under the mapped OU.

## Decision

1. **New knob `mapping_path`, bind template unchanged.**

   ```toml
   [auth.ldaps]
   dn_template = "{username}@example.com"
   mapping_path = "/usr/local/etc/vauban/access/ldaps_mapping.conf"
   ```

   Production path matches Casbin (no `config/` infix). Repo
   default: `config/access/ldaps_mapping.conf`. Install mode
   `0644` `root:wheel`, same as `policy.csv`.

2. **Declarative line DSL -- kinds `static` and `match`.** Not
   Python, not `eval`, not JSON. Comments `#`. File order does not
   change the result.

   ```text
   static  CN=Domain Admins,CN=Users,DC=netris,DC=local  Administrators
   match   CN={name},OU=UserGroup,OU=Vauban,DC=netris,DC=local  {name}
   ```

3. **`{name}` is a capture, never an interpolation into LDAP.**
   Matching runs on keys already returned by the directory. The
   only placeholder in this file is `{name}`. `{username}` is
   illegal here (bind-only).

4. **`static` reserves the target User Group name.** After all
   `static` hits, a `match` whose captured `{name}` equals a
   `static` target is skipped. Example: `CN=Administrators,OU=UserGroup,…`
   does not grant User Group `Administrators` when that name is
   already a `static` target (typically `Domain Admins`).

5. **No implicit User Group create.** Unknown names are skipped.
   Mapping does not set Casbin roles or `is_superuser`.

6. **Supervisor parses pre-seal, fail-closed, provisions the AST
   to `vauban-web`.** `vauban-auth` never reads the file. No
   hot-reload in Phase 1. When aggregation is enabled, a missing
   or illegal file refuses boot.

7. **Phase 1 keys are DN-shaped.** A later `mail` key kind (Google
   Secure LDAP) can be added in this file; a second mapping format
   is rejected.

## Consequences

- Reviews reject `dn_template = "/usr/local/etc/…"`, Python mapping
  snippets in production config, and `format!` of `{name}` into
  filters.
- Parser, reserved-target evaluation, and install-path pins belong
  in the architecture 1.1 pyramid (section 15).
- Editing `ldaps_mapping.conf` is the same privilege class as
  editing `policy.csv`: after restart, LDAP users can gain any
  **existing** User Group the AST allows.
