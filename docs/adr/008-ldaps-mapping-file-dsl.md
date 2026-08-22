# ADR 008: LDAPS mapping file (`resolve` / `static` / `match`)

**Status:** Accepted (amended 2026-08-22)  
**Date:** 2026-08-21  
**Amended:** 2026-08-22 (shared parser, raw-byte provision, `\`
rejected, 128 KiB cap; `resolve` plane; no `groups_base_dn`)  
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
`AuthLdapProvision` and `substitute_bind_dn`. Putting the
reverse-search base in `vauban.conf` (`groups_base_dn`) split
"how to find groups" from "how to map them" and forced a
heuristic ("if `memberOf` is empty, fall back").

A dynamic rule that maps `CN={name},…` to User Group `{name}` can
collide with a privileged User Group (`Administrators`) if someone
creates that CN under the mapped OU.

Market directories use two LDAP mechanisms (attribute on the
user vs attribute on the group). The file must name the
mechanism, not the vendor. Coverage lives in Architecture 1.1
Appendix B.

## Decision

1. **New knob `mapping_path`, bind template unchanged.**

   ```toml
   [auth.ldaps]
   dn_template = "{username}@example.com"
   mapping_path = "/usr/local/etc/vauban/access/ldaps_mapping.conf"
   ```

   Production path matches Casbin (no `config/` infix). Repo
   default: `config/access/ldaps_mapping.conf`. Install mode
   `0644` `root:wheel`, same as `policy.csv`. No
   `groups_base_dn` in `vauban.conf`.

2. **Declarative line DSL -- kinds `resolve`, `static`, and
   `match`.** Not Python, not `eval`, not JSON. Comments `#`.
   File order does not change `static` / `match` results.
   Multiple `resolve` lines **union** keys (max 3).

   ```text
   resolve  user-attr  memberOf
   static   CN=Domain Admins,CN=Users,DC=netris,DC=local  Administrators
   match    CN={name},OU=UserGroup,OU=Vauban,DC=netris,DC=local  {name}
   ```

   `resolve` grammar:

   ```text
   resolve  user-attr   <attr>
   resolve  group-attr  <attr>  base <dn>  [key dn|mail]
   ```

   Phase 1 allowlist: `memberOf` | `isMemberOf` |
   `isDirectMemberOf` | `member` | `uniqueMember`. Aggregation
   on without a `resolve` line refuses boot.

3. **`{name}` is a capture, never an interpolation into LDAP.**
   Matching runs on keys already returned by the directory. The
   only placeholder in this file is `{name}`. `{username}` is
   illegal here (bind-only).

4. **`static` reserves the target User Group name.** After all
   `static` hits, a `match` whose captured `{name}` equals a
   `static` target is skipped (comparison is case-insensitive,
   same folding as `vauban_groups.name`). `static` does **not**
   consume the key: the same directory key is still scored by
   `match` lines; only the **target name** is reserved. Example:
   `CN=Administrators,OU=UserGroup,…` does not grant User Group
   `Administrators` when that name is already a `static` target
   (typically `Domain Admins`). `static` does not expand into
   searches.

5. **No implicit User Group create.** Unknown names are skipped
   at apply time (a group created after boot is visible on the
   next login). Mapping does not set Casbin roles or
   `is_superuser`.

6. **Supervisor validates pre-seal, fail-closed, splits the
   parse.** Compiled **resolve plan** -> auth
   (`AuthLdapAggregationProvision`). **Raw file bytes** -> web
   (`WebLdapMappingProvision`). Both sides call
   `shared::ldap_mapping::parse`. A compiled mapping AST on the
   wire is rejected. `vauban-auth` never reads the file and never
   sees User Group names. No hot-reload in Phase 1. When
   aggregation is enabled, a missing, oversized, illegal, or
   resolve-less file refuses boot. Maximum file size is
   **128 KiB**.

7. **Shipped default is a commented catalogue.**
   [`config/access/ldaps_mapping.conf`](../../config/access/ldaps_mapping.conf)
   lists market directories, most common first. Example Google
   domains use `netris.eu`. Comments-only is empty of rules.

8. **Match is whole-key, `{name}` once, no escapes.** A `match`
   line contains `{name}` exactly once in the key; equality is on
   the normalized key, never a substring. The capture is taken
   from the original (pre-lowercase) key. A mapping-file key that
   contains `\` refuses boot. A directory key that contains `\`
   never matches. RFC 4514 escaped DNs are not mappable in
   Phase 1.

## Consequences

- Reviews reject `dn_template = "/usr/local/etc/…"`,
  `groups_base_dn` in `vauban.conf`, Python mapping snippets in
  production config, and `format!` of `{name}` into filters.
- Parser, reserved-target evaluation, install-path pins, the
  128 KiB cap, the `\` boot-refuse, the `resolve` allowlist, and
  the comments-only default belong in the architecture 1.1
  pyramid (section 15).
- Editing `ldaps_mapping.conf` is the same privilege class as
  editing `policy.csv`: after restart, LDAP users can gain any
  **existing** User Group the AST allows, and the operator
  chooses how keys are collected.
- Vendor coverage and the OK / +attr / +compare / out legend
  live in Architecture 1.1 Appendix B, not in this ADR.
