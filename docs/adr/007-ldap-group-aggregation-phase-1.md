# ADR 007: LDAP User Group aggregation (Phase 1)

**Status:** Accepted (amended 2026-08-22)  
**Date:** 2026-08-21  
**Amended:** 2026-08-22 (no deactivation on missing entry;
`resolve` plan from the mapping file; incomplete-read caps)  
**Related:**
[LDAPS Auth Architecture 1.1](../technical/Vauban_LDAPS_Auth_Architecture_EN(1.1).md),
[ADR 008 -- Mapping file DSL](008-ldaps-mapping-file-dsl.md),
[IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md)

## Context

Vauban already binds to LDAPS, JIT-provisions a local shadow
account (`auth_source = Ldap`, no local password), and leaves User
Group membership to administrators. Access Rules consume those User
Groups. Directory-side group changes therefore stay invisible until
someone edits the UI.

A draft product note asked for (1) mapping directory groups onto
existing User Groups, (2) a refresh bound of 15 minutes without a
service account, and (3) fail-closed handling when the directory
disappears. Vauban has no OAuth token refresh that re-presents the
user password. Storing that password, or searching the directory
anonymously, would break the 1.0 privsep and anti-downgrade story.

The first accepted draft treated "bind OK, then entry not found"
as "user deleted -- deactivate." After a successful bind that
signal is almost always misconfiguration (wrong attribute, Google
credentials-only ACL, Authentik without `memberOf`), not deletion.
A user actually removed from the directory cannot bind.

## Decision

1. **Phase 1 LDAP I/O is login-only.** After a successful simple
   bind, `vauban-auth` runs the group search on the **same**
   brokered TLS session and returns directory keys. Idle-session
   refresh, WebSocket revalidation, and AccessGuard do not open
   LDAPS. The 15-minute mid-session bound is deferred to Phase 2
   (vault-held read identity + periodic job).

2. **Auth resolves; web maps; Access Rules stay unchanged.**
   `vauban-auth` does not load Casbin or `user_groups`. `vauban-web`
   applies [ADR 008](008-ldaps-mapping-file-dsl.md) and replaces
   membership. Union / priority among Access Rules is out of scope.

3. **Replace-set on LDAP shadow accounts.** A successful resolution
   (including zero groups) fully replaces that user's `user_groups`.
   Local accounts are never written. Manual extra groups on an LDAP
   user do not survive the next successful resolution.

4. **Direct groups only.** No nested / transitive membership
   (no AD `LDAP_MATCHING_RULE_IN_CHAIN` in Phase 1). Operators map
   to groups assigned directly to users.

5. **Three directory signals after a successful bind, two effects.**
   Signals stay distinct in logs and tests. Phase 1 never
   deactivates from a search signal.

   | Signal | Directory signal | Phase 1 effect |
   |---|---|---|
   | A | Complete entry read (no range truncation, no overflow) | Replace `user_groups`; reset failure counter |
   | B | Explicit no-such-object / empty / insufficient access (not TCP/TLS) | **Same as C** -- keep groups; increment counter; do **not** deactivate |
   | C | Timeout / malformed / TLS drop / `memberOf;range=` / key-list overflow / referral-only | Keep groups; increment counter; at threshold purge groups **without** deactivating; one ops alert (latched on crossing) |

   Bind-level failure still only denies login (1.0 anti-enumeration).
   It is not case B and does not increment the aggregation counter.

   Deactivation of directory-deleted users is Phase 2 (search
   without the user bind).

6. **Default fail-closed threshold is 3** consecutive incomplete
   resolutions, configurable, per directory source for counting and
   alerting, applied to the user who just logged in. The counter
   lives in-memory in `vauban-web` and resets on restart. A later
   case A restores groups (auto-heal).

7. **Open proxy sessions are not killed** when membership shrinks.
   The next session-open / AccessGuard uses the new `user_groups`.

8. **User Groups are not Casbin roles.** Mapping cannot set
   `is_superuser` / `is_staff`.

9. **Resolution is declared in `ldaps_mapping.conf`, not in
   `vauban.conf`.** `resolve user-attr` / `resolve group-attr`
   lines (ADR 008) are compiled into `AuthLdapAggregationProvision`.
   No `groups_base_dn` knob. No "if `memberOf` is empty, fall
   back" heuristic. Referrals are never followed.
   `AuthLdapProvision` layout stays unchanged.

10. **Incomplete reads are never a silent subset.** AD
    `memberOf;range=`, more than 1024 keys, a key payload over
    192 KiB, or a search PDU over 256 KiB is case C.

11. **Web derives `aggregation_enabled` from supervisor
    provision.** A missing provision while LDAPS is enabled
    refuses web boot. Web TOML is not the authority (an empty AST
    would replace-set every LDAP user to zero groups).

12. **Every replace-set is audited**
    (`ldap_aggregation_replaced` / `emptied` / `purged_failsafe`).

## Consequences

- Roadmaps must not claim "directory revocation lands within 15
  minutes on an idle browser session" until Phase 2 overturns
  decision 1.
- Roadmaps must not claim "a user deleted in AD is deactivated in
  Vauban on next login" until Phase 2 overturns decision 5.
- Implementation extends the hand-rolled BER codec with
  SearchRequest / SearchResult, plus an RFC 4515 filter encoder.
  New IPC variants are **appended** ([ADR 004](004-flat-message-enum.md)).
- Threat inventory and pyramid for this surface live in LDAPS
  Architecture 1.1 sections 13 and 15.
- Onboarding: uncomment the vendor block in the shipped
  `ldaps_mapping.conf` (Architecture 1.1 Appendix B). Nested AD
  groups and users with more than ~1500 direct `memberOf` values
  are unsupported in Phase 1.
