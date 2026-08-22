# ADR 007: LDAP User Group aggregation (Phase 1)

**Status:** Accepted  
**Date:** 2026-08-21  
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

5. **Three search outcomes after a successful bind**, never merged:

   | Case | Directory signal | Effect |
   |---|---|---|
   | A | Entry read | Replace `user_groups`; reset failure counter |
   | B | Explicit no-such-object (not TCP/TLS) | Deactivate shadow account; purge groups |
   | C | Timeout / malformed / TLS drop on the search | Keep groups; increment counter; at threshold purge groups **without** deactivating; one ops alert |

   Bind-level failure still only denies login (1.0 anti-enumeration).
   It is not case B.

6. **Default fail-closed threshold is 3** consecutive case-C
   searches, configurable, per directory source for counting and
   alerting, applied to the user who just logged in.

7. **Open proxy sessions are not killed** when membership shrinks.
   The next session-open / AccessGuard uses the new `user_groups`.

8. **User Groups are not Casbin roles.** Mapping cannot set
   `is_superuser` / `is_staff`.

## Consequences

- Roadmaps must not claim "directory revocation lands within 15
  minutes on an idle browser session" until Phase 2 overturns
  decision 1.
- Implementation extends the hand-rolled BER codec with
  SearchRequest / SearchResult, plus an RFC 4515 filter encoder.
  New IPC variants are **appended** ([ADR 004](004-flat-message-enum.md)).
- Threat inventory and pyramid for this surface live in LDAPS
  Architecture 1.1 sections 13 and 15.
- Onboarding must tell operators that nested AD groups are not
  visible in Phase 1.
