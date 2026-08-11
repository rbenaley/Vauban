# ADR 001: Login rate limit store and multi-instance posture

**Status:** Accepted  
**Date:** 2026-08-03  
**Related:**
[`src/login_limit.rs`](../../src/login_limit.rs),
[`src/app/login.rs`](../../src/app/login.rs) (`request_login_link`),
`[login]` in `config/*.toml`,
[auth tenant smoke runbook](../runbooks/auth_tenant_smoke_test.md),
[architecture audit -- Toasty / out-of-scope follow-ups](../../.cursor/audits/vcp_architecture_toasty_query_debt_2026-08-02.md)

## Context

Magic-link request (`#[procedure] request_login_link`) is
anti-enumeration: unknown emails, lockouts, and **per-request** SMTP
failures all present the same "Check your email" UX (`Ok(true)`). When
the process-local mail circuit breaker is **open** (after consecutive
SMTP failures; see `[mail] circuit_*` and `MailCircuitBreaker`), every
address gets the same unavailable outcome (`Ok(false)` + shared copy)
so outages do not become an account-existence oracle. Abuse control
today is an **in-process** per-email window + lockout (`LoginRateLimiter`
in `app_context`, keyed by normalized email, thresholds from `[login]`).

That store is process-local (`Mutex<HashMap<…>>`). Under **N** active
portal replicas without a shared counter, an attacker can multiply the
configured budget by roughly **N** (and lose lockout after restart).
The architecture audit listed this as an open product/ops follow-up
outside Toasty debt.

VCP already depends on PostgreSQL for sessions, magic-link tokens, and
tenant data. Redis (or another dedicated cache) is not in the stack.
Edge rate limits (reverse proxy / WAF by IP) help against floods but
do not replace **per-email** lockout for passwordless enumeration and
mailbox bombing.

The product needs an explicit posture so roadmaps do not invent a
cache dependency prematurely, and so operators do not assume the
`[login]` knobs are cluster-wide while the process is still single-node.

## Decision

1. **Supported default = single process (or sticky single writer).**
   The in-process `LoginRateLimiter` is the accepted implementation
   for the topologies VCP ships today: one `vcp` process serving the
   portal (optionally behind a TLS-terminating proxy). `[login]`
   `max_attempts` / `window_secs` / `lockout_secs` apply to that
   process only.

2. **Active-active multi-instance without a shared counter is not a
   supported security posture for login rate limits.** Running N
   replicas that each keep a private map is allowed as a deploy
   experiment, but operators must treat the effective attempt budget
   as up to **N ×** the configured values, and must not claim the
   in-process limiter is cluster-global.

3. **When a shared limiter is required, the store is PostgreSQL.**
   If / when VCP adopts true active-active portal replicas as a
   supported deploy, login attempt / lockout state moves to a small
   Postgres-backed table (or equivalent SQL atomic upsert) keyed by
   normalized email. Reasons:
   - Postgres is already mandatory for auth and magic links;
   - avoids a new Redis (or similar) operational dependency;
   - lockout can survive process restart like magic-link token rows.
   A future ADR or amend of this one is required before introducing
   Redis/Memcached solely for this purpose.

4. **Edge limits are complementary, not a substitute.** IP / global
   request throttling at the reverse proxy or WAF remains encouraged
   defense-in-depth. It does not satisfy the per-email anti-enumeration
   and mailbox-bombing controls that live in `request_login_link`.

5. **Implementation of the Postgres-backed limiter is deferred** until
   multi-instance active-active is an actual product/ops requirement
   (or an explicitly scheduled change). Accepting this ADR does not
   require a code change today; it freezes the target store and the
   single-process default.

## Consequences

- Design reviews reject "add Redis for login rate limit" unless a new
  ADR supersedes decision (3).
- Deploy / capacity docs that describe horizontal portal scale must
  either keep sticky single-writer semantics for login, or schedule the
  Postgres-backed limiter before calling multi-instance supported.
- Anti-enumeration E2E and the in-process unit/proptest suite remain
  valid for the single-process path; a shared-store implementation
  must deliver the full `auth_tenant` / login pyramid, including
  contention (battle) across logical "replicas" against one DB.
- The audit follow-up "in-process login rate limiter (multi-instance)"
  is closed as **decided here**; work items are only the deferred
  Postgres implementation when triggers fire.
