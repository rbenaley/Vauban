# ADR 009: MCP hop 2 keeps the Vauban visit ticket (no MCP OAuth for now)

**Status:** Accepted  
**Date:** 2026-10-03  
**Crate:** 0.9.45  
**Related:**
[MCP Architecture 1.0](../technical/Vauban_MCP_Architecture_EN(1.0).md),
[IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md),
[MCP user guide](../user/Vauban_MCP_User_Guide_EN.md),
[Runbook -- API key compromise](../runbooks/mcp_api_key_compromise.md)

## Context

An MCP visit is opened in two hops. Hop 1 (`POST /api/v1/mcp/sessions`
on `vauban-web`) authenticates a Vauban user with a `vbn_` API key,
runs Casbin (`assets:connect_mcp`), the access rules and the
justification, asks `vauban-access` for a session token and the
effective tools, and returns a short-lived **visit ticket** `vbw_`.
Hop 2 (`POST /mcp`, JSON-RPC) presents that ticket as
`Authorization: Bearer`. The ticket is bound to a frozen allow-list,
lives at most `[mcp].session_ttl_seconds` (default 3600), is
re-checked about every 30 s, and is subject to HITL and Mission Seal.

In 0.9.45, hop 2 is served on the public HTTPS listener of
`vauban-web` (one name, port 443), with two client modes: **direct**
(any HTTP client that can send a static bearer header) and **tunnel**
(a local stdio shim that opens an inner TLS session terminated in the
leaf, so the web process relays only ciphertext).

The MCP specification describes OAuth 2.1 as the authorization
mechanism for HTTP transports: authorization-server metadata
discovery, PKCE, and, since the 2025-06-18 revision, the MCP server as
a pure resource server with protected-resource metadata and resource
indicators. Hosted connectors (assistant web apps, agent platforms)
implement that flow and cannot set a static header. They are the one
client category Vauban does not serve today.

The question is whether Vauban should implement MCP OAuth at hop 2 now.

## Decision

1. **Not now.** Hop 2 stays authenticated by the Vauban visit ticket.
   `vauban-web` does not expose authorization-server or
   protected-resource metadata for `/mcp`, and a missing or invalid
   bearer answers `401` with JSON-RPC `-32003` without an OAuth
   challenge, so no client attempts a discovery flow that cannot
   succeed.

2. **Why.**

   - The authorization semantics already live at hop 1: identity
     (`vbn_` or UI cookie), Casbin, access rules, justification, bounded
     lifetime, frozen tools. An OAuth authorization server would either
     duplicate them or wrap them behind a token issuer reachable by any
     client. The authority over a visit must remain `vauban-access`,
     reached through hop 1.
   - Acting as an OAuth authorization server adds unauthenticated
     public surface to the only process already on the Internet:
     metadata endpoints, a consent UI, token and refresh endpoints and,
     for connectors that register themselves, an anonymous dynamic
     client registration endpoint. None of that exists today and each
     piece is a new target on port 443.
   - The clients that need OAuth run in a vendor's cloud. That model
     conflicts with the client IP allow-list, with the appliance being
     reachable only from the operator's network, and with the HITL and
     Mission Seal model where the approver is a human near the agent and
     subject to separation of duties.
   - For the clients Vauban targets (local agents, IDEs, SDKs, server
     scripts) the tunnel mode is stronger than an OAuth bearer: the web
     process never sees the ticket or the content, and the leaf's
     identity is pinned.
   - The authorization chapter of the specification changed materially
     between the two protocol versions Vauban pins (`2024-11-05`,
     `2025-03-26`) and the next one (`2025-06-18`, refused today).
     Implementing a moving target before the pinned versions move is
     premature.

3. **If this is revisited**, OAuth fronts **hop 1, not hop 2**: Vauban
   acts as an OAuth *resource server* only, trusts the enterprise
   identity provider (no dynamic client registration), and exchanges
   the validated access token for a visit ticket through the existing
   hop-1 pipeline. The ticket, the frozen allow-list, HITL and Mission
   Seal are not replaced by OAuth scopes.

4. **Revisit triggers:** a customer requirement for hosted connectors
   that cannot run the shim; stabilisation of the specification's
   authorization chapter across the versions Vauban supports; or
   Vauban adopting the identity-provider role for other reasons.

## Consequences

- Client compatibility is decided by one question: can the client send
  `Authorization: Bearer` on its own, or run a local stdio server?

  | Client | Mode | Served |
  |--------|------|--------|
  | Runs a local stdio MCP server (desktop assistants, IDEs, SDKs) | tunnel, or direct if it can also set the header | yes |
  | HTTP client that can set a static header (scripts, server frameworks, `curl`) | direct | yes |
  | Hosted connector requiring OAuth, no static header | none | **no**, today and after this ADR |

- The user guide and the hop-1 Connect page describe the two modes and
  name the third category as unsupported. Roadmaps and sales material
  must not claim "MCP OAuth" or "works with hosted connectors" without a
  new ADR that overturns this one.
- The `vbw_` ticket remains the credential to protect at hop 2: short
  TTL, bound to the frozen allow-list, visible to `vauban-web` once at
  hop 1 and never again in tunnel mode. A compromised `vbn_` follows
  the existing runbook (revoke or regenerate; live visits are cut).
- No new protocol is introduced by this ADR, so it carries no R4
  threat inventory. The inventory for the hop-2 relay and the tunnel
  belongs to their implementation plan; the threat summary is in the
  MCP Architecture document, §4.6.
- A source pin must assert the absence of OAuth discovery on `/mcp`:
  no `/.well-known/oauth-authorization-server` or
  `/.well-known/oauth-protected-resource` route under the web router,
  and no `WWW-Authenticate` challenge carrying `resource_metadata` on a
  `401` from `/mcp`.
