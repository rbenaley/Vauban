# ADR 010: MCP upstream TLS is pinned to the asset SPKI

**Status:** Accepted  
**Date:** 2026-10-15  
**Crate:** 0.9.47  
**Related:**
[MCP Architecture 1.0](../technical/Vauban_MCP_Architecture_EN(1.0).md),
[ADR 009](009-mcp-no-oauth-for-now.md)

## Context

Hop 2 speaks MCP to an upstream the operator registered on the asset.
That TCP connection is brokered by the supervisor and handed to
`vauban-proxy-mcp`. The bytes after the handshake are the tool call.
A network position on that TCP connection can present a different
certificate.

## Decision

Every MCP upstream byte goes through TLS. The trust anchor is the
asset's `SHA256:<base64>` SPKI pin, stored with the asset. It does not
come from the certificate the peer presents.

`upstream_over_tls` refuses a missing or blank pin before the broker
is asked to connect, including when the target is loopback.
`tls_pin::connect_pinned` checks the leaf certificate's SPKI
fingerprint against that pin and refuses a mismatch. The custom
verifier looks only at that fingerprint. Certificate expiry and the
subject name are not checked: the pin replaces the PKI. That is the
choice.

Plaintext, including to loopback, is refused.

## Threat inventory

| Attacker | Entry | Language joined | Trust anchor | If the certificate or packet is rewritten |
| --- | --- | --- | --- | --- |
| Network position on the brokered TCP connection | Upstream handshake | TLS | Asset pin `SHA256:<base64>`, not the presented certificate | Handshake refused (`attack_wrong_spki_pin_is_rejected`) |
| Caller that omits the pin, including a loopback target | Open, discover, re-broker | TLS (never started) | The same pin, required before connect | Refused before the broker and inside `upstream_over_tls` (`attack_missing_tls_pin_is_rejected`) |

## Consequences

- `rustls`'s `dangerous()` hook exists only in `tls_pin.rs`, to install
  this verifier.
- A certificate that is expired or named for another host, but that
  carries the pinned key, is accepted. Operators who need name and
  expiry checks as well would be adding a second policy on top of the
  pin; this ADR does not do that.
- The lint `vauban-proxy-mcp/scripts/check_mcp_upstream_tls_mandatory.sh`
  keeps the production call sites on this path.
