# Runbook -- MCP staging acceptance

> Manual validation after shipping the MCP leaf (crates **0.9.44**,
> hop 2 moved onto the bastion HTTPS listener in **0.9.45**).
> Hop 1 is `POST /api/v1/mcp/sessions` with a `vbn_` key. Hop 2 is
> `POST /mcp` on that same HTTPS origin with the returned `vbw_` bearer.
> The proxy has no listener, no `/health` and no `/session` control plane.
> The 0.9.45 transport checks are in
> [mcp_hop2_relay_smoke_test.md](mcp_hop2_relay_smoke_test.md)
> (section D covers leaf shutdown).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for **0.9.44**.

Related:

- [Privsep 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md)
- Lint: `vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh`
- Packaging: `pkg/check-mcp-pkg.sh`

## Automated prerequisites

```bash
bash vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh
bash pkg/check-mcp-pkg.sh
rtk cargo test -p vauban-proxy-mcp -p vauban-supervisor -p vauban-web -- mcp -- --test-threads=1
```

`[mcp].enabled` stays false in `config/default.toml` and
`config/vauban.conf` until this runbook is executed on a staging host
that has set `enabled = true` in an overlay. `allow_loopback_targets`
stays false.

## A -- open and relay

1. Create an MCP asset and an access rule whose tool allow-list is non-empty.
2. `POST /api/v1/mcp/sessions` with a `vbn_` key, the asset id, and a justification of 10 to 1000 characters.
3. Pass: the JSON contains `session_id`, `url`, and a `bearer` that starts with `vbw_`. `POST /api/v1/sessions` with the same asset does not return a `vbw_`.
4. `POST /mcp` on the proxy with `Authorization: Bearer <vbw_>` and a JSON-RPC `initialize`. Pass: the proxy answers, and a call outside the frozen allow-list is refused before the upstream (`-32001` or `-32033`).
5. `POST /health` and `POST /session` on the proxy are 404.

## B -- HITL by a second human

1. Put one tool in HITL on the access rule and repeat A.
2. `tools/call` on that tool returns `-32030`.
3. A second human who is not the opener approves it on `/sessions/mcp`.
4. Pass: the same `tools/call` is then relayed. The opener cannot approve their own pending.

## C -- linked restart, no reqwest

1. Kill `vauban-proxy-mcp`.
2. Pass: the supervisor restarts the linked group `{web, proxy_ssh, proxy_rdp, proxy_mcp}` and the pipes come back.
3. `vauban-proxy-mcp` does not link `reqwest`. `bash vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh` is clean.
4. A `TcpConnect` aimed at the proxy's own listen port is refused.
