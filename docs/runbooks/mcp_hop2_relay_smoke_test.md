# Runbook -- MCP hop 2 on the bastion HTTPS listener

> Manual validation after shipping **hop 2 on vauban-web :443**
> (crates **0.9.45**): the MCP leaf has no listening socket; `POST /mcp`
> is relayed on a dedicated data pipe, and the tunnel mode terminates
> TLS inside the leaf.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for **0.9.45**. Do not ship without A–C.

Related:

- [MCP Architecture 1.0](../technical/Vauban_MCP_Architecture_EN(1.0).md) §4
- [ADR 009](../adr/009-mcp-no-oauth-for-now.md)
- [MCP staging acceptance](mcp_staging_gwt_acceptance.md)
- Lint: `vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh`

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p shared -p vauban-proxy-mcp -p vauban-supervisor -p vauban-web --all-targets -- -D warnings
bash vauban-proxy-mcp/scripts/check_mcp_no_lab_escape.sh
rtk cargo test -p shared -p vauban-proxy-mcp -p vauban-supervisor -p vauban-web -- mcp_relay -- --test-threads=1
```

## Lab prerequisites

- Binaries **0.9.45** coordinated (shared wire, supervisor, web, proxy-mcp).
- `[mcp].enabled = true` and `[mcp].require_seal = true` in production config.
- No `[mcp].bind_addr` key. Boot must refuse a file that still has it.
- One MCP asset, one `vbn_` key, and a second human who can approve HITL.
- Client IP allow-list that includes the operator workstation and excludes a second address.

## A -- Direct hop 2 on 443

1. `POST /api/v1/mcp/sessions` with the `vbn_` key. The returned `url` is `https://<bastion>/mcp` on port 443 (or the configured HTTPS port), not a dedicated MCP port.
2. `POST` that URL with `Authorization: Bearer <vbw_>` and a JSON-RPC `tools/list`. The response is the allow-listed catalogue.
3. From an address outside `security.allowed_client_networks`, the same `POST /mcp` never reaches the leaf (the web log has no relay for that IP).
4. `ss` / `sockstat` on the bastion shows no listen socket owned by `vauban-proxy-mcp`.

Pass: steps 1–4. A listen on 19443, or an `http://` hop-2 URL, is a fail.

## B -- Tunnel and pin mismatch

1. On the asset, set `connection_config.transport` to `tunnel` and open a new visit.
2. Run `vauban-mcp` (stdio) against that visit. A `tools/list` through the shim succeeds, and the web log does not contain the `vbw_` or the JSON-RPC body.
3. Change the recorded SPKI pin in the shim's known-hosts file and retry. The shim must refuse the handshake.
4. From an address outside `security.allowed_client_networks`, `GET /mcp/tunnel` is refused and the leaf log shows no `McpTunnelOpen` for that address.

Pass: the matching pin works, the mismatched pin is refused, and a denied address never opens a tunnel. A shim that continues after a pin change is a fail.

## C -- Linked restart keeps the data pipe

1. With a direct visit open, kill `vauban-proxy-mcp`.
2. The supervisor restarts `{web, proxy_ssh, proxy_rdp, proxy_mcp}`.
3. Open a new hop 1. Hop 2 on `POST /mcp` works again. The leaf still has no listen socket.

Pass: the new visit relays. A leaf that exits "data pipe required" after the restart is a fail.

## D -- Graceful shutdown of the leaf

1. With the supervisor running and `proxy_mcp` up, send SIGINT (Ctrl+C) to the supervisor.
2. The leaf log contains `Shutdown flag set, exiting main loop to run destructors`.
3. The supervisor log contains `proxy_mcp: Exited with code 0` and does not contain `proxy_mcp: Still running after timeout`.

Pass: the leaf exits 0 on the IPC shutdown, in the same breath as the other children. A `proxy_mcp: Still running, sending SIGKILL` line is a fail.
