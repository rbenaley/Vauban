# Runbook -- MCP hop 2 on the bastion HTTPS listener

> Manual validation after shipping **hop 2 on vauban-web :443**
> (crates **0.9.45**, hardened in **0.9.46**): the MCP leaf has no
> listening socket; `POST /mcp` is relayed on a dedicated data pipe,
> and the tunnel mode terminates TLS inside the leaf.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for **0.9.46**. Do not ship without A–C.

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
rtk cargo test -p vauban-proxy-mcp -- data_pipe seal -- --test-threads=1
rtk cargo test -p vauban-proxy-mcp --test leaf_identity_boot_e2e_test -- --test-threads=1
rtk cargo test -p vauban-mcp -- --test-threads=1
bash shared/scripts/check_test_seams.sh
```

Known limit: `leaf_identity_boot_e2e_test` boots the real leaf binary, but on a macOS developer host the sandbox is a no-op. Real Capsicum is exercised only by step C.3 on FreeBSD staging. Linux Landlock is not exercised by any automated test either. CI does not replace C.3.

## Lab prerequisites

- Binaries **0.9.46** coordinated (shared wire, supervisor, web, proxy-mcp, `vauban-mcp` shim).
- `[mcp].enabled = true` and `[mcp].require_seal = true` in production config.
- No `[mcp].bind_addr` key. Boot must refuse a file that still has it.
- One MCP asset, one `vbn_` key, and a second human who can approve HITL.
- Client IP allow-list that includes the operator workstation and excludes a second address.

## A -- Direct hop 2 on 443

1. `POST /api/v1/mcp/sessions` with the `vbn_` key. The returned `url` is `https://<bastion>/mcp` on port 443 (or the configured HTTPS port), not a dedicated MCP port.
2. `POST` that URL with `Authorization: Bearer <vbw_>` and a JSON-RPC `tools/list`. The response is the allow-listed catalogue.
3. From an address outside `security.allowed_client_networks`, the same `POST /mcp` never reaches the leaf (the web log has no relay for that IP).
4. `ss` / `sockstat` on the bastion shows no listen socket owned by `vauban-proxy-mcp`.
5. Open `wss://<bastion>/mcp/tunnel` from an allowed address and send one 1 MiB binary frame (for example `websocat -b` fed by `head -c 1048576 /dev/zero`). The socket is closed by web (frames are capped at 192 KiB). Then repeat step 2: direct mode still answers. Also send step 2 with a 9 KiB `Authorization` header: the answer is `431` and the leaf log has no relay for it.

Pass: steps 1–5. A listen on 19443, an `http://` hop-2 URL, or a step-2 failure after the 1 MiB frame, is a fail.

## B -- Tunnel and pin mismatch

1. On the asset, set `connection_config.transport` to `tunnel` and open a new visit. Before the first shim run, open `/assets/manage/<uuid>` and record the **Tunnel fingerprint (SPKI)** (`SHA256:...`).
2. Run `vauban-mcp` (stdio) against that visit. The fingerprint it prints on first use equals the one recorded in step 1. A `tools/list` through the shim succeeds, and the web log does not contain the `vbw_` or the JSON-RPC body.
3. Change the recorded SPKI pin in the shim's known-hosts file (`$XDG_CONFIG_HOME/vauban/known_mcp_hosts`) and retry. The shim must refuse the handshake.
4. From an address outside `security.allowed_client_networks`, `GET /mcp/tunnel` is refused and the leaf log shows no `McpTunnelOpen` for that address.
5. Make hop 1 return a hop-2 `url` on another host (for example a staging reverse proxy that rewrites the `url` field). The shim refuses with a host mismatch, and the known-hosts entry for `--url` is unchanged. An `http://` `--url` is refused before any request. Note on a 0.9.45 pin store: replace the entry with a bare-host line (`<bastion> SHA256:...`, no port) holding the recorded pin and run the shim. The line becomes `<bastion>:<port>` and the shim logs `migrated legacy MCP tunnel pin`. Put a different pin on a bare-host line instead and the shim refuses with `differs from the legacy line`, leaving the file unchanged.
6. From one allowed address, open about 20 idle WebSockets on `/mcp/tunnel` (`[mcp].max_tunnels_per_ip = 16`). The 17th and later get `503`. A second address still connects. Wait past the TLS handshake timeout (10 s) or `[mcp].tunnel_idle_seconds`: the leaf logs the closes, and the first address can open tunnels again.

Pass: the matching pin works, the mismatched pin is refused, a denied address never opens a tunnel, a substituted hop-1 host is refused, and idle tunnels give their slots back. A shim that continues after a pin change or a host change is a fail.

## C -- Linked restart keeps the data pipe

1. With a direct visit open, kill `vauban-proxy-mcp`.
2. The supervisor restarts `{web, proxy_ssh, proxy_rdp, proxy_mcp}`.
3. In the leaf boot log after the restart, `MCP tunnel identity installed before the sandbox` comes before `MCP gateway ready`, the line `MCP seal policy` shows `require_seal=true`, and `MCP data loop limits` shows the `[mcp]` values (`relay_timeout` is `relay_timeout_seconds - 30`).
4. Open a new hop 1. Hop 2 on `POST /mcp` works again. The leaf still has no listen socket.

Pass: the new visit relays, the identity is installed before the gateway is ready, and the seal policy is on. A leaf that exits "data pipe required" after the restart, logs `MCP tunnel identity required before the sandbox`, or logs `require_seal=false` in production, is a fail.

## D -- Graceful shutdown of the leaf

1. With the supervisor running and `proxy_mcp` up, send SIGINT (Ctrl+C) to the supervisor.
2. The leaf log contains `Shutdown flag set, exiting main loop to run destructors`.
3. The supervisor log contains `proxy_mcp: Exited with code 0` and does not contain `proxy_mcp: Still running after timeout`.

Pass: the leaf exits 0 on the IPC shutdown, in the same breath as the other children. A `proxy_mcp: Still running, sending SIGKILL` line is a fail.
