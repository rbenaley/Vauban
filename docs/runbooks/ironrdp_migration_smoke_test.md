# Runbook -- IronRDP upgrade manual smoke test

> Manual validation checklist against a REAL Windows RDP target after any
> IronRDP stack bump in `vauban-proxy-rdp` (no RDP server is available in
> CI, so the connect/reactivation paths can only be exercised end-to-end
> by hand). First applied for the 0.14 -> 0.17 migration (connector 0.10,
> session 0.11, input 0.7, sspi 0.21).
>
> Audience: release engineers.
> Severity: BLOCKING for the release -- do not ship an IronRDP bump
> without a full pass.

## Automated prerequisites (must be green BEFORE the manual pass)

```bash
rtk cargo test --workspace -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target -- --test-threads=1
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target --all-targets
```

The proxy suite carries the migration guards: locked-version pins
(`test_locked_ironrdp_stack_versions_are_pinned`), NTLM-only posture
(`test_ntlm_only_network_client_refuses_all_requests`), connector
security posture (`test_connector_config_security_posture`), the
DeactivateAll structural pins, and the input-pipeline proptest
invariants I1-I4.

## Manual checklist (Windows 10/11 or Server target, NLA enabled)

Connect through the Vauban web viewer (`/sessions/rdp/{uuid}`) with a
user holding an active RDP access rule.

1. **NLA/NTLM login** -- the session opens against a target with
   `SecurityLayer=SSL+NLA`; no fallback prompt, credentials injected by
   the proxy. A wrong password must fail BEFORE any desktop is shown.
2. **Certificate pinning (VAU-001)** -- with a pinned SPKI: connection
   succeeds; after swapping the server certificate: connection refused
   and the mismatch flag persisted.
3. **H.264 video mode** -- browser with WebCodecs: `mode video` log
   line, smooth updates. Verify the PNG fallback in a browser without
   WebCodecs (or `VideoDecoder` disabled).
4. **Resize + Deactivation-Reactivation** -- toggle browser fullscreen
   (client-initiated resize via Display Control), THEN change the
   resolution server-side (Settings > Display) to force a Server
   Deactivate All PDU. Expected: `Deactivation-Reactivation Sequence
   completed` log, desktop re-renders at the new size, no black frame
   longer than ~0.5 s (encoder grace period).
5. **Stuck-modifier fix regression** -- hold Shift, Cmd+Tab (or
   Alt+Tab) away, come back, type: no uppercase ghosting. Toggle
   CapsLock outside the tab, come back: lock state resynchronized on
   first keydown.
6. **Clean teardown** -- close the tab: `WebSocket closed` with
   `cause = "close"`, proxy session ends, recording finalized and
   playable.

## Known-good reference

| Stack | Validated on | By |
|---|---|---|
| ironrdp 0.17.0 / connector 0.10 / session 0.11 / input 0.7 / sspi 0.21.2 | _pending first manual pass_ | _--_ |
