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

## Kerberos / Restricted Admin (phase A) -- live AD validation

> Applies whenever the Kerberos CredSSP leg changes (the local
> `connect_begin` / `CredsspSequence` mirrors in
> `vauban-proxy-rdp/src/session.rs`, the supervisor KDC **FD broker**, or an
> `sspi` bump). Requires a REAL Active Directory lab: a domain
> controller (KDC) and a domain-joined Windows target with
> `DisableRestrictedAdmin = 0`. No AD is available in CI -- the
> in-repo coverage stops at `kerberos_posture_pin_test.rs` (TSCredentials
> stay identity-free in `CredentialLess`), KDC FD lint/proptest/battle
> (`check_kerberos_kdc_fd.sh`), and the `web::rdp_kerberos_mode_test` E2E suite.
> Coordinated deploy: supervisor + proxy-rdp **0.9.30+**.

Prerequisites:

- `[auth.kerberos]` configured in the supervisor config (`enabled =
  true`, `realm`, `kdc_host` = the DC's FQDN or IP, `kdc_port = 88`).
- The RDP asset in Kerberos mode: `Authentication Mode = Kerberos -
  Restricted Admin` in the asset form, hostname = the target's FQDN
  (an IP is rejected by the form -- checkpoint 1 below).
- Target account is a member of `Administrators` on the target
  (Restricted Admin only exists for administrative logons).

Checklist:

1. **FQDN enforcement** -- editing the asset to an IP-literal hostname
   while in Kerberos mode is refused with the SPN explanation; the row
   is unchanged.
2. **Kerberos login** -- connect via the web viewer. Expected logs:
   supervisor `Kerberos KDC FD leased to proxy_rdp` (twice for AS then
   TGS); proxy performs local framed I/O (no KDC payload bytes on the
   supervisor IPC). Session opens WITHOUT any NTLM exchange. On the
   DC: events 4768 (TGT) + 4769 (service ticket for TERMSRV). On the
   target: logon event 4624 with `Restricted Admin Mode: Yes`.
3. **No password delegation** -- on the target, `mimikatz
   sekurlsa::logonpasswords` (lab only!) must NOT surface the proxy's
   account password for the RDP logon session; a `dir
   \\otherserver\share` from inside the session must FAIL (no
   delegable credentials -- the defining Restricted Admin property).
4. **Fail-closed: KDC unreachable** -- stop the KDC (or set a wrong
   `kdc_host`), reconnect. The session MUST fail with a KDC FD lease /
   I/O error; the proxy MUST NOT silently fall back to NTLM (grep: no
   NTLMSSP in the proxy debug logs). Supervisor must NOT log a
   payload-relay success line.
5. **Fail-closed: NTLM downgrade** -- point the asset (still in
   Kerberos mode) at a NON-domain-joined RDP host. CredSSP must abort
   (`kerberos` package cannot negotiate), not complete via NTLM.
6. **NTLM regression** -- switch the asset back to `Password / NTLMv2`
   mode: the historical NTLM path must work unchanged against the same
   target.

## Known-good reference

| Stack | Validated on | By |
|---|---|---|
| ironrdp 0.17.0 / connector 0.10 / session 0.11 / input 0.7 / sspi 0.21.2 | _pending first manual pass_ | _--_ |
