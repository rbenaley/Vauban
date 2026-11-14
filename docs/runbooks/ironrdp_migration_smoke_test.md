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
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target-rdp -- --test-threads=1
rtk cargo clippy --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target-rdp --all-targets
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
> Coordinated deploy: supervisor, vauban-web and proxy-rdp **0.9.50+**,
> together. 0.9.50 appends IPC messages (`KerberosKdcLeaseRequest`,
> `RdpSessionOpenFailed`), an auth mode and an audit event type that an
> older peer cannot decode.

Before the live checklist, run the two harnesses that need no Active
Directory (see section 11.3.1 of the RDP architecture document):

```bash
cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target-rdp \
  credssp_loop -- --test-threads=1
```

```bash
VAUBAN_TEST_MIT_KDC=1 cargo test --manifest-path vauban-proxy-rdp/Cargo.toml \
  --target-dir target-rdp -- --ignored mit_kdc --test-threads=1
```

Pass: 13 tests, then 3 tests. They validate how the proxy drives its
Kerberos library; the checklist below is what validates a real domain.

Prerequisites:

- `[auth.kerberos]` configured in the supervisor config (`enabled =
  true`, `realm`, `kdc_host` = the DC's FQDN or IP, `kdc_port = 88`).
- The RDP asset in a Kerberos mode: `Authentication Mode = Kerberos -
  Restricted Admin` (checkpoints 1 to 6) or `Kerberos` (checkpoints 7
  to 9) in the asset form, hostname = the target's FQDN (an IP is
  rejected by the form -- checkpoint 1 below).
- For `Kerberos - Restricted Admin`: the target account is a member of
  `Administrators` on the target (Restricted Admin only exists for
  administrative logons). For `Kerberos`: a domain account allowed to
  log on through Remote Desktop Services (`Remote Desktop Users`), NOT
  a local administrator.
- The asset's `Domain` field holds the **DNS name** of the domain
  (`corp.example.com`), not the NetBIOS short name (`CORP`). It becomes
  the Kerberos realm, upper-cased. The form refuses an empty domain or
  a short name in Kerberos mode (checkpoint 1b below).
- The supervisor was started normally. It removes `KRB5_CONFIG` and any
  `SSPI_KDC_URL*` variable from the environment its children inherit,
  and starts `vauban-proxy-rdp` with `KRB5_CONFIG=/dev/null`, so the
  host's `krb5.conf` never remaps the realm or the KDC.

Checklist:

1. **FQDN enforcement** -- editing the asset to an IP-literal hostname
   while in Kerberos mode is refused with the SPN explanation; the row
   is unchanged.
1b. **Domain enforcement** -- in Kerberos mode, saving the asset with an
   empty `Domain`, or with `CORP`, is refused with a message asking for
   the DNS name of the domain; the row is unchanged. The same asset in
   `Password / NTLMv2` mode still accepts `CORP`.
1c. **Ambient configuration isolation** -- start the supervisor with
   `SSPI_KDC_URL=tcp://203.0.113.9:88` and `KRB5_CONFIG=/tmp/hostile.conf`
   exported in its shell. Expected: the supervisor logs `Removed ambient
   Kerberos configuration from the environment` naming both variables;
   `ps eww <pid of vauban-proxy-rdp>` shows `KRB5_CONFIG=/dev/null` and
   no `SSPI_KDC_URL`; a Kerberos login still reaches the configured KDC
   only. Pass: no packet to `203.0.113.9`.
1d. **Realm routing** -- configure two realms under
   `[[auth.kerberos.realms]]`, each with its own KDC. Open one session
   on an asset of each domain. Expected: each DC logs event 4768 for its
   own users only. An asset whose domain is in NEITHER realm fails with
   `Kerberos realm <REALM> is not configured in [auth.kerberos]` in the
   supervisor log; no connection is attempted.
1e. **KDC failover** -- list two KDC hosts for a realm and stop the
   first (or point it at a closed port). Expected: the session opens;
   the supervisor logs `Kerberos KDC failover: earlier KDC hosts did not
   answer`. With every host down, the session fails with `no KDC
   reachable (tried N/N endpoints)` within `timeout_secs`, and the proxy
   does not fall back to NTLM.
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
7. **Standard Kerberos login (non-administrator)** -- set the asset to
   `Authentication Mode = Kerberos` with an account that is in `Remote
   Desktop Users` and NOT in `Administrators`. Connect via the web
   viewer. Expected: the session opens WITHOUT any NTLM exchange; DC
   events 4768 + 4769 (`TERMSRV/<fqdn>`); on the target, logon event
   4624 with `Authentication Package: Kerberos` and `Restricted Admin
   Mode: -` (or `No`). The same account in `Kerberos - Restricted
   Admin` mode must be REFUSED by the target (not an administrator).
8. **Standard Kerberos: fail-closed** -- repeat checkpoints 4 and 5
   with the asset in `Kerberos` mode. Same expectations: KDC down or a
   non-domain-joined target fails the session, with no NTLMSSP in the
   proxy debug logs.
9. **Standard Kerberos: delegation is expected** -- from inside the
   session of checkpoint 7, `dir \\otherserver\share` SUCCEEDS (the
   target holds delegable credentials, as with `Password / NTLMv2`).
   This is the documented difference with checkpoint 3, not a defect:
   the form states it under the `Kerberos` option.
10. **Failure reasons** -- for each row, provoke the failure with an
   account that holds `assets:manage`, and check the toast, the
   `RdpAuthFailed` audit event (`reason`, `auth_mode`) and the
   `vauban-proxy-rdp` warning `RDP session refused: NLA authentication
   failed` carrying the same `reason`.

   | Provoke | Expected `reason` | Toast mentions |
   |---|---|---|
   | wrong stored password | `pre_auth_failed` | stored credential |
   | username that does not exist | `client_principal_unknown` | username, DNS domain |
   | asset hostname = a DNS alias with no SPN | `service_principal_unknown` | `TERMSRV/`, `setspn` |
   | bastion clock 10 minutes ahead | `clock_skew` | NTP |
   | KDC stopped | `kdc_unreachable` | `[auth.kerberos]` |
   | asset domain of a realm absent from the table | `realm_not_configured` | `[[auth.kerberos.realms]]` |
   | account disabled in AD | `account_disabled_or_locked` | disabled, locked out |
   | account with "Do not require Kerberos preauthentication" | `pre_auth_not_required` | pre-authentication |
   | Restricted Admin mode, `DisableRestrictedAdmin = 1` | `restricted_admin_refused` | `DisableRestrictedAdmin` |
   | Kerberos mode, target outside the domain | `kerberos_package_refused` | No NTLM fallback |

11. **Reason disclosure** -- repeat one row of checkpoint 10 as a user
   who can open the session but does NOT hold `assets:manage`. The toast
   is `The target refused the authentication. Contact an administrator
   of this asset.` for every row. The audit event still carries the
   reason.
12. **No exchange data leaves the proxy** -- during checkpoint 10, the
   web process log and the browser never show KDC or target text (no
   `Additional error text`, no principal name). That text appears only
   in the `vauban-proxy-rdp` log.
13. **Mode over the API** -- with an API key that holds
   `assets:manage`:

   ```bash
   curl -sS -X POST https://<bastion>/api/v1/assets/manage \
     -H "Authorization: Bearer $VAUBAN_API_KEY" -H 'Content-Type: application/json' \
     -d '{"name":"srv01-krb","hostname":"srv01.corp.example.com","asset_type":"rdp","rdp_auth_mode":"kerberos","rdp_domain":"corp.example.com"}'
   ```

   Expected: HTTP 200, `connection_config.rdp_auth_mode` = `kerberos`.
   The same request with `"rdp_auth_mode":"kerbeross"`, with
   `"hostname":"192.0.2.10"`, or with `"rdp_domain":"CORP"` returns
   HTTP 400 and creates nothing. A `PUT` on the created asset with only
   `{"hostname":"192.0.2.10"}` returns HTTP 400 and leaves the asset
   unchanged.
14. **Unknown mode on the form** -- submit the asset form with a
   tampered `rdp_auth_mode` value (browser developer tools). Expected:
   an error flash naming the three accepted modes; the asset is not
   created, or keeps its stored mode on edit.
15. **Mode badge** -- `/assets/manage` shows `NTLM`, `Kerberos` or
   `Kerberos RA` next to each RDP asset and nothing next to SSH assets.
   The user-zone list `/assets` shows no such badge.
16. **NTLM policy: deny** -- set `ntlm_policy = "deny"` under `[rdp]`
   and restart. Expected:
   - an asset in `Password / NTLMv2` mode opens no session; the toast
     for a holder of `assets:manage` names `[rdp] ntlm_policy`; no row
     appears in the session list; the audit log has `RdpAuthFailed` with
     `reason = ntlm_forbidden`;
   - an asset in either Kerberos mode opens as in checkpoints 2 and 7;
   - the asset forms show `Password / NTLMv2 (forbidden by policy)`
     greyed out;
   - `ps eww <pid of vauban-proxy-rdp>` does not show
     `VAUBAN_RDP_NTLM_POLICY` (read, then removed).
17. **NTLM policy: proxy-side enforcement** -- (lab only) with
   `ntlm_policy = "deny"`, run vauban-web with a configuration that says
   `"allow"` while the supervisor keeps `"deny"`. Connect to an NTLM
   asset. Expected: the web tier lets the request through, the proxy
   logs `RDP session refused: NTLM is forbidden by policy`, and the
   session does not open.
18. **NTLM policy: mistyped value** -- set `ntlm_policy = "denny"`.
   Expected: the supervisor refuses to start and names the key. NTLM is
   not silently allowed.
19. **NTLM count** -- with the default policy, the dashboard
   access-posture tile shows `RDP assets on NTLM  n/total`. Switch one
   asset to a Kerberos mode: `n` decreases by one.
20. **NLA downgrade** -- (lab only) point an asset at a target that
   does not offer NLA (for example an xrdp host with a pinned
   certificate), or strip `PROTOCOL_HYBRID` from the X.224 Connection
   Request on the path. Expected, in every mode including `Password /
   NTLMv2`: no session; reason `negotiation_refused`; nothing is sent
   after the X.224 exchange (no TLS handshake, no KDC lease in the
   supervisor log). Before 0.9.50 the NTLM mode opened such a session
   without NLA: list the assets that relied on it before upgrading.
21. **Restricted Admin: nothing in the Client Info PDU** -- (lab only)
   on a target where TLS can be inspected, open a `Kerberos - Restricted
   Admin` session and check that the Client Info PDU carries an empty
   password. Together with checkpoint 3, this is what "the password
   never reaches the target" means.
22. **Restricted Admin not announced** -- on a target with Restricted
   Admin disabled, a `Kerberos - Restricted Admin` session fails with
   `negotiation_refused` (the target does not set
   `RESTRICTED_ADMIN_MODE_SUPPORTED`) or `restricted_admin_refused`.
   Record which one a real Windows target produces.

## Credential envelope (web does not decrypt)

The web viewer forwards the stored password (vault envelope or historical
plaintext) in `RdpSessionOpen.password`. The proxy opens a `credentials`
envelope through its vault pipe and refuses a truncated envelope. A
plaintext value is used as-is when no vault is configured (local dev).

Pass: a session against a vault-enrolled asset opens, and the web process
log contains no `VaultDecrypt` for domain `credentials`. A stored value
of `v1:` (no payload) is refused before any RDP handshake.

## Known-good reference

| Stack | Validated on | By |
|---|---|---|
| ironrdp 0.17.0 / connector 0.10 / session 0.11 / input 0.7 / sspi 0.21.2 | _pending first manual pass_ | _--_ |
