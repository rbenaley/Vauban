# Runbook -- RDP Remote Credential Guard smoke test

> Manual validation of the `kerberos_remote_guard` RDP mode against a
> real, domain-joined Windows target. CI covers the proxy's CredSSP
> sequence against an in-process KDC and target, and the policy of the
> redirection channel behind a scripted Kerberos session. It cannot
> cover a Windows target accepting the logon and using the channel:
> that is this checklist.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the release that ships the mode, and for
> any later bump of the IronRDP pin or of `sspi`. Do not ship without
> A to G.

Related:

- [RDP Architecture](../technical/Vauban_RDP_Architecture_EN(1.0).md),
  "Remote Credential Guard"
- [IronRDP upgrade smoke test](ironrdp_migration_smoke_test.md): run it
  first; this checklist assumes the three other modes still work.
- Lints: `vauban-proxy-rdp/scripts/check_patch_pins.sh`

The names below are examples. Replace `srv01.contoso.com` (target),
`dc01.contoso.com` (domain controller), `contoso.com` (domain),
`CONTOSO` (short domain name), `jdoe` (an account that is NOT a local
administrator of the target) and `192.0.2.10` (the address of the
domain controller) with those of the lab.

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
bash vauban-proxy-rdp/scripts/check_patch_pins.sh
rtk cargo test -p shared --all-features -- remote_guard rdp_auth
rtk cargo test -p vauban-supervisor --all-features -- remote_guard
rtk cargo test -p vauban-proxy-rdp -- remote_guard credssp_loop_tests
rtk cargo test -p vauban-proxy-rdp --test auth_mode_profile_invariants_test --test patch_pins_invariants_test
rtk cargo test -p vauban-web --all-features --test integration_tests -- --test-threads=1 remote_guard rdp_kerberos_mode rdp_ntlm_policy
# hand-off:
just validate
```

## Lab prerequisites

- A domain-joined Windows target that accepts Remote Credential Guard
  (the policy "Remote host allows delegation of non-exportable
  credentials", or `DisableRestrictedAdmin = 0` under
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`), reachable by its
  fully-qualified name.
- `[auth.kerberos]` configured for the realm, as for the other
  Kerberos modes.
- Two domain accounts allowed to log on through Remote Desktop: one
  that is not a local administrator of the target, one that is.
- The pinned TLS fingerprint of the target on the asset.
- Read access to the `vauban-proxy-rdp` log.

Create one RDP asset per account, hostname `srv01.contoso.com`, domain
`contoso.com`, mode `Kerberos - Remote Credential Guard`.

To type in the session, open a command prompt on the target
(Windows key + R, `cmd`).

## A -- Forms and configuration

1. With no `remote_guard_outbound_identity` key under `[rdp]`, open the
   asset form and select the mode.
2. Set `remote_guard_outbound_identity = "allow"`, restart, reload the
   form.
3. Set `remote_guard_outbound_identity = "services"`, restart.
4. Set it to `"Allow"`, restart.

Pass: (1) the notice says the session has no identity on the network
and names `"deny"`; (2) it says the target can act as the user and
names `"allow"`; the form has no control for the setting in either
case; (3) and (4) the supervisor and vauban-web refuse to start, and
the error for `"services"` says the value is planned and not
implemented. Restore `"deny"` (or remove the key) and restart.

## B -- Logon without outbound identity (`deny`, non-administrator)

1. Connect to the asset of `jdoe`.
2. In the session: `klist`.
3. `klist get cifs/dc01.contoso.com`.
4. `dir \\dc01.contoso.com\SYSVOL`.
5. Leave the session open for ten minutes, then read the proxy log.

Pass:

- the desktop opens; the proxy log has `Remote Credential Guard channel
  ready` with `outbound_identity=deny`;
- `klist` lists one ticket, `krbtgt/CONTOSO.COM`, flagged `forwarded`;
- step 3 fails with `0xc00000bb` ("The request is not supported");
- step 4 fails; no file is listed;
- the log has one `operation refused by policy` line for the session,
  then at most one `operations refused by policy` count per five
  minutes; it has no `ticket obtained by the target` line;
- the session is still usable after ten minutes.

## C -- Logon with outbound identity (`allow`, non-administrator)

Set `remote_guard_outbound_identity = "allow"`, restart, log `jdoe` off
the target (`logoff` in the session of B), then:

1. Connect to the asset of `jdoe`.
2. `klist`.
3. `klist get cifs/dc01.contoso.com`.
4. `dir \\dc01.contoso.com\SYSVOL`.
5. Read the proxy log.

Pass:

- the proxy log has `outbound_identity=allow`;
- `klist` lists service tickets next to the forwarded TGT;
- step 3 succeeds; step 4 lists the share;
- the log has, for the session, `ticket requested by the target` and
  `ticket obtained by the target` lines whose `service` is the service
  asked for (`cifs/dc01.contoso.com` among them), and nothing else from
  the requests: no key, no token;
- a few tens of operations at logon, then none while the session is
  idle: no line repeats several times per second.

## D -- Administrator account

Repeat B and C with the account that is a local administrator of the
target.

Pass: same results.

## E -- No NTLM

With `allow`, in a session of C:

1. `net view \\192.0.2.10`.
2. `dir \\192.0.2.10\C$` (administrator account).

Pass: both fail. The proxy log has `redirected NTLM refused` or no line
at all for them; it has no line that reports an NTLM operation as
performed.

`dir \\192.0.2.10\SYSVOL` fails on any Windows client whatever the
authentication: `SYSVOL` and `NETLOGON` require mutual authentication.
Do not use those two shares for this check.

## F -- Reconnection

With `allow`:

1. Connect, open a command prompt, run `klist` and note the start time
   of the `krbtgt` ticket.
2. Close the browser tab without logging off.
3. Connect again to the same asset.
4. `klist`, then `klist get ldap/dc01.contoso.com`.

Pass: the same Windows session comes back (the command prompt is still
there); the `krbtgt` ticket has a newer start time; step 4 succeeds.

## G -- Refusals

1. Point an asset in this mode at a target that does not accept Remote
   Credential Guard (the policy and the registry value of the
   prerequisites are off).
2. Store a wrong password on an asset in this mode and connect.
3. Set `ntlm_policy = "deny"`, restart, connect to an asset in this
   mode.

Pass: (1) no session; a holder of `assets:manage` reads that the target
did not negotiate, or refused the Remote Credential Guard logon; the
audit log has `RdpAuthFailed` with `reason = negotiation_refused` or
`remote_guard_refused`; (2) `reason = pre_auth_failed`; (3) the session
opens: the mode is a Kerberos mode.

## H -- Process environment

`ps eww <pid of vauban-proxy-rdp>`.

Pass: `VAUBAN_RDP_REMOTE_GUARD_OUTBOUND_IDENTITY` is not shown (read,
then removed).

## Not covered

A target whose Kerberos module is newer than Windows Server 2022
(Windows 11 24H2, Windows Server 2025). The proxy sends the ASN.1 slot
values documented for it, unchecked. If such a target does not accept
them, the session opens, outbound requests fail, and under `allow` the
proxy closes the session with the log line `the target asks for tickets
without end and never brings back a KDC reply`. Report the Windows
version with that line.

## Known-good reference

| Stack | Validated on | By |
|---|---|---|
| IronRDP main at `a8da54ba` / sspi 0.23.1, proxy of the release that ships the mode | _pending first manual pass_ | _--_ |

The redirected operations of this stack, with the IronRDP client
instead of the proxy, passed against a domain-joined Windows target on
2026-11-21: logon, outbound Kerberos, reconnection, for an
administrator and a non-administrator.
