# Runbook -- atomic connection_config, SSH codes, ACME retry, IACS claim

> Manual validation after shipping the follow-ups to the 0.9.53
> session-ownership work: `connection_config` written key by key, SSH
> one-shot operations answering with codes, ACME renewal asked again
> after a failure, and the IACS session claimed when the tunnel opens.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for section D on any deployment that uses IACS
> tunnels. The automated suite covers each decision; this runbook
> covers what only a live bastion shows.

Related:

- [IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md), sections 9.5.2 and 9.5.3
- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md), section 4.3
- [ACME TLS Architecture 1.0](../technical/Vauban_ACME_TLS_Architecture_EN(1.0).md), section 7.1
- [0.9.53 session ownership smoke test](session_ownership_0953_smoke_test.md)
- Lint: `vauban-web/scripts/check_connection_config_writes.sh`

## Upgrade notes

Read these before deploying. Each one is a behavior change.

1. **Deploy every service together.** `vauban-web` presents the IACS
   session token to the supervisor when it opens a tunnel
   (`SessionClaimRequest`). An older supervisor does not know the
   message and the tunnel is not opened. An older `vauban-web` next to
   a new supervisor opens the tunnel, but no IACS file is granted: no
   `session.json`, no capture.
2. **SSH proxy and web.** `vauban-proxy-ssh` answers the host key
   fetch, the key push and the key test with a code. An older proxy
   still works; its error is then shown as the generic sentence.
3. **Pinning.** A pin is stored only if the pin of the asset is still
   the one the page showed. Two administrators pinning the same asset
   at the same time: the second is asked to reload. The API answers
   409.
4. **ACME.** `vauban-web` asks for a renewal again by itself after a
   refusal or a failure: 15 minutes, then 30, one hour, up to six
   hours. This supersedes upgrade note 4 of the 0.9.53 runbook: there
   is no need to restart `vauban-web` after correcting a
   configuration, though a restart still asks at once.

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets -- -D warnings
bash vauban-web/scripts/check_connection_config_writes.sh
rtk cargo test -p vauban-web --all-features --lib -- models::asset ssh_open_failure tasks::acme
rtk cargo test -p vauban-web --all-features --test integration_tests -- config_patch trust_anchor_flag -- --test-threads=1
rtk cargo test -p vauban-supervisor --all-features -- attack_ session_owner session_claim
rtk cargo test -p vauban-proxy-ssh --all-features
```

## Lab prerequisites

- A supervisor-launched bastion, the same build on every service.
- Two administrator accounts (`assets:manage`).
- One SSH asset, one RDP asset, one MCP asset, one IACS asset.
- Shell access to the bastion host and to the logs.

## A -- A pin survives a concurrent write

1. Open the same SSH asset under `/assets/manage` in two browsers, as
   the two administrators. In both, the host key is not pinned yet.
2. In the first, use **Fetch Host Key**. **Expected:** pinned.
3. In the second, without reloading, change the host key of the
   target, then use **Fetch Host Key**. **Expected:** the red fragment
   asking to confirm the change, not a silent replacement.
4. Still without reloading the second browser, edit the asset there
   (change the description only) and save. Reload the first browser.
   **Expected:** the pinned key is still the one of step 2.
5. Repeat 1 to 4 on the RDP asset (**Fetch Certificate**).

## B -- An edit keeps a flag raised meanwhile

1. Open the edit form of an SSH asset and leave it open.
2. Change the host key of the target and try to connect as a user.
   **Expected:** refused, the asset page turns red.
3. Save the form of step 1 with a changed description. **Expected:**
   the description is saved and the asset page is still red.

## C -- SSH operations show a constant sentence

1. On an SSH asset with a stored password, break the password and use
   **Push public key**. **Expected:** the toast says the target refused
   the stored credentials. It quotes nothing from the target.
2. Make `~/.ssh` unwritable on the target and push again.
   **Expected:** the toast says the command run on the target failed;
   the output of the target is in the `vauban-proxy-ssh` log with
   `reason=remote_command_failed`.
3. Change the host key of the target and use **Test key-based
   authentication**. **Expected:** the toast says the target presented
   a host key that is not the pinned one, and the asset page turns red.
4. Stop the target and use **Fetch Host Key**. **Expected:** the
   sentence about the connection.

## D -- IACS still records

1. Open an IACS tunnel, authenticate from the EWS, open two channels,
   close them, end the session. **Expected:** `session.json` with an
   end time, `channels/001.pcap.gz`, `channels/002.pcap.gz`, no raw
   `.pcap`, and `meta.json`.
2. Open a tunnel, authenticate, and disconnect without opening a
   channel. **Expected:** `session.json` and a `meta.json` with an
   empty channel list.
3. Open a tunnel and wait an hour before authenticating (within the
   waiting-client TTL). **Expected:** as step 1.
4. **Expected in the supervisor log for steps 1 to 3:** no
   `Refused session claim`, no `Refused audit recording lease`, no
   `Refused recording unlink`. Any such line during normal use is a
   finding to report, with the session identifier.

## E -- ACME asks again

Skip when `[server.tls.acme] enabled = false`.

1. Remove a domain from `[server.tls.acme] domains`, restart the
   supervisor only, then restart `vauban-web` with a certificate inside
   the renewal window (it has kept the old list in memory until then;
   start it from a copy of the old file). **Expected:** the supervisor
   refuses with `reason=acme_domain_not_configured`; the `vauban-web`
   log says the renewal will be asked again in 15 minutes.
2. Restore the domain and restart the supervisor only. **Expected:**
   within 15 minutes, without restarting `vauban-web`, the renewal
   runs and the certificate is activated.
3. **Expected in the certificate directory:** no `*.tmp` file.
