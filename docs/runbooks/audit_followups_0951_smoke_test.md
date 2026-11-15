# Runbook -- 0.9.51 audit follow-ups smoke test

> Manual validation after shipping 0.9.51, which closes four audit
> findings (root-side ACME write, file brokers without a caller check,
> `X-Forwarded-For`, CSRF on the pin routes) and two RDP information
> leaks (error text in the browser, credentials in asset API responses).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for sections A, C, and E on any deployment that
> uses ACME, a reverse proxy, or the JSON API. The automated suite covers
> each decision; this runbook covers what only a live bastion shows.

Related:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md) (file broker callers)
- [ACME TLS Architecture 1.0](../technical/Vauban_ACME_TLS_Architecture_EN(1.0).md), section 7.1
- [IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md), sections 7.6, 9.4, 9.5
- [RDP Architecture 1.0](../technical/Vauban_RDP_Architecture_EN(1.0).md), section 11.6 and Appendix B.1
- [Adversarial review](adversarial_review.md)
- Lints: `vauban-web/scripts/check_pin_routes_csrf.sh`,
  `vauban-web/scripts/check_test_asset_names_unique.sh`

## Upgrade notes

Read these before deploying. Each one is a behavior change.

1. **ACME.** The supervisor now reads `[server.tls.acme]` itself and
   refuses a renewal request whose directory or domains differ from it.
   `vauban-web` and the supervisor must read the same configuration:
   restart both after changing that table.
2. **Reverse proxies.** `X-Forwarded-For` is read from the right. With
   several proxies in a row, list every one of them in
   `trusted_proxies`. A single proxy that appends to `X-Forwarded-For`
   needs no change. A proxy that sets only `X-Real-IP` (nginx with just
   `proxy_set_header X-Real-IP $remote_addr`) must be declared with
   `[security] client_ip_header = "x-real-ip"`: `X-Real-IP` is no longer
   read as a fallback, and without the setting every client would be
   seen at the proxy's address.
3. **JSON API.** `GET /api/v1/assets` returns seven fields per asset
   (`id`, `uuid`, `name`, `hostname`, `port`, `asset_type`, `status`).
   The admin endpoints no longer return `password`, `private_key`, or
   `passphrase`; they return `credentials_present` instead.
4. **RDP proxy and web.** Deploy `vauban-web` and `vauban-proxy-rdp`
   together. An older proxy still works, but every non-NLA failure is
   then shown as the generic sentence.

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets -- -D warnings
bash vauban-web/scripts/check_pin_routes_csrf.sh
rtk cargo test -p vauban-supervisor --all-features -- attack_ file_broker -- --test-threads=1
rtk cargo test -p vauban-web --all-features --lib -- middleware::tests rdp_open_failure models::asset
rtk cargo test -p vauban-web --all-features --test integration_tests -- pin_csrf attack_assets_read attack_api_never -- --test-threads=1
rtk cargo test --manifest-path vauban-proxy-rdp/Cargo.toml --target-dir target-rdp
```

## Lab prerequisites

- A supervisor-launched bastion, version 0.9.51 on every service.
- An administrator (`assets:manage`) and a regular user with an access
  rule on one SSH asset and one RDP asset.
- An API key for each of the two accounts.
- Shell access to the bastion host and to the supervisor log.

## A -- ACME renewal takes its paths from the supervisor

Skip when `[server.tls.acme] enabled = false`.

1. With ACME enabled against the staging directory, force a renewal
   (restart `vauban-web` with a certificate inside the renewal window).
   **Expected:** the supervisor log shows `Received ACME renewal request
   from web`, the certificate and key are written at
   `[server.tls] cert_path` and `key_path`, and the account file at
   `[server.tls.acme] account_key_path`.
2. Edit `domains` in the configuration, restart `vauban-web` only, and
   force a renewal. **Expected:** the supervisor log shows
   `Refused ACME renewal request` with `reason=acme_domain_not_configured`,
   and no file under the certificate directory changes (compare `ls -l`
   timestamps).
3. Restart the supervisor. **Expected:** the next renewal succeeds.

## B -- File brokers refuse a service that has no reason to ask

1. Open an SSH session and an RDP session with recording on, close
   them, and play both recordings back. **Expected:** recording and
   playback work as before, and the supervisor log has no
   `Refused file broker request` line.
   The same holds for `Refused recording write lease`.
2. Open an RDP session with recording on and resize the window twice.
   **Expected:** the session directory holds `001.mp4`, `002.mp4`,
   `003.mp4` and a `meta.json` listing the three segments.
3. Open an IACS session with one channel and close it. **Expected:**
   `session.json` has an end time and a reason (it is the one file
   written twice), and `channels/001.pcap.gz` exists.
4. **Expected over a day of normal use:** that line never appears. Each
   occurrence names a service and an operation; a service that is not a
   proxy asking for `recording_write`, or anything but `audit` asking
   for `audit_log_segment`, is a finding to report.

## C -- The client address behind a reverse proxy

Skip when `trusted_proxies` is empty.

1. Through the proxy, sign in. **Expected:** the session list and the
   audit trail show your real address.
2. Send a request through the proxy with a forged header:

   ```bash
   curl -sk -H 'X-Forwarded-For: 10.9.9.9' https://<bastion>/login -o /dev/null
   ```

   Then fail a login five times with the same header. **Expected:** the
   rate limiter and the audit trail record your real address, not
   `10.9.9.9`.
3. With two proxies in a row and only the outer one listed, the audit
   trail shows the inner proxy's address. Add it to `trusted_proxies`,
   restart `vauban-web`, and repeat step 1. **Expected:** your real
   address.
4. If `allowed_client_networks` is set, connect from an address outside
   it while sending `X-Forwarded-For: <an allowed address>`.
   **Expected:** refused.
5. In `x-real-ip` mode, repeat step 2 with
   `-H 'X-Forwarded-For: 10.9.9.9'`. **Expected:** your real address is
   recorded; the header is ignored.

## D -- Pinning needs the token

1. As the administrator, open an SSH asset under `/assets/manage`, and
   use **Fetch Host Key**. **Expected:** the key is fetched and pinned.
2. Change the host key of the target, reload the page, and use
   **Accept New Key** in the red fragment. **Expected:** the new key is
   pinned. This exercises the confirmation sent in the request body by a
   fragment that HTMX swapped in.
3. Repeat 1 and 2 on an RDP asset (**Fetch Certificate**, **Accept New
   Certificate**).
4. From the browser console of another origin, or with `curl` and only
   the session cookie:

   ```bash
   curl -sk -X POST -b 'access_token=<token>' \
     'https://<bastion>/assets/manage/<uuid>/fetch-host-key?confirm=true' -i
   ```

   **Expected:** a client error, and the pinned key is unchanged.

## E -- Asset responses carry no credential

1. With the regular user's API key:

   ```bash
   curl -sk -H 'Authorization: Bearer <key>' https://<bastion>/api/v1/assets | jq '.[0] | keys'
   ```

   **Expected:** exactly `asset_type`, `hostname`, `id`, `name`, `port`,
   `status`, `uuid`.
2. With the administrator's API key, read an asset that has a password:

   ```bash
   curl -sk -H 'Authorization: Bearer <key>' \
     https://<bastion>/api/v1/assets/manage/<uuid> | jq '{credentials_present, connection_config}'
   ```

   **Expected:** `credentials_present` contains `"password"`,
   `connection_config` has no `password`, `private_key`, or `passphrase`
   key, and no value starts with `v1:`.
3. Open a session on that asset. **Expected:** it still logs in: the
   stored credential is untouched.

## F -- RDP failures show a constant sentence

1. Point an RDP asset at a host that refuses the connection and connect.
   **Expected:** the toast is a fixed sentence about reaching the
   target. The detail is in the `vauban-web` or supervisor log.
2. Replace the certificate of an RDP target (or pin a wrong
   fingerprint) and connect. **Expected:** the toast says the target
   presented a certificate that is not the pinned one, the asset page
   turns red, and the `vauban-proxy-rdp` log has
   `reason=server_certificate_mismatch` with the detail.
3. Break TLS on the target for another reason (for example a TLS 1.0
   only listener). **Expected:** the toast says the TLS handshake
   failed, and the asset page does **not** turn red.

## Sign-off

| Section | Result | Operator | Date |
|---------|--------|----------|------|
| A | | | |
| B | | | |
| C | | | |
| D | | | |
| E | | | |
| F | | | |
