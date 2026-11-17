# Runbook -- 0.9.53 session ownership smoke test

> Manual validation after shipping the session-ownership work: recording
> leases bound to the service that serves the session, files opened
> without following a symlink, one log event per line, SSH open failures
> as codes, atomic mismatch flags, and the ACME hardening.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for sections A and B on any deployment that
> records sessions. The automated suite covers each decision; this
> runbook covers what only a live bastion shows: that every recorder
> still obtains its files.

Related:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md), sections 4.3 and 4.5
- [IAM Architecture 1.1](../technical/Vauban_IAM_Architecture_EN(1.1).md), section 9.5.1
- [ACME TLS Architecture 1.0](../technical/Vauban_ACME_TLS_Architecture_EN(1.0).md), section 7.1
- [0.9.51 audit follow-ups smoke test](audit_followups_0951_smoke_test.md)
- [Adversarial review](adversarial_review.md)
- Lint: `shared/scripts/check_log_single_line.sh`

## Upgrade notes

Read these before deploying. Each one is a behavior change.

1. **Deploy every service together.** `vauban-audit` asks the
   supervisor for its files with a new message
   (`AuditRecordingFileRequest`). An older audit service next to a new
   supervisor obtains no file: no `meta.json`, no IACS capture. An
   older supervisor does not know the message.
2. **SSH proxy and web.** `vauban-proxy-ssh` answers a failed session
   open with a code. An older proxy still works, but every failure is
   then shown as the generic sentence and a changed host key is no
   longer flagged while connecting.
3. **Recording storage.** The supervisor no longer follows a symlink
   below the recording storage root when it creates or unlinks a file.
   The root itself may be a symlink. If `YYYY` or `YYYY/MM`
   directories are symlinks to another volume, new recordings in them
   are refused: mount the volume instead, or link the root. Playback
   and deletion still follow such links.
4. **ACME.** At most three renewals are started per fifteen minutes.
   `vauban-web` does not ask again by itself after a refusal: after
   correcting a configuration, restart it, and no more than three times
   in a quarter of an hour.
5. **Logs.** A line feed or carriage return inside a logged value is
   written as `\n` or `\r`. A log parser that relied on multi-line
   events sees one line per event.

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace --all-targets -- -D warnings
bash shared/scripts/check_log_single_line.sh
rtk cargo test -p shared --all-features --lib -- recording_open log_line
rtk cargo test -p vauban-supervisor --all-features -- attack_ session_owner file_broker
rtk cargo test -p vauban-audit --all-features --bin vauban-audit -- lease_source meta_path non_meta
rtk cargo test -p vauban-proxy-ssh --all-features -- host_key open_failure error_text
rtk cargo test -p vauban-web --all-features --test integration_tests -- trust_anchor_flag ssh_host_key_mismatch -- --test-threads=1
```

## Lab prerequisites

- A supervisor-launched bastion, the same build on every service.
- A user with an access rule on one SSH asset, one RDP asset, one MCP
  asset and one IACS asset, recording on.
- Shell access to the bastion host, the recording storage and the
  supervisor log.

## A -- Every recorder still obtains its files

For each protocol, open a session, use it, close it, and look at
`<storage>/YYYY/MM/<session_id>/`.

1. **SSH.** **Expected:** `session.cast` and `meta.json`. Playback
   works.
2. **RDP.** Resize the window twice during the session. **Expected:**
   `001.mp4` and one further segment per accepted resolution change,
   and a `meta.json` that lists them. Playback works.
3. **RDP with Kerberos**, if configured. **Expected:** as step 2.
4. **MCP.** **Expected:** `session.mcp.jsonl`, `session.cast` and
   `meta.json`.
5. **IACS.** Open two channels, close them, end the session.
   **Expected:** `session.json` with an end time and a reason,
   `channels/001.pcap.gz` and `channels/002.pcap.gz`, no raw `.pcap`
   left, and `meta.json`.
6. **IACS without a channel.** Authenticate and disconnect without
   opening a tunnel. **Expected:** `session.json` and a `meta.json`
   with an empty channel list.
7. **Expected in the supervisor log for steps 1 to 6:** no
   `Refused recording write lease`, no `Refused audit recording lease`,
   no `Refused recording unlink`. Any such line during normal use is a
   finding to report, with the session identifier.

## B -- A long session keeps recording

1. Keep an RDP session open for an hour and resize it at the end.
   **Expected:** a new segment is created.
2. Restart `vauban-web` during an SSH session. **Expected:** the
   session and its recording are unaffected.

## C -- A changed SSH host key is flagged

1. Change the host key of an SSH target (or pin a wrong key) and
   connect as a user. **Expected:** the toast says the target presented
   a host key that is not the pinned one; the asset page under
   `/assets/manage` turns red; the `vauban-proxy-ssh` log has
   `reason=host_key_mismatch`.
2. Point an SSH asset at a host that refuses the connection and
   connect. **Expected:** the toast is the sentence about the
   connection; the asset page does **not** turn red.
3. Store a wrong password and connect. **Expected:** the toast says
   the target refused the stored credentials; the asset page does not
   turn red.
4. As an administrator, use **Accept New Key** on the asset of step 1.
   **Expected:** the warning clears and a session opens.

## D -- One log event per line

1. Create an asset whose description or name you can control from the
   API, then trigger an error that logs a value you chose, with a line
   feed in it. A simple one: request a path with an encoded line feed.

   ```bash
   curl -sk "https://<bastion>/assets/%0AINFO%20forged%20entry" -o /dev/null
   ```

   **Expected:** in the `vauban-web` log the request is one line, with
   `\n` in the path if it is logged at all, and no line starts with
   `INFO forged entry`.

## E -- ACME

Skip when `[server.tls.acme] enabled = false`.

1. Force a renewal against the staging directory. **Expected:** it
   succeeds; the certificate directory holds no `*.tmp` file; the
   supervisor log names absolute paths.
2. Restart `vauban-web` four times within a few minutes with a
   certificate inside the renewal window. **Expected:** the fourth
   request is refused with `reason=acme_too_soon`. Wait fifteen
   minutes and restart once more. **Expected:** the renewal runs.

## Sign-off

| Section | Result | Operator | Date |
|---------|--------|----------|------|
| A | | | |
| B | | | |
| C | | | |
| D | | | |
| E | | | |
