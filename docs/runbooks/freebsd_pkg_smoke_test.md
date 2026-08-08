# Runbook -- FreeBSD package install smoke

> Staging ops checklist after building/installing `pkg/vcp-*.pkg`.
>
> Audience: staging / production operators on FreeBSD.
> Severity: **BLOCKING** for first package deploy or packaging changes.
>
> Related: [`storage_helper_ops.md`](storage_helper_ops.md),
> [`http_edge_smoke_test.md`](http_edge_smoke_test.md) §B2 (SIGHUP),
> `scripts/check_freebsd_pkg.sh`, `just package`.

## Automated prerequisites

```bash
bash scripts/check_freebsd_pkg.sh
rtk cargo test --test integration_tests -- freebsd_pkg -- --test-threads=1
rtk cargo test -p vcp --lib access_log -- --test-threads=1
```

`just package` / `pkg create` require a **FreeBSD** host with `pkg(8)`.

## Lab prerequisites

- FreeBSD staging host, PostgreSQL 18, root or `pkg` privileges.
- Release binaries: `just release` then `just package`.
- DNS / `webauthn_origin` / ACME domains aligned with `config/vcp.conf`.

## A -- Install and enable

```bash
pkg add ./pkg/vcp-<version>.pkg
sysrc vcp_store_enable=YES
sysrc vcp_enable=YES
service vcp_store start
service vcp start
```

Pass: both services running; `VCP_CONFIG_DIR` effective via rc.d
(`/usr/local/etc/vcp`); helper log shows `vcp-store listening`.
`service vcp status` reports the **daemon supervisor**
(`/var/run/vcp.pid`, same convention as `/var/run/vcp-store.pid`);
newsyslog signals `/var/run/vcp/vcp.pid` (process_guard, note the
subdirectory) for the access log. `service vcp stop` must leave
`vcp_store` running and must **not** leave a restart storm in
`/var/log/vcp.log`.

```bash
ls /usr/local/share/vcp/assets/manifest.toml   # Topcoat release bundle
service vcp status                              # supervisor at /var/run/vcp.pid
service vcp_store status
cat /var/run/vcp.pid /var/run/vcp/vcp.pid
service vcp stop && service vcp_store status    # store still up
```

Stop `vcp` **before** `vcp_store`. If the store socket disappears while
`daemon -r` is supervising the portal, every restart panics with
`storage helper connect failed … Connection refused` and the portal
respawns about once per second until the supervisor is killed.

### A2 -- Reserved port 443 for an unprivileged portal

The portal drops to uid `vcp` but listens on 443. `rc.d/vcp` loads
`mac_portacl(4)`, adds a rule for that single uid, and only then unreserves
the low port range. Verify after the first start:

```bash
kldstat -m mac_portacl
sysctl security.mac.portacl.rules        # expect uid:800:tcp:443
sysctl net.inet.ip.portrange.reservedlow net.inet.ip.portrange.reservedhigh
sockstat -4 -6 -l | grep ':443'          # owner must be vcp, not root
```

Pass: rule present, listener owned by `vcp`. If `mac_portacl` cannot load,
`vcp_prestart` refuses to start rather than leaving every low port open to
all users. Set `sysrc vcp_portacl_enable=NO` when the portal listens on a
port >= 1024 or behind a TLS-terminating proxy.

Certificates live in `0700 root:wheel` `/usr/local/etc/vcp/certs`; the
portal reaches them through a FACL (`ensure_portal_cert_acl`) because it
reads `server.key` and ACME rewrites the pair on renewal:

```bash
getfacl /usr/local/etc/vcp/certs | grep vcp
su -m vcp -c 'sh -c "head -c1 /usr/local/etc/vcp/certs/server.key >/dev/null"' \
  && echo cert_readable
```

### Troubleshooting: `daemon(8)` must stay root

`rc.subr` wraps the whole command in `su -m <user> -c ...` whenever its
internal `_user` variable is set. Two distinct bugs can trigger that:

1. Naming the service account variable `${name}_user` (`vcp_user` /
   `vcp_store_user`): rc.subr owns that name.
2. A sourced helper assigning `_user=...` from a precmd. sh `local` is
   **dynamically scoped** and precmds run inside `run_rc_command`, after
   it computed `_user` but before it builds the command line, so the
   assignment clobbers rc.subr's own variable (this is why `acl.sh`
   namespaces everything under `_vcpacl_`).

Diagnose with `env rc_debug=YES /usr/local/etc/rc.d/vcp_store start` and
read the `DEBUG: run_rc_command: doit:` line: any `su -m` wrapper there
means `daemon(8)` starts **unprivileged**, which produces both of these:

| Symptom | Failing call inside `daemon(8)` |
|---|---|
| `daemon: open: Permission denied` | `open_log()` on the `-o` path, before `daemon(3)` |
| `daemon: failed to set user environment` | `setusercontext(LOGIN_SETALL)` in `restrict_process()` |

Packaged rc.d uses `vcp_runas` / `vcp_store_runas`, so `daemon(8)` runs as
root, opens the log and pidfile, then drops privileges via `-u`.

```bash
# Confirm the supervisor is root and the child is the service user:
ps -o user,command -p "$(cat /var/run/vcp-store.pid)"
grep -n 'runas' /usr/local/etc/rc.d/vcp /usr/local/etc/rc.d/vcp_store
# Prove privilege drop works standalone:
/usr/sbin/daemon -u vcp /usr/bin/true; echo vcp_daemon:$?
/usr/sbin/daemon -u vcp-storage /usr/bin/true; echo store_daemon:$?
```

`setusercontext` also needs an **existing** home directory (pw home alone is
not enough) and a usable login class:

```bash
ls -ld /var/empty /var/db/vcp/portal /var/db/vcp/storage
pw usershow vcp
pw usershow vcp-storage
# Unblock without reinstall:
mkdir -p /var/empty /var/db/vcp/portal /var/db/vcp/storage
chmod 555 /var/empty
chown vcp:vcp /var/db/vcp/portal
chown vcp-storage:vcp-storage /var/db/vcp/storage
chmod 755 /var/db/vcp/portal
chmod 0700 /var/db/vcp/storage
pw usermod vcp -d /var/db/vcp/portal -L daemon -s /usr/sbin/nologin
pw usermod vcp-storage -d /var/db/vcp/storage -L daemon -s /usr/sbin/nologin
cap_mkdb /etc/login.conf
service vcp_store restart
service vcp restart
```

### Troubleshooting: hard-to-stop `vcp` / store-down restart storm

`daemon -r` respawns the portal on every exit. `service vcp stop` must
kill the **supervisor** (`/var/run/vcp.pid`). Killing only
`/var/run/vcp/vcp.pid` (process_guard) leaves `-r` running — the next
child appears within a second, so stop seems to "fail".

```bash
# Immediate unblock on a host still running the old rc.d:
pkill -f 'daemon: vcp\[' || true
rm -f /var/run/vcp.pid /var/run/vcp/vcp.pid
# After upgrading the package, a single stop is enough:
service vcp stop
```

If `/var/log/vcp.log` shows `storage helper connect failed … Connection
refused` in a tight loop, `vcp_store` is down — start the store first
(or stop the portal supervisor as above).

### Troubleshooting: `asset bundle missing` restart loop

`daemon -r` restarts the portal every second when the release Topcoat
bundle is missing at `/usr/local/share/vcp/assets` (staged from
`target/assets` by `just release` + `just package`). Symptom in
`/var/log/vcp.log`: panic at `src/app.rs` after
`vcp listening on https://0.0.0.0:443`.

```bash
service vcp stop
ls /usr/local/share/vcp/assets/manifest.toml
# Hotfix until the next pkg rebuild (from the release checkout):
#   cp -R target/assets /usr/local/share/vcp/assets
#   chmod -R a+rX /usr/local/share/vcp/assets
# Remove a leftover layout from older packages:
#   rm -rf /usr/local/bin/assets
service vcp start
```

If a log was rotated before `newsyslog.conf.d/vcp.conf` carried an
`owner:group` field, the live file is `root:wheel` and the service user
cannot reopen it:

```bash
ls -l /var/log/vcp*.log
chown vcp:wheel /var/log/vcp.log /var/log/vcp-access.log
chown vcp-storage:wheel /var/log/vcp-store.log
chmod 640 /var/log/vcp*.log
```

## B -- Reboot survival (FACL + /var/run)

```bash
reboot
# after boot:
service vcp_store status && service vcp status
getfacl /var/run/vcp
getfacl /var/run/vcp/store.sock
```

Pass: `/var/run/vcp` recreated with `user:vcp` ACE; socket connectable by
portal; blob root still `0700` vcp-storage only.

## C -- Peercred + artefact

1. Authenticated admin upload or GET of a known release package.
2. Optional: confirm foreign UID cannot use the socket.

Pass: artifact GET **200**; helper rejects non-800 peers.

## D -- Access log SIGHUP

```bash
newsyslog -F /var/log/vcp-access.log   # or: kill -HUP "$(cat /var/run/vcp/vcp.pid)"
# generate one HTTPS request, then:
tail -n 3 /var/log/vcp-access.log
```

Pass: new CLF lines append to the live path after rotation (portal reopened
the FD). See http-edge runbook §B2.

## Fail criteria

| Fail | Meaning |
|------|---------|
| Portal starts without `VCP_CONFIG_DIR` and looks for a checkout path | rc.d export missing |
| Socket connect EACCES after reboot | FACL / prepare_vcp_run_dir not applied |
| Access log empty after newsyslog | SIGHUP went to wrong pid or reopen missing |
| `migration apply` failed at install | Postgres down or `VCP_PACKAGE_ROOT` wrong |
