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

### Troubleshooting: `daemon: open: Permission denied`

On FreeBSD 13/14, `daemon -o` opens the log **as root** before `-u`.
`daemon: open: Permission denied` means that `open(2)` on the `-o` path
failed (not the pidfile — that would say `ppidfile`).

```bash
ls -ld /var/log
ls -lo /var/log/vcp-store.log   # watch for uchg/schg/sappnd
getfacl /var/log /var/log/vcp-store.log 2>/dev/null
# Isolate -o vs -P:
/usr/sbin/daemon -u vcp-storage -o /tmp/vcp-store.log /usr/bin/true; echo tmp:$?
/usr/sbin/daemon -P /var/run/vcp-store.pid -u vcp-storage /usr/bin/true; echo pid:$?
# Unblock flat layout:
touch /var/log/vcp-store.log
chown vcp-storage:wheel /var/log/vcp-store.log
chmod 640 /var/log/vcp-store.log
chflags noschg,nouchg /var/log/vcp-store.log 2>/dev/null || true
service vcp_store start
```

Packaged `rc.d` prestart touches `/var/log/vcp*.log` on every start.

### Troubleshooting: `daemon: failed to set user environment`

`daemon -u` calls `setusercontext(LOGIN_SETALL)`. Needs an **existing** home
directory on disk (pw home alone is not enough) and a usable login class.

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
# Prove setusercontext works:
/usr/sbin/daemon -u vcp /usr/bin/true; echo vcp_daemon:$?
/usr/sbin/daemon -u vcp-storage /usr/bin/true; echo store_daemon:$?
service vcp_store restart
service vcp restart
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
