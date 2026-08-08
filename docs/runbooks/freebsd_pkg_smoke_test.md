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
