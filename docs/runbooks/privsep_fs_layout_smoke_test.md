# Runbook -- Privsep filesystem layout smoke test

> Manual validation after shipping the **privsep FS layout gate**
> (issue #40): `pkg/privsep_fs_layout.list` is applied by
> `privsep_fs_apply.sh` and verified fail-closed by `vauban-supervisor`
> before any leaf spawn (production + `privsep=true` only).
> CI covers parse / evaluate / pins; staging proves a live FreeBSD
> package tree (`0600` + NFSv4 ACEs on `vauban.conf`).
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for production `privsep=true` boots.

Related:

- [Privsep Architecture 1.3](../technical/Vauban_Privsep_Architecture_EN(1.3).md) §6.2 / §7.4 / §7.5 / §7.6
- Catalogue: `pkg/privsep_fs_layout.list`
- Apply helper: `pkg/privsep_fs_apply.sh`
- Lint: `vauban-supervisor/scripts/check_privsep_fs_layout.sh`

## Automated prerequisites

```bash
bash vauban-supervisor/scripts/check_privsep_fs_layout.sh
rtk cargo fmt -p vauban-supervisor -- --check
rtk cargo clippy -p vauban-supervisor --all-targets -- -D warnings
rtk cargo test -p vauban-supervisor -- privsep_fs respawn_decision pkg_privsep -- --test-threads=1
```

## Lab prerequisites

- Packaged (or `pkg add`) binaries with production `vauban.conf`
  (`environment = "production"`, `privsep = true`).
- Ability to `getfacl` / `setfacl` on `/usr/local/etc/vauban/vauban.conf`.
- Ability to read supervisor logs (`/var/log/vauban.log` or daemon console).

## A -- Broken ACEs must not spawn web / linked-restart

1. Confirm a healthy layout: `getfacl /usr/local/etc/vauban/vauban.conf`
   lists `user:vb-web` (and the other `vb-*` accounts).
2. Copy the file over itself (or `cp` a template) so the inode loses
   NFSv4 ACEs; leave `chmod 600`. Do **not** re-run apply.
3. `service vauban restart` (or start).
4. Expect the supervisor to **refuse to boot** with a layout mismatch
   (`missing ACL for user:vb-web` or equivalent). Logs must **not**
   contain `Respawned web` or `Restarting linked group`.
5. Re-apply:
   ```sh
   . /usr/local/share/vauban/privsep_fs_apply.sh
   apply_privsep_layout /usr/local /usr/local/share/vauban/privsep_fs_layout.list
   ```
   Then start again.

Pass: one fail-closed refusal; no web/ssh crash loop; apply restores boot.

## B -- Intact layout boots

1. Layout from a normal `pkg install` / `pkg upgrade` (apply runs after
   `sed -i` in `+POST_INSTALL`).
2. `service vauban start`.
3. Supervisor logs `Privsep filesystem layout matches the catalogue`.
4. `vauban-web` serves the back-office; `proxy_ssh` stays up.

Pass: production boot with privsep; no layout error.

## C -- pkg reinstall reapplies the catalogue

1. After a successful A restore, `pkg upgrade -f vauban` (or reinstall).
2. `getfacl` still lists `user:vb-web:r` on `vauban.conf`.
3. Service starts without a layout mismatch.

Pass: `+POST_INSTALL` apply from the staged `.list` is the install path.
