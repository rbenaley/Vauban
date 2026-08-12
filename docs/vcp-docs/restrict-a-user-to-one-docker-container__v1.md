---
title: Restrict a user to one Docker container
slug: restrict-a-user-to-one-docker-container
summary: "Use a sudoers whitelist so an operator can only manage the lifecycle of a single container."
category: Security
status: PUBLISHED
version: v1
---

Application owners often need to start, stop, or restart their own container on a host reached through the bastion — without a root shell and without touching anyone else's workload. The mechanism is a `sudo(8)` policy that whitelists a fixed list of `docker` command lines for one account.

This guide uses the account `adm_app1` and the container `app1`. Substitute your own names; keep one policy file per account/container pair.

::: callout
Prerequisites: root access on the target host, Docker installed with the container `app1` already created, and a local account `adm_app1`. Never add that account to the `docker` group — group membership grants full control of the daemon, which is equivalent to root on the host and defeats this whole policy.
:::

## 1. Create the policy file

Always edit through `visudo`: it locks the file and refuses to save a broken policy. Drop-in files under `/etc/sudoers.d/` keep the change reviewable and removable.

```
# visudo -f /etc/sudoers.d/container_app1_commands
# visudo -c -f /etc/sudoers.d/container_app1_commands
# chmod 0440 /etc/sudoers.d/container_app1_commands
```

`visudo -c -f` re-checks the syntax, and `0440` is the mode sudo expects. A file with wrong permissions is ignored, which silently leaves the operator with no rights at all.

## 2. Whitelist the Docker commands

Declare a command alias listing every allowed invocation, in full, with absolute paths:

```
Cmnd_Alias CONTAINER_APP1_COMMANDS = \
/usr/bin/docker start app1,\
/usr/bin/docker stop app1,\
/usr/bin/docker restart app1,\
/usr/bin/docker stop -t 30 app1,\
/usr/bin/docker restart -t 30 app1,\
/usr/bin/docker pause app1,\
/usr/bin/docker unpause app1,\
/usr/bin/docker kill app1
```

Matching is literal and argument-sensitive: `docker stop app1` and `docker stop -t 30 app1` are two distinct entries, and neither authorizes the other. Check the binary path on your host (`command -v docker`) before copying the block — a wrong path means every command is refused.

::: callout
Do not whitelist `docker exec`, `docker run`, or any wildcard such as `/usr/bin/docker *`. Those let the operator mount the host filesystem or spawn a privileged container, which is a direct path to root.
:::

## 3. Grant the alias to the account

In the same file, bind the alias to the account:

```
adm_app1 ALL=(root) NOPASSWD: CONTAINER_APP1_COMMANDS
```

`(root)` is the target user the commands run as, and `NOPASSWD` avoids a password prompt on an account that may authenticate through the bastion rather than with a local secret. Grant nothing else: no `ALL` command set, no extra alias on the same line.

## 4. Verify as the operator

Log in as `adm_app1` and list the effective rights before testing a real action:

```
$ sudo -l
User adm_app1 may run the following commands on vauban:
    (root) NOPASSWD: CONTAINER_APP1_COMMANDS
$ sudo docker restart app1
app1
```

If `sudo -l` shows more than the alias, another sudoers file is widening the account — audit `/etc/sudoers` and the rest of `/etc/sudoers.d/`.

## 5. Optional: drop the sudo prefix

For day-to-day comfort, a shell function in the operator's `~/.bashrc` routes `docker` through sudo:

```
docker() {
  sudo /usr/bin/docker "$@"
}
```

```
$ source ~/.bashrc
$ docker stop app1
```

::: callout
This is ergonomics, not a security control. The sudoers policy still decides what runs; the function only saves typing, and it can be removed by the user at any time.
:::

## 6. Everything else is refused

Any command outside the list is denied and logged — including the same verb on a different container:

```
adm_app1@vauban:~$ docker restart app2
Sorry, user adm_app1 is not allowed to execute '/usr/bin/docker restart app2' as root on vauban.
```

Denials land in the host's sudo log (`/var/log/auth.log` or `/var/log/secure`, depending on the distribution), and the bastion session recording keeps the full transcript for audit.

## Operational notes

- One file per account/container pair, named after the pair (`container_app1_commands`), so revoking access is a single `rm` plus `visudo -c`.
- Extend the alias when the operator needs a new verb; never fall back to a broader rule to avoid an edit.
- Re-run `visudo -c` after any change, and re-check the Docker binary path after a Docker upgrade or a package migration.
- Combine with the bastion: Vauban decides who reaches the host and records the session, while sudoers decides what the account can do once there.
- Review the policy when the container is renamed — the whitelist keys on the exact container name and stops matching silently.
