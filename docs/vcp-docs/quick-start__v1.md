---
title: Quick start — install Vauban LTS on FreeBSD
slug: quick-start
summary: "Download the LTS package from Builds, verify SHA-256, and install on FreeBSD."
category: Getting started
status: PUBLISHED
version: v1
---

Vauban LTS ships as a signed FreeBSD 15 package published in this portal. This guide takes you from Builds to a running bastion: download with a 5-minute link, verify SHA-256, install PostgreSQL 18, enable ACME, start the service, then create the first superuser. No agent is installed on protected machines — every SSH, RDP, and IACS session is brokered by the bastion.

::: callout
Prerequisites: a FreeBSD 15 server with root access, a DNS A/AAAA record pointing at that host, TCP/443 reachable from the public Internet (ACME TLS-ALPN-01), and an LTS (or Industrial LTS) subscription so builds are available for your organization.
:::

# 1. Download the package from this portal

Open Builds, select the LTS release (for 1.0.0 LTS the file is `vauban-1.0.0+LTS.pkg`), then click 5-minute download link. The portal issues a one-shot URL valid for five minutes. Copy the fetch command and run it on the bastion — no portal session is required on that host.

```
$ fetch https://access.vauban.sh/releases/<token>/vauban-1.0.0+LTS.pkg
```

If the countdown expires, generate a new link from Builds (or Revoke the old one). You can also use Download in the browser and copy the file to the host; the 5-minute link is the path meant for the server.

::: callout
The token is bound to that package name. Do not share a live link. After five minutes it returns expired; regenerate from Builds.
:::

# 2. Verify the SHA-256

Do not install until the digest matches. In Builds, open Verify signature (or copy the SIGNATURE column). On the FreeBSD host:

```
$ sha256 vauban-1.0.0+LTS.pkg
```

The 64-hex output must match the portal exactly. A mismatch means a truncated download or a substituted file — discard it and generate a new 5-minute link.

# 3. Install PostgreSQL 18

The bastion requires PostgreSQL 18, started before Vauban. The package post-install creates the `vauban` role and database when Postgres is already up.

```
# pkg install postgresql18-server
# pkg install postgresql18-contrib
# sysrc postgresql_enable=yes
# service postgresql initdb && service postgresql start
```

# 4. Install Vauban LTS

```
# pkg install vauban-1.0.0+LTS.pkg
# sysrc vauban_enable=YES
# vi /usr/local/etc/vauban/vauban.conf
```

`+POST_INSTALL` generates `secret_key`, the vault master key at `/var/vauban/vault/master.key`, and injects the database URL. Back up the vault key: loss makes encrypted secrets unrecoverable.

# 5. Configure FQDN and ACME

Replace the placeholders with the bastion's public name. TLS is issued automatically (TLS-ALPN-01 on port 443).

```
public_origins = ["https://bastion.domain.tld"]

[server.tls.acme]
enabled = true
email = "user@domain.tld"
domains = ["bastion.domain.tld"]
```

`public_origins` must be HTTPS and must match the name operators type in the browser. ACME `domains` must match the DNS record.

# 6. Start and verify

```
# service vauban start
# cat /var/log/vauban.log
```

Log rotation is shipped at `/usr/local/etc/newsyslog.conf.d/vauban.conf`. The supervisor stays root and forks privilege-separated children (web, auth, access, vault, audit, SSH/RDP proxies).

# 7. Create a superuser

At least one superuser is required to administer the bastion.

```
# /usr/local/libexec/vauban/vauban-supervisor create-superuser
```

Sign in on `https://bastion.domain.tld`. MFA (TOTP) is required for the web UI. From there, enroll SSH, RDP, and IACS assets and grant access through RBAC.

# Next steps

- Enroll the first asset in the admin UI and open a recorded session (SSH asciicast, RDP fMP4, IACS PCAP).
- Align origin settings only after the public HTTPS name is final.
