---
title: Export asset SSH public keys for Ansible
slug: export-asset-ssh-public-keys-for-ansible
summary: "Use vauban-supervisor asset-pubkeys --format plain to produce user@host key lines for mass Ansible authorized_keys updates."
category: Deployment
status: PUBLISHED
version: v1
---

Vauban stores each bastion asset's SSH public key in the asset record when `auth_type = ssh_key`. Operators often need that inventory on the target side too: push the same keys into `.ssh/authorized_keys` on hundreds of hosts so jump or automation accounts stay aligned with the bastion catalog.

The supervisor admin command `asset-pubkeys` reads those public keys from the database (OpenSSH text in `connection_config` — no vault decryption) and prints them in a machine-friendly layout.

::: callout
Only non-deleted assets with `auth_type = ssh_key` are included. Password-auth assets never appear. In plain mode, rows without a usable public key are skipped so the stream stays pipe-safe.
:::

## Command

On a host that can reach the Vauban database with the usual supervisor config:

```
# /usr/local/libexec/vauban/vauban-supervisor asset-pubkeys --format plain
```

Default output (omit `--format`, or use `--format table`) is a psql-style table for humans. Prefer `--format plain` for automation.

## Plain line format

Each line is:

```
user@hostname ssh-ed25519 AAAA... comment
```

- The first field is `user@host` (login from `connection_config.username` when set, otherwise `connection_username`, then `@` and the asset hostname).
- The remainder of the line is the OpenSSH public key (type, key material, optional comment), suitable for an `authorized_keys` entry.
- One line per asset that has a non-empty public key; ordering is by hostname.

Example:

```
root@db-01.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial root@db-01
deploy@app-02.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherExampleKey deploy@app-02
```

## Capture a file for Ansible

Redirect stdout to an inventory-side artifact (keep it off world-readable paths):

```
# /usr/local/libexec/vauban/vauban-supervisor asset-pubkeys --format plain > /var/tmp/vauban-asset-pubkeys.txt
# chmod 600 /var/tmp/vauban-asset-pubkeys.txt
```

Sanity checks before a mass push:

- Line count matches the number of ssh_key assets you expect.
- Spot-check a few `user@host` values against the Vauban UI.
- Confirm every line starts with `user@` and contains a key type (`ssh-ed25519`, `ssh-rsa`, …).

## Feed Ansible

Ansible does not need a custom inventory plugin: treat the file as data. A typical pattern:

- Build or refresh the plain file on the controller or CI runner that can run `vauban-supervisor`.
- Parse each line into `user`, `host`, and `key`.
- Target `host` with remote user `user`, and ensure the key line is present in that user's `~/.ssh/authorized_keys`.

Illustrative playbook sketch (adapt paths, become, and host matching to your estate):

```
---
- name: Sync Vauban asset pubkeys into authorized_keys
  hosts: all
  gather_facts: false
  vars:
    vauban_pubkeys_file: /var/tmp/vauban-asset-pubkeys.txt
  tasks:
    - name: Load plain export
      ansible.builtin.slurp:
        src: "{{ vauban_pubkeys_file }}"
      register: apk_raw
      delegate_to: localhost
      run_once: true

    - name: Parse user@host and key
      ansible.builtin.set_fact:
        vauban_pubkey_rows: >-
          {{
            (apk_raw.content | b64decode).splitlines()
            | map('regex_replace', '^(\\S+)\\s+(.+)$', '\\1|\\2')
            | list
          }}
      run_once: true

    - name: Ensure key for this host
      vars:
        row: "{{ item.split('|') }}"
        asset_login: "{{ row[0].split('@')[0] }}"
        asset_host: "{{ row[0].split('@')[1] }}"
        asset_key: "{{ row[1] }}"
      ansible.builtin.authorized_key:
        user: "{{ asset_login }}"
        key: "{{ asset_key }}"
        state: present
      when: inventory_hostname == asset_host or inventory_hostname in asset_host
      loop: "{{ vauban_pubkey_rows }}"
      loop_control:
        label: "{{ item.split('|')[0] }}"
```

::: callout
Match `asset_host` to your Ansible inventory carefully (FQDN vs short name). Prefer an explicit map or `ansible_host` alignment over loose substring matches before you run against production.
:::

## Operational notes

- Re-run the export whenever assets or their SSH public keys change in Vauban; treat the file as a generated artifact, not a hand-edited source of truth.
- Public keys are not secret, but the file still describes your jump topology — restrict who can read it and how it is shipped to runners.
- Assets missing a public key are omitted in plain mode; use `--format table` if you need to see empty-key rows for cleanup.
- This path does not push private keys and does not call the vault.

## Related commands

- Human review: `vauban-supervisor asset-pubkeys` (table).
- Full supervisor admin surface: see the Vauban operator README (`Asset Pubkeys` section).
