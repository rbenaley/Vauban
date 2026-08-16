# Runbook -- Local lint tools (`just lint`)

> How to install the extra tools required by `just lint` / `just validate`
> on a developer laptop. There is no remote CI; this gate is local-only.
>
> Audience: every developer and agent before declaring a task done.
> Severity: **BLOCKING** for `just validate`.

## Automated prerequisites

```bash
just lint
```

## Required tools

### cargo-deny

```bash
cargo install cargo-deny --locked
cargo deny --version
```

`just deny` runs `cargo deny check advisories` on the workspace lockfile
and on `vauban-proxy-rdp/Cargo.lock`. Config: [`deny.toml`](../../deny.toml).

### Semgrep

This machine uses **MacPorts**, not Homebrew. Do not run `brew`.

The MacPorts `semgrep` port is an old devel snapshot (0.14) and is
**not** the tool `just semgrep` expects. Install the current CLI via
MacPorts Python:

```bash
# Preferred: MacPorts pip3 --user (lands in ~/Library/Python/*/bin)
pip3 install --user semgrep
# Alternative isolated install:
#   sudo port install pipx
#   pipx install semgrep
# `just semgrep` also searches ~/Library/Python/*/bin and ~/.local/bin
# when `semgrep` is not on PATH.
semgrep --version
```

`just semgrep` runs
[`.semgrep/untrusted-input.yml`](../../.semgrep/untrusted-input.yml)
with `--error`. Missing binary is a hard failure (no silent skip).

## A -- First-time laptop

1. Install both tools above.
2. `just lint` from the repo root.
3. Expect every `*/scripts/check_*.sh` to print `[lint] ...` and exit 0.

Pass: `just lint` exits 0.

## B -- Agent / validate

1. After any significant Rust change, `just validate` (build, lint, clippy
   `-D warnings`, tests).
2. Do not declare done on clippy or tests alone.

Pass: `just validate` exits 0.

## Related links

- [Adversarial review](adversarial_review.md)
- [LDAPS bind-DN smoke](ldaps_bind_dn_smoke_test.md)
- [WORM eager-boot smoke](worm_eager_boot_smoke_test.md)
