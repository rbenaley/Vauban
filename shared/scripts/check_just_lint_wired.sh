#!/usr/bin/env bash
# Pin: `just validate` must invoke `just lint` so structural checks are not optional.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JUST="${ROOT}/Justfile"

if [[ ! -f "${JUST}" ]]; then
    echo "[lint] missing Justfile" >&2
    exit 1
fi

if ! grep -qE '^validate:' "${JUST}"; then
    echo "[lint] Justfile has no validate recipe" >&2
    exit 1
fi

# The validate body must call just lint (not merely mention it in a comment).
if ! awk '/^validate:/{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}" | grep -q 'just lint'; then
    echo "[lint] just validate must run \`just lint\`" >&2
    exit 1
fi

# The lab archive under .cursor/ must not supply check_*.sh. Those
# scripts lint the archive, not the product tree.
if ! awk '/^lint:/{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}" | grep -q 'path \./\.cursor'; then
    echo "[lint] just lint must prune .cursor so the lab archive is not linted" >&2
    exit 1
fi

# MCP packaging dry-check (Mac-safe) runs once, with the other lints.
# Live FreeBSD A–C stays in the staging runbook.
if ! awk '/^lint:/{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}" | grep -q 'just check-mcp-pkg'; then
    echo "[lint] just lint must run \`just check-mcp-pkg\`" >&2
    exit 1
fi

# Feature-gated shared suites (`required-features`) run because `just test`
# passes `--all-features`. A plain `cargo test --workspace` skips them.
if ! awk '/^test /{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}" | grep -q -- '--all-features'; then
    echo "[lint] just test must pass --all-features so shared required-features suites run" >&2
    exit 1
fi

echo "[lint] just validate runs lint (including check-mcp-pkg); just test passes --all-features"
