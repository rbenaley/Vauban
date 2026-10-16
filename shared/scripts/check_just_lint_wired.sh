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
validate_body="$(awk '/^validate:/{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}")"
if ! grep -q 'just lint' <<<"${validate_body}"; then
    echo "[lint] just validate must run \`just lint\`" >&2
    exit 1
fi
if ! grep -q 'just clippy' <<<"${validate_body}"; then
    echo "[lint] just validate must run \`just clippy\`" >&2
    exit 1
fi
if ! grep -q 'just test' <<<"${validate_body}"; then
    echo "[lint] just validate must run \`just test\`" >&2
    exit 1
fi
# `just build` compiles the same crates rustc will compile again for tests.
if grep -q 'just build' <<<"${validate_body}"; then
    echo "[lint] just validate must not run \`just build\`" >&2
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
test_body="$(awk '/^test /{p=1;next} p && /^[a-zA-Z]/{exit} p' "${JUST}")"
if ! grep -q -- '--all-features' <<<"${test_body}"; then
    echo "[lint] just test must pass --all-features so shared required-features suites run" >&2
    exit 1
fi

# vauban_test is one catalog. Those three packages stay single-threaded
# and are excluded from the parallel workspace invocation.
if ! grep -q -- '--exclude vauban-web --exclude vauban-access --exclude vauban-supervisor' <<<"${test_body}"; then
    echo "[lint] just test must exclude the vauban_test packages from the parallel run" >&2
    exit 1
fi
catalog_line="$(grep -- '-p vauban-web -p vauban-access -p vauban-supervisor' <<<"${test_body}" || true)"
if [[ -z "${catalog_line}" ]] || ! grep -q -- '--test-threads=1' <<<"${catalog_line}"; then
    echo "[lint] just test must run vauban-web, vauban-access, and vauban-supervisor with --test-threads=1" >&2
    exit 1
fi

# RDP's lockfile must not share the workspace target directory.
if ! grep -q 'rdp_manifest := rdp_path + " --target-dir target-rdp"' "${JUST}"; then
    echo "[lint] rdp_manifest must compile into target-rdp" >&2
    exit 1
fi

echo "[lint] just validate is lint + clippy + test; just test passes --all-features; RDP uses target-rdp"
