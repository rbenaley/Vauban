#!/usr/bin/env bash
# Structural lint: forbid any Redis/Valkey dependency.
#
# Redis was fully removed from Vauban (VAU-012 follow-up): the rate limiter is
# in-memory only and the cache is an in-process no-op. Nothing may re-introduce
# an external cache server, so the following must NOT appear:
#
#   1. `vauban-web/Cargo.toml` may not declare a `redis` dependency.
#   2. The production portion of `vauban-web/src/**/*.rs` (everything before the
#      first `#[cfg(test)]` per file) may not reference the redis crate,
#      Valkey, the default Redis port, a `redis://` URL, or a
#      `MultiplexedConnection`.
#   3. The `config/**` TOML/conf files may not carry a Redis URL.
#
# A non-zero exit code blocks CI on the first offending occurrence.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # vauban-web
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"             # repository root
CARGO_TOML="${ROOT}/Cargo.toml"
SRC_DIR="${ROOT}/src"
CONFIG_DIR="${REPO_ROOT}/config"

# Forbidden tokens. `\bredis\b` does not match `is_redis` (underscore is a word
# char), but we removed every such helper anyway.
PATTERN='\bredis\b|valkey|6379|MultiplexedConnection|redis://'

errors=0

report() {
    # $1 = file, reads "line_no:line" on stdin
    while IFS=: read -r line_no line; do
        echo "[lint] ${1}:${line_no} -- forbidden Redis/Valkey reference; the cache is in-memory only" >&2
        echo "    > ${line}" >&2
        errors=$((errors + 1))
    done
}

# Rule 1: no redis dependency in Cargo.toml.
if [[ -f "${CARGO_TOML}" ]]; then
    grep -niE "^[[:space:]]*redis[[:space:]]*=" "${CARGO_TOML}" | report "${CARGO_TOML}" || true
fi

# Rule 2: no Redis reference in the production portion of src/**.
if [[ -d "${SRC_DIR}" ]]; then
    while IFS= read -r -d '' file; do
        prod_portion="$(awk '/#\[cfg\(test\)\]/{exit} {print}' "${file}")"
        printf '%s\n' "${prod_portion}" | grep -niE "${PATTERN}" | report "${file}" || true
    done < <(find "${SRC_DIR}" -type f -name "*.rs" -print0)
fi

# Rule 3: no Redis URL in the config files.
if [[ -d "${CONFIG_DIR}" ]]; then
    while IFS= read -r -d '' file; do
        grep -niE "${PATTERN}" "${file}" | report "${file}" || true
    done < <(find "${CONFIG_DIR}" -type f \( -name "*.toml" -o -name "*.conf" \) -print0)
fi

if (( errors > 0 )); then
    echo "[lint] ${errors} forbidden Redis/Valkey reference(s) found." >&2
    exit 1
fi

echo "[lint] no Redis/Valkey dependency (cache is in-memory, rate limiter is in-process)."
