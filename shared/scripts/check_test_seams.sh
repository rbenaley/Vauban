#!/usr/bin/env bash
# The `shared` feature `test-seams` exposes env-free constructors
# (`AccessGuard::from_fds`, `session_token::proxy_gate::init_with_key`)
# that let a test install a session-token key or an AccessGuard without
# going through the supervisor-provided environment. A production build
# must never carry them.
#
# Enforces:
#   1. `test-seams` is named only in a `[dev-dependencies]` table (or a
#      `[target.*.dev-dependencies]` table) of any Cargo.toml, plus its
#      own declaration `test-seams = []` in shared/Cargo.toml. Never in
#      `[dependencies]`, `[workspace.dependencies]`, nor in another
#      crate's `[features]` (a forwarding feature would let a release
#      build switch it on).
#   2. `cfg(feature = "test-seams")` appears only under shared/src/.
#   3. Outside shared/src/, `init_with_key(` / `AccessGuard::from_fds(` are called
#      only from test code: `*/tests/**`, `*_test.rs` / `*_tests.rs`
#      files, or an inline top-level `#[cfg(test)] mod <name> {` block.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

fail=0

# 1. Manifests.
while IFS= read -r manifest; do
    bad="$(awk -v file="$manifest" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*\[/ { section = $0; gsub(/[[:space:]]/, "", section); next }
        /test-seams/ {
            if (section ~ /^\[(.*\.)?dev-dependencies(\..*)?\]$/) next
            if (file == "./shared/Cargo.toml" && section == "[features]" \
                && $0 ~ /^test-seams[[:space:]]*=[[:space:]]*\[\][[:space:]]*(#.*)?$/) next
            printf "%s:%d: %s %s\n", file, NR, section, $0
        }
    ' "$manifest")"
    if [[ -n "$bad" ]]; then
        echo "ERROR: test-seams outside [dev-dependencies]:" >&2
        echo "$bad" >&2
        fail=1
    fi
done < <(find . \( -path ./target -o -path ./.git -o -path ./.cursor -o -path '*/target' \) -prune \
    -o -name Cargo.toml -print | sort)

# 2. The feature gate lives in shared only.
gates="$(grep -rn --include='*.rs' 'feature *= *"test-seams"' . \
    --exclude-dir=target --exclude-dir=.git --exclude-dir=.cursor \
    | grep -v '^\./shared/src/' || true)"
if [[ -n "$gates" ]]; then
    echo "ERROR: cfg(feature = \"test-seams\") outside shared/src/:" >&2
    echo "$gates" >&2
    fail=1
fi

# 3. Call sites outside shared/src/ are test code.
while IFS= read -r file; do
    case "$file" in
        ./shared/src/*) continue ;;
        */tests/*) continue ;;
        *_test.rs|*_tests.rs) continue ;;
    esac
    bad="$(awk -v file="$file" '
        prev_cfg_test && /^(pub(\([a-z]+\))? )?mod [A-Za-z0-9_]+ *\{/ { in_test = 1 }
        { prev_cfg_test = ($0 ~ /^#\[cfg\(test\)\]/) }
        in_test && /^\}/ { in_test = 0; next }
        !in_test && /(init_with_key|AccessGuard::from_fds)\(/ && !/^[[:space:]]*\/\// {
            printf "%s:%d: %s\n", file, NR, $0
        }
    ' "$file")"
    if [[ -n "$bad" ]]; then
        echo "ERROR: test seam called from production code:" >&2
        echo "$bad" >&2
        fail=1
    fi
done < <(grep -rlE --include='*.rs' '(init_with_key|AccessGuard::from_fds)\(' . \
    --exclude-dir=target --exclude-dir=.git --exclude-dir=.cursor | sort)

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi
echo "[lint] test-seams is dev-only and its constructors are called from tests only"
