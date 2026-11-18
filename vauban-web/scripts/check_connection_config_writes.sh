#!/usr/bin/env bash
#
# Lint: a handler never writes the whole `connection_config` of an
# existing asset.
#
# `connection_config` holds the pinned identity of a target, the
# mismatch flags, the credentials and the MCP catalogue. A handler that
# reads the asset and later writes the whole document back undoes
# whatever was stored in between: a pin, a flag raised by a failed
# connection. Writes go through `models::asset`:
#
#   - `patch_connection_config`        named keys, one statement;
#   - `ConfigPatch::between(..).expression()`  what an edit changed;
#   - `update_connection_config_with`  a document that depends on the
#                                      current one.
#
# Rule: in every source file of vauban-web except `models/asset.rs`
# (which implements the three ways above), and in the supervisor's
# `admin.rs` (the credential migration), outside tests, every
# `connection_config.eq(` / `config_col.eq(` of an `UPDATE` is one of:
#
#   - a `ConfigPatch` expression;
#   - the empty document `serde_json::json!({})` (the scrub of a deleted
#     asset);
#   - the `.set(` of a statement whose `.filter(` compares the column
#     with the document that was read (a compare-and-swap).
#
# An `INSERT` creates the document and is not concerned.
#
# Mirrors `tests/web/config_patch_test.rs`.
#
# Usage: bash vauban-web/scripts/check_connection_config_writes.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

status=0
writes=0

while IFS= read -r file; do
    result="$(awk '
        /#\[cfg\(test\)\]/ { exit }
        /diesel::insert_into\(/ { statement = "insert" }
        /diesel::update\(/ { statement = "update"; compared = 0 }
        /connection_config\.eq\(|config_col\.eq\(/ {
            # A filter compares the column; it does not write it. The
            # statement it belongs to is a compare-and-swap.
            if ($0 ~ /\.filter\(/) { compared = 1; next }
            if (statement == "insert") next
            if (compared) { print "ok " NR; next }
            arg = $0
            sub(/.*(connection_config|config_col)\.eq\(/, "", arg)
            if (arg ~ /^crate::models::asset::ConfigPatch/ ||
                arg ~ /^[a-z_]+\.expression\(\)/ ||
                arg ~ /^serde_json::json!\(\{\}\)/) {
                print "ok " NR
            } else {
                print "bad " NR ": " $0
            }
        }
    ' "${file}")"
    while IFS= read -r line; do
        case "${line}" in
            ok\ *) writes=$((writes + 1)) ;;
            bad\ *)
                echo "ERROR: ${file#"${CRATE_DIR}/"}:${line#bad }"
                echo "       write named keys with patch_connection_config, the change of an edit with ConfigPatch::between,"
                echo "       or compare the column with the document that was read"
                status=1
                ;;
        esac
    done <<< "${result}"
done < <(
    find "${CRATE_DIR}/src" -name '*.rs' ! -path "${CRATE_DIR}/src/models/asset.rs" | sort
    echo "${CRATE_DIR}/../vauban-supervisor/src/admin.rs"
)

if [ "${writes}" -eq 0 ] && [ "${status}" -eq 0 ]; then
    echo "ERROR: no connection_config write found; the lint looks at nothing"
    status=1
fi

if [ "${status}" -eq 0 ]; then
    echo "OK: ${writes} connection_config writes go through ConfigPatch or a compare-and-swap"
fi
exit "${status}"
