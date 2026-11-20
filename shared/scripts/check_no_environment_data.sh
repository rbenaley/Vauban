#!/usr/bin/env bash
#
# Lint: no value from a real environment in tracked files.
#
# This repository is public and its history cannot be rewritten. A
# hostname, an address or a home directory copied from a real system
# stays readable forever once it is committed. Examples use reserved
# values instead.
#
# This script covers the part of that rule a pattern can find:
#
# 1. An IPv4 address is loopback, unspecified, in an RFC 5737
#    documentation block (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
#    or listed in `environment_data_baseline.txt`. The baseline holds the
#    addresses the tree already used when the lint was added; it is not
#    extended: a new example takes an RFC 5737 address.
# 2. A home directory (`/Users/<name>`, `/home/<name>`) uses a generic
#    name.
#
# It cannot find a real domain name, user name or identifier: naming one
# here would publish it. That part is the review of the staged diff
# before every commit.
#
# Not an address: a dotted number with an octet above 255 or a leading
# zero, and one whose four parts are all below 10 (a section number).
#
# Usage: bash shared/scripts/check_no_environment_data.sh [directory]
# Without argument, the tracked files of the repository are scanned.
# With a directory, every text file under it is (used by the tests).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BASELINE="${SCRIPT_DIR}/environment_data_baseline.txt"
SCAN_DIR="${1:-}"

IPV4='(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}(\.?($|[^0-9.]))'
HOME_DIR='/(Users|home)/[A-Za-z0-9._-]+'

# file:line:match, for every candidate.
candidates() {
    local pattern="$1"
    if [[ -n "${SCAN_DIR}" ]]; then
        grep -rnIoE "${pattern}" "${SCAN_DIR}" 2>/dev/null || true
    else
        git -C "${REPO_DIR}" grep -nIoE "${pattern}" -- . \
            ':!*.lock' ':!*.svg' ':!vauban-web/static/js/vendor' \
            ':!shared/scripts/environment_data_baseline.txt' \
            ':!shared/scripts/check_no_environment_data.sh' \
            ':!shared/tests/environment_data_invariants_test.rs' \
            2>/dev/null || true
    fi
}

status=0

bad_addresses="$(candidates "${IPV4}" | awk -v baseline="${BASELINE}" '
    BEGIN {
        while ((getline line < baseline) > 0) {
            sub(/#.*/, "", line); gsub(/[[:space:]]/, "", line)
            if (line != "") known[line] = 1
        }
    }
    {
        where = $0
        if (!match($0, /([0-9]+\.){3}[0-9]+/)) next
        # The match sits after "file:line:"; take the last dotted quad.
        rest = $0; address = ""
        while (match(rest, /([0-9]+\.){3}[0-9]+/)) {
            address = substr(rest, RSTART, RLENGTH)
            rest = substr(rest, RSTART + RLENGTH)
        }
        n = split(address, octet, ".")
        if (n != 4) next
        small = 1
        for (i = 1; i <= 4; i++) {
            if (octet[i] + 0 > 255) next
            if (length(octet[i]) > 1 && substr(octet[i], 1, 1) == "0") next
            if (octet[i] + 0 > 9) small = 0
        }
        if (small) next
        if (octet[1] == 127) next
        if (address == "0.0.0.0" || address == "255.255.255.255") next
        if (octet[1] == 192 && octet[2] == 0 && octet[3] == 2) next
        if (octet[1] == 198 && octet[2] == 51 && octet[3] == 100) next
        if (octet[1] == 203 && octet[2] == 0 && octet[3] == 113) next
        if (address in known) next
        split(where, part, ":")
        print part[1] ":" part[2] ": " address
    }
')"
if [[ -n "${bad_addresses}" ]]; then
    echo "[lint] IPv4 address outside loopback and the RFC 5737 documentation blocks:" >&2
    echo "${bad_addresses}" >&2
    echo "[lint] use 192.0.2.x, 198.51.100.x or 203.0.113.x; never an address of a real system." >&2
    status=1
fi

bad_homes="$(candidates "${HOME_DIR}" | awk '
    {
        if (!match($0, /\/(Users|home)\/[A-Za-z0-9._-]+$/)) next
        path = substr($0, RSTART, RLENGTH)
        name = path; sub(/^\/(Users|home)\//, "", name)
        if (name ~ /^(user|username|name|dev|builder|vauban|example|jdoe|john|alice|bob|runner)$/) next
        split($0, part, ":")
        print part[1] ":" part[2] ": " path
    }
')"
if [[ -n "${bad_homes}" ]]; then
    echo "[lint] home directory of a named user:" >&2
    echo "${bad_homes}" >&2
    echo "[lint] use a path relative to the repository, /path/to/..., or a generic name such as /home/user." >&2
    status=1
fi

if [[ "${status}" -ne 0 ]]; then
    exit 1
fi
echo "no environment data ok"
