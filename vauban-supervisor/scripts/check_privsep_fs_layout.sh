#!/usr/bin/env bash
# Bidirectional pin: pkg/+POST_INSTALL must not chmod/chown/setfacl
# except by sourcing privsep_fs_apply.sh (issue #40).
#
# INV-FS-1  +POST_INSTALL sources apply_privsep_layout
# INV-FS-2  no raw chmod/chown/setfacl/set_acl in +POST_INSTALL
# INV-FS-3  apply.sh + catalogue exist; ALL matches +PRE_INSTALL users
# INV-FS-4  supervisor include_str! the repo catalogue; verify-only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$ROOT"
else
    cd "$SCRIPT_DIR/../.."
fi

POST="pkg/+POST_INSTALL"
APPLY="pkg/privsep_fs_apply.sh"
LIST="pkg/privsep_fs_layout.list"
PRE="pkg/+PRE_INSTALL"
FS_RS="vauban-supervisor/src/privsep_fs.rs"
MAIN="vauban-supervisor/src/main.rs"
BUILD="pkg/build-pkg.sh"
fail=0

err() {
    echo "FAIL: $1" >&2
    fail=1
}

if ! grep -q 'privsep_fs_apply.sh' "$POST" || ! grep -q 'apply_privsep_layout' "$POST"; then
    err "INV-FS-1: +POST_INSTALL must source apply_privsep_layout"
fi

if grep -E '^[[:space:]]*(chmod|chown|setfacl|set_acl|set_default_acl|detect_acl_type)[[:space:]]' "$POST"; then
    err "INV-FS-2: +POST_INSTALL must not call chmod/chown/setfacl (use apply.sh)"
fi

if [[ ! -f "$APPLY" || ! -f "$LIST" ]]; then
    err "INV-FS-3: catalogue and apply helper must exist under pkg/"
fi

for u in vb-audit vb-vault vb-access vb-auth vb-ssh vb-rdp vb-web vb-iacs vb-mailer; do
    if ! grep -q "create_user_if_missing $u " "$PRE"; then
        err "INV-FS-3: +PRE_INSTALL must create $u (ALL list drift)"
    fi
    if ! grep -q "\"$u\"" "$FS_RS"; then
        err "INV-FS-3: privsep_fs.rs SVC_USERS must include $u"
    fi
done

if ! grep -q 'include_str!("../../pkg/privsep_fs_layout.list")' "$FS_RS"; then
    err "INV-FS-4: supervisor must include_str! the repo catalogue"
fi

if grep -qE '\b(setfacl|chmod|chown)\s*\(' "$FS_RS"; then
    err "INV-FS-4: privsep_fs.rs must be verify-only (no setfacl/chmod/chown)"
fi

if ! grep -q 'check_privsep_fs_layout' "$MAIN"; then
    err "INV-FS-4: run_supervisor must call check_privsep_fs_layout"
fi

if ! grep -q 'privsep_fs_layout.list' "$BUILD" || ! grep -q 'privsep_fs_apply.sh' "$BUILD"; then
    err "INV-FS-3: build-pkg.sh must stage the catalogue and apply helper"
fi

if [[ "$fail" -ne 0 ]]; then
    exit 1
fi
echo "OK: privsep FS layout pins"
