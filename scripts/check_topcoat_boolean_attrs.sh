#!/usr/bin/env bash
# Ban stringly boolean HTML attrs in view! (selected/checked/disabled/…).
#
# Topcoat omits boolean attrs only when the expression is the bool `false`.
# Passing `""` still emits `selected=""` / `disabled=""` — and for <select>,
# every marked option is selected; browsers keep the *last* one. That silently
# rewrote Target organization / Channel on admin release edit (Save = wrong
# client / channel).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_topcoat_boolean_attrs: $*" >&2
  exit 1
}

# Conditional string "selected"/"" (or checked/disabled) — always emits attr.
if rg -n --glob '*.rs' \
  -e 'selected=\(if[[:space:]]' \
  -e 'checked=\(if[[:space:]]' \
  -e 'disabled=\(if[[:space:]]' \
  -e 'required=\(if[[:space:]]' \
  -e 'selected=\(.*\{[[:space:]]*"selected"[[:space:]]*\}' \
  -e 'checked=\(.*\{[[:space:]]*"checked"[[:space:]]*\}' \
  src/ >/tmp/vcp_bool_attrs_hits.txt 2>/dev/null; then
  cat /tmp/vcp_bool_attrs_hits.txt >&2
  fail "use boolean selected=(cond) / selected=(true); never if { \"selected\" } else { \"\" }"
fi

# Soft pin: release edit must keep boolean channel + org selection.
EDIT="src/app/admin/releases/release_id.rs"
[[ -f "$EDIT" ]] || fail "missing $EDIT"
grep -nE 'selected=\(org\.id == org_id\)' "$EDIT" >/dev/null \
  || fail "$EDIT must use selected=(org.id == org_id)"
grep -n 'selected=(track_selected)' "$EDIT" >/dev/null \
  || fail "$EDIT must use selected=(track_selected)"
grep -n 'selected=(channel_eol)' "$EDIT" >/dev/null \
  || fail "$EDIT must use selected=(channel_eol)"

echo "check_topcoat_boolean_attrs: OK"
