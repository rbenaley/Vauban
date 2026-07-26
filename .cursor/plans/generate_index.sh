#!/usr/bin/env bash
# Regenerate the "Full catalog A-Z" section of INDEX.md from plan frontmatter.
# Manual sections above the AUTO-CATALOG markers are preserved.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
INDEX="${DIR}/INDEX.md"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

status_for() {
  local file="$1"
  local fm
  fm="$(awk 'BEGIN{n=0} /^---[[:space:]]*$/{n++; if(n==2) exit; next} n==1{print}' "$file")"
  if [[ -z "$fm" ]]; then
    echo "Open"
    return
  fi
  local statuses has_open=0 has_cancelled=0 has_completed=0 s
  statuses="$(printf '%s\n' "$fm" | grep -E '^[[:space:]]+status:[[:space:]]+' | awk '{print $2}' | tr -d '"' || true)"
  if [[ -z "$statuses" ]]; then
    echo "Open"
    return
  fi
  while IFS= read -r s; do
    [[ -z "$s" ]] && continue
    case "$s" in
      pending|in_progress) has_open=1 ;;
      cancelled) has_cancelled=1 ;;
      completed) has_completed=1 ;;
    esac
  done <<<"$statuses"
  if [[ "$has_open" -eq 1 ]]; then
    echo "Open"
  elif [[ "$has_cancelled" -eq 1 ]]; then
    echo "Abandoned"
  elif [[ "$has_completed" -eq 1 ]]; then
    echo "Done"
  else
    echo "Open"
  fi
}

name_for() {
  local file="$1" fm name
  fm="$(awk 'BEGIN{n=0} /^---[[:space:]]*$/{n++; if(n==2) exit; next} n==1{print}' "$file")"
  name="$(printf '%s\n' "$fm" | grep -E '^name:[[:space:]]+' | head -1 | sed 's/^name:[[:space:]]*//; s/^["'\'']//; s/["'\'']$//')"
  if [[ -z "$name" ]]; then
    basename "$file" .plan.md
  else
    printf '%s' "$name"
  fi
}

{
  echo "<!-- AUTO-CATALOG:BEGIN -->"
  echo "| Plan | File | Status |"
  echo "|------|------|--------|"
  LC_ALL=C find "$DIR" -maxdepth 1 -name '*.plan.md' -print | LC_ALL=C sort | while IFS= read -r f; do
    base="$(basename "$f")"
    name="$(name_for "$f" | tr '|' '/')"
    st="$(status_for "$f")"
    printf '| %s | [`%s`](%s) | %s |\n' "$name" "$base" "$base" "$st"
  done
  echo "<!-- AUTO-CATALOG:END -->"
} >"$TMP"

if [[ ! -f "$INDEX" ]]; then
  mv "$TMP" "$INDEX"
  exit 0
fi

if ! grep -q '<!-- AUTO-CATALOG:BEGIN -->' "$INDEX"; then
  echo "ERROR: $INDEX missing AUTO-CATALOG markers" >&2
  exit 1
fi

awk -v cat="$TMP" '
  /<!-- AUTO-CATALOG:BEGIN -->/ {
    while ((getline line < cat) > 0) print line
    close(cat)
    skip=1
    next
  }
  /<!-- AUTO-CATALOG:END -->/ { skip=0; next }
  !skip { print }
' "$INDEX" >"${TMP}.out"

mv "${TMP}.out" "$INDEX"
echo "Updated $INDEX"
