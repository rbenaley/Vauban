#!/bin/sh
# Packaging pin for the MCP leaf (uid 910, loopback targets refused).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
conf="$root/config/vauban.conf"
toml="$root/config/default.toml"
cargo="$root/vauban-proxy-mcp/Cargo.toml"

test -f "$cargo" || { echo "missing $cargo"; exit 1; }
grep -q 'name = "vauban-proxy-mcp"' "$cargo"

awk '
  $0 ~ /^\[services\.proxy_mcp\]/ { in_s=1; next }
  $0 ~ /^\[/ { in_s=0 }
  in_s && $0 ~ /^uid = 910$/ { uid=1 }
  in_s && $0 ~ /^gid = 910$/ { gid=1 }
  END { if (!uid || !gid) { print "proxy_mcp uid/gid must be 910"; exit 1 } }
' "$conf"

grep -q 'allow_loopback_targets = false' "$toml"
grep -q 'allow_loopback_targets = false' "$conf"
grep -q 'require_seal = true' "$toml"
grep -q 'require_seal = true' "$conf"
awk '
  $0 ~ /^\[mcp\]/ { in_m=1; next }
  $0 ~ /^\[/ { in_m=0 }
  in_m && $0 ~ /bind_addr/ { found=1 }
  END { if (found) { print "vauban.conf [mcp] must not keep bind_addr"; exit 1 } }
' "$conf"
echo "mcp pkg pin ok"
