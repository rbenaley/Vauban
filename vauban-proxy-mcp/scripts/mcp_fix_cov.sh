#!/usr/bin/env bash
# Coverage gate for the MCP security fixes (MCP Arch §13.1).
#
#   1. FULL_FILES: every executable non-test line must be hit (100 %).
#   2. Every other .rs file changed since $MCP_FIX_BASE in the covered crates:
#      every changed executable line must be hit (diff coverage).
#
# Lines that cannot run under `cargo test` (sandboxed main loops, FreeBSD-only
# paths) are listed in vauban-proxy-mcp/scripts/mcp_fix_cov_exceptions.txt as
# `path:line  # reason` or `path:~substring  # reason` (every line containing
# the substring).
# Test modules (from the first `#[cfg(test)]` + `mod` pair to EOF) are ignored.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

base="${MCP_FIX_BASE:-$(git merge-base HEAD mcp-patch-01 2>/dev/null || git rev-parse HEAD~1)}"
# Lines identical to the trunk came from merging it, not from this branch:
# a changed line counts only if it also differs from $MCP_FIX_UPSTREAM.
# Set MCP_FIX_UPSTREAM= (empty) to measure against $base alone.
upstream="${MCP_FIX_UPSTREAM-$(git rev-parse --verify -q main 2>/dev/null || true)}"
lcov="target/llvm-cov/mcp-fixes.lcov"
exceptions="vauban-proxy-mcp/scripts/mcp_fix_cov_exceptions.txt"

# Each fix lot appends the modules it owns.
FULL_FILES=(
  vauban-vault/src/authz.rs
  vauban-access/src/peer_authz.rs
  shared/src/json_redact.rs
  vauban-proxy-mcp/src/upstream_http.rs
  vauban-proxy-mcp/src/audit.rs
  shared/src/mcp_tool_fingerprint.rs
  vauban-proxy-mcp/src/tool_drift.rs
  vauban-proxy-mcp/src/agent_view.rs
  vauban-web/src/services/mcp_tool_drift.rs
  shared/src/session_token/replay_cache.rs
)

export DATABASE_URL="${DATABASE_URL:-postgresql://vauban_test:vauban_test@localhost/vauban_test}"

if [[ "${MCP_FIX_COV_SKIP_RUN:-0}" != "1" ]]; then
  cargo llvm-cov clean --workspace
  # Single-threaded like `just test`: the DB-backed suites share one schema.
  cargo llvm-cov --no-report -p shared --features json-redact,mcp-mandate,session-token,access-guard -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-vault -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-access -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-proxy-mcp -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-supervisor -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-web --lib -- --test-threads=1
  # Besides the MCP suites: the JIT revoke cascade and duration clamp end
  # suspended MCP sessions, cutting events end live sessions of every
  # protocol, and API key revocation and group member removal call the
  # cutting seams.
  cargo llvm-cov --no-report -p vauban-web --test integration_tests -- --test-threads=1 \
    mcp jit_grant_revocation jit_revocation_pins cutting_events test_revoke_api_key delete_confirm_flow
  mkdir -p "$(dirname "$lcov")"
  cargo llvm-cov report --lcov --output-path "$lcov"
fi

changed="$(git diff --name-only "$base" -- shared/src vauban-vault/src vauban-access/src vauban-proxy-mcp/src vauban-web/src vauban-supervisor/src | grep '\.rs$' || true)"

python3 - "$lcov" "$base" "$exceptions" "${FULL_FILES[*]}" "$changed" "$upstream" <<'PY'
import os, re, subprocess, sys

lcov_path, base, exc_path, full_raw, changed_raw, upstream = sys.argv[1:7]
root = os.getcwd()
full = [f for f in full_raw.split() if f]
changed = [f for f in changed_raw.split() if f and f not in full]

hits = {}
cur = None
for line in open(lcov_path, encoding="utf-8"):
    line = line.strip()
    if line.startswith("SF:"):
        p = os.path.relpath(line[3:], root)
        cur = hits.setdefault(p, {})
    elif line.startswith("DA:") and cur is not None:
        n, c = line[3:].split(",")[:2]
        n, c = int(n), int(c)
        cur[n] = max(cur.get(n, 0), c)

exc = set()
exc_text = []
if os.path.exists(exc_path):
    for raw in open(exc_path, encoding="utf-8"):
        raw = raw.split("  #", 1)[0].strip()
        if not raw or raw.startswith("#"):
            continue
        p, rest = raw.split(":", 1)
        if rest.startswith("~"):
            exc_text.append((p, rest[1:]))
        else:
            exc.add((p, int(rest)))

def excluded(path, n, src_lines):
    if (path, n) in exc:
        return True
    text = src_lines[n - 1] if 0 < n <= len(src_lines) else ""
    return any(p == path and needle in text for p, needle in exc_text)

def test_cutoff(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("#["):
                j += 1
            nxt = lines[j].strip() if j < len(lines) else ""
            if (nxt.startswith("mod ") or nxt.startswith("pub mod ")) and nxt.endswith("{"):
                return i + 1
    return len(lines) + 1

def test_only(path):
    return re.search(r"(_tests?\.rs|/test_upstream\.rs|/tests/.*\.rs)$", path) is not None

def diff_lines(ref, path):
    out = subprocess.run(["git", "diff", "-U0", ref, "--", path],
                         capture_output=True, text=True, check=True).stdout
    nums = set()
    for m in re.finditer(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", out, re.M):
        start, count = int(m.group(1)), int(m.group(2) or "1")
        nums.update(range(start, start + count))
    return nums

def changed_lines(path):
    nums = diff_lines(base, path)
    if upstream:
        nums &= diff_lines(upstream, path)
    return nums

fail = False
def check(path, wanted):
    global fail
    if not os.path.exists(path):
        print(f"skip   {path} (not present yet)")
        return
    cutoff = test_cutoff(path)
    src_lines = open(path, encoding="utf-8").read().splitlines()
    da = hits.get(path, {})
    lines = [n for n in sorted(da) if n < cutoff and (wanted is None or n in wanted)
             and not excluded(path, n, src_lines)]
    missed = [n for n in lines if da[n] == 0]
    total = len(lines)
    pct = 100.0 if total == 0 else 100.0 * (total - len(missed)) / total
    tag = "full" if wanted is None else "diff"
    status = "ok  " if not missed else "FAIL"
    print(f"{status} {tag} {pct:6.2f}% {path} ({total} lines)")
    if missed:
        fail = True
        print("       uncovered: " + ", ".join(map(str, missed[:60])))

for f in full:
    check(f, None)
for f in changed:
    if not test_only(f):
        check(f, changed_lines(f))
sys.exit(1 if fail else 0)
PY
