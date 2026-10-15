#!/usr/bin/env bash
# Coverage ratchet for the whole MCP feature (MCP Arch §13 test pyramid).
#
# Every MCP module listed in MCP_FILES must stay at or above the line
# coverage recorded in vauban-proxy-mcp/scripts/mcp_cov_baseline.txt.
# MCP_COV_WRITE_BASELINE=1 rewrites the baseline from the current run
# (only ever raise it, in the commit that adds the tests).
# MCP_COV_SKIP_RUN=1 reuses target/llvm-cov/mcp.lcov.
# A file may miss its floor by one line: the mail outbox worker and the IPC
# pumps make a line or two run or not depending on timing.
#
# Exceptions and the test-module cutoff are shared with mcp_fix_cov.sh.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

lcov="target/llvm-cov/mcp.lcov"
baseline="vauban-proxy-mcp/scripts/mcp_cov_baseline.txt"
exceptions="vauban-proxy-mcp/scripts/mcp_fix_cov_exceptions.txt"

MCP_FILES=(
  shared/src/mcp_policy.rs
  shared/src/mcp_mandate.rs
  shared/src/mcp_drift_iam.rs
  shared/src/mcp_tool_fingerprint.rs
  shared/src/json_redact.rs
  shared/src/session_token/replay_cache.rs
  vauban-access/src/mcp_pdp.rs
  vauban-access/src/mcp_rule_tools.rs
  vauban-proxy-mcp/src/agent_view.rs
  vauban-proxy-mcp/src/async_ipc.rs
  vauban-proxy-mcp/src/audit.rs
  vauban-proxy-mcp/src/fd_passing.rs
  vauban-proxy-mcp/src/main.rs
  vauban-proxy-mcp/src/mandate.rs
  vauban-proxy-mcp/src/mcp_recording.rs
  vauban-proxy-mcp/src/phase_c.rs
  vauban-proxy-mcp/src/tls_pin.rs
  vauban-proxy-mcp/src/tool_constraints.rs
  vauban-proxy-mcp/src/tool_drift.rs
  vauban-proxy-mcp/src/upstream_http.rs
  vauban-proxy-mcp/src/upstream_rebroker.rs
  vauban-proxy-mcp/src/vault.rs
  vauban-web/src/services/mcp_session.rs
  vauban-web/src/services/mcp_mail.rs
  vauban-web/src/services/mcp_control.rs
  vauban-web/src/services/mcp_attribute_diff.rs
  vauban-web/src/services/mcp_discover.rs
  vauban-web/src/services/mcp_recheck.rs
  vauban-web/src/services/mcp_drift.rs
  vauban-web/src/services/mcp_tool_drift.rs
  vauban-web/src/services/mcp_rule_prune.rs
  vauban-web/src/services/session_termination.rs
  vauban-web/src/services/policy_recheck.rs
  vauban-web/src/services/access_decision.rs
  vauban-web/src/handlers/mcp_relay.rs
  vauban-web/src/handlers/web/mcp.rs
  vauban-web/src/handlers/web/mcp_access.rs
  vauban-web/src/handlers/web/mcp_discover.rs
  vauban-web/src/handlers/web/mcp_hitl.rs
  vauban-web/src/handlers/api/mcp_sessions.rs
  vauban-web/src/ipc/proxy_mcp.rs
  vauban-web/src/templates/mcp/mod.rs
  vauban-web/src/templates/sessions/mcp_hitl_list.rs
  vauban-web/src/templates/assets/mcp_tool_option.rs
)

export DATABASE_URL="${DATABASE_URL:-postgresql://vauban_test:vauban_test@localhost/vauban_test}"

if [[ "${MCP_COV_SKIP_RUN:-0}" != "1" ]]; then
  cargo llvm-cov clean --workspace
  # Single-threaded like `just test`: the DB-backed suites share one schema.
  cargo llvm-cov --no-report -p shared --features json-redact,mcp-mandate,session-token,access-guard -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-access -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-proxy-mcp -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-web --lib -- --test-threads=1
  cargo llvm-cov --no-report -p vauban-web --test integration_tests -- --test-threads=1 mcp cutting_events jit_grant_revocation jit_revocation_pins
  mkdir -p "$(dirname "$lcov")"
  cargo llvm-cov report --lcov --output-path "$lcov"
fi

python3 - "$lcov" "$baseline" "$exceptions" "${MCP_COV_WRITE_BASELINE:-0}" "${MCP_FILES[@]}" <<'PY'
import os, sys

lcov_path, baseline_path, exc_path, write = sys.argv[1:5]
files = sys.argv[5:]
root = os.getcwd()

hits = {}
cur = None
for line in open(lcov_path, encoding="utf-8"):
    line = line.strip()
    if line.startswith("SF:"):
        cur = hits.setdefault(os.path.relpath(line[3:], root), {})
    elif line.startswith("DA:") and cur is not None:
        n, c = line[3:].split(",")[:2]
        cur[int(n)] = max(cur.get(int(n), 0), int(c))

exc, exc_text = set(), []
for raw in open(exc_path, encoding="utf-8"):
    raw = raw.split("  #", 1)[0].strip()
    if not raw or raw.startswith("#"):
        continue
    p, rest = raw.split(":", 1)
    if rest.startswith("~"):
        exc_text.append((p, rest[1:]))
    else:
        exc.add((p, int(rest)))

def test_cutoff(lines):
    for i, l in enumerate(lines):
        if l.strip().startswith("#[cfg(test)]"):
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("#["):
                j += 1
            nxt = lines[j].strip() if j < len(lines) else ""
            if (nxt.startswith("mod ") or nxt.startswith("pub mod ")) and nxt.endswith("{"):
                return i + 1
    return len(lines) + 1

def pct(path):
    src = open(path, encoding="utf-8").read().splitlines()
    cutoff = test_cutoff(src)
    da = hits.get(path, {})
    lines = [n for n in da if n < cutoff and (path, n) not in exc
             and not any(p == path and needle in src[n - 1] for p, needle in exc_text)]
    if not lines:
        return 100.0, 0
    return 100.0 * sum(1 for n in lines if da[n] > 0) / len(lines), len(lines)

current = {f: pct(f) for f in files}

if write == "1":
    with open(baseline_path, "w", encoding="utf-8") as out:
        out.write("# path  line-coverage-%  (written by MCP_COV_WRITE_BASELINE=1; only raise)\n")
        for f in files:
            out.write(f"{f} {current[f][0]:.2f}\n")
    print(f"baseline written: {baseline_path}")

floor = {}
for raw in open(baseline_path, encoding="utf-8"):
    raw = raw.strip()
    if raw and not raw.startswith("#"):
        p, v = raw.split()
        floor[p] = float(v)

fail = False
total_hit = total = 0
for f in files:
    got, n = current[f]
    want = floor.get(f)
    total += n
    total_hit += got * n / 100.0
    if want is None:
        print(f"FAIL  missing baseline {f}")
        fail = True
        continue
    ok = got + 0.005 + 100.0 / max(n, 1) >= want
    fail |= not ok
    print(f"{'ok  ' if ok else 'FAIL'} {got:6.2f}% (floor {want:6.2f}%) {f} ({n} lines)")
print(f"MCP total {100.0 * total_hit / max(total, 1):.2f}% over {total} lines")
sys.exit(1 if fail else 0)
PY
