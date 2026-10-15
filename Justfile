# Vauban build recipes
#
# vauban-proxy-rdp is excluded from the Cargo workspace due to irreconcilable
# pre-release dependency conflicts in the RustCrypto ecosystem (ironrdp/picky/sspi
# vs russh/ssh-key). These recipes ensure it is always built alongside the workspace.
#
# --target-dir target ensures vauban-proxy-rdp outputs binaries into the shared
# target/ directory where the supervisor expects them (bin_path = "./target/debug").

rdp_path     := "--manifest-path vauban-proxy-rdp/Cargo.toml"
rdp_manifest := rdp_path + " --target-dir target"

# Workspace config/ for recipes that boot or load conf (not a global export).
repo_config_dir := justfile_directory() / "config"

# Build all crates (workspace + vauban-proxy-rdp)
build *ARGS:
    cargo build --workspace {{ARGS}}
    cargo build {{rdp_manifest}} {{ARGS}}

# Check all crates without producing binaries
check *ARGS:
    cargo check --workspace {{ARGS}}
    cargo check {{rdp_manifest}} {{ARGS}}

# Run all tests (single-threaded per harness to reduce DB contention).
# Requires PostgreSQL for crates that hit DATABASE_URL (see config/testing.toml).
# vauban-web exposes a single integration crate (`integration_tests`) so the
# workspace run does not spawn two binaries racing on the same catalog.
test *ARGS:
    cargo test --workspace {{ARGS}} -- --test-threads=1
    cargo test {{rdp_manifest}} {{ARGS}} -- --test-threads=1

# MCP acceptance GWT filter (docs/technical/Vauban_MCP_Architecture_EN(1.0).md).
# Covers V-1, V-8, V-15, L0-1, B-5, B-6, B-7, B-11 (proxy-mcp unit + web source pins).
# V-15 AccessGuard timeout substrate is also asserted inside proxy-mcp `gwt_v15_*`.
# Also runs the proxy `gwt_*` tests of the MCP security fixes.
# FreeBSD live checklist: docs/runbooks/mcp_staging_gwt_acceptance.md
test-mcp-gwt:
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp gwt_ -- --test-threads=1
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp upstream_rebroker -- --test-threads=1
    cargo test -p vauban-supervisor --bin vauban-supervisor test_supervisor_tcp_broker_bypasses -- --test-threads=1
    cargo test -p vauban-web --test integration_tests gwt_ -- --test-threads=1
    cargo test -p vauban-web --test integration_tests mcp_audit_fixes -- --test-threads=1
    cargo test -p vauban-web --test integration_tests mcp_security_fixes -- --test-threads=1
    cargo test -p vauban-web --test integration_tests mcp_hitl_decide -- --test-threads=1
    cargo test -p shared --lib --features access-guard test_authorize_timeout_when_backend_silent -- --test-threads=1
    cargo test -p shared --lib --features access-guard,mcp-mandate test_mcp_mandate_ -- --test-threads=1
    cargo test -p shared --lib --features mcp-mandate plan_mandate_pdp -- --test-threads=1
    cargo test -p vauban-access --lib mcp_pdp -- --test-threads=1
    cargo test -p vauban-access --lib peer_authz -- --test-threads=1
    cargo test -p vauban-vault --bin vauban-vault proxy_mcp -- --test-threads=1
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp mcp_fix_e2e -- --test-threads=1
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp audit::tests -- --test-threads=1
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp tool_drift -- --test-threads=1
    cargo test -p vauban-proxy-mcp --bin vauban-proxy-mcp heartbeat_reports_worm_refusals -- --test-threads=1
    cargo test -p shared --lib --features session-token replay_cache -- --test-threads=1
    cargo test -p shared --lib --features json-redact json_redact -- --test-threads=1
    cargo test -p vauban-web --lib mcp_discover -- --test-threads=1

# MCP test pyramid (docs/technical/Vauban_MCP_Architecture_EN(1.0).md §13):
# every in-process MCP layer (unit, invariant pins, proptest, battle, attack,
# wire, web and IPC end to end). Filters are substrings of the test path, so
# a new `mcp_*` test module is picked up without editing this recipe.
# Smoke runbooks and `just test-full-stack mcp` are the two layers above it.
test-mcp-pyramid:
    cargo test -p shared --features mcp-mandate --test mcp_source_invariants --test mcp_policy_proptest --test mcp_mandate_battle --test mcp_wire_frozen_test -- --test-threads=1
    cargo test -p shared --features session-token --test session_token_proptest --test mcp_replay_battle_test -- --test-threads=1
    cargo test -p shared --features mcp-mandate --test mcp_mandate_proptest -- --test-threads=1
    cargo test -p shared --features json-redact --test json_redact_proptest -- --test-threads=1
    cargo test -p shared --lib --features access-guard,mcp-mandate,session-token,json-redact -- --test-threads=1 mcp json_redact replay_cache
    cargo test -p vauban-proxy-mcp -- --test-threads=1
    cargo test -p vauban-mcp -- --test-threads=1
    cargo test -p vauban-access --lib -- --test-threads=1 mcp peer_authz
    cargo test -p vauban-vault --bin vauban-vault -- --test-threads=1 proxy_mcp
    cargo test -p vauban-supervisor --bin vauban-supervisor -- --test-threads=1 broker
    cargo test -p vauban-supervisor --bin vauban-supervisor -- --test-threads=1 heartbeat_dispatches_tcp_connect_read_during_pong_wait
    for f in vauban-proxy-mcp/scripts/check_mcp_*.sh; do bash "$f" || exit 1; done
    cargo test -p vauban-web --lib -- --test-threads=1 mcp session_termination policy_recheck access_decision templates::sessions::recording_
    cargo test -p vauban-web --test integration_tests -- --test-threads=1 mcp cutting_events jit_grant_revocation jit_revocation_pins

# Full-stack tests (vauban-e2e, outside the workspace): real supervisor and
# every service on a throw-away `vauban_e2e` database, driven by headless
# Chrome. Mandatory after every merge. ARGS filter scenarios (`auth::`).
# VAUBAN_E2E_HEADED=1 shows the browser, VAUBAN_E2E_KEEP=1 keeps the tree.
test-full-stack *ARGS: build
    VAUBAN_E2E_CHROMEDRIVER="$(bash vauban-e2e/scripts/chromedriver.sh)" \
        cargo test --manifest-path vauban-e2e/Cargo.toml --target-dir target --test full_stack -- {{ARGS}}

# Coverage gate for the MCP security fixes (MCP Arch §13.1):
# 100 % on the fix modules, diff coverage on every other changed line.
# Needs cargo-llvm-cov. MCP_FIX_BASE overrides the diff base.
cov-mcp-fixes:
    bash vauban-proxy-mcp/scripts/mcp_fix_cov.sh

# Coverage ratchet for every MCP module (MCP Arch §13): each file stays at or
# above vauban-proxy-mcp/scripts/mcp_cov_baseline.txt. Needs cargo-llvm-cov.
# MCP_COV_WRITE_BASELINE=1 raises the floor in the commit that adds the tests.
cov-mcp:
    bash vauban-proxy-mcp/scripts/mcp_cov.sh

# Run clippy on all crates (warnings are errors, same as the agent cycle).
clippy *ARGS:
    cargo clippy --workspace --all-targets {{ARGS}} -- -D warnings
    cargo clippy {{rdp_manifest}} --all-targets {{ARGS}} -- -D warnings

# Structural check_*.sh + cargo-deny advisories + Semgrep.
# Fail-closed if cargo-deny or semgrep is missing (see docs/runbooks/local_lint_tools.md).
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    while IFS= read -r script; do
        echo "==> ${script}"
        bash "${script}"
    # Prune .cursor: the MCP lab archive lives there and is not the
    # product tree. Its check_*.sh would lint that copy and fail validate.
    done < <(find . \( -path ./target -o -path ./.git -o -path ./.cursor \) -prune -o -path '*/scripts/check_*.sh' -print | sort)
    just deny
    just semgrep

# RustSec advisories on both lockfiles (cargo-deny).
deny *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! cargo deny --version >/dev/null 2>&1; then
        echo "cargo-deny is not installed. See docs/runbooks/local_lint_tools.md" >&2
        exit 1
    fi
    cargo deny check advisories {{ARGS}}
    cargo deny --manifest-path vauban-proxy-rdp/Cargo.toml check advisories {{ARGS}}

# Semgrep class rules (untrusted interpolation + in-band verifying key).
semgrep:
    #!/usr/bin/env bash
    set -euo pipefail
    SEMGREP=""
    if command -v semgrep >/dev/null 2>&1; then
        SEMGREP="$(command -v semgrep)"
    else
        for cand in "$HOME/Library/Python/"*/bin/semgrep "$HOME/.local/bin/semgrep"; do
            if [[ -x "${cand}" ]]; then
                SEMGREP="${cand}"
                break
            fi
        done
    fi
    if [[ -z "${SEMGREP}" ]]; then
        echo "semgrep is not installed. See docs/runbooks/local_lint_tools.md" >&2
        exit 1
    fi
    # pip --user installs a wrapper that execs `pysemgrep` from the same dir.
    export PATH="$(dirname "${SEMGREP}"):${PATH}"
    "${SEMGREP}" --config .semgrep/untrusted-input.yml --error --quiet

# Full validation cycle: build + lint + clippy + test (stops on first failure).
# Packaging dry-check is extra (Mac-safe; FreeBSD live A–C stays in
# docs/runbooks/mcp_staging_gwt_acceptance.md).
# Exports VAUBAN_CONFIG_DIR to the repo config/ for the duration (release
# binaries do not fall back to compile-time workspace paths).
validate:
    #!/usr/bin/env bash
    set -euo pipefail
    export VAUBAN_CONFIG_DIR="{{repo_config_dir}}"
    just build
    just lint
    just clippy
    just test
    just test-mcp-pyramid
    just check-mcp-pkg

# Build release binaries
release:
    cargo build --workspace --release
    cargo build {{rdp_manifest}} --release

# Examples: just run | just run --release | just run -- -- create-superuser
# Run the supervisor (workspace default-members → vauban-supervisor).
# Always points VAUBAN_CONFIG_DIR at the repo config/ (staging / laptop).
run *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    export VAUBAN_CONFIG_DIR="{{repo_config_dir}}"
    cargo run {{ARGS}}

# Prerequisite: just release (or just build --release). FreeBSD + pkg(8) required.
# Build the FreeBSD package (runs pkg/build-pkg.sh)
package:
    cd pkg && ./build-pkg.sh

# Dry-check MCP FreeBSD packaging (vb-mcp 910). On FreeBSD after pkg add: --live
check-mcp-pkg *args:
    ./pkg/check-mcp-pkg.sh {{args}}

# Uses {{rdp_path}} (no --target-dir): `cargo update` only rewrites
# Cargo.lock and rejects --target-dir.
# Update dependencies in both lockfiles (workspace + vauban-proxy-rdp)
update *ARGS:
    cargo update {{ARGS}}
    cargo update {{rdp_path}} {{ARGS}}

# Scan both lockfiles for RustSec advisories (cargo audit uses -f, not
# --manifest-path, so the rdp lock is passed explicitly). Both scans always
# run; the recipe fails if either lockfile has advisories (CI-friendly).
# Audit dependencies in both lockfiles (workspace + vauban-proxy-rdp)
audit *ARGS:
    #!/usr/bin/env bash
    set -uo pipefail
    rc=0
    cargo audit {{ARGS}} || rc=1
    cargo audit -f vauban-proxy-rdp/Cargo.lock {{ARGS}} || rc=1
    exit $rc

# Clean all build artifacts
clean:
    cargo clean

# Build sealed mailer leaf (Capsicum SMTP outbox drainer)
build-mailer *ARGS:
    cargo build -p vauban-mailer {{ARGS}}

# Run sealed mailer in foreground (requires supervisor-brokered env:
# VAUBAN_IPC_READ/WRITE, VAUBAN_FD_PASSING_SOCKET, VAUBAN_DATABASE_URL).
# Prefer supervisor spawn in normal deploys; this recipe is for lab debug.
run-mailer *ARGS:
    cargo run -p vauban-mailer {{ARGS}}

# Build evidence sub-crate (Inspect analyzer + hydrator pipeline)
build-evidence *ARGS:
    cargo build -p vauban-web-evidence {{ARGS}}
