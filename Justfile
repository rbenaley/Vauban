# Vauban build recipes
#
# vauban-proxy-rdp is excluded from the Cargo workspace due to irreconcilable
# pre-release dependency conflicts in the RustCrypto ecosystem (ironrdp/picky/sspi
# vs russh/ssh-key). These recipes ensure it is always built alongside the workspace.
#
# RDP compiles into target-rdp/ so its lockfile cannot invalidate the
# workspace target/. link-rdp points ./target/{debug,release}/vauban-proxy-rdp
# at that artifact: the supervisor execs bin_path = "./target/debug".

rdp_path     := "--manifest-path vauban-proxy-rdp/Cargo.toml"
rdp_manifest := rdp_path + " --target-dir target-rdp"

# Workspace config/ for recipes that boot or load conf (not a global export).
repo_config_dir := justfile_directory() / "config"

# Build all crates (workspace + vauban-proxy-rdp)
build *ARGS:
    cargo build --workspace {{ARGS}}
    cargo build {{rdp_manifest}} {{ARGS}}
    just link-rdp

# Point the supervisor's bin_path at the RDP artifact in target-rdp/.
# No-op until that binary exists (check, clippy, and test do not need it).
link-rdp:
    #!/usr/bin/env bash
    set -euo pipefail
    for profile in debug release; do
        src="target-rdp/${profile}/vauban-proxy-rdp"
        if [[ -x "${src}" ]]; then
            mkdir -p "target/${profile}"
            ln -sfn "../../${src}" "target/${profile}/vauban-proxy-rdp"
        fi
    done

# Check all crates without producing binaries
check *ARGS:
    cargo check --workspace {{ARGS}}
    cargo check {{rdp_manifest}} {{ARGS}}

# Run all tests.
# Requires PostgreSQL for crates that hit DATABASE_URL (see config/testing.toml).
# vauban-web, vauban-access, and vauban-supervisor share the vauban_test
# catalog, so that invocation stays single-threaded. vauban-db uses a
# throwaway database and runs with the other crates at Cargo's default
# parallelism. vauban-web exposes a single integration crate
# (`integration_tests`) so two binaries cannot race on the same catalog.
# `--all-features` turns on shared's optional features while that crate is
# the test root (`mcp-mandate`, `session-token`, `json-redact`, and the
# rest). Without it, Cargo skips every `required-features` suite. A filter
# is `just test gwt_`.
test *ARGS:
    cargo test --workspace --all-features --exclude vauban-web --exclude vauban-access --exclude vauban-supervisor {{ARGS}}
    cargo test --all-features -p vauban-web -p vauban-access -p vauban-supervisor {{ARGS}} -- --test-threads=1
    cargo test {{rdp_manifest}} {{ARGS}}

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
    # Packaging pin lives next to pkg/, not under scripts/, so the find
    # above does not see it. One run, with the other structural checks.
    just check-mcp-pkg
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

# Full validation cycle: lint + clippy + test (stops on first failure).
# Clippy and test already compile the crates; `just build` stays the
# recipe that produces a runnable tree (and the RDP symlink).
# The MCP packaging dry-check runs inside lint. FreeBSD live A–C stays in
# docs/runbooks/mcp_staging_gwt_acceptance.md.
# Exports VAUBAN_CONFIG_DIR to the repo config/ for the duration (release
# binaries do not fall back to compile-time workspace paths).
validate:
    #!/usr/bin/env bash
    set -euo pipefail
    export VAUBAN_CONFIG_DIR="{{repo_config_dir}}"
    just lint
    just clippy
    just test

# Build release binaries
release:
    cargo build --workspace --release
    cargo build {{rdp_manifest}} --release
    just link-rdp

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
