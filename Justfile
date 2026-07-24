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

# Run clippy on all crates
clippy *ARGS:
    cargo clippy --workspace {{ARGS}}
    cargo clippy {{rdp_manifest}} {{ARGS}}

# Build release binaries
release:
    cargo build --workspace --release
    cargo build {{rdp_manifest}} --release

# Examples: just run | just run --release | just run -- -- create-superuser
# Run the supervisor (workspace default-members → vauban-supervisor)
run *ARGS:
    cargo run {{ARGS}}

# Prerequisite: just release (or just build --release). FreeBSD + pkg(8) required.
# Build the FreeBSD package (runs pkg/build-pkg.sh)
package:
    cd pkg && ./build-pkg.sh

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
