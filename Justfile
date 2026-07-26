# VCP build recipes
#
# Single-package crate (`vcp`). Use `just` instead of ad-hoc cargo commands.
# Local runs default to VCP_ENVIRONMENT=development (layered TOML under config/).

export VCP_ENVIRONMENT := env("VCP_ENVIRONMENT", "development")

# Build the binary
build *ARGS:
    cargo build {{ARGS}}

# Check without producing binaries
check *ARGS:
    cargo check {{ARGS}}

# Format Rust sources
fmt:
    cargo fmt --all

# Format check (CI)
fmt-check:
    cargo fmt --all -- --check

# Run tests (single-threaded; needs vcp_test — see db-create-test)
test *ARGS:
    cargo test {{ARGS}} -- --test-threads=1

# Clippy with warnings as errors
clippy *ARGS:
    cargo clippy --all-targets {{ARGS}} -- -D warnings

# Full validation cycle: fmt check + clippy + tests
validate: fmt-check clippy test

# Build release binary
release:
    cargo build --release

# Run the portal over HTTPS (defaults to development config, port 8443)
# Examples: just run | just run --release
# Smoke: curl -k https://127.0.0.1:8443/login
run *ARGS:
    cargo run {{ARGS}}

# Hot-reload via Topcoat CLI (requires `cargo install topcoat-cli`)
dev *ARGS:
    topcoat dev {{ARGS}}

# Create local Postgres database `vcp` if missing
db-create:
    createdb vcp || true

# Drop and recreate local Postgres database `vcp` (destructive)
db-reset:
    dropdb --if-exists vcp
    createdb vcp

# Create Postgres `vcp_test` + role for automated tests
db-create-test:
    bash scripts/setup_test_db.sh

# Drop and recreate `vcp_test` (destructive), then re-grant
db-reset-test:
    dropdb --if-exists vcp_test || true
    bash scripts/setup_test_db.sh

# Update Cargo.lock
update *ARGS:
    cargo update {{ARGS}}

# Scan Cargo.lock for RustSec advisories
audit *ARGS:
    cargo audit {{ARGS}}

# Clean build artifacts
clean:
    cargo clean
