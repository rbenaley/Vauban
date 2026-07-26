# VCP build recipes
#
# Single-package crate (`vcp`). Use `just` instead of ad-hoc cargo commands.
# Local runs default to VCP_ENVIRONMENT=development (layered TOML under config/).

export VCP_ENVIRONMENT := env("VCP_ENVIRONMENT", "development")

# Build the binary
build *ARGS:
    cargo build {{ARGS}}

# Bundle Topcoat assets into target/assets (builds via topcoat-cli)
bundle *ARGS:
    topcoat asset bundle {{ARGS}}

# Check without producing binaries
check *ARGS:
    cargo check {{ARGS}}

# Format Rust sources + Topcoat view! macros
# Note: topcoat-cli 0.4 panics on `signal` declarations — those files are skipped.
fmt:
    cargo fmt --all
    just topcoat-fmt

# topcoat fmt over src, skipping files that declare runtime signals.
# topcoat-cli 0.4 panics on `signal` (unimplemented in the formatter).
# Use grep (not rg) so this works outside Cursor's PATH.
topcoat-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v topcoat >/dev/null 2>&1; then
      echo "error: topcoat CLI required (cargo install topcoat-cli)" >&2
      exit 1
    fi
    files=()
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      if grep -E -q '^[[:space:]]*signal[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$f"; then
        continue
      fi
      files+=("$f")
    done < <(git ls-files 'src/*.rs' 'src/**/*.rs')
    if ((${#files[@]} == 0)); then
      echo "topcoat-fmt: no eligible files" >&2
      exit 0
    fi
    echo "topcoat-fmt: formatting ${#files[@]} files (signal decls skipped)" >&2
    topcoat fmt "${files[@]}"

# Format check (CI): rustfmt --check, then topcoat fmt must be a no-op
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo fmt --all -- --check
    if ! command -v topcoat >/dev/null 2>&1; then
      echo "error: topcoat CLI required (cargo install topcoat-cli)" >&2
      exit 1
    fi
    # Compare file digests before/after so uncommitted WIP does not false-fail.
    before=$(mktemp)
    after=$(mktemp)
    trap 'rm -f "$before" "$after"' EXIT
    (cd src && find . -name '*.rs' -print0 | sort -z | xargs -0 shasum -a 256) >"$before"
    just topcoat-fmt
    (cd src && find . -name '*.rs' -print0 | sort -z | xargs -0 shasum -a 256) >"$after"
    if ! cmp -s "$before" "$after"; then
      echo "error: topcoat fmt would change sources; run: just fmt" >&2
      diff -u "$before" "$after" | head -n 80 || true
      exit 1
    fi

# Run tests (single-threaded; needs vcp_test — see db-create-test)
# Bundles assets first so stylesheet!/runtime script resolve.
test *ARGS: bundle
    cargo test {{ARGS}} -- --test-threads=1

# Clippy with warnings as errors
clippy *ARGS:
    cargo clippy --all-targets {{ARGS}} -- -D warnings

# Full validation cycle: fmt check + clippy + asset bundle + tests
validate: fmt-check clippy test

# Build release binary + asset bundle
release:
    topcoat asset bundle --release

# Run the portal over HTTPS (defaults to development config, port 8443)
# Examples: just run | just run --release
# Smoke: curl -k https://127.0.0.1:8443/login
# Bundles assets so Concept CSS / Fontsource / runtime script resolve.
run *ARGS: bundle
    cargo run {{ARGS}}

# Hot-reload via Topcoat CLI (requires `cargo install topcoat-cli`)
# Note: custom HTTPS TLS is provided by `just run`, not by `topcoat dev`.
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
