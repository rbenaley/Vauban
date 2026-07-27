# VCP build recipes
#
# Single-package crate (`vcp`). Use `just` instead of ad-hoc cargo commands.
# Local runs default to VCP_ENVIRONMENT=development (layered TOML under config/).
#
# Topcoat CLI (`topcoat-cli`) is required for asset bundling and `view!` fmt.
# Recipes that need it call `ensure-topcoat`, which installs the pinned version
# on first use — so `just validate` and `just run` work without a prior manual
# `cargo install`.
#
# Automated tests need Postgres role/DB `vcp_test`. `ensure-vcp-test` provisions
# them on first use so `just validate` / `just test` do not require a prior
# `just db-create-test`.

export VCP_ENVIRONMENT := env("VCP_ENVIRONMENT", "development")

# Prefer cargo-installed binaries even when the parent shell PATH is thin
# (IDE tasks, minimal CI images, fresh shells).
cargo_home := env_var_or_default("CARGO_HOME", env_var("HOME") + "/.cargo")
export PATH := cargo_home + "/bin:" + env_var("PATH")

# Keep in sync with README / topcoat facade pin in Cargo.toml.
topcoat_cli_version := "0.4.0"

# Match config/testing.toml (user/password/db host).
vcp_test_url := "postgresql://vcp_test:vcp_test@localhost/vcp_test"

# Install pinned topcoat-cli when missing. Used by validate, run, bundle, fmt.
[private]
ensure-topcoat:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v topcoat >/dev/null 2>&1; then
      exit 0
    fi
    echo "topcoat CLI not found; installing topcoat-cli {{topcoat_cli_version}}…" >&2
    echo "(one-time; needs network + write access to {{cargo_home}}/bin)" >&2
    cargo install topcoat-cli --version "{{topcoat_cli_version}}"
    if ! command -v topcoat >/dev/null 2>&1; then
      echo "error: topcoat-cli installed but 'topcoat' is still not on PATH" >&2
      echo "hint: add {{cargo_home}}/bin to PATH, then re-run" >&2
      exit 1
    fi
    echo "topcoat CLI ready: $(command -v topcoat)" >&2

# Provision Postgres role/DB vcp_test when missing. Used by validate / test.
[private]
ensure-vcp-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v psql >/dev/null 2>&1; then
      echo "error: psql required to provision vcp_test (install PostgreSQL client tools)" >&2
      exit 1
    fi
    if PGPASSWORD=vcp_test psql -h localhost -U vcp_test -d vcp_test -Atc 'SELECT 1' >/dev/null 2>&1; then
      exit 0
    fi
    echo "Postgres vcp_test role/DB missing; running db-create-test…" >&2
    just db-create-test
    if ! PGPASSWORD=vcp_test psql -h localhost -U vcp_test -d vcp_test -Atc 'SELECT 1' >/dev/null 2>&1; then
      echo "error: could not connect as vcp_test after setup ({{vcp_test_url}})" >&2
      echo "hint: ensure PostgreSQL is running and your OS user can createdb/createuser" >&2
      exit 1
    fi
    echo "vcp_test ready" >&2

# Build the binary
build *ARGS:
    cargo build {{ARGS}}

# Bundle Topcoat assets into target/assets.
# Builds first: the bundler scans the compiled binary for asset! decls
# (Tailwind OUT_DIR CSS, fonts, etc.). Safe to call without a prior validate.
bundle *ARGS: ensure-topcoat build
    # Explicit --bin: the package also ships `vcp-cli` (Toasty migrations).
    topcoat asset bundle --bin vcp {{ARGS}}

# Check without producing binaries
check *ARGS:
    cargo check {{ARGS}}

# Format Rust sources + Topcoat view! macros
# Note: topcoat-cli 0.4 panics on `signal` declarations — those files are skipped.
fmt: ensure-topcoat
    cargo fmt --all
    just topcoat-fmt

# topcoat fmt over src, skipping files that declare runtime signals.
# topcoat-cli 0.4 panics on `signal` (unimplemented in the formatter).
# Use grep (not rg) so this works outside Cursor's PATH.
topcoat-fmt: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
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
fmt-check: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    cargo fmt --all -- --check
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

# Run tests (single-threaded). Ensures vcp_test + asset bundle first.
test *ARGS: ensure-vcp-test bundle
    cargo test {{ARGS}} -- --test-threads=1

# Clippy with warnings as errors
clippy *ARGS:
    cargo clippy --all-targets {{ARGS}} -- -D warnings

# Full validation cycle: fmt check + clippy + ensure vcp_test + asset bundle + tests
validate: fmt-check clippy test

# Build release binary + asset bundle
release: ensure-topcoat
    cargo build --release
    topcoat asset bundle --bin vcp --release

# Run the portal over HTTPS (defaults to development config, port 3000)
# Examples: just run | just run --release
# Smoke: curl -k https://127.0.0.1:3000/login
# Bundles assets so Concept CSS / Fontsource / runtime script resolve.
# Does not require a prior `just validate` — installs CLI + builds + bundles.
run *ARGS: bundle
    cargo run {{ARGS}}

# Hot-reload via Topcoat CLI (auto-installs topcoat-cli if missing)
# Note: custom HTTPS TLS is provided by `just run`, not by `topcoat dev`.
dev *ARGS: ensure-topcoat
    topcoat dev {{ARGS}}

# Create local Postgres database `vcp` if missing
db-create:
    createdb vcp || true

# Drop and recreate local Postgres database `vcp` (destructive), then apply migrations
db-reset:
    dropdb --if-exists vcp
    createdb vcp
    just db-migrate

# Apply pending Toasty migrations (development URL from layered TOML)
db-migrate:
    cargo run --bin vcp-cli -- migration apply

# Diff models vs last snapshot and write a new migration (optional NAME=…)
db-migrate-generate NAME="migration":
    cargo run --bin vcp-cli -- migration generate --name {{NAME}}

# Create Postgres `vcp_test` + role for automated tests
db-create-test:
    bash scripts/setup_test_db.sh

# Drop and recreate `vcp_test` (destructive), then re-grant (schema via db::connect)
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
