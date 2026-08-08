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
topcoat_cli_version := "0.5.0"

# ensure-vcp-test probe (Unix socket). App tests use config/testing.toml (TCP).
vcp_test_url := "postgresql://vcp_test:vcp_test@/vcp_test"

# Install / upgrade pinned topcoat-cli. Used by validate, run, bundle, fmt.
# A stale CLI (e.g. grammar 0.4 with `todo!()` on `signal` pretty-print) panics
# mid-`topcoat fmt`; always enforce {{topcoat_cli_version}}.
[private]
ensure-topcoat:
    #!/usr/bin/env bash
    set -euo pipefail
    want="{{topcoat_cli_version}}"
    have=""
    if command -v topcoat >/dev/null 2>&1; then
      # `topcoat fmt -V` prints e.g. "topcoat-fmt 0.5.0"
      have=$(topcoat fmt -V 2>/dev/null | awk '{print $NF}' || true)
    fi
    if [[ "$have" == "$want" ]]; then
      exit 0
    fi
    if [[ -n "$have" ]]; then
      echo "topcoat CLI $have != pin $want; upgrading topcoat-cli…" >&2
    else
      echo "topcoat CLI not found; installing topcoat-cli $want…" >&2
    fi
    echo "(needs network + write access to {{cargo_home}}/bin)" >&2
    cargo install topcoat-cli --version "$want" --force
    if ! command -v topcoat >/dev/null 2>&1; then
      echo "error: topcoat-cli installed but 'topcoat' is still not on PATH" >&2
      echo "hint: add {{cargo_home}}/bin to PATH, then re-run" >&2
      exit 1
    fi
    have=$(topcoat fmt -V 2>/dev/null | awk '{print $NF}' || true)
    if [[ "$have" != "$want" ]]; then
      echo "error: expected topcoat-cli $want after install, got '${have:-unknown}'" >&2
      exit 1
    fi
    echo "topcoat CLI ready: $(command -v topcoat) ($have)" >&2

# Provision Postgres role/DB vcp_test when missing. Used by validate / test.
[private]
ensure-vcp-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v psql >/dev/null 2>&1; then
      echo "error: psql required to provision vcp_test (install PostgreSQL client tools)" >&2
      exit 1
    fi
    # Unix-domain socket only (do not pass -h / PGHOST hostname — that forces TCP).
    unset PGHOST 2>/dev/null || true
    if PGPASSWORD=vcp_test psql -U vcp_test -d vcp_test -Atc 'SELECT 1' >/dev/null 2>&1; then
      exit 0
    fi
    echo "Postgres vcp_test role/DB missing; running db-create-test…" >&2
    just db-create-test
    if ! PGPASSWORD=vcp_test psql -U vcp_test -d vcp_test -Atc 'SELECT 1' >/dev/null 2>&1; then
      echo "error: could not connect as vcp_test after setup ({{vcp_test_url}})" >&2
      echo "hint: ensure PostgreSQL is running; provisioning uses -U postgres over the Unix socket (set PGPASSWORD or ~/.pgpass)" >&2
      exit 1
    fi
    echo "vcp_test ready" >&2

# cargo build only (no asset step). Prefer `just build` for local work.
[private]
cargo-build *ARGS:
    cargo build {{ARGS}}

# Refresh target/assets when missing, older than the vcp binary, or built for
# a different Cargo profile. Topcoat 0.5 Tailwind AssetIds embed OUT_DIR — a
# rebuild without rebundle (or a test-profile bundle left behind after
# `just test`) leaves a stale manifest and panics on first HTML render.
[private]
ensure-asset-bundle *ARGS: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    profile=debug
    for arg in {{ARGS}}; do
      if [[ "$arg" == "--release" ]]; then
        profile=release
      fi
    done
    bin="target/${profile}/vcp"
    manifest="target/assets/manifest.toml"
    stamp="target/assets/.bundle-profile"
    if [[ ! -f "$bin" ]]; then
      echo "error: missing ${bin}; build the binary before bundling assets" >&2
      exit 1
    fi
    need=0
    if [[ ! -f "$manifest" ]]; then
      need=1
    elif [[ ! -f "$stamp" ]] || [[ "$(cat "$stamp")" != "$profile" ]]; then
      need=1
    elif [[ "$bin" -nt "$manifest" ]]; then
      need=1
    fi
    if [[ "$need" -eq 0 ]]; then
      echo "ensure-asset-bundle: up to date (${manifest}, profile=${profile})" >&2
      exit 0
    fi
    echo "ensure-asset-bundle: bundling assets for ${bin} (profile=${profile})…" >&2
    # Explicit --bin: the package also ships `vcp-store`.
    topcoat asset bundle --bin vcp {{ARGS}}
    mkdir -p target/assets
    printf '%s\n' "$profile" >"$stamp"

# Build the binary and refresh assets when the binary is newer than the
# manifest (or the manifest is missing / wrong profile).
build *ARGS: (cargo-build ARGS) (ensure-asset-bundle ARGS)

# Force-bundle Topcoat assets into target/assets (always runs the bundler).
# Builds first: the bundler scans the compiled binary for asset! decls
# (Tailwind OUT_DIR CSS, fonts, etc.). Profile must match the binary:
# `just bundle` | `just bundle --release`.
bundle *ARGS: ensure-topcoat (cargo-build ARGS)
    #!/usr/bin/env bash
    set -euo pipefail
    profile=debug
    for arg in {{ARGS}}; do
      if [[ "$arg" == "--release" ]]; then
        profile=release
      fi
    done
    topcoat asset bundle --bin vcp {{ARGS}}
    mkdir -p target/assets
    printf '%s\n' "$profile" >target/assets/.bundle-profile

# Check without producing binaries
check *ARGS:
    cargo check {{ARGS}}

# Format Rust sources + Topcoat view! macros
fmt: ensure-topcoat
    cargo fmt --all
    just topcoat-fmt

# topcoat fmt over all src Rust files (0.5 formats signal decls and mail!).
topcoat-fmt: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    files=()
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      files+=("$f")
    done < <(git ls-files 'src/*.rs' 'src/**/*.rs')
    if ((${#files[@]} == 0)); then
      echo "topcoat-fmt: no eligible files" >&2
      exit 0
    fi
    echo "topcoat-fmt: formatting ${#files[@]} files" >&2
    topcoat fmt "${files[@]}"

# Format check (pure): rustfmt --check, then topcoat fmt must be a no-op.
# Does not assume a prior `just fmt`. Prefer `just validate` locally.
fmt-check: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    cargo fmt --all -- --check
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

# After `just fmt`: rustfmt --check only (topcoat already applied; no 2nd pass).
[private]
verify-fmt:
    cargo fmt --all -- --check

# Compile tests, then bundle assets from the Cargo *test* profile.
# Integration tests link the test-profile lib; a debug-profile bundle (from
# `just bundle` / `just run`) does not match Tailwind AssetIds and panics in
# `load_assets`. Stamp the profile so a later `just run` rebundles debug.
[private]
ensure-test-asset-bundle *ARGS: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    echo "ensure-test-asset-bundle: cargo test --no-run…" >&2
    cargo test --no-run {{ARGS}}
    echo "ensure-test-asset-bundle: bundling assets (profile=test)…" >&2
    topcoat asset bundle --bin vcp --profile test
    mkdir -p target/assets
    printf '%s\n' "test" >target/assets/.bundle-profile

# Run tests (single-threaded). Ensures vcp_test + test-profile asset bundle.
test *ARGS: ensure-vcp-test (ensure-test-asset-bundle ARGS)
    cargo test {{ARGS}} -- --test-threads=1

# Clippy with warnings as errors
clippy *ARGS:
    cargo clippy --all-targets {{ARGS}} -- -D warnings

# Full validation cycle: apply fmt once, rustfmt --check, clippy, then tests.
# Uses `verify-fmt` (not `fmt-check`) so topcoat fmt does not run twice.
validate: fmt verify-fmt clippy test

# Build release binary + asset bundle
release: ensure-topcoat
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release
    topcoat asset bundle --bin vcp --release
    mkdir -p target/assets
    printf '%s\n' "release" >target/assets/.bundle-profile

# Run the portal over HTTPS (defaults to development config, port 3000)
# Examples: just run | just run --release
# Smoke: curl -k https://127.0.0.1:3000/login
# Builds then refreshes assets when needed (see ensure-asset-bundle) so
# binary AssetIds match target/assets. Prefer this over bare `cargo run`.
# Fail closed early when server.pid_file (default /tmp/vcp.pid) names a
# live process named `vcp` — not a generic "port in use" check.
run *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    pid_file="${VCP_PID_FILE:-/tmp/vcp.pid}"
    if [[ -f "${pid_file}" ]]; then
        pid="$(tr -d '[:space:]' <"${pid_file}" || true)"
        if [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
            comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
            base="${comm##*/}"
            if [[ "${base}" == "vcp" ]]; then
                echo "error: another vcp process is already running (pid ${pid}, pid_file ${pid_file}); stop it before starting a new instance" >&2
                exit 1
            fi
        fi
    fi
    just build {{ARGS}}
    cargo run {{ARGS}}

# Hot-reload via Topcoat CLI (auto-installs topcoat-cli if missing)
# Note: custom HTTPS TLS is provided by `just run`, not by `topcoat dev`.
dev *ARGS: ensure-topcoat
    topcoat dev {{ARGS}}

# Create local Postgres database `vcp` if missing (admin: postgres, Unix socket)
db-create:
    env -u PGHOST PGUSER="${VCP_PG_ADMIN_USER:-postgres}" createdb vcp || true

# Drop and recreate local Postgres database `vcp` (destructive), then apply migrations
db-reset:
    env -u PGHOST PGUSER="${VCP_PG_ADMIN_USER:-postgres}" dropdb --if-exists vcp
    env -u PGHOST PGUSER="${VCP_PG_ADMIN_USER:-postgres}" createdb vcp
    just db-migrate

# Apply pending Toasty migrations (development URL from layered TOML)
db-migrate:
    cargo run --bin vcp -- migration apply

# Diff models vs last snapshot and write a new migration (optional NAME=…)
db-migrate-generate NAME="migration":
    cargo run --bin vcp -- migration generate --name {{NAME}}

# Seed full demo catalog (docs, GA builds, sample issues). Boot alone is minimal.
# Respects VCP_ENVIRONMENT (default development). Does not start HTTPS.
seed-data:
    cargo run -- seed-data

# Create Postgres `vcp_test` + role for automated tests
db-create-test:
    bash scripts/setup_test_db.sh

# Drop and recreate `vcp_test` (destructive), then re-grant (schema via db::connect)
db-reset-test:
    env -u PGHOST PGUSER="${VCP_PG_ADMIN_USER:-postgres}" dropdb --if-exists vcp_test || true
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
