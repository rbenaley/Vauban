#!/usr/bin/env bash
# Structural pins for the Topcoat 0.8 pin (0.8.0 lots + 0.8.1 Strict).
# Uses grep so `cargo test` / CI work without ripgrep on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_topcoat_0_8: $*" >&2
  exit 1
}

if grep -REn --include='*.rs' -e 'signal[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' src/ >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'signal[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' src/ >&2 || true
  fail "statement-form signals are gone in 0.8; use let name = signal(cx, || …)"
fi

if ! grep -n '\.runtime()' src/app.rs >/dev/null; then
  fail "router must call .runtime() (Topcoat 0.8)"
fi

if ! grep -n 'error_boundary' src/app.rs >/dev/null; then
  fail "root_layout must use error_boundary"
fi

if ! grep -n 'error_boundary' src/app/admin.rs >/dev/null; then
  fail "admin_layout must use error_boundary"
fi

if ! grep -n 'error_boundary' src/app/org.rs >/dev/null; then
  fail "org_layout must use error_boundary"
fi

if ! grep -n 'runtime::script' src/app.rs >/dev/null; then
  fail "root_layout must include topcoat::runtime::script"
fi

if ! grep -n 'rust-version = "1.98"' Cargo.toml >/dev/null; then
  fail "Cargo.toml rust-version must be 1.98 (Topcoat 0.8 MSRV)"
fi

if ! grep -n 'topcoat_cli_version := "0.8.1"' Justfile >/dev/null; then
  fail "Justfile must pin topcoat-cli 0.8.1"
fi

if grep -n 'topcoat = { version = "0.7' Cargo.toml >/dev/null; then
  fail "must not land on Topcoat 0.7.0"
fi

if ! grep -n 'topcoat = { version = "0.8.1"' Cargo.toml >/dev/null; then
  fail "Cargo.toml facade must pin topcoat 0.8.1"
fi

if ! grep -n 'TrailingSlash::Strict' src/app.rs >/dev/null; then
  fail "router must set TrailingSlash::Strict (POST slash stays 404)"
fi

if ! grep -n 'version = "0.1.2"' Cargo.toml >/dev/null; then
  fail "Cargo.toml [package] version must be 0.1.2 after the 0.8.1 pin"
fi

if ! grep -n 'is_current' src/app/_components/rail.rs >/dev/null; then
  fail "vb_rail must use href.is_current for query-stable active items"
fi

echo "check_topcoat_0_8: ok"
