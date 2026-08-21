#!/usr/bin/env bash
# Structural pins for the Topcoat 0.6.2 upgrade (Lot 1+).
# Uses grep so `cargo test` / CI work without ripgrep on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_topcoat_0_6: $*" >&2
  exit 1
}

if grep -REn --include='*.rs' -e '^[[:space:]]*#\[path_param\]' src/ >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e '^[[:space:]]*#\[path_param\]' src/ >&2 || true
  fail "#[path_param] is removed in Topcoat 0.6; use path_param!(name)"
fi

if grep -REn --include='*.rs' -e 'CxBuilder' src/ >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'CxBuilder' src/ >&2 || true
  fail "CxBuilder is removed in Topcoat 0.6; layers take &Cx"
fi

if grep -REn --include='*.rs' -e 'trust_origin(' src/ >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'trust_origin(' src/ >&2 || true
  fail "SessionConfig::trust_origin is gone; use OriginPolicy::trust_origins"
fi

if ! grep -n 'path_param!' src/app/org.rs >/dev/null; then
  fail "org slug must be declared with path_param!"
fi
if ! grep -n 'not_found!' src/app/admin.rs >/dev/null; then
  fail "admin nest must register not_found!(\"/admin\") for unmatched /admin URLs"
fi
if ! grep -n 'NotFoundError' src/app.rs >/dev/null; then
  fail "root layout must brand NotFoundError"
fi
if grep -n 'raw_path_params' src/app/org/builds/ephemeral.rs >/dev/null; then
  fail "ephemeral download must use typed path_param!, not raw_path_params"
fi
if ! grep -n 'path_param!' src/app/releases/eph_token.rs >/dev/null; then
  fail "ephemeral token must be a typed path_param!"
fi

if ! grep -n 'OriginPolicy' src/app.rs >/dev/null; then
  fail "router must register OriginPolicy"
fi

if ! grep -n 'BodyLimit' src/app.rs >/dev/null; then
  fail "router must register BodyLimit"
fi

if ! grep -n 'max_request_body_mib' src/config.rs >/dev/null; then
  fail "ServerConfig must expose max_request_body_mib"
fi

for f in config/vcp.conf config/default.toml config/development.toml config/testing.toml; do
  grep -n 'max_request_body_mib' "$f" >/dev/null \
    || fail "$f must declare max_request_body_mib"
done

if ! grep -n 'target/\${profile}/assets\|dirname "\$bin"/assets\|release/assets' Justfile >/dev/null; then
  fail "Justfile must bundle assets next to the scanned binary"
fi

if ! grep -n 'RELEASE_DIR}/assets\|release/assets' pkg/build-pkg.sh >/dev/null; then
  fail "build-pkg.sh must stage target/release/assets"
fi

if ! grep -n 'href!' src/app.rs src/app/login.rs src/app/_components/rail.rs >/dev/null; then
  fail "portal entry, login, and rail must build URLs with href!"
fi
if ! grep -n 'base_url' src/app.rs >/dev/null; then
  fail "router must register base_url for absolute mail hrefs"
fi
if grep -REn --include='*.rs' -e 'see_other\("/admin|redirect\("/admin|href="/admin|action="/admin' src/app >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'see_other\("/admin|redirect\("/admin|href="/admin|action="/admin' src/app >&2 || true
  fail "admin URLs must use href!(page), not raw path strings"
fi
if grep -REn --include='*.rs' -e 'format!\("/admin|format!\("/\{|see_other\(format!' src/app >/dev/null 2>&1; then
  grep -REn --include='*.rs' -e 'format!\("/admin|format!\("/\{|see_other\(format!' src/app >&2 || true
  fail "portal URLs must use href!, not format! path strings"
fi

echo "check_topcoat_0_6: ok"
