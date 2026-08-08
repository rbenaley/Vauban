#!/usr/bin/env bash
# Structural invariants for FreeBSD pkg/ packaging + runtime config discovery.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "check_freebsd_pkg: $*" >&2
  exit 1
}

for f in \
  pkg/+MANIFEST \
  pkg/+PRE_INSTALL \
  pkg/+POST_INSTALL \
  pkg/+PRE_DEINSTALL \
  pkg/+POST_DEINSTALL \
  pkg/build-pkg.sh \
  pkg/acl.sh \
  pkg/rc.d/vcp \
  pkg/rc.d/vcp_store \
  pkg/newsyslog.conf.d/vcp.conf
do
  [[ -f "$f" ]] || fail "missing $f"
done

grep -n 'PROVIDE: vcp_store' pkg/rc.d/vcp_store >/dev/null \
  || fail "rc.d/vcp_store must PROVIDE vcp_store"
grep -n 'PROVIDE: vcp' pkg/rc.d/vcp >/dev/null \
  || fail "rc.d/vcp must PROVIDE vcp"
grep -nE 'REQUIRE:.*vcp_store' pkg/rc.d/vcp >/dev/null \
  || fail "rc.d/vcp must REQUIRE vcp_store"
grep -n 'postgresql' pkg/rc.d/vcp >/dev/null \
  || fail "rc.d/vcp must REQUIRE postgresql"

grep -n 'VCP_CONFIG_DIR=' pkg/rc.d/vcp >/dev/null \
  || fail "rc.d/vcp must export VCP_CONFIG_DIR"
grep -n 'VCP_CONFIG_DIR=' pkg/rc.d/vcp_store >/dev/null \
  || fail "rc.d/vcp_store must export VCP_CONFIG_DIR"
grep -n '/usr/local/etc/vcp' pkg/rc.d/vcp >/dev/null \
  || fail "rc.d/vcp must default config dir to /usr/local/etc/vcp"

grep -n 'prepare_vcp_run_dir' pkg/acl.sh >/dev/null \
  || fail "acl.sh must define prepare_vcp_run_dir"
grep -n 'prepare_vcp_run_dir' pkg/rc.d/vcp_store >/dev/null \
  || fail "vcp_store rc.d must call prepare_vcp_run_dir"
grep -n 'ensure_store_socket_acl' pkg/rc.d/vcp_store >/dev/null \
  || fail "vcp_store rc.d must ensure socket FACL after bind"

# Portal must not use daemon -P (process_guard owns vcp.pid).
if grep -nE '^command_args=.*-P' pkg/rc.d/vcp >/dev/null; then
  fail "rc.d/vcp must not use daemon -P (conflicts with process_guard pidfile)"
fi
grep -n 'vcp.pid' pkg/newsyslog.conf.d/vcp.conf >/dev/null \
  || fail "newsyslog must reference /var/run/vcp/vcp.pid"
grep -nE '[[:space:]]1[[:space:]]*$|[[:space:]]1$' pkg/newsyslog.conf.d/vcp.conf >/dev/null \
  || fail "newsyslog access log line must signal 1 (SIGHUP)"
if grep -nE '[ZJXY]' pkg/newsyslog.conf.d/vcp.conf >/dev/null; then
  fail "newsyslog must not enable compression flags Z/J/X/Y"
fi

grep -n 'bin/vcp' pkg/build-pkg.sh >/dev/null \
  || fail "build-pkg.sh must stage bin/vcp"
grep -n 'sbin/vcp-store' pkg/build-pkg.sh >/dev/null \
  || fail "build-pkg.sh must stage sbin/vcp-store"
grep -n 'vcp_policy.csv' pkg/build-pkg.sh >/dev/null \
  || fail "build-pkg.sh must ship vcp_policy.csv"
if grep -n 'model.conf' pkg/build-pkg.sh pkg/+MANIFEST >/dev/null 2>&1; then
  fail "package must not ship Casbin model.conf"
fi
grep -n 'META_TMP\|\.pkg-meta' pkg/build-pkg.sh >/dev/null \
  || fail "build-pkg.sh must substitute version into a temp metadata dir"
if grep -nE 'sed -i' pkg/build-pkg.sh >/dev/null; then
  fail "build-pkg.sh must not sed -i tracked package metadata"
fi

grep -n '800' pkg/+PRE_INSTALL >/dev/null || fail "PRE_INSTALL must create UID 800"
grep -n '801' pkg/+PRE_INSTALL >/dev/null || fail "PRE_INSTALL must create UID 801"
grep -n 'vcp-storage' pkg/+PRE_INSTALL >/dev/null || fail "PRE_INSTALL must create vcp-storage"

# Runtime config discovery: release paths must not bake CARGO_MANIFEST_DIR.
# Checkout fallback is allowed only under cfg(test) / feature = "test-support".
if awk '
  /pub fn find_config_dir\(\)/ { in_fn=1; next }
  in_fn && /CARGO_MANIFEST_DIR/ { bad=1 }
  in_fn && /^    pub fn / { in_fn=0 }
  END { exit bad ? 0 : 1 }
' src/config.rs; then
  fail "find_config_dir() must not use CARGO_MANIFEST_DIR"
fi
if awk '
  /fn resolve_paths/ { in_fn=1 }
  in_fn && /CARGO_MANIFEST_DIR/ { bad=1 }
  in_fn && /^    (pub )?fn |^impl / && !/resolve_paths/ { in_fn=0 }
  END { exit bad ? 0 : 1 }
' src/config.rs; then
  fail "resolve_paths must not use CARGO_MANIFEST_DIR"
fi
if awk '
  BEGIN { depth=0; brace=0 }
  /#\[cfg\(.*test/ { depth=1; brace=0; next }
  depth {
    nopen = gsub(/\{/, "{")
    nclose = gsub(/\}/, "}")
    brace += nopen - nclose
    if (brace <= 0 && nclose > 0) depth=0
    next
  }
  /CARGO_MANIFEST_DIR/ { bad=1 }
  END { exit bad ? 0 : 1 }
' src/config.rs; then
  fail "CARGO_MANIFEST_DIR in config.rs only under cfg(test)/test-support"
fi

grep -n 'fn find_config_dir_from' src/config.rs >/dev/null \
  || fail "Config::find_config_dir_from must exist (injectable, no set_var)"
grep -n 'fn package_root_from' src/config.rs >/dev/null \
  || fail "Config::package_root_from must exist (injectable, no set_var)"
grep -n 'fn package_root' src/config.rs >/dev/null \
  || fail "Config::package_root must exist for Toasty migrations"
grep -n 'VCP_CONFIG_DIR' justfile >/dev/null \
  || fail "justfile must export VCP_CONFIG_DIR for integration tests"
grep -n 'VCP_PACKAGE_ROOT' justfile >/dev/null \
  || fail "justfile must export VCP_PACKAGE_ROOT for integration tests"
if grep -nE 'std::env::set_var|env::set_var|allow\(unsafe_code\)' src/config.rs >/dev/null; then
  fail "src/config.rs must not call set_var / allow(unsafe_code)"
fi
if grep -nE 'std::env::set_var|env::set_var|allow\(unsafe_code\)' \
  tests/integration_tests/common/mod.rs >/dev/null; then
  fail "integration common must not call set_var / allow(unsafe_code)"
fi
# just test must not enable test-support (desyncs Topcoat asset catalog).
if grep -nE 'cargo test.*features test-support|features test-support.*cargo test' justfile >/dev/null; then
  fail "just test must not pass --features test-support (breaks asset AssetIds)"
fi
grep -n 'spawn_reopen_on_hangup' src/main.rs >/dev/null \
  || fail "main must spawn access-log SIGHUP reopen"
grep -n 'fn reopen' src/tls/access_log.rs >/dev/null \
  || fail "AccessLog must implement reopen"

echo "check_freebsd_pkg: OK"
