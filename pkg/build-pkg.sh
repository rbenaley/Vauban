#!/bin/sh
# Build the Vauban FreeBSD package from release binaries.
#
# Package version is taken from [workspace.package] version in Cargo.toml
# (e.g. 0.5.0). It is substituted into +MANIFEST and +POST_INSTALL at build time.
#
# Usage:  ./build-pkg.sh
#
# Prerequisites:
#   - just build --release   (or: just release)
#   - FreeBSD host with pkg(8) installed
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
STAGING="${SCRIPT_DIR}/staging"
VERSION=$(sed -n '/^\[workspace\.package\]/,/^version/{s/^version *= *"\(.*\)"/\1/p;}' "${PROJECT_ROOT}/Cargo.toml")
if [ -z "$VERSION" ]; then
    echo "ERROR: could not extract version from Cargo.toml"
    exit 1
fi
RELEASE_DIR="${PROJECT_ROOT}/target/release"

echo "==> Building Vauban ${VERSION} package..."

# ---- Verify release binaries exist ----------------------------------------
_missing=""
for _bin in vauban-access vauban-audit vauban-auth vauban-proxy-iacs vauban-proxy-rdp \
            vauban-proxy-ssh vauban-supervisor vauban-vault vauban-web; do
    if [ ! -f "${RELEASE_DIR}/${_bin}" ]; then
        _missing="${_missing} ${_bin}"
    fi
done
if [ -n "$_missing" ]; then
    echo "ERROR: missing release binaries:${_missing}"
    echo "Run 'just build --release' first."
    exit 1
fi

# ---- Clean previous staging -----------------------------------------------
rm -rf "${STAGING}"

# ---- Stage files -----------------------------------------------------------
echo "==> Staging files..."

mkdir -p "${STAGING}/usr/local/bin"
mkdir -p "${STAGING}/usr/local/libexec/vauban"
mkdir -p "${STAGING}/usr/local/etc/vauban/certs"
mkdir -p "${STAGING}/usr/local/etc/vauban/access"
mkdir -p "${STAGING}/usr/local/etc/rc.d"
mkdir -p "${STAGING}/usr/local/share/vauban/migrations"

for _svc in vauban-access vauban-audit vauban-auth vauban-proxy-iacs vauban-proxy-rdp \
            vauban-proxy-ssh vauban-supervisor vauban-vault vauban-web; do
    install -m 755 "${RELEASE_DIR}/${_svc}" "${STAGING}/usr/local/libexec/vauban/"
done

install -m 644 "${PROJECT_ROOT}/config/vauban.conf" "${STAGING}/usr/local/etc/vauban/vauban.conf"
install -m 644 "${PROJECT_ROOT}/config/access/model.conf" "${STAGING}/usr/local/etc/vauban/access/model.conf"
install -m 644 "${PROJECT_ROOT}/config/access/default_policy.csv" "${STAGING}/usr/local/etc/vauban/access/policy.csv"

cp -R "${PROJECT_ROOT}/vauban-db/migrations/"* "${STAGING}/usr/local/share/vauban/migrations/"

install -m 555 "${SCRIPT_DIR}/rc.d/vauban" "${STAGING}/usr/local/etc/rc.d/vauban"

# ---- Generate plist from staged migrations ---------------------------------
echo "==> Generating plist..."
PLIST="${SCRIPT_DIR}/plist"

cat > "${PLIST}" <<'PLIST_STATIC'
libexec/vauban/vauban-audit
libexec/vauban/vauban-auth
libexec/vauban/vauban-proxy-iacs
libexec/vauban/vauban-proxy-rdp
libexec/vauban/vauban-proxy-ssh
libexec/vauban/vauban-access
libexec/vauban/vauban-supervisor
libexec/vauban/vauban-vault
libexec/vauban/vauban-web
etc/vauban/vauban.conf
etc/vauban/access/model.conf
etc/vauban/access/policy.csv
PLIST_STATIC

for _mig_dir in $(ls -d "${STAGING}/usr/local/share/vauban/migrations"/*/ 2>/dev/null | sort); do
    _name=$(basename "${_mig_dir}")
    for _sql in up.sql down.sql; do
        if [ -f "${_mig_dir}/${_sql}" ]; then
            echo "share/vauban/migrations/${_name}/${_sql}" >> "${PLIST}"
        fi
    done
done

echo "etc/rc.d/vauban" >> "${PLIST}"

echo "@dir libexec/vauban" >> "${PLIST}"
echo "@dir etc/vauban/access" >> "${PLIST}"
echo "@dir etc/vauban/certs" >> "${PLIST}"
echo "@dir etc/vauban" >> "${PLIST}"

for _mig_dir in $(ls -d "${STAGING}/usr/local/share/vauban/migrations"/*/ 2>/dev/null | sort -r); do
    echo "@dir share/vauban/migrations/$(basename "${_mig_dir}")" >> "${PLIST}"
done

echo "@dir share/vauban/migrations" >> "${PLIST}"
echo "@dir share/vauban" >> "${PLIST}"

# ---- Replace version placeholders ------------------------------------------
for _tmpl in +MANIFEST +POST_INSTALL; do
    sed "s/%%VERSION%%/${VERSION}/g" "${SCRIPT_DIR}/${_tmpl}" > "${SCRIPT_DIR}/${_tmpl}.tmp"
    mv "${SCRIPT_DIR}/${_tmpl}.tmp" "${SCRIPT_DIR}/${_tmpl}"
done

# ---- Create package --------------------------------------------------------
echo "==> Creating package..."
pkg create \
    -m "${SCRIPT_DIR}" \
    -r "${STAGING}" \
    -p "${PLIST}" \
    -o "${SCRIPT_DIR}/"

echo "==> Package created: ${SCRIPT_DIR}/vauban-${VERSION}.pkg"
echo "==> Install with: pkg add ./vauban-${VERSION}.pkg"

rm -rf "${STAGING}"
rm -f "${PLIST}"
