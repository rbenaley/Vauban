#!/bin/sh
# Build the Vauban FreeBSD package from release binaries.
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
VERSION="0.2.0"
RELEASE_DIR="${PROJECT_ROOT}/target/release"

echo "==> Building Vauban ${VERSION} package..."

# ---- Verify release binaries exist ----------------------------------------
_missing=""
for _bin in create_superuser migrate_secrets reset_2FA reset_password seed_data \
            vauban-audit vauban-auth vauban-proxy-rdp vauban-proxy-ssh \
            vauban-rbac vauban-supervisor vauban-vault vauban-web; do
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
mkdir -p "${STAGING}/usr/local/etc/rc.d"
mkdir -p "${STAGING}/usr/local/share/vauban/migrations"

for _bin in create_superuser migrate_secrets reset_2FA reset_password seed_data; do
    install -m 755 "${RELEASE_DIR}/${_bin}" "${STAGING}/usr/local/bin/"
done

for _svc in vauban-audit vauban-auth vauban-proxy-rdp vauban-proxy-ssh \
            vauban-rbac vauban-supervisor vauban-vault vauban-web; do
    install -m 755 "${RELEASE_DIR}/${_svc}" "${STAGING}/usr/local/libexec/vauban/"
done

install -m 644 "${PROJECT_ROOT}/config/default.toml"    "${STAGING}/usr/local/etc/vauban/default.toml.sample"
install -m 644 "${PROJECT_ROOT}/config/production.toml" "${STAGING}/usr/local/etc/vauban/production.toml.sample"

cp -R "${PROJECT_ROOT}/vauban-web/migrations/"* "${STAGING}/usr/local/share/vauban/migrations/"

install -m 555 "${SCRIPT_DIR}/rc.d/vauban" "${STAGING}/usr/local/etc/rc.d/vauban"

# ---- Replace version placeholder in +POST_INSTALL -------------------------
sed "s/%%VERSION%%/${VERSION}/g" "${SCRIPT_DIR}/+POST_INSTALL" > "${SCRIPT_DIR}/+POST_INSTALL.tmp"
mv "${SCRIPT_DIR}/+POST_INSTALL.tmp" "${SCRIPT_DIR}/+POST_INSTALL"

# ---- Create package --------------------------------------------------------
echo "==> Creating package..."
pkg create \
    -m "${SCRIPT_DIR}" \
    -r "${STAGING}" \
    -p "${SCRIPT_DIR}/plist" \
    -o "${SCRIPT_DIR}/"

echo "==> Package created: ${SCRIPT_DIR}/vauban-${VERSION}.pkg"
echo "==> Install with: pkg add ./vauban-${VERSION}.pkg"

rm -rf "${STAGING}"
