#!/bin/sh
# Build the VCP FreeBSD package from release binaries.
#
# Version comes from Cargo.toml package.version. Substitutions for
# +MANIFEST / +POST_INSTALL use a temporary metadata directory so tracked
# sources are never rewritten in-place.
#
# Usage:  ./build-pkg.sh
# Prereq: just release (or cargo build --release + asset bundle)
# Host:   FreeBSD with pkg(8)
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
STAGING="${SCRIPT_DIR}/staging"
META_TMP="${SCRIPT_DIR}/.pkg-meta.$$"
VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${PROJECT_ROOT}/Cargo.toml" | head -1)
if [ -z "$VERSION" ]; then
    echo "ERROR: could not extract version from Cargo.toml" >&2
    exit 1
fi
RELEASE_DIR="${PROJECT_ROOT}/target/release"

echo "==> Building VCP ${VERSION} package..."

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "ERROR: pkg create requires a FreeBSD host (uname=$(uname -s))" >&2
    exit 1
fi
if ! command -v pkg >/dev/null 2>&1; then
    echo "ERROR: pkg(8) not found" >&2
    exit 1
fi

for _bin in vcp vcp-store; do
    if [ ! -f "${RELEASE_DIR}/${_bin}" ]; then
        echo "ERROR: missing ${RELEASE_DIR}/${_bin}" >&2
        echo "Run 'just release' first." >&2
        exit 1
    fi
done

# Topcoat AssetBundle::load() walks near the binary: /usr/local/bin/assets.
ASSETS_SRC="${PROJECT_ROOT}/target/assets"
if [ ! -f "${ASSETS_SRC}/manifest.toml" ]; then
    echo "ERROR: missing ${ASSETS_SRC}/manifest.toml" >&2
    echo "Run 'just release' (builds + topcoat asset bundle --release)." >&2
    exit 1
fi
if [ -f "${ASSETS_SRC}/.bundle-profile" ]; then
    _profile=$(cat "${ASSETS_SRC}/.bundle-profile")
    if [ "${_profile}" != "release" ]; then
        echo "ERROR: asset bundle profile is '${_profile}', need 'release'" >&2
        echo "Run 'just release' (or 'just bundle --release')." >&2
        exit 1
    fi
fi

rm -rf "${STAGING}" "${META_TMP}"
mkdir -p "${STAGING}/usr/local/bin"
mkdir -p "${STAGING}/usr/local/sbin"
mkdir -p "${STAGING}/usr/local/libexec/vcp"
mkdir -p "${STAGING}/usr/local/etc/vcp/certs"
mkdir -p "${STAGING}/usr/local/etc/vcp/access"
mkdir -p "${STAGING}/usr/local/etc/rc.d"
mkdir -p "${STAGING}/usr/local/etc/newsyslog.conf.d"
mkdir -p "${STAGING}/usr/local/share/vcp"

echo "==> Staging files..."
install -m 755 "${RELEASE_DIR}/vcp" "${STAGING}/usr/local/bin/vcp"
install -m 755 "${RELEASE_DIR}/vcp-store" "${STAGING}/usr/local/sbin/vcp-store"
# Topcoat looks for assets next to the binary (/usr/local/bin/assets).
cp -R "${ASSETS_SRC}" "${STAGING}/usr/local/bin/assets"
# Drop the local build stamp; operators do not need it on the host.
rm -f "${STAGING}/usr/local/bin/assets/.bundle-profile"
find "${STAGING}/usr/local/bin/assets" -type d -exec chmod 755 {} +
find "${STAGING}/usr/local/bin/assets" -type f -exec chmod 644 {} +
install -m 644 "${PROJECT_ROOT}/config/vcp.conf" "${STAGING}/usr/local/etc/vcp/vcp.conf"
install -m 644 "${PROJECT_ROOT}/config/vcp-store.conf" "${STAGING}/usr/local/etc/vcp/vcp-store.conf"
install -m 644 "${PROJECT_ROOT}/config/access/vcp_policy.csv" \
    "${STAGING}/usr/local/etc/vcp/access/vcp_policy.csv"
install -m 555 "${SCRIPT_DIR}/rc.d/vcp_store" "${STAGING}/usr/local/etc/rc.d/vcp_store"
install -m 555 "${SCRIPT_DIR}/rc.d/vcp" "${STAGING}/usr/local/etc/rc.d/vcp"
install -m 644 "${SCRIPT_DIR}/newsyslog.conf.d/vcp.conf" \
    "${STAGING}/usr/local/etc/newsyslog.conf.d/vcp.conf"
install -m 644 "${SCRIPT_DIR}/acl.sh" "${STAGING}/usr/local/libexec/vcp/acl.sh"

# Toasty migrations for POST_INSTALL / `vcp migration` (VCP_PACKAGE_ROOT).
install -m 644 "${PROJECT_ROOT}/Toasty.toml" "${STAGING}/usr/local/share/vcp/Toasty.toml"
cp -R "${PROJECT_ROOT}/toasty" "${STAGING}/usr/local/share/vcp/toasty"

echo "==> Generating plist..."
PLIST="${SCRIPT_DIR}/plist"
{
    echo "bin/vcp"
    echo "sbin/vcp-store"
    echo "libexec/vcp/acl.sh"
    echo "@config etc/vcp/vcp.conf"
    echo "@config etc/vcp/vcp-store.conf"
    echo "etc/vcp/access/vcp_policy.csv"
    echo "etc/rc.d/vcp_store"
    echo "etc/rc.d/vcp"
    echo "@config etc/newsyslog.conf.d/vcp.conf"
    echo "share/vcp/Toasty.toml"
    find "${STAGING}/usr/local/share/vcp/toasty" -type f | sed "s|^${STAGING}/usr/local/||" | sort
    find "${STAGING}/usr/local/bin/assets" -type f | sed "s|^${STAGING}/usr/local/||" | sort
    find "${STAGING}/usr/local/bin/assets" -type d | sed "s|^${STAGING}/usr/local/||" | sort | while read -r _d; do
        echo "@dir ${_d}"
    done
    echo "@dir libexec/vcp"
    echo "@dir etc/vcp/access"
    echo "@dir etc/vcp/certs"
    echo "@dir etc/vcp"
    echo "@dir share/vcp/toasty"
    echo "@dir share/vcp"
} > "${PLIST}"

echo "==> Preparing package metadata (temp; sources unchanged)..."
mkdir -p "${META_TMP}"
for _f in +MANIFEST +PRE_INSTALL +POST_INSTALL +PRE_DEINSTALL +POST_DEINSTALL; do
    sed "s/%%VERSION%%/${VERSION}/g" "${SCRIPT_DIR}/${_f}" > "${META_TMP}/${_f}"
    chmod 755 "${META_TMP}/${_f}" 2>/dev/null || true
done
# MANIFEST must not be executable
chmod 644 "${META_TMP}/+MANIFEST"

echo "==> Creating package..."
pkg create \
    -m "${META_TMP}" \
    -r "${STAGING}" \
    -p "${PLIST}" \
    -o "${SCRIPT_DIR}/"

echo "==> Package created: ${SCRIPT_DIR}/vcp-${VERSION}.pkg"
echo "==> Install with: pkg add ./vcp-${VERSION}.pkg"

rm -rf "${STAGING}" "${META_TMP}"
rm -f "${PLIST}"
