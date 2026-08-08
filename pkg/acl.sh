#!/bin/sh
# FACL helpers for VCP runtime paths (NFSv4 / ZFS vs POSIX.1e / UFS).
# Sourced by rc.d/vcp_store, rc.d/vcp, and +POST_INSTALL.
#
# Default (inheritable) ACLs are best-effort: some UFS configs reject them
# (acl_calc_mask EINVAL). Access ACLs are mandatory when setfacl works.

_acl_type=""

detect_acl_type() {
    if getfacl "$1" 2>/dev/null | grep -q 'owner@'; then
        _acl_type="nfsv4"
    else
        _acl_type="posix"
    fi
}

set_acl() {
    _user=$1
    _perms=$2
    _path=$3
    case "$_acl_type" in
        nfsv4)
            getfacl "$_path" 2>/dev/null | grep -q "user:${_user}:" ||
                setfacl -a 0 "u:${_user}:${_perms}::allow" "$_path"
            ;;
        *)
            setfacl -m "u:${_user}:${_perms}" "$_path"
            ;;
    esac
}

set_default_acl() {
    _user=$1
    _perms=$2
    _path=$3
    case "$_acl_type" in
        nfsv4)
            getfacl "$_path" 2>/dev/null | grep "user:${_user}:" | grep -q ':fd' ||
                setfacl -a 0 "u:${_user}:${_perms}:fd:allow" "$_path" 2>/dev/null
            ;;
        *)
            setfacl -d -m "u:${_user}:${_perms}" "$_path" 2>/dev/null
            ;;
    esac
}

# Prepare /var/run/vcp for the helper listen socket (tmpfs — call every start).
# Owner vcp-storage:0700; portal UID vcp may traverse (rx) and inherit rw on the socket.
prepare_vcp_run_dir() {
    _run="${1:-/var/run/vcp}"
    mkdir -p "${_run}"
    chown vcp-storage:vcp-storage "${_run}"
    chmod 0700 "${_run}"
    detect_acl_type "${_run}"
    set_acl "vcp" "rx" "${_run}"
    set_default_acl "vcp" "rw" "${_run}"
}

# Portal reads server.crt / server.key and ACME rewrites them on renewal, so
# the portal UID needs rwx on the 0700 root-owned certs dir (and rw on the
# files ACME replaces). Keep the dir mode itself closed to everyone else.
ensure_portal_cert_acl() {
    _certs="${1:-/usr/local/etc/vcp/certs}"
    _portal="${2:-vcp}"
    [ -d "${_certs}" ] || return 0
    detect_acl_type "${_certs}"
    set_acl "${_portal}" "rwx" "${_certs}"
    set_default_acl "${_portal}" "rw" "${_certs}"
    for _f in "${_certs}"/*; do
        [ -f "${_f}" ] || continue
        detect_acl_type "${_f}"
        set_acl "${_portal}" "rw" "${_f}"
    done
}

# Ensure store.sock is reachable by portal UID after bind (umask 077).
ensure_store_socket_acl() {
    _sock="${1:-/var/run/vcp/store.sock}"
    if [ -S "${_sock}" ]; then
        detect_acl_type "${_sock}"
        set_acl "vcp" "rw" "${_sock}"
    fi
}
