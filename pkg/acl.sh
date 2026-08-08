#!/bin/sh
# FACL helpers for VCP runtime paths (NFSv4 / ZFS vs POSIX.1e / UFS).
# Sourced by rc.d/vcp_store, rc.d/vcp, and +POST_INSTALL.
#
# Default (inheritable) ACLs are best-effort: some UFS configs reject them
# (acl_calc_mask EINVAL). Access ACLs are mandatory when setfacl works.
#
# CRITICAL: every variable here is prefixed _vcpacl_. sh "local" is
# dynamically scoped and rc.d precmds run *inside* rc.subr's
# run_rc_command, after it computed its own _user/_group/... locals but
# before it builds the command line. A bare "_user=vcp" in these helpers
# makes rc.subr wrap the service in "su -m vcp", silently demoting
# daemon(8) (open: Permission denied / failed to set user environment).

_vcpacl_type=""

detect_acl_type() {
    if getfacl "$1" 2>/dev/null | grep -q 'owner@'; then
        _vcpacl_type="nfsv4"
    else
        _vcpacl_type="posix"
    fi
}

set_acl() {
    _vcpacl_user=$1
    _vcpacl_perms=$2
    _vcpacl_path=$3
    case "$_vcpacl_type" in
        nfsv4)
            getfacl "$_vcpacl_path" 2>/dev/null | grep -q "user:${_vcpacl_user}:" ||
                setfacl -a 0 "u:${_vcpacl_user}:${_vcpacl_perms}::allow" "$_vcpacl_path"
            ;;
        *)
            setfacl -m "u:${_vcpacl_user}:${_vcpacl_perms}" "$_vcpacl_path"
            ;;
    esac
}

set_default_acl() {
    _vcpacl_user=$1
    _vcpacl_perms=$2
    _vcpacl_path=$3
    case "$_vcpacl_type" in
        nfsv4)
            getfacl "$_vcpacl_path" 2>/dev/null | grep "user:${_vcpacl_user}:" | grep -q ':fd' ||
                setfacl -a 0 "u:${_vcpacl_user}:${_vcpacl_perms}:fd:allow" "$_vcpacl_path" 2>/dev/null
            ;;
        *)
            setfacl -d -m "u:${_vcpacl_user}:${_vcpacl_perms}" "$_vcpacl_path" 2>/dev/null
            ;;
    esac
}

# Prepare /var/run/vcp for the helper listen socket (tmpfs — call every start).
# Owner vcp-storage:0700; portal UID vcp may traverse (rx) and inherit rw on the socket.
prepare_vcp_run_dir() {
    _vcpacl_run="${1:-/var/run/vcp}"
    mkdir -p "${_vcpacl_run}"
    chown vcp-storage:vcp-storage "${_vcpacl_run}"
    chmod 0700 "${_vcpacl_run}"
    detect_acl_type "${_vcpacl_run}"
    set_acl "vcp" "rx" "${_vcpacl_run}"
    set_default_acl "vcp" "rw" "${_vcpacl_run}"
}

# Portal reads server.crt / server.key and ACME rewrites them on renewal, so
# the portal UID needs rwx on the 0700 root-owned certs dir (and rw on the
# files ACME replaces). Keep the dir mode itself closed to everyone else.
ensure_portal_cert_acl() {
    _vcpacl_certs="${1:-/usr/local/etc/vcp/certs}"
    _vcpacl_portal="${2:-vcp}"
    [ -d "${_vcpacl_certs}" ] || return 0
    detect_acl_type "${_vcpacl_certs}"
    set_acl "${_vcpacl_portal}" "rwx" "${_vcpacl_certs}"
    set_default_acl "${_vcpacl_portal}" "rw" "${_vcpacl_certs}"
    for _vcpacl_f in "${_vcpacl_certs}"/*; do
        [ -f "${_vcpacl_f}" ] || continue
        detect_acl_type "${_vcpacl_f}"
        set_acl "${_vcpacl_portal}" "rw" "${_vcpacl_f}"
    done
}

# Ensure store.sock is reachable by portal UID after bind (umask 077).
ensure_store_socket_acl() {
    _vcpacl_sock="${1:-/var/run/vcp/store.sock}"
    if [ -S "${_vcpacl_sock}" ]; then
        detect_acl_type "${_vcpacl_sock}"
        set_acl "vcp" "rw" "${_vcpacl_sock}"
    fi
}
