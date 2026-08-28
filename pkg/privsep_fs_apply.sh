# Apply the privsep filesystem catalogue (chmod / chown / setfacl).
# Sourced by +POST_INSTALL after secret_key / database sed -i, because
# those replace the vauban.conf inode and destroy ACEs.
#
# Usage: apply_privsep_layout <prefix> <layout.list>

# Service accounts created by +PRE_INSTALL (keep in lock-step with ALL).
SVC_USERS="vb-audit vb-vault vb-access vb-auth vb-ssh vb-rdp vb-web vb-iacs vb-mailer"

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

expand_acl_who() {
    case "$1" in
        -) echo "" ;;
        ALL) echo "${SVC_USERS}" ;;
        *) echo "$1" | tr ',' ' ' ;;
    esac
}

apply_privsep_layout() {
    _prefix=$1
    _list=$2

    if [ ! -f "$_list" ]; then
        echo "ERROR: privsep layout catalogue missing: ${_list}" >&2
        return 1
    fi

    echo "==> Applying privsep filesystem layout from ${_list}..."

    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            '' | \#*) continue ;;
        esac

        set -- $_line
        _kind=$1
        _path=$2
        _owner=$3
        _group=$4
        _mode=$5
        _acl_who=$6
        _ace=$7
        _inherit=$8
        _flags=$9

        _path=$(echo "$_path" | sed "s|\${PREFIX}|${_prefix}|g")

        if [ "$_kind" = "dir" ]; then
            mkdir -p "$_path"
        elif [ "$_kind" = "file" ]; then
            if [ ! -e "$_path" ]; then
                if [ "$_flags" = "if_exists" ]; then
                    continue
                fi
                echo "ERROR: required path missing: ${_path}" >&2
                return 1
            fi
        else
            echo "ERROR: unknown layout kind: ${_kind}" >&2
            return 1
        fi

        chown "${_owner}:${_group}" "$_path"
        chmod "$_mode" "$_path"

        if [ "$_ace" = "-" ]; then
            continue
        fi

        detect_acl_type "$_path"
        for _u in $(expand_acl_who "$_acl_who"); do
            set_acl "$_u" "$_ace" "$_path"
            if [ "$_inherit" = "fd:r" ]; then
                set_default_acl "$_u" "r" "$_path"
            fi
        done
    done <"$_list"
}
