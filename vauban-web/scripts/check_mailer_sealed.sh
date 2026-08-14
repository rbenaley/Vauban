#!/usr/bin/env bash
# Lot B structural lint: vauban-web must not broker SMTP; gate lives on Mailer.
# Uses grep (not rg) so cargo-test sandboxes without ripgrep in PATH still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WEB_SRC="$ROOT/vauban-web/src"
SUP_MAIN="$ROOT/vauban-supervisor/src/main.rs"
MAILER_MAIN="$ROOT/vauban-mailer/src/main.rs"

fail() {
    echo "check_mailer_sealed.sh: $*" >&2
    exit 1
}

# Web must not request SMTP connects or host smtp_client session code.
if grep -REq --include='*.rs' 'request_smtp_connect|pending_smtp_connects' "$WEB_SRC"; then
    fail "vauban-web still references request_smtp_connect / pending_smtp_connects"
fi
if grep -REq --include='*.rs' 'services::smtp_client|mod smtp_client|SmtpSession::open' "$WEB_SRC"; then
    fail "vauban-web still references smtp_client session path"
fi
if grep -REq --include='*.rs' 'start_mailer_dispatcher' "$WEB_SRC"; then
    fail "vauban-web still spawns start_mailer_dispatcher"
fi

# Supervisor: mailer whitelist on Service::Mailer, not Service::Web.
if grep -Eq 'matches!\(target_service, Service::Web\).*mailer\.allows' "$SUP_MAIN"; then
    fail "supervisor still gates mailer.allows on Service::Web"
fi
if ! grep -Eq 'matches!\(target_service, Service::Mailer\)' "$SUP_MAIN"; then
    fail "supervisor must gate mailer broker on Service::Mailer"
fi
if ! grep -Eq 'Service::Mailer => "mailer"' "$SUP_MAIN"; then
    fail "supervisor must map Service::Mailer to mailer service key"
fi

# Mailer leaf: sandbox + broker target.
if ! grep -Eq 'setup_service_sandbox_extended' "$MAILER_MAIN"; then
    fail "vauban-mailer must enter Capsicum sandbox"
fi
# REGRESSION (FreeBSD ConflictingFdRights crash-loop): fd_passing_socket must
# NOT appear in the ipc_fds vec passed as the first argument.
if grep -Eq 'vec!\[ipc_read_fd, ipc_write_fd, fd_passing_socket\]' "$MAILER_MAIN"; then
    fail "vauban-mailer must not list fd_passing_socket in ipc_fds (one fd, one kind)"
fi
if ! grep -Eq 'let ipc_fds = vec!\[ipc_read_fd, ipc_write_fd\]' "$MAILER_MAIN"; then
    fail "vauban-mailer ipc_fds must be supervisor read/write pipes only"
fi
if ! grep -Eq 'fd_receiver_fds.*fd_passing_socket|Some\(vec!\[fd_passing_socket\]\)' "$MAILER_MAIN"; then
    fail "vauban-mailer must declare fd_passing_socket as fd_receiver only"
fi
if ! grep -Eq 'one fd, one kind' "$MAILER_MAIN"; then
    fail "vauban-mailer must document one-fd-one-kind invariant at seal site"
fi
if ! grep -REq --include='*.rs' 'MailerSmtpProvision|wait_for_mailer_provision' "$ROOT/vauban-mailer/src"; then
    fail "vauban-mailer must wait for MailerSmtpProvision"
fi
if ! grep -REq --include='*.rs' 'target_service: Service::Mailer' "$ROOT/vauban-mailer/src"; then
    fail "vauban-mailer broker must use Service::Mailer"
fi
# Catalogue drift: MAILER_KINDS must exist in shared sandbox profiles.
if ! grep -Eq 'pub const MAILER_KINDS' "$ROOT/shared/src/sandbox/profiles.rs"; then
    fail "shared sandbox profiles must define MAILER_KINDS"
fi

# Frozen discriminant pin (shared).
if ! grep -Eq 'Service::Mailer.as_token_discriminant\(\), 9\)' "$ROOT/shared/src/messages.rs"; then
    fail "shared must pin Service::Mailer discriminant 9"
fi

echo "check_mailer_sealed.sh: OK"
