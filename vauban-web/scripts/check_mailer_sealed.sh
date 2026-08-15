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

# REGRESSION (staging 2026-08-14): Postgres pool must warm up BEFORE cap_enter.
if ! grep -REq --include='*.rs' 'fn create_pool_sandboxed' "$ROOT/vauban-mailer/src"; then
    fail "vauban-mailer must define create_pool_sandboxed"
fi
if ! grep -REq --include='*.rs' 'fn force_create_all_connections' "$ROOT/vauban-mailer/src"; then
    fail "vauban-mailer must define force_create_all_connections"
fi
WARM_OFF=$(grep -n 'force_create_all_connections' "$MAILER_MAIN" | head -1 | cut -d: -f1)
SEAL_OFF=$(grep -n 'setup_service_sandbox_extended' "$MAILER_MAIN" | head -1 | cut -d: -f1)
if [ -z "$WARM_OFF" ] || [ -z "$SEAL_OFF" ]; then
    fail "vauban-mailer main must call force_create_all_connections and setup_service_sandbox_extended"
fi
if [ "$WARM_OFF" -ge "$SEAL_OFF" ]; then
    fail "vauban-mailer must force_create_all_connections before setup_service_sandbox_extended"
fi
# No Pool::builder after the seal call in main.rs.
AFTER_SEAL=$(awk "/setup_service_sandbox_extended/{p=1} p" "$MAILER_MAIN")
if echo "$AFTER_SEAL" | grep -Eq 'Pool::builder'; then
    fail "vauban-mailer must not build a DB pool after the Capsicum seal"
fi

# Operator logs: one queue summary, SMTP 550 must not stay silent.
if ! grep -Eq 'pub fn log_emails_queued' "$ROOT/vauban-web/src/services/mailer.rs"; then
    fail "vauban-web mailer must expose log_emails_queued (single fan-out line)"
fi
QUEUED_LINE=$(grep -n '"Email queued"' "$ROOT/vauban-web/src/services/mailer.rs" | head -1 | cut -d: -f1)
if [ -z "$QUEUED_LINE" ]; then
    fail "Mailer::queue must keep an Email queued debug breadcrumb"
fi
QUEUED_WINDOW=$(sed -n "$((QUEUED_LINE - 8)),${QUEUED_LINE}p" "$ROOT/vauban-web/src/services/mailer.rs")
if echo "$QUEUED_WINDOW" | grep -q 'info!'; then
    fail "Mailer::queue must not info-log Email queued per recipient"
fi
if ! echo "$QUEUED_WINDOW" | grep -q 'debug!'; then
    fail "Mailer::queue Email queued breadcrumb must be debug!"
fi
if ! grep -Eq 'log_emails_queued' "$ROOT/vauban-web/src/handlers/web/sessions.rs"; then
    fail "JIT queue helpers must emit log_emails_queued"
fi
if ! grep -Eq 'Mailer drain: delivery failed' "$ROOT/vauban-mailer/src/outbox.rs"; then
    fail "vauban-mailer must log Mailer drain: delivery failed on permanent SMTP errors"
fi
if ! grep -Eq 'pub async fn rset' "$ROOT/vauban-mailer/src/smtp_client.rs"; then
    fail "vauban-mailer SMTP session must implement RSET after a failed envelope"
fi
if ! grep -Eq 'session\.rset\(\)' "$ROOT/vauban-mailer/src/outbox.rs"; then
    fail "vauban-mailer drain must call session.rset() after a failed send"
fi

# Frozen discriminant pin (shared).
if ! grep -Eq 'Service::Mailer.as_token_discriminant\(\), 9\)' "$ROOT/shared/src/messages.rs"; then
    fail "shared must pin Service::Mailer discriminant 9"
fi

echo "check_mailer_sealed.sh: OK"
