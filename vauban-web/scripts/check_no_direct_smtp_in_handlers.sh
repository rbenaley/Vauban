#!/usr/bin/env bash
# Issue #10 -- Lint guard: SMTP must never be invoked from a handler.
#
# Why: every email-sending site MUST go through the transactional
# outbox (`Mailer::queue` -> `email_outbox` -> dispatcher task). A
# handler that opens an SMTP socket directly would:
#
#   1. Hold the request thread for the duration of the SMTP exchange
#      (defeats the asynchronous fire-and-forget design).
#   2. Bypass the supervisor whitelist (the supervisor only honours
#      `request_smtp_connect`, but a tokio TcpStream::connect would
#      hit the FreeBSD jail's `inet` rights instead, defeating the
#      sandbox).
#   3. Skip the at-least-once retry budget and the audit row in
#      `email_outbox`, so transient failures silently lose
#      notifications.
#
# This script greps the handler tree for forbidden symbols and fails
# CI if any are found. The dispatcher task and the smtp_client module
# are the only legitimate consumers and are excluded by virtue of
# living outside `src/handlers/`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HANDLER_DIR="${ROOT}/src/handlers"

if [[ ! -d "${HANDLER_DIR}" ]]; then
    echo "[lint] handler directory not found: ${HANDLER_DIR}" >&2
    exit 2
fi

# Forbidden patterns: any direct reference to the smtp_client module,
# its public entry points, or third-party SMTP crates we explicitly
# never want to grow into.
PATTERN='(smtp_client::|SmtpSession::open|services::smtp_client|lettre::|use lettre)'

violations=$(grep -REn --include='*.rs' -E "${PATTERN}" "${HANDLER_DIR}" || true)

if [[ -n "${violations}" ]]; then
    echo "[lint] Direct SMTP usage detected in handlers:" >&2
    echo "${violations}" >&2
    echo >&2
    echo "[lint] Email sending MUST go through the transactional" >&2
    echo "[lint] outbox: state.mailer.queue(&mut conn, &event)." >&2
    echo "[lint] See vauban-web/src/services/mailer.rs (Issue #10)." >&2
    exit 1
fi

echo "[lint] no direct SMTP usage in handlers"
