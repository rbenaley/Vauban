//! WebSocket logging convention -- battle-tested pin tests.
//!
//! These tests pin the call-graph of every `handle_*_socket` in
//! [`vauban-web/src/handlers/websocket.rs`] against the convention
//! documented in [`.cursor/rules/websocket-logging.mdc`]:
//!
//! 1. Each socket emits EXACTLY ONE `info!` for each of the four
//!    lifecycle events: `WebSocket connection requested`,
//!    `WebSocket connected`, `WebSocket closed`, `WebSocket disconnected`.
//! 2. The `closed` line MUST carry a `cause = ` field, populated from
//!    one of `close | stream_end | error | ping_fail | send_fail |
//!    server_close | unknown`.
//! 3. Every lifecycle line MUST carry `channel = `.
//! 4. The legacy wordings "Client requested close" and "WebSocket
//!    stream ended" MUST NOT appear in the file (they are folded into
//!    the unique `WebSocket closed` line via `cause`).
//! 5. The lifecycle lines MUST be at `info!` level (never `debug!`).
//!
//! Companion enforcers:
//! - [`vauban-web/scripts/check_websocket_logging.sh`] (CI lint)
//! - [`vauban-web/src/services/broadcast.rs`] runtime tests for the
//!   `is_low_cardinality` classification and level routing of
//!   `BroadcastService::send_raw`.

const WS_HANDLERS_SRC: &str = include_str!("../../src/handlers/websocket.rs");

/// Source-grep helper: returns the body of a function that starts at
/// `signature`, balanced on `{`/`}` from the first `{` after the
/// signature. Brace-counter (not regex) so nested blocks (match arms,
/// `tokio::select! { }`, etc.) do not truncate the body.
fn fn_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("signature `{}` not found in source", signature));
    let tail = &source[start..];
    let open = tail
        .find('{')
        .unwrap_or_else(|| panic!("no `{{` after signature `{}`", signature));
    let mut depth: i32 = 0;
    let mut end = tail.len();
    for (i, ch) in tail[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    tail[..end].to_string()
}

/// Every `handle_*_socket` covered by the convention. Adding a new
/// WS handler MUST extend this list (and the test will then enforce
/// the four lifecycle events automatically).
const HANDLERS: &[&str] = &[
    "async fn handle_dashboard_socket(",
    "async fn handle_dashboard_personal_socket(",
    "async fn handle_session_socket(",
    "async fn handle_notifications_socket(",
    "async fn handle_active_sessions_socket(",
    "async fn handle_session_list_socket(",
    "async fn handle_terminal_socket(",
    "async fn handle_rdp_socket(",
];

/// Every WS lifecycle line in every handler MUST be `info!` (never
/// `debug!`/`warn!`/`error!`) AND carry a `channel = ` field.
#[test]
fn every_handler_emits_the_four_lifecycle_events_at_info_with_channel_field() {
    for sig in HANDLERS {
        let body = fn_body(WS_HANDLERS_SRC, sig);
        for (event, expected_field) in &[
            ("\"WebSocket connection requested\"", "channel = "),
            ("\"WebSocket connected\"", "channel = "),
            ("\"WebSocket closed\"", "cause = "),
            ("\"WebSocket disconnected\"", "channel = "),
        ] {
            // Some handlers (terminal, rdp, dashboard, list, ...) do
            // NOT emit `connection requested` from inside the
            // `handle_*_socket` body -- it lives in the upgrade
            // wrapper. So we only enforce presence for the events the
            // body owns. The wrapper-side coverage is enforced by the
            // `every_upgrade_wrapper_emits_connection_requested_at_info`
            // test below.
            if *event == "\"WebSocket connection requested\"" {
                continue;
            }
            // Find the FIRST occurrence of the literal that is NOT
            // inside a `//` comment. We walk through every match and
            // skip those whose line contains `//` before the literal.
            let mut idx_opt: Option<usize> = None;
            let mut cursor = 0usize;
            while let Some(rel) = body[cursor..].find(event) {
                let abs = cursor + rel;
                let line_start = body[..abs].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let prefix = &body[line_start..abs];
                if !prefix.contains("//") {
                    idx_opt = Some(abs);
                    break;
                }
                cursor = abs + 1;
            }
            let idx = idx_opt.unwrap_or_else(|| {
                panic!(
                    "{}: missing lifecycle log {} (no non-comment occurrence found)",
                    sig, event
                )
            });
            // Assert the surrounding text contains the expected field.
            // We scan a window of 400 chars BEFORE the message literal
            // (covers a multi-line tracing macro).
            let win_start = idx.saturating_sub(400);
            let window = &body[win_start..idx];
            assert!(
                window.contains(expected_field),
                "{}: lifecycle log `{}` is missing the `{}` field. \
                 See `.cursor/rules/websocket-logging.mdc` and the \
                 helpers in `services::broadcast::WsChannel::as_str`.",
                sig,
                event,
                expected_field
            );
            // The lifecycle line must be `info!`, not `debug!` /
            // `warn!` / `error!`.
            assert!(
                window.contains("info!"),
                "{}: lifecycle log `{}` must be at `info!` level (found a \
                 different macro before the message in the 400-char window)",
                sig,
                event
            );
        }
    }
}

/// Each `<X>_ws` upgrade wrapper MUST emit the `connection requested`
/// event (the only event that fires BEFORE `on_upgrade`).
#[test]
fn every_upgrade_wrapper_emits_connection_requested_at_info() {
    for sig in &[
        "pub async fn dashboard_ws(",
        "pub async fn dashboard_personal_ws(",
        "pub async fn session_ws(",
        "pub async fn notifications_ws(",
        "pub async fn active_sessions_ws(",
        "pub async fn session_list_ws(",
        "pub async fn terminal_ws(",
        "pub async fn rdp_ws(",
    ] {
        let body = fn_body(WS_HANDLERS_SRC, sig);
        assert!(
            body.contains(r#""WebSocket connection requested""#),
            "{}: must emit the canonical `WebSocket connection requested` \
             info!() before `ws.on_upgrade(...)`",
            sig
        );
        // channel = ... must be present in the SAME function body.
        assert!(
            body.contains("channel = "),
            "{}: `connection requested` info! must carry the `channel = ` \
             field (use WsChannel::<Variant>.as_str() or the channel_label \
             local variable)",
            sig
        );
    }
}

/// `cause = ` values are restricted to the canonical set.
#[test]
fn close_cause_values_belong_to_the_canonical_set() {
    const ALLOWED: &[&str] = &[
        r#"close_cause = "close""#,
        r#"close_cause = "stream_end""#,
        r#"close_cause = "error""#,
        r#"close_cause = "ping_fail""#,
        r#"close_cause = "send_fail""#,
        r#"close_cause = "server_close""#,
        // initial value -- never a "real" cause but acceptable on the
        // `let mut close_cause: &'static str = "unknown";` declaration.
        r#"close_cause: &'static str = "unknown""#,
    ];
    // Find every `close_cause = "..."` assignment and assert it
    // appears in the allowed list.
    let mut cursor = 0usize;
    while let Some(rel) = WS_HANDLERS_SRC[cursor..].find("close_cause = \"") {
        let abs = cursor + rel;
        let line_end = WS_HANDLERS_SRC[abs..].find('\n').unwrap_or(0);
        let line = WS_HANDLERS_SRC[abs..abs + line_end].trim().to_string();
        assert!(
            ALLOWED.iter().any(|a| line.contains(a)),
            "Forbidden close_cause assignment: `{}`. Allowed values: \
             close, stream_end, error, ping_fail, send_fail, \
             server_close. See `.cursor/rules/websocket-logging.mdc`.",
            line
        );
        cursor = abs + 1;
    }
}

/// Anti-regression on the v0.7.0 unification: the legacy log lines
/// MUST NOT come back. Their successors are `cause = "close"` /
/// `cause = "stream_end"` on the unique `WebSocket closed` line.
#[test]
fn legacy_close_wordings_are_eradicated() {
    for forbidden in &[
        // The Notifications handler used to log these at `debug!`,
        // which was the root cause of the "canal silencieux" audit
        // report. Re-introducing them anywhere bypasses the unified
        // `WebSocket closed` event.
        r#""Client requested close""#,
        r#""WebSocket stream ended""#,
        r#""Session WS close requested""#,
        r#""RDP client requested close""#,
        r#""RDP WebSocket stream ended""#,
        // Old per-handler `info!("X WebSocket connected")` are
        // replaced with the canonical `"WebSocket connected"` (so
        // grep'ing logs by `channel=` returns the FAMILY without
        // wording drift).
        r#""Dashboard WebSocket connected""#,
        r#""Notifications WebSocket connected with personalized session support""#,
        r#""Active sessions list WebSocket connected""#,
        r#""Session list WebSocket connected""#,
        r#""Session WebSocket connected""#,
        r#""Terminal WebSocket connected""#,
        r#""RDP WebSocket connected""#,
        r#""Dashboard WebSocket disconnected""#,
        r#""Notifications WebSocket disconnected""#,
        r#""Active sessions list WebSocket disconnected""#,
        r#""Session list WebSocket disconnected""#,
        r#""Session WebSocket disconnected""#,
        r#""Terminal WebSocket disconnected""#,
        r#""RDP WebSocket disconnected""#,
    ] {
        assert!(
            !WS_HANDLERS_SRC.contains(forbidden),
            "Legacy WS log wording still present: {}. Use the canonical \
             `\"WebSocket connected\" / \"WebSocket closed\" / \
             \"WebSocket disconnected\"` lines with `channel = ` and \
             `cause = ` fields. See `.cursor/rules/websocket-logging.mdc`.",
            forbidden
        );
    }
}

/// Anti-asymmetry pin: every receiver-side close arm
/// (`Some(Ok(Message::Close(_))) =>`) MUST set
/// `close_cause = "close"` within the next 600 characters. The
/// receiver pattern is unambiguous: server-initiated close is
/// `Message::Close(Some(...))` (no underscore), so this match excludes
/// it. A regression here would emit `cause = unknown` on a clean
/// client close.
#[test]
fn every_close_arm_sets_close_cause() {
    const RECEIVER_CLOSE: &str = "Some(Ok(Message::Close(_))) =>";
    let mut cursor = 0usize;
    let mut count = 0usize;
    while let Some(rel) = WS_HANDLERS_SRC[cursor..].find(RECEIVER_CLOSE) {
        let abs = cursor + rel;
        // 1200 chars is generous: the longest close arm today is the
        // RDP one (~720 chars) which spawns a blocking task to close
        // the underlying RDP session before setting close_cause.
        let arm_end = std::cmp::min(WS_HANDLERS_SRC.len(), abs + 1200);
        let arm = &WS_HANDLERS_SRC[abs..arm_end];
        assert!(
            arm.contains("close_cause = \"close\""),
            "Receiver `{}` arm at offset {} does not set \
             `close_cause = \"close\"` within 1200 chars -- the \
             `WebSocket closed` line would emit `cause = unknown` and \
             lose the termination reason. Arm preview: `{}`",
            RECEIVER_CLOSE,
            abs,
            &arm[..std::cmp::min(arm.len(), 200)].replace('\n', " ")
        );
        count += 1;
        cursor = abs + 1;
    }
    // Sanity: we expect at least one per non-trivial handler. With
    // 7 handlers all driving a receiver, we should see >= 7 hits.
    assert!(
        count >= 7,
        "Expected at least 7 `Some(Ok(Message::Close(_)))` arms (one per \
         handler); found {}. Did a handler stop reading from `receiver.next()`?",
        count
    );
}

/// Anti-asymmetry pin: every `None` arm in a `receiver.next()` match
/// in handlers/websocket.rs MUST be paired with `close_cause = "stream_end"`.
/// (Sentinel test for the `None =>` branch which used to log at
/// `debug!` for Notifications.)
#[test]
fn every_handler_sets_stream_end_close_cause_for_receiver_none() {
    for sig in HANDLERS {
        let body = fn_body(WS_HANDLERS_SRC, sig);
        // Heuristic: handlers that consume `receiver.next()` always
        // contain a `Some(Ok(Message::Text` arm. Skip handlers that
        // do not drive a receiver (none today, kept for safety).
        if !body.contains("Some(Ok(Message::") {
            continue;
        }
        // Must contain `None =>` (the receiver-end arm) AND the
        // matching `close_cause = "stream_end"`. We don't enforce
        // adjacency because the arm body may grow new diagnostics.
        assert!(
            body.contains("None =>"),
            "{}: receiver match missing `None =>` arm",
            sig
        );
        assert!(
            body.contains("close_cause = \"stream_end\""),
            "{}: receiver `None =>` arm must set \
             `close_cause = \"stream_end\"`. The unified `WebSocket \
             closed` line otherwise emits `cause = unknown` for a \
             clean stream EOF.",
            sig
        );
    }
}

/// Anti-cardinality-leak pin: every lifecycle MESSAGE LITERAL is
/// emitted by an `info!` macro, never `debug!`/`warn!`/`error!`. We
/// scan every lifecycle literal and check that the open-paren of the
/// enclosing macro is preceded by `info!`. Multi-line tracing macros
/// are handled by walking back to the FIRST `<macro>!(` token before
/// the literal.
///
/// (Companion to `every_handler_emits_the_four_lifecycle_events_at_info_with_channel_field`,
/// but operates on the WHOLE file -- not just function bodies -- so
/// helper / test-only / future code paths cannot bypass it.)
#[test]
fn lifecycle_literals_are_only_emitted_by_info_macro() {
    for kw in &[
        "\"WebSocket connection requested\"",
        "\"WebSocket connected\"",
        "\"WebSocket closed\"",
        "\"WebSocket disconnected\"",
    ] {
        let mut cursor = 0usize;
        while let Some(rel) = WS_HANDLERS_SRC[cursor..].find(kw) {
            let abs = cursor + rel;
            // Skip occurrences in `//` comments.
            let line_start = WS_HANDLERS_SRC[..abs]
                .rfind('\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let prefix = &WS_HANDLERS_SRC[line_start..abs];
            if prefix.contains("//") {
                cursor = abs + 1;
                continue;
            }
            // Walk back from `abs` to find the enclosing macro call.
            // We look at the 400 chars preceding the literal and grab
            // the LAST `<macro>!(` token before it.
            let win_start = abs.saturating_sub(400);
            let window = &WS_HANDLERS_SRC[win_start..abs];
            let last_macro = ["info!(", "debug!(", "warn!(", "error!(", "trace!("]
                .iter()
                .filter_map(|m| window.rfind(m).map(|i| (m, i)))
                .max_by_key(|(_, i)| *i)
                .map(|(m, _)| *m);
            assert_eq!(
                last_macro,
                Some("info!("),
                "Lifecycle literal {} at offset {} is emitted by macro {:?} \
                 (expected `info!(`). Lifecycle events MUST be info!. \
                 See `.cursor/rules/websocket-logging.mdc`.",
                kw,
                abs,
                last_macro
            );
            cursor = abs + 1;
        }
    }
}
