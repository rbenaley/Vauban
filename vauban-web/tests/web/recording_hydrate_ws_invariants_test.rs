//! Structural invariants for Recording Details hydration auto-refresh.
//!
//! | ID | Contract |
//! |----|----------|
//! | **I-HYDRATE-WS-1** | Payload embeds `recording_hydrated` + `session_uuid` |
//! | **I-HYDRATE-WS-2** | Broadcast always schedules a delayed catch-up re-send |
//! | **I-HYDRATE-WS-3** | Detail template filters on event kind AND this UUID |
//! | **I-HYDRATE-WS-4** | Detail template polls `every 5s` (WS race safety net) |
//! | **I-HYDRATE-WS-5** | Notifications handler treats `Lagged` as non-fatal |
//! | **I-HYDRATE-WS-6** | Pure payload helper is the sole body builder |

const HYDRATOR_SRC: &str = include_str!("../../src/services/recording_hydrator.rs");
const DETAIL_HTML: &str = include_str!("../../templates/sessions/recording_detail.html");
const LIST_HTML: &str = include_str!("../../templates/sessions/recording_list.html");
const WS_SRC: &str = include_str!("../../src/handlers/websocket.rs");

fn fn_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("signature `{signature}` not found"));
    let tail = &source[start..];
    let open = tail
        .find('{')
        .unwrap_or_else(|| panic!("no `{{` after `{signature}`"));
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

#[test]
fn i_hydrate_ws_1_payload_helper_embeds_stable_literals() {
    assert!(
        HYDRATOR_SRC.contains("pub const RECORDING_HYDRATED_EVENT"),
        "I-HYDRATE-WS-1: event kind must be a named constant"
    );
    assert!(
        HYDRATOR_SRC.contains("pub fn recording_hydrated_json_payload"),
        "I-HYDRATE-WS-1/6: pure payload helper must be public for proptest"
    );
    let body = fn_body(HYDRATOR_SRC, "pub fn recording_hydrated_json_payload(");
    assert!(
        body.contains("RECORDING_HYDRATED_EVENT"),
        "payload helper must use the named event constant"
    );
    assert!(
        body.contains("session_uuid"),
        "payload helper must embed session_uuid"
    );
}

#[test]
fn i_hydrate_ws_2_broadcast_always_schedules_retry() {
    let body = fn_body(HYDRATOR_SRC, "async fn broadcast_recording_hydrated(");
    assert!(
        body.contains("RECORDING_HYDRATED_RETRY_SECS"),
        "I-HYDRATE-WS-2: must sleep RECORDING_HYDRATED_RETRY_SECS before retry"
    );
    assert!(
        body.contains("tokio::spawn"),
        "I-HYDRATE-WS-2: retry must be fire-and-forget"
    );
    // Exactly one spawn in the helper (the retry); not zero, not a loop.
    let spawns = body.matches("tokio::spawn").count();
    assert_eq!(
        spawns, 1,
        "I-HYDRATE-WS-2: exactly one retry spawn, found {spawns}"
    );
}

#[test]
fn i_hydrate_ws_3_detail_template_filters_event_and_uuid() {
    let trigger = DETAIL_HTML
        .split(r#"id="recording-detail-ws-trigger""#)
        .nth(1)
        .expect("WS trigger element");
    let window = &trigger[..trigger.find("</div>").unwrap_or(800).min(trigger.len())];
    assert!(
        window.contains("htmx:wsAfterMessage"),
        "I-HYDRATE-WS-3: must listen on htmx:wsAfterMessage"
    );
    assert!(
        window.contains("'recording_hydrated'"),
        "I-HYDRATE-WS-3: must filter on recording_hydrated"
    );
    assert!(
        window.contains("{{ recording.session_uuid }}"),
        "I-HYDRATE-WS-3: must filter on THIS session uuid"
    );
}

#[test]
fn i_hydrate_ws_4_detail_template_polls_every_5s() {
    let trigger = DETAIL_HTML
        .split(r#"id="recording-detail-ws-trigger""#)
        .nth(1)
        .expect("WS trigger element");
    assert!(
        trigger.contains("every 5s"),
        "I-HYDRATE-WS-4: every 5s safety net required (tokio broadcast \
         does not replay; WS subscribe can race the hydrator)"
    );
    // List keeps its coarser poll; detail must be stricter while pending.
    assert!(
        LIST_HTML.contains("every 30s"),
        "list page must keep every 30s (regression guard)"
    );
}

#[test]
fn i_hydrate_ws_5_notifications_handler_treats_lagged_as_non_fatal() {
    let body = fn_body(WS_SRC, "async fn handle_notifications_socket(");
    assert!(
        body.contains("RecvError::Lagged"),
        "I-HYDRATE-WS-5: must match Lagged explicitly"
    );
    // Lagged arm must NOT set should_close = true (would drop the tab).
    let lagged_idx = body
        .find("RecvError::Lagged")
        .expect("Lagged arm");
    let lagged_window = &body[lagged_idx..lagged_idx.saturating_add(400)];
    assert!(
        !lagged_window.contains("should_close = true"),
        "I-HYDRATE-WS-5: Lagged must not tear down the notifications socket \
         (detail page relies on it staying up for the every-5s + retry path)"
    );
    assert!(
        lagged_window.contains("warn!"),
        "I-HYDRATE-WS-5: Lagged must be visible at warn! for operators"
    );
}

#[test]
fn i_hydrate_ws_6_broadcast_uses_pure_payload_helper() {
    let body = fn_body(HYDRATOR_SRC, "async fn broadcast_recording_hydrated(");
    assert!(
        body.contains("recording_hydrated_json_payload"),
        "I-HYDRATE-WS-6: broadcast must not inline a second JSON format!"
    );
    assert!(
        !body.contains(r#"r#"{{"type":"recording_hydrated""#),
        "I-HYDRATE-WS-6: no inline payload format! in broadcast helper"
    );
}
