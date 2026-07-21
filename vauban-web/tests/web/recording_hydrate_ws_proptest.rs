//! Property tests for the Recording Details hydration WebSocket contract.
//!
//! Invariants under test (see also `recording_hydrate_ws_invariants_test`):
//! - **I-HYDRATE-WS-1**: payload always embeds `recording_hydrated` + uuid
//! - **I-HYDRATE-WS-3**: detail-page filter matches iff both tokens present
//! - **I-HYDRATE-WS-5**: payload carries no PII keys

use proptest::prelude::*;
use uuid::Uuid;
use vauban_web::services::broadcast::{BroadcastService, WsChannel, WsMessage};
use vauban_web::services::recording_hydrator::{
    RECORDING_HYDRATED_EVENT, recording_detail_ws_filter_matches, recording_hydrated_json_payload,
};

fn uuid_strat() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// I-HYDRATE-WS-1 / I-HYDRATE-WS-3: the JSON body alone is enough for
    /// the detail-page `indexOf` filter to accept its own session.
    #[test]
    fn payload_always_matches_own_session_filter(uuid in uuid_strat()) {
        let payload = recording_hydrated_json_payload(&uuid);
        prop_assert!(
            recording_detail_ws_filter_matches(&payload, &uuid),
            "payload={payload}"
        );
        prop_assert!(
            payload.contains(RECORDING_HYDRATED_EVENT),
            "must embed the stable event kind literal"
        );
        prop_assert!(
            payload.contains(&uuid.to_string()),
            "must embed the canonical UUID Display form"
        );
    }

    /// Cross-session isolation: a hydration event for A must never
    /// refresh a detail tab watching B (thundering-herd guard).
    #[test]
    fn payload_never_matches_unrelated_session(
        a in uuid_strat(),
        b in uuid_strat(),
    ) {
        prop_assume!(a != b);
        let payload = recording_hydrated_json_payload(&a);
        prop_assert!(recording_detail_ws_filter_matches(&payload, &a));
        prop_assert!(
            !recording_detail_ws_filter_matches(&payload, &b),
            "filter must reject foreign uuid (a={a} b={b} payload={payload})"
        );
    }

    /// The HTMX OOB envelope (what actually rides `/ws/notifications`)
    /// must still satisfy the detail filter — `indexOf` runs on the
    /// full wire string, not the inner JSON alone.
    #[test]
    fn htmx_oob_envelope_still_matches_detail_filter(uuid in uuid_strat()) {
        let json = recording_hydrated_json_payload(&uuid);
        let wire = WsMessage::new("jit-notification", json).to_htmx_html();
        prop_assert!(
            wire.contains(r#"id="jit-notification""#),
            "must keep the shared OOB target"
        );
        prop_assert!(
            recording_detail_ws_filter_matches(&wire, &uuid),
            "detail filter must match the OOB envelope (wire={wire})"
        );
    }

    /// I-HYDRATE-WS-5: only opaque session_uuid + event type travel on
    /// the global Notifications channel.
    #[test]
    fn payload_never_embeds_pii_keys(uuid in uuid_strat()) {
        let payload = recording_hydrated_json_payload(&uuid);
        for key in [
            "username",
            "user_id",
            "email",
            "asset_name",
            "hostname",
            "credential",
            "password",
            "token",
        ] {
            prop_assert!(
                !payload.contains(key),
                "forbidden key `{key}` in payload={payload}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Round-trip through a live BroadcastService: whatever lands on
    /// the channel must still pass the detail filter for that uuid.
    #[test]
    fn broadcast_wire_form_round_trips_filter(uuid in uuid_strat()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let wire = rt.block_on(async move {
            let svc = BroadcastService::new();
            let mut rx = svc.subscribe(&WsChannel::Notifications).await;
            let json = recording_hydrated_json_payload(&uuid);
            svc.send(
                &WsChannel::Notifications,
                WsMessage::new("jit-notification", json),
            )
            .await
            .expect("send");
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .expect("timeout")
                .expect("recv")
        });
        prop_assert!(
            recording_detail_ws_filter_matches(&wire, &uuid),
            "wire={wire}"
        );
    }
}
