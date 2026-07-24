//! Property pins for evidence / mailer extract structural contracts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::messages::Service;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Discriminants 0..=8 stay frozen; Mailer is always 9.
    #[test]
    fn mailer_discriminant_stable_and_unique(
        idx in 0u8..10
    ) {
        let services = [
            Service::Supervisor,
            Service::Web,
            Service::Auth,
            Service::Access,
            Service::Vault,
            Service::Audit,
            Service::ProxySsh,
            Service::ProxyRdp,
            Service::ProxyIacs,
            Service::Mailer,
        ];
        prop_assume!((idx as usize) < services.len());
        let d = services[idx as usize].as_token_discriminant();
        prop_assert_eq!(d, idx);
        if idx == 9 {
            prop_assert_eq!(services[9], Service::Mailer);
        }
    }
}

#[test]
fn evidence_analyzer_public_api_surface_is_stable() {
    // Link pin: Inspect handlers reach the analyzer via the web re-export.
    use shared::iacs_protocol::ExpectedProfile;
    use vauban_web::services::iacs_packet_analyzer::analyze_channel_bytes;

    let err = analyze_channel_bytes(&[], ExpectedProfile::Passthrough);
    assert!(err.is_err(), "empty PCAP must fail parse");
}

#[test]
fn hydrator_ws_helpers_live_in_evidence() {
    use vauban_web_evidence::hydrator::{
        RECORDING_HYDRATED_EVENT, recording_detail_ws_filter_matches,
        recording_hydrated_json_payload,
    };
    let uuid = uuid::Uuid::nil();
    let payload = recording_hydrated_json_payload(&uuid);
    assert!(payload.contains(RECORDING_HYDRATED_EVENT));
    assert!(recording_detail_ws_filter_matches(&payload, &uuid));
}
