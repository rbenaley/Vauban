//! Property pins for evidence / mailer extract structural contracts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::messages::Service;
use vauban_web::services::mailer::{EmailRecipient, format_queue_summary};

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// A fan-out of N recipients is still ONE line, and every address
    /// appears in that line (operator "à qui").
    #[test]
    fn queue_summary_is_single_line_and_names_everyone(
        n in 1usize..12,
        fail in proptest::bool::ANY,
    ) {
        let recipients: Vec<EmailRecipient> = (0..n)
            .map(|i| EmailRecipient::new(format!("u{i}@example.test"), format!("user{i}")))
            .collect();
        let errors = if fail {
            vec!["smtp 550 user unknown".to_string()]
        } else {
            Vec::new()
        };
        let line = format_queue_summary("access_request.submitted", &recipients, n, 0, &errors);
        prop_assert!(!line.contains('\n'));
        prop_assert!(!line.contains('\r'));
        prop_assert!(line.contains("access_request.submitted"));
        for r in &recipients {
            prop_assert!(line.contains(&r.address));
            prop_assert!(line.contains(&r.display_name));
        }
        if fail {
            prop_assert!(line.contains("failed=1"));
            prop_assert!(line.contains("550"));
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
