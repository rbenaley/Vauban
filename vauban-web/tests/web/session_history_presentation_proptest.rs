//! Property-based invariants for the session-history presentation seam.

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use vauban_web::templates::sessions::presentation::{
    DisplayIdentity, RecordingState, SessionPresentationInput, TimelineEvent, credential_label,
    display_identity, duration_seconds, recording_state, timeline_event,
};

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::<Utc>::UNIX_EPOCH + Duration::seconds(seconds)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn pending_sentinel_never_crosses_the_ui(
        credential in "[a-zA-Z0-9._-]{0,32}",
        requester in "[a-zA-Z0-9._-]{1,32}",
        status in "[a-z_]{1,20}",
        session_type in prop_oneof![
            Just("ssh".to_string()),
            Just("rdp".to_string()),
            Just("iacs_tunnel".to_string()),
        ],
    ) {
        let input = SessionPresentationInput {
            credential_id: "pending",
            credential_username: &credential,
            requester_username: &requester,
            session_type: &session_type,
            tunnel_target_addr: None,
            status: &status,
            created_at: at(100),
            connected_at: None,
            disconnected_at: None,
            recording_path: None,
            is_recorded: true,
        };

        prop_assert_eq!(
            display_identity(&input),
            DisplayIdentity::Requester(requester.clone())
        );
        prop_assert!(!credential_label(&input).to_ascii_lowercase().contains("pending"));
        prop_assert_eq!(recording_state(&input), RecordingState::NotRecorded);
    }

    #[test]
    fn a_real_credential_named_pending_is_preserved(
        credential_id in "[a-zA-Z0-9-]{1,32}".prop_filter(
            "the real id is not the sentinel",
            |id| id != "pending",
        ),
    ) {
        let input = SessionPresentationInput {
            credential_id: &credential_id,
            credential_username: "pending",
            requester_username: "alice",
            session_type: "ssh",
            tunnel_target_addr: None,
            status: "active",
            created_at: at(100),
            connected_at: Some(at(200)),
            disconnected_at: None,
            recording_path: None,
            is_recorded: true,
        };
        prop_assert_eq!(
            display_identity(&input),
            DisplayIdentity::Credential("pending".to_string())
        );
        prop_assert_eq!(credential_label(&input), "pending");
    }

    #[test]
    fn timeline_always_has_a_truthful_anchor(
        created in 0_i64..1_000_000,
        connected in prop::option::of(0_i64..1_000_000),
    ) {
        let input = SessionPresentationInput {
            credential_id: "local",
            credential_username: "root",
            requester_username: "alice",
            session_type: "ssh",
            tunnel_target_addr: None,
            status: "active",
            created_at: at(created),
            connected_at: connected.map(at),
            disconnected_at: None,
            recording_path: None,
            is_recorded: true,
        };
        match (connected, timeline_event(&input)) {
            (Some(expected), TimelineEvent::Connected(actual)) => {
                prop_assert_eq!(actual, at(expected));
            }
            (None, TimelineEvent::Requested(actual)) => {
                prop_assert_eq!(actual, at(created));
            }
            _ => prop_assert!(false, "timeline event kind drifted"),
        }
    }

    #[test]
    fn duration_is_never_fabricated_without_connection(
        status in "[a-z_]{1,20}",
        disconnected in prop::option::of(0_i64..1_000_000),
    ) {
        let input = SessionPresentationInput {
            credential_id: "pending",
            credential_username: "pending",
            requester_username: "alice",
            session_type: "ssh",
            tunnel_target_addr: None,
            status: &status,
            created_at: at(100),
            connected_at: None,
            disconnected_at: disconnected.map(at),
            recording_path: None,
            is_recorded: true,
        };
        prop_assert_eq!(duration_seconds(&input, at(1_000_001)), None);
    }

    #[test]
    fn iacs_without_credential_uses_target_or_unavailable(
        target in prop::option::of("[0-9.]{1,15}:[0-9]{1,5}"),
    ) {
        let input = SessionPresentationInput {
            credential_id: "iacs",
            credential_username: "",
            requester_username: "alice",
            session_type: "iacs_tunnel",
            tunnel_target_addr: target.as_deref(),
            status: "tunnel_active",
            created_at: at(100),
            connected_at: Some(at(200)),
            disconnected_at: None,
            recording_path: None,
            is_recorded: false,
        };
        match target.as_ref() {
            Some(value) => prop_assert_eq!(
                display_identity(&input),
                DisplayIdentity::TunnelTarget(value.clone())
            ),
            None => prop_assert_eq!(display_identity(&input), DisplayIdentity::Unavailable),
        }
    }
}
