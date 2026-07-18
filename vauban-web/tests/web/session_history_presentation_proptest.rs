//! Property-based invariants for the session-history presentation seam.

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use vauban_web::templates::sessions::presentation::{
    DisplayIdentity, RecordingState, SessionPresentationInput, TimelineEvent, credential_label,
    display_identity, duration_seconds, identity_pair, is_jit_grant, recording_identity_pair,
    recording_state, timeline_event,
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

    /// Totality: `identity_pair()` never panics and its target never
    /// diverges from `display_identity()` (anti-divergence pin between
    /// the single-identity rendering and the pair rendering), for any
    /// unicode input.
    #[test]
    fn identity_pair_is_total_and_target_matches_display_identity(
        credential_id in "\\PC{0,16}",
        credential in "\\PC{0,32}",
        requester in "\\PC{0,32}",
        session_type in "\\PC{0,16}",
        target in prop::option::of("\\PC{0,32}"),
        status in "\\PC{0,16}",
    ) {
        let input = SessionPresentationInput {
            credential_id: &credential_id,
            credential_username: &credential,
            requester_username: &requester,
            session_type: &session_type,
            tunnel_target_addr: target.as_deref(),
            status: &status,
            created_at: at(100),
            connected_at: Some(at(200)),
            disconnected_at: None,
            recording_path: None,
            is_recorded: false,
        };
        let pair = identity_pair(&input);
        prop_assert_eq!(pair.target, display_identity(&input));
    }

    /// The `pending` credential sentinel of a JIT grant never crosses
    /// the pair rendering: no arrow, no credential target, and the
    /// requester appears exactly once (as the target, labelled
    /// `Requested by`) -- never `alice -> alice`.
    #[test]
    fn jit_grant_pair_never_duplicates_the_requester(
        credential in "[a-zA-Z0-9._-]{0,32}",
        requester in "[a-zA-Z0-9._-]{0,32}",
    ) {
        let input = SessionPresentationInput {
            credential_id: "pending",
            credential_username: &credential,
            requester_username: &requester,
            session_type: "ssh",
            tunnel_target_addr: None,
            status: "approved",
            created_at: at(100),
            connected_at: None,
            disconnected_at: None,
            recording_path: None,
            is_recorded: false,
        };
        prop_assert!(is_jit_grant(input.credential_id));
        let pair = identity_pair(&input);
        prop_assert!(pair.requester.is_none());
        prop_assert!(pair.arrow_requester().is_none());
        prop_assert!(!matches!(pair.target, DisplayIdentity::Credential(_)));
        let trimmed = requester.trim();
        if trimmed.is_empty() {
            prop_assert_eq!(pair.target, DisplayIdentity::Unavailable);
        } else {
            prop_assert_eq!(pair.target, DisplayIdentity::Requester(trimmed.to_string()));
        }
    }

    /// Fidelity: outside JIT, with a non-empty credential, the pair is
    /// exactly `trim(requester) -> Credential(trim(credential))`, and
    /// the arrow shows iff the requester survives trimming.
    #[test]
    fn non_jit_pair_is_faithful_to_the_row(
        credential_id in "[a-zA-Z0-9-]{1,16}".prop_filter(
            "not the sentinel",
            |id| id != "pending",
        ),
        credential in "[ ]{0,2}[a-zA-Z0-9._-]{1,32}[ ]{0,2}",
        requester in "[ ]{0,2}[a-zA-Z0-9._-]{0,32}[ ]{0,2}",
    ) {
        let input = SessionPresentationInput {
            credential_id: &credential_id,
            credential_username: &credential,
            requester_username: &requester,
            session_type: "ssh",
            tunnel_target_addr: None,
            status: "active",
            created_at: at(100),
            connected_at: Some(at(200)),
            disconnected_at: None,
            recording_path: None,
            is_recorded: false,
        };
        let pair = identity_pair(&input);
        prop_assert_eq!(
            pair.target.clone(),
            DisplayIdentity::Credential(credential.trim().to_string())
        );
        let trimmed_requester = requester.trim();
        if trimmed_requester.is_empty() {
            prop_assert!(pair.requester.is_none());
            prop_assert!(pair.arrow_requester().is_none());
        } else {
            prop_assert_eq!(pair.requester.as_deref(), Some(trimmed_requester));
            prop_assert_eq!(pair.arrow_requester(), Some(trimmed_requester));
        }
    }

    /// Recording rows: the pair is total on unicode input, the arrow
    /// shows iff BOTH usernames survive trimming, and both sides are
    /// trimmed verbatim (no sentinel is possible on recordings).
    #[test]
    fn recording_pair_arrow_iff_both_sides_present(
        requester in "\\PC{0,32}",
        credential in "\\PC{0,32}",
    ) {
        let pair = recording_identity_pair(&requester, &credential);
        let trimmed_requester = requester.trim();
        let trimmed_credential = credential.trim();
        if trimmed_credential.is_empty() {
            prop_assert_eq!(pair.target.clone(), DisplayIdentity::Unavailable);
        } else {
            prop_assert_eq!(
                pair.target.clone(),
                DisplayIdentity::Credential(trimmed_credential.to_string())
            );
        }
        if !trimmed_requester.is_empty() && !trimmed_credential.is_empty() {
            prop_assert_eq!(pair.arrow_requester(), Some(trimmed_requester));
        } else {
            prop_assert!(pair.arrow_requester().is_none());
        }
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
