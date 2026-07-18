//! Property-based invariants for the login-session self-revocation
//! guard and the current-session presentation (profile bug: the
//! caller's own active session must never be revocable).

use chrono::{Duration, Utc};
use proptest::prelude::*;
use uuid::Uuid;
use vauban_web::handlers::web::build_sessions_html;
use vauban_web::models::AuthSession;
use vauban_web::services::login_sessions::{
    SelfRevocation, is_current_session, self_revocation_guard,
};

fn uuid_from(bits: u128) -> Uuid {
    Uuid::from_u128(bits)
}

fn session_row(id: i32, uuid: Uuid, token_hash: &str) -> AuthSession {
    AuthSession {
        id,
        uuid,
        user_id: 1,
        token_hash: token_hash.to_string(),
        ip_address: ipnetwork::IpNetwork::new(std::net::IpAddr::from([127, 0, 0, 1]), 32)
            .expect("valid network"),
        user_agent: Some("Test/1.0".to_string()),
        device_info: format!("Device {id}"),
        last_activity: Utc::now(),
        expires_at: Utc::now() + Duration::hours(1),
        is_current: false,
        created_at: Utc::now(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Fail-closed: the guard refuses exactly when the target IS the
    /// current session, for arbitrary uuids.
    #[test]
    fn guard_refuses_iff_target_is_current(target in any::<u128>(), current in any::<u128>()) {
        let decision = self_revocation_guard(uuid_from(target), uuid_from(current));
        if target == current {
            prop_assert_eq!(decision, SelfRevocation::RefusedCurrentSession);
        } else {
            prop_assert_eq!(decision, SelfRevocation::Allowed);
        }
        // The guard and the presentation predicate can never diverge:
        // a row rendered as "current" is exactly a row the guard
        // refuses to revoke.
        prop_assert_eq!(
            is_current_session(uuid_from(target), uuid_from(current)),
            decision == SelfRevocation::RefusedCurrentSession
        );
    }

    /// Exact marking: over an arbitrary session list, exactly the rows
    /// whose uuid equals the current jti are marked current (at most
    /// one, since uuids are unique in `auth_sessions`).
    #[test]
    fn exactly_the_jti_row_is_marked_current(
        seeds in prop::collection::vec(any::<u128>(), 1..12),
        pick in any::<prop::sample::Index>(),
    ) {
        let current = uuid_from(seeds[pick.index(seeds.len())]);
        let marked = seeds
            .iter()
            .filter(|s| is_current_session(uuid_from(**s), current))
            .count();
        let expected = seeds.iter().filter(|s| uuid_from(**s) == current).count();
        prop_assert_eq!(marked, expected);
        prop_assert!(marked >= 1, "the picked seed must be marked current");
    }

    /// `build_sessions_html` (WS live push, keyed by per-connection
    /// token hash): the current row renders "This device" and never a
    /// revoke form; every other row renders exactly one revoke form
    /// with its own uuid.
    #[test]
    fn ws_sessions_html_never_offers_revoke_on_the_current_row(
        n in 1_usize..8,
        pick in any::<prop::sample::Index>(),
    ) {
        let sessions: Vec<AuthSession> = (0..n)
            .map(|i| {
                let idx = i32::try_from(i).expect("small index");
                session_row(idx, Uuid::from_u128(i as u128 + 1), &format!("hash-{i}"))
            })
            .collect();
        let current = &sessions[pick.index(sessions.len())];
        let html = build_sessions_html(&sessions, &current.token_hash);

        let revoke_marker = format!("/accounts/login-sessions/{}/revoke", current.uuid);
        prop_assert!(
            !html.contains(&revoke_marker),
            "the current row must never carry a revoke form"
        );
        prop_assert!(html.contains("This device"));
        prop_assert_eq!(html.matches("Current session").count(), 1);

        for other in sessions.iter().filter(|s| s.uuid != current.uuid) {
            let marker = format!("/accounts/login-sessions/{}/revoke", other.uuid);
            prop_assert_eq!(
                html.matches(&marker).count(),
                1,
                "each non-current row carries exactly one revoke form"
            );
        }
    }

    /// An empty client token hash (generic broadcast fallback) marks
    /// no row as current: no badge, and no row is protected in the
    /// HTML (the server-side guard remains the real protection).
    #[test]
    fn ws_sessions_html_with_empty_client_hash_marks_nothing_current(n in 1_usize..8) {
        let sessions: Vec<AuthSession> = (0..n)
            .map(|i| {
                let idx = i32::try_from(i).expect("small index");
                session_row(idx, Uuid::from_u128(i as u128 + 1), &format!("hash-{i}"))
            })
            .collect();
        let html = build_sessions_html(&sessions, "");
        prop_assert!(!html.contains("Current session"));
        prop_assert!(!html.contains("This device"));
    }
}
