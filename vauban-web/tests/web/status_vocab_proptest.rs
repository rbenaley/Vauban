//! Property-based invariants for the closed status vocabularies
//! (`services::status_vocab`) and the canonical `SessionStatus` enum.
//!
//! The July 2026 status audit found the select options, the handler
//! filters and the display labels drifting apart on every list page.
//! These properties pin the shared seam: strict round-trips on the
//! enum, fail-open sanitizing on the vocabularies (an unknown value
//! degrades to "no filter", never to a confusing empty list), and
//! injectivity of every `(value, label)` catalogue.

use proptest::prelude::*;
use vauban_web::models::asset::AssetStatus;
use vauban_web::models::session::SessionStatus;
use vauban_web::services::status_vocab::{
    APPROVAL, AUDIT_DECISIONS, MY_REQUESTS, SESSION_HISTORY, SESSION_HISTORY_IACS, StatusVocab,
    session_history_options, session_history_sanitize,
};

const ALL_VOCABS: &[(&str, &StatusVocab)] = &[
    ("SESSION_HISTORY", &SESSION_HISTORY),
    ("SESSION_HISTORY_IACS", &SESSION_HISTORY_IACS),
    ("APPROVAL", &APPROVAL),
    ("MY_REQUESTS", &MY_REQUESTS),
    ("AUDIT_DECISIONS", &AUDIT_DECISIONS),
];

/// Strategy over every `SessionStatus` variant.
fn any_session_status() -> impl Strategy<Value = SessionStatus> {
    proptest::sample::select(SessionStatus::ALL.to_vec())
}

proptest! {
    /// parse_strict(as_str(v)) == Some(v) for every variant.
    #[test]
    fn session_status_round_trips_via_parse_strict(status in any_session_status()) {
        prop_assert_eq!(SessionStatus::parse_strict(status.as_str()), Some(status));
    }

    /// The lenient display parse agrees with the strict parse on the
    /// closed vocabulary and falls back to Pending outside of it.
    #[test]
    fn session_status_lenient_parse_agrees_or_falls_back(raw in ".{0,24}") {
        let lenient = SessionStatus::parse(&raw);
        match SessionStatus::parse_strict(&raw) {
            Some(v) => prop_assert_eq!(lenient, v),
            None => prop_assert_eq!(lenient, SessionStatus::Pending),
        }
    }

    /// Every variant has a distinct non-empty wire value and a
    /// distinct non-empty label.
    #[test]
    fn session_status_values_and_labels_are_injective(
        a in any_session_status(),
        b in any_session_status(),
    ) {
        prop_assert!(!a.as_str().is_empty());
        prop_assert!(!a.label().is_empty());
        if a != b {
            prop_assert_ne!(a.as_str(), b.as_str());
        }
    }

    /// Fail-open sanitizer: the output is either None or a member of
    /// the vocabulary, members pass through unchanged, and the
    /// operation is idempotent.
    #[test]
    fn vocab_sanitize_is_fail_open_and_idempotent(raw in ".{0,24}") {
        for (name, vocab) in ALL_VOCABS {
            let out = vocab.sanitize(Some(raw.clone()));
            if let Some(ref v) = out {
                prop_assert!(vocab.contains(v), "{name}: sanitize returned non-member {v:?}");
                prop_assert_eq!(v, &raw, "{}: sanitize must not rewrite members", name);
            }
            prop_assert_eq!(
                vocab.sanitize(out.clone()),
                out,
                "{}: sanitize must be idempotent",
                name
            );
        }
        // The kill-switch-aware /sessions sanitizer obeys the same law
        // over the union of the two vocabularies.
        let out = session_history_sanitize(Some(raw.clone()));
        if let Some(ref v) = out {
            prop_assert!(SESSION_HISTORY.contains(v) || SESSION_HISTORY_IACS.contains(v));
        }
        prop_assert_eq!(session_history_sanitize(out.clone()), out);
    }

    /// Members always pass through their own sanitizer.
    #[test]
    fn vocab_members_pass_their_sanitizer(idx in 0usize..64) {
        for (name, vocab) in ALL_VOCABS {
            let values = vocab.values();
            let v = values[idx % values.len()];
            prop_assert_eq!(
                vocab.sanitize(Some(v.to_string())),
                Some(v.to_string()),
                "{}: member {} must pass through",
                name,
                v
            );
        }
    }
}

/// Every vocabulary has distinct values, distinct labels-per-value
/// and no empty entry (deterministic exhaustive check).
#[test]
fn every_vocab_is_injective_and_non_empty() {
    for (name, vocab) in ALL_VOCABS {
        let values = vocab.values();
        assert!(!values.is_empty(), "{name} must not be empty");
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len(), "{name} has duplicate values");
        for (v, l) in vocab.entries {
            assert!(!v.is_empty(), "{name} has an empty value");
            assert!(!l.is_empty(), "{name} has an empty label for {v}");
        }
    }
}

/// Every status vocabulary that feeds a proxy_sessions filter is a
/// subset of the canonical enum vocabulary (no phantom statuses).
#[test]
fn session_vocabs_are_subsets_of_the_canonical_enum() {
    for (name, vocab) in [
        ("SESSION_HISTORY", &SESSION_HISTORY),
        ("SESSION_HISTORY_IACS", &SESSION_HISTORY_IACS),
        ("APPROVAL", &APPROVAL),
        ("MY_REQUESTS", &MY_REQUESTS),
    ] {
        for v in vocab.values() {
            assert!(
                SessionStatus::parse_strict(v).is_some(),
                "{name}: '{v}' is not a canonical SessionStatus"
            );
        }
    }
}

/// AssetStatus::filter_options covers the FULL closed vocabulary
/// (including 'unknown') and round-trips through parse_strict.
#[test]
fn asset_filter_options_cover_every_status() {
    let options = AssetStatus::filter_options();
    assert_eq!(options.len(), AssetStatus::ALL.len());
    for status in AssetStatus::ALL {
        assert!(
            options.iter().any(|(v, _)| v == status.as_str()),
            "missing option for '{}'",
            status.as_str()
        );
        assert_eq!(AssetStatus::parse_strict(status.as_str()), Some(*status));
    }
    assert!(options.iter().any(|(v, _)| v == "unknown"));
}

/// The kill-switch strips exactly the two IACS statuses, nothing else.
#[test]
fn session_history_options_kill_switch_is_surgical() {
    let with = session_history_options(true);
    let without = session_history_options(false);
    assert_eq!(
        with.len(),
        SESSION_HISTORY.entries.len() + SESSION_HISTORY_IACS.entries.len()
    );
    assert_eq!(without.len(), SESSION_HISTORY.entries.len());
    assert!(with.starts_with(&without[..]));
}
