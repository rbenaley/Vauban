//! Property tests for issue notify unique keys and excerpt bounds.

use proptest::prelude::*;
use vcp::issue_notify::{
    EXCERPT_MAX_CHARS, NotifyEvent, excerpt_text, filter_recipient_ids, outbox_unique_key,
};

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn excerpt_bound_and_escape_length(s in ".*") {
        let out = excerpt_text(&s);
        let overflow = s.trim().chars().count() > EXCERPT_MAX_CHARS;
        let max = EXCERPT_MAX_CHARS + usize::from(overflow);
        prop_assert!(out.chars().count() <= max);
    }

    #[test]
    fn unique_key_stable_across_ids(
        issue_id in 1u64..10_000,
        source_id in 0u64..10_000,
        recipient in 1u64..10_000,
        kind in 0u8..4,
    ) {
        let event = match kind {
            0 => NotifyEvent::Create,
            1 => NotifyEvent::Comment,
            2 => NotifyEvent::SupportComment,
            _ => NotifyEvent::Status,
        };
        let a = outbox_unique_key(issue_id, event, source_id, recipient);
        let b = outbox_unique_key(issue_id, event, source_id, recipient);
        prop_assert_eq!(a, b);
        prop_assert_eq!(a.1, event.as_str());
    }

    #[test]
    fn filtered_ids_never_include_actor_when_excluded(
        ids in prop::collection::vec(1u64..500, 0..16),
        actor in 1u64..500,
    ) {
        let out = filter_recipient_ids(&ids, actor, true);
        prop_assert!(!out.contains(&actor));
        let mut sorted = out.clone();
        sorted.sort_unstable();
        sorted.dedup();
        prop_assert_eq!(out, sorted);
    }
}
