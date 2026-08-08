//! Property tests for release-note inline ``code`` parsing (integration crate).

use proptest::prelude::*;
use vcp::release_notes::{
    InlineSegment, backticks_are_balanced, flatten_inline_segments, parse_inline_code,
};

use crate::common::prop_config;

proptest! {
    #![proptest_config(prop_config(96))]

    #[test]
    fn prop_code_segments_never_contain_backticks(
        s in ".*{0,80}"
    ) {
        for seg in parse_inline_code(&s) {
            if let InlineSegment::Code(c) = seg {
                prop_assert!(
                    !c.contains('`'),
                    "Code segment must not retain backticks: {c:?}"
                );
            }
        }
    }

    #[test]
    fn prop_segment_count_bounded_by_tick_pairs(s in ".*{0,80}") {
        let ticks = s.chars().filter(|c| *c == '`').count();
        let pairs = ticks / 2;
        let segs = parse_inline_code(&s);
        // Each pair can contribute at most one Code + surrounding Text pieces.
        prop_assert!(segs.len() <= pairs * 2 + 1 + s.len().min(1));
    }

    #[test]
    fn prop_balanced_input_code_count_matches_pairs(
        left in "[^`]{0,10}",
        mid in "[^`]{0,10}",
        right in "[^`]{0,10}"
    ) {
        let raw = format!("{left}`{mid}`{right}");
        prop_assert!(backticks_are_balanced(&raw));
        let codes = parse_inline_code(&raw)
            .into_iter()
            .filter(|s| matches!(s, InlineSegment::Code(_)))
            .count();
        prop_assert_eq!(codes, 1);
        prop_assert_eq!(flatten_inline_segments(&parse_inline_code(&raw)), format!("{left}{mid}{right}"));
    }
}
