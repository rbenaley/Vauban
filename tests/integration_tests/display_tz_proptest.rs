//! Property tests for timezone formatting.

use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use proptest::prelude::*;
use vcp::tz::format_local;

proptest! {
    #![proptest_config(crate::common::prop_config(24))]

    #[test]
    fn prop_format_local_contains_date_parts(hour in 0u32..24) {
        let dt = Utc.with_ymd_and_hms(2026, 6, 23, hour, 30, 0).unwrap();
        let s = format_local(dt, Tz::UTC);
        prop_assert!(s.contains("2026-06-23"));
        prop_assert!(s.contains("UTC") || s.contains("Z"));
    }
}

proptest! {
    #![proptest_config(crate::common::prop_config(16))]

    #[test]
    fn prop_paris_differs_from_utc_outside_overlap(hour in 10u32..20) {
        let dt = Utc.with_ymd_and_hms(2026, 6, 23, hour, 0, 0).unwrap();
        let utc = format_local(dt, Tz::UTC);
        let paris = format_local(dt, Tz::Europe__Paris);
        prop_assert_ne!(utc, paris);
    }
}
