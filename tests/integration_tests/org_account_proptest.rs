//! Property tests for org account nav segment stability.

use proptest::prelude::*;
use vcp::nav::{NavSection, nav_from_path};

proptest! {
    #![proptest_config(crate::common::prop_config(32))]

    #[test]
    fn prop_account_path_maps_to_account_section(
        slug in "[a-z][a-z0-9-]{1,24}"
    ) {
        let path = format!("/{slug}/account");
        let (section, crumb) = nav_from_path(&path);
        prop_assert_eq!(section, NavSection::Account);
        prop_assert_eq!(crumb, "account");
    }
}
