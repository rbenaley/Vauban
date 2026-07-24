//! Property tests: legacy RDP BLAKE3 sidecar path via `with_added_extension`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use std::path::PathBuf;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// `foo.mp4` + added `blake3` always yields `foo.mp4.blake3`.
    #[test]
    fn with_added_extension_blake3_appends_after_mp4(
        stem in "[A-Za-z0-9_-]{1,32}"
    ) {
        let media = PathBuf::from(format!("{stem}.mp4"));
        let sidecar = media.with_added_extension("blake3");
        let expected = PathBuf::from(format!("{stem}.mp4.blake3"));
        let display = sidecar.to_string_lossy().into_owned();
        prop_assert!(
            display.ends_with(".mp4.blake3"),
            "sidecar must end with .mp4.blake3, got {display}"
        );
        prop_assert_eq!(sidecar, expected);
    }
}
