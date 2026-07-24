//! Property tests for recording path validators (anti-traversal / session anchor).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use shared::recording_paths::{
    validate_recording_delete_relative_path, validate_recording_file_relative_path,
    validate_recording_gzip_relative_paths, validate_recording_unlink_relative_path,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Any relative path containing a `..` path component is rejected.
    #[test]
    fn parent_dir_component_always_rejects(
        session in "[A-Za-z0-9_-]{8,32}",
        prefix in "[A-Za-z0-9_]{0,16}",
        suffix in "[A-Za-z0-9_]{0,16}",
    ) {
        // Force a real ParentDir component (`foo/../bar`), not `foo../bar`.
        let path = if prefix.is_empty() {
            format!("../{suffix}{session}.pcap")
        } else {
            format!("{prefix}/../{suffix}{session}.pcap")
        };
        prop_assert!(
            validate_recording_file_relative_path(&path, &session).is_err()
        );
        prop_assert!(
            validate_recording_delete_relative_path(&path, &session).is_err()
        );
        prop_assert!(
            validate_recording_unlink_relative_path(&path, &session).is_err()
        );
    }

    /// Absolute paths and empty paths always reject.
    #[test]
    fn absolute_or_empty_always_rejects(
        session in "[A-Za-z0-9_-]{8,32}",
        rest in "[A-Za-z0-9._/-]{1,48}",
    ) {
        prop_assert!(validate_recording_file_relative_path("", &session).is_err());
        let abs = format!("/{rest}{session}");
        prop_assert!(validate_recording_file_relative_path(&abs, &session).is_err());
        prop_assert!(validate_recording_delete_relative_path(&abs, &session).is_err());
    }

    /// Paths that omit the session_id substring are rejected.
    #[test]
    fn session_id_substring_required(
        session in "[A-Za-z0-9]{12,24}",
        other in "[A-Za-z0-9]{12,24}",
    ) {
        prop_assume!(session != other);
        prop_assume!(!other.contains(&session));
        let path = format!("2026/05/{other}.pcap");
        prop_assert!(
            validate_recording_file_relative_path(&path, &session).is_err()
        );
        prop_assert!(
            validate_recording_delete_relative_path(&path, &session).is_err()
        );
        prop_assert!(
            validate_recording_unlink_relative_path(&path, &session).is_err()
        );
    }

    /// Unlink accepts only raw `.pcap` (not `.pcap.gz`); file/delete agree
    /// on structure for a legit layout.
    #[test]
    fn unlink_accepts_only_raw_pcap(
        session in "[A-Za-z0-9_-]{8,32}",
    ) {
        let raw = format!("2026/05/{session}/chan.pcap");
        let gz = format!("2026/05/{session}/chan.pcap.gz");
        prop_assert!(validate_recording_unlink_relative_path(&raw, &session).is_ok());
        prop_assert!(validate_recording_unlink_relative_path(&gz, &session).is_err());
        prop_assert!(validate_recording_file_relative_path(&raw, &session).is_ok());
        prop_assert!(validate_recording_file_relative_path(&gz, &session).is_ok());
        prop_assert!(validate_recording_delete_relative_path(&raw, &session).is_ok());
        prop_assert!(validate_recording_delete_relative_path(&gz, &session).is_ok());
    }

    /// Gzip pair validation requires `.pcap` src and `.pcap.gz` dst with
    /// session_id in both.
    #[test]
    fn gzip_pair_consistency(session in "[A-Za-z0-9_-]{8,32}") {
        let src = format!("2026/05/{session}/c.pcap");
        let dst = format!("2026/05/{session}/c.pcap.gz");
        prop_assert!(validate_recording_gzip_relative_paths(&src, &dst, &session).is_ok());
        prop_assert!(
            validate_recording_gzip_relative_paths(&dst, &src, &session).is_err()
        );
        prop_assert!(
            validate_recording_gzip_relative_paths(&src, &src, &session).is_err()
        );
    }
}
