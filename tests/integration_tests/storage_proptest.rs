//! Property tests for storage IDs, scopes, and image extension catalogue.

use proptest::prelude::*;
use vcp::storage::{StorageScope, is_uuid_key, normalize_image_ext};

proptest! {
    #![proptest_config(crate::common::prop_config(48))]

    #[test]
    fn prop_uuid_key_never_path_like(s in ".*") {
        if is_uuid_key(&s) {
            prop_assert_eq!(s.len(), 36);
            prop_assert!(!s.contains(".."));
            prop_assert!(!s.contains('/'));
            prop_assert!(!s.contains('\\'));
            prop_assert!(!s.contains('\0'));
            prop_assert!(s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        }
    }

    #[test]
    fn prop_normalize_image_ext_catalogue(
        raw in "(png|PNG|jpg|JPG|jpeg|JPEG|webp|WEBP|gif|GIF|svg|SVG|bmp|exe|)"
    ) {
        let got = normalize_image_ext(&raw);
        match raw.trim().to_ascii_lowercase().as_str() {
            "png" => prop_assert_eq!(got, Some("png")),
            "jpg" | "jpeg" => prop_assert_eq!(got, Some("jpeg")),
            "webp" => prop_assert_eq!(got, Some("webp")),
            _ => prop_assert!(got.is_none()),
        }
    }

    #[test]
    fn prop_scope_parse_roundtrip(label in "(release|image|other|RELEASE|)") {
        match label.trim() {
            "release" => {
                prop_assert_eq!(StorageScope::parse(&label), Some(StorageScope::Release));
                prop_assert_eq!(StorageScope::Release.as_str(), "release");
            }
            "image" => {
                prop_assert_eq!(StorageScope::parse(&label), Some(StorageScope::Image));
                prop_assert_eq!(StorageScope::Image.as_str(), "image");
            }
            _ => prop_assert!(StorageScope::parse(&label).is_none()),
        }
    }

    #[test]
    fn prop_object_key_shapes_reject_traversal(
        org in "[0-9]{1,6}",
        uuid in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ext in "(png|jpeg|webp)",
    ) {
        let key = format!("{org}/{uuid}.{ext}");
        prop_assert!(!key.contains(".."));
        prop_assert!(is_uuid_key(&uuid));
        prop_assert!(normalize_image_ext(&ext).is_some());
    }
}
