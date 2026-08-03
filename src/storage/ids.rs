//! Opaque storage identifier validation (architecture §5).

use std::sync::OnceLock;

use regex::Regex;

/// Storage family / IPC scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageScope {
    Release,
    Image,
}

impl StorageScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Image => "image",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "release" => Some(Self::Release),
            "image" => Some(Self::Image),
            _ => None,
        }
    }
}

fn decimal_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]{1,20}$").expect("decimal id regex"))
}

fn uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$").expect("uuid regex")
    })
}

fn ext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(png|jpe?g|webp)$").expect("ext regex"))
}

/// Validate a release or organization id (decimal u64 text).
pub fn is_decimal_id(raw: &str) -> bool {
    !raw.is_empty() && !raw.contains('\0') && decimal_id_re().is_match(raw)
}

/// Validate image_id / upload_id (lowercase UUID v4 text).
pub fn is_uuid_key(raw: &str) -> bool {
    !raw.is_empty() && !raw.contains('\0') && uuid_re().is_match(raw)
}

/// Validate image extension (`png` / `jpeg` / `jpg` / `webp`).
pub fn is_image_ext(raw: &str) -> bool {
    !raw.is_empty() && !raw.contains('\0') && ext_re().is_match(raw)
}

/// Normalize `jpg` → `jpeg` for storage naming.
pub fn normalize_image_ext(ext: &str) -> Option<&'static str> {
    match ext.trim().to_ascii_lowercase().as_str() {
        "png" => Some("png"),
        "jpg" | "jpeg" => Some("jpeg"),
        "webp" => Some("webp"),
        _ => None,
    }
}

pub fn release_rel_path(release_id: &str) -> Option<String> {
    is_decimal_id(release_id).then(|| format!("releases/{release_id}.pkg"))
}

pub fn image_rel_path(org_id: &str, image_id: &str, ext: &str) -> Option<String> {
    if !is_decimal_id(org_id) || !is_uuid_key(image_id) {
        return None;
    }
    let ext = normalize_image_ext(ext)?;
    Some(format!("images/{org_id}/{image_id}.{ext}"))
}

pub fn tmp_rel_path(upload_id: &str) -> Option<String> {
    is_uuid_key(upload_id).then(|| format!("tmp/{upload_id}.partial"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest_util;
    use proptest::prelude::*;

    #[test]
    fn accepts_canonical_ids() {
        assert!(is_decimal_id("1"));
        assert!(is_decimal_id("18446744073709551615"));
        assert!(is_uuid_key("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_image_ext("png"));
        assert!(is_image_ext("jpg"));
        assert_eq!(normalize_image_ext("JPG"), Some("jpeg"));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(!is_decimal_id("../1"));
        assert!(!is_decimal_id("1/2"));
        assert!(!is_decimal_id(""));
        assert!(!is_uuid_key("../x"));
        assert!(!is_uuid_key("550e8400e29b41d4a716446655440000"));
        assert!(!is_image_ext("svg"));
        assert!(!is_image_ext("png/../x"));
        assert!(release_rel_path("..").is_none());
        assert!(tmp_rel_path("not-a-uuid").is_none());
    }

    proptest! {
        #![proptest_config(proptest_util::cases(48))]

        #[test]
        fn prop_decimal_never_contains_dotdot(
            s in ".*"
        ) {
            if is_decimal_id(&s) {
                prop_assert!(!s.contains(".."));
                prop_assert!(!s.contains('/'));
                prop_assert!(!s.contains('\\'));
                prop_assert!(!s.contains('\0'));
            }
        }

        #[test]
        fn prop_uuid_shape_or_reject(s in ".*") {
            if is_uuid_key(&s) {
                prop_assert_eq!(s.len(), 36);
                prop_assert!(!s.contains(".."));
                prop_assert!(!s.contains('/'));
            }
        }
    }
}
