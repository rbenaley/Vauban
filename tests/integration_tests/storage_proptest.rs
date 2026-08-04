//! Property tests for storage IDs, scopes, WebAuthn helpers, and image catalogue.

use proptest::prelude::*;
use serde_json::json;
use vcp::storage::{
    StorageErrorCode, StorageScope, canonical_summary, credential_fingerprint, ct_eq_hex,
    is_uuid_key, normalize_admin_label, normalize_image_ext, webauthn_host_is_ip,
};

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

    #[test]
    fn prop_error_code_roundtrip(
        code in "(not_found|invalid_id|quota|org_quota|bad_image|digest_mismatch|integrity_mismatch|io|busy)"
    ) {
        let parsed = StorageErrorCode::parse(&code).expect("closed code");
        prop_assert_eq!(parsed.as_str(), code.as_str());
    }

    #[test]
    fn prop_ct_eq_hex_reflexive(hex in "[0-9a-f]{64}") {
        prop_assert!(ct_eq_hex(&hex, &hex));
        let mut other = hex.clone();
        other.replace_range(63..64, if &hex[63..64] == "0" { "1" } else { "0" });
        prop_assert!(!ct_eq_hex(&hex, &other));
    }

    /// Whitespace-only labels are always rejected; any non-ws char survives trim.
    #[test]
    fn prop_admin_label_requires_non_whitespace(
        ws in "[ \\t\\n\\r]*",
        body in "[A-Za-z0-9._-]{1,48}",
        pad in "[ \\t]*",
    ) {
        prop_assert!(normalize_admin_label(&ws).is_none());
        let padded = format!("{ws}{body}{pad}");
        let got = normalize_admin_label(&padded).expect("non-empty body");
        prop_assert_eq!(got, body.as_str());
    }

    /// Fingerprint is stable, 64 hex chars, and sensitive to either input half.
    #[test]
    fn prop_credential_fingerprint_stable_hex(
        cred in prop::collection::vec(any::<u8>(), 1..64),
        cose in prop::collection::vec(any::<u8>(), 1..64),
        flip in prop::bool::ANY,
    ) {
        let a = credential_fingerprint(&cred, &cose);
        prop_assert_eq!(a.len(), 64);
        prop_assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        prop_assert_eq!(&a, &credential_fingerprint(&cred, &cose));
        let mut other_cred = cred.clone();
        let mut other_cose = cose.clone();
        if flip {
            other_cred[0] ^= 0xff;
        } else {
            other_cose[0] ^= 0xff;
        }
        prop_assert_ne!(a, credential_fingerprint(&other_cred, &other_cose));
    }

    /// Helper-issued C1 summaries stay digest-bound and operator-readable.
    #[test]
    fn prop_canonical_summary_release_embeds_id_and_digest_prefix(
        release_id in "[0-9]{1,8}",
        digest in "[0-9a-f]{64}",
    ) {
        let summary = canonical_summary(
            "release_put_commit",
            &json!({"release_id": release_id, "digest": digest}),
        );
        prop_assert!(summary.starts_with("release_put_commit id="));
        prop_assert!(summary.contains(&release_id));
        prop_assert!(summary.contains(&digest[..12]));
        prop_assert!(summary.contains('…'));
    }

    #[test]
    fn prop_canonical_summary_delete_org_stable(org_id in "[0-9]{1,8}") {
        let summary = canonical_summary("delete_org", &json!({"org_id": org_id}));
        prop_assert_eq!(summary, format!("delete_org org_id={org_id}"));
    }

    /// DNS hostnames are never treated as IP RP IDs; dotted quads are.
    #[test]
    fn prop_webauthn_host_ip_vs_dns(
        a in 0u8..=255,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
        dns_label in "[a-z][a-z0-9-]{0,20}",
    ) {
        let ip = format!("{a}.{b}.{c}.{d}");
        prop_assert!(webauthn_host_is_ip(&ip));
        prop_assert!(!webauthn_host_is_ip("localhost"));
        let host = format!("{dns_label}.example");
        prop_assert!(!webauthn_host_is_ip(&host));
    }
}
