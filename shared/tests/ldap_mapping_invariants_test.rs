//! Source-shape pins for the shipped LDAPS mapping catalogue and DSL.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use shared::ldap_mapping::{self, MappingFile};

const SHIPPED: &str = include_str!("../../config/access/ldaps_mapping.conf");

fn uncommented_lines(src: &str) -> Vec<&str> {
    src.lines()
        .filter_map(|line| {
            let cut = line.split('#').next().unwrap_or("").trim();
            if cut.is_empty() { None } else { Some(cut) }
        })
        .collect()
}

#[test]
fn shipped_catalogue_is_comments_only() {
    let ast: MappingFile = ldap_mapping::parse(SHIPPED.as_bytes()).expect("parse shipped");
    assert!(
        uncommented_lines(SHIPPED).is_empty(),
        "shipped ldaps_mapping.conf must be comments-only"
    );
    assert!(
        !ast.has_resolve(),
        "comments-only catalogue must report has_resolve() == false"
    );
}

#[test]
fn shipped_catalogue_documents_dsl_keywords() {
    for keyword in ["resolve", "static", "match", "user-attr", "group-attr"] {
        assert!(
            SHIPPED.contains(keyword),
            "shipped catalogue must document {keyword}"
        );
    }
}

#[test]
fn shipped_catalogue_has_no_uncommented_username_placeholder() {
    for line in uncommented_lines(SHIPPED) {
        assert!(
            !line.contains("{username}"),
            "uncommented line must not carry {{username}}: {line}"
        );
    }
}

#[test]
fn shipped_file_is_under_size_cap() {
    assert!(
        SHIPPED.len() <= ldap_mapping::MAX_MAPPING_FILE_BYTES,
        "shipped mapping file {} bytes exceeds cap",
        SHIPPED.len()
    );
}
