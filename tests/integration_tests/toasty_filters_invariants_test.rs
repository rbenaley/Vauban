//! Source-shape invariants for Toasty filtered queries.

use std::process::Command;

#[test]
fn inv_check_toasty_filters_script() {
    let output = Command::new("bash")
        .arg("scripts/check_toasty_filters.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_toasty_filters.sh");
    assert!(
        output.status.success(),
        "scripts/check_toasty_filters.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_docs_load_filtered_uses_status_field() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org/docs.rs"));
    assert!(src.contains("fn load_filtered_docs_page"));
    assert!(src.contains("macro_rules! docs_filtered_query"));
    assert!(
        src.contains("fields().status()"),
        "docs loaders must filter status via fields().status()"
    );
    assert!(src.contains("DOC_STATUS_PUBLISHED"));
    let idx = src
        .find("fn load_filtered_docs_page")
        .expect("load_filtered_docs_page");
    let window = &src[idx..idx.saturating_add(800).min(src.len())];
    assert!(
        window.contains(".limit(") && window.contains(".offset("),
        "load_filtered_docs_page must SQL page with limit/offset"
    );
}

#[test]
fn inv_docs_detail_includes_body() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/doc.rs"
    ));
    assert!(src.contains("include(DocArticle::fields().body())"));
}

#[test]
fn inv_builds_load_releases_uses_channel_and_tenant_sql() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(src.contains("fn load_releases_for_org"));
    assert!(src.contains("fields().channel()"));
    assert!(
        src.contains("organization_id().in_list") || src.contains("in_list([RELEASE_GA_ORG_ID"),
        "load_releases_for_org must filter organization_id via in_list"
    );
    assert!(src.contains("RELEASE_STATUS_PUBLISHED"));
    assert!(src.contains("fn find_visible_release_by_version"));
}

#[test]
fn inv_seats_membership_count_uses_sql_count() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seats.rs"));
    assert!(src.contains(".count()"));
    assert!(
        !src.contains("rows.len()"),
        "membership_count must not use rows.len()"
    );
}

#[test]
fn inv_companies_load_uses_ilike_and_in_list() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/load.rs"
    ));
    assert!(src.contains("ilike_with_escape"));
    assert!(src.contains("in_list"));
    assert!(src.contains(".limit(") && src.contains(".offset("));
}

#[test]
fn inv_shared_sql_search_helpers_exist() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sql_search.rs"));
    assert!(src.contains("fn ilike_contains"));
    assert!(src.contains("fn escape_ilike_literal"));
    let list = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/list_page.rs"));
    assert!(list.contains("fn page_offset"));
}
