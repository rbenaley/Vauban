//! Source-shape invariants for request-scoped domain SQL dedup.

use std::process::Command;

#[test]
fn inv_check_request_sql_dedup_script() {
    let output = Command::new("bash")
        .arg("scripts/check_request_sql_dedup.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_request_sql_dedup.sh");
    assert!(
        output.status.success(),
        "scripts/check_request_sql_dedup.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_docs_count_is_memoized_and_shared() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org/docs.rs"));
    assert!(src.contains("#[memoize]"));
    assert!(src.contains("fn count_filtered_docs_memo"));
    assert!(src.contains("count_filtered_docs_memo(cx"));
    let load = src
        .find("fn load_filtered_docs_page")
        .expect("load_filtered_docs_page");
    assert!(
        src[load..].contains("count_filtered_docs(cx"),
        "load_filtered_docs_page must call count_filtered_docs (memoized)"
    );
}

#[test]
fn inv_org_issues_count_is_memoized() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(src.contains("fn count_filtered_issues_memo"));
    assert!(src.contains("count_filtered_issues_memo(cx"));
}

#[test]
fn inv_admin_issues_resolve_and_count_memoized() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    assert!(src.contains("fn resolve_org_id_memo"));
    assert!(src.contains("fn count_admin_filtered_issues_memo"));
    assert!(src.contains("count_admin_filtered_issues_memo(cx"));
}

#[test]
fn inv_companies_page_and_shard_share_memo_wrapper() {
    let load = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/load.rs"
    ));
    assert!(load.contains("fn company_cards_page_memo"));
    assert!(load.contains("fn company_cards_page"));

    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies.rs"
    ));
    let shard = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/search_shard.rs"
    ));
    assert!(page.contains("company_cards_page(cx"));
    assert!(shard.contains("company_cards_page(cx"));
    assert!(
        !page.contains("load_company_cards_page("),
        "page must not call load_company_cards_page directly"
    );
    assert!(
        !shard.contains("load_company_cards_page("),
        "shard must not call load_company_cards_page directly"
    );
}
