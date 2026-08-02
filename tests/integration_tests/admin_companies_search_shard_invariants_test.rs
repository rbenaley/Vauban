//! Source-shape invariants for admin companies search shard.

use std::process::Command;

#[test]
fn inv_check_admin_companies_search_shard_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_companies_search_shard.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_companies_search_shard.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_companies_search_shard.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shard_rechecks_staff_before_loading() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/search_shard.rs"
    ));
    assert!(src.contains("#[shard]"));
    assert!(src.contains("admin_companies_search_results"));
    assert!(src.contains("require_staff"));
    assert!(src.contains("companies_manage"));
    assert!(src.contains("data-admin-companies-search-shard"));
    assert!(!src.contains("path_param"));

    let staff = src.find("require_staff(cx)").expect("require_staff(cx)");
    let manage = src
        .find("perms.companies_manage")
        .expect("perms.companies_manage");
    let load = src.find("Organization::all").expect("Organization::all");
    assert!(
        staff < manage && manage < load,
        "gate order: require_staff -> companies_manage -> load"
    );
}

#[test]
fn inv_page_wires_query_signal_and_shard() {
    let page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies.rs"
    ));
    assert!(page.contains("admin_companies_search_results"));
    assert!(page.contains("signal query"));
    assert!(page.contains("normalize_query"));
    assert!(
        page.contains("page: Option<u32>"),
        "AdminCompaniesQuery must include page"
    );
    assert!(page.contains("list_toolbar"), "pager must use list_toolbar");
    assert!(page.contains("COMPANIES_PAGE_SIZE"));
}

#[test]
fn inv_shard_paginates_with_companies_page_size() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/search_shard.rs"
    ));
    assert!(
        src.contains("page_slice") && src.contains("COMPANIES_PAGE_SIZE"),
        "shard must paginate with page_slice / COMPANIES_PAGE_SIZE"
    );
}

#[test]
fn inv_helpers_company_matches_query() {
    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/companies_search.rs"
    ));
    assert!(helpers.contains("pub fn company_matches_query"));
    assert!(helpers.contains("pub fn normalize_query"));
}
