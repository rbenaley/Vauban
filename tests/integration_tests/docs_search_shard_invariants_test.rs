//! Source-shape invariants for docs search shard.

use std::process::Command;

#[test]
fn inv_check_docs_search_shard_script() {
    let output = Command::new("bash")
        .arg("scripts/check_docs_search_shard.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_docs_search_shard.sh");
    assert!(
        output.status.success(),
        "scripts/check_docs_search_shard.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_shard_never_reads_org_from_path_params() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/search_shard.rs"
    ));
    assert!(src.contains("#[shard]"));
    assert!(src.contains("docs_search_results"));
    assert!(
        !src.contains("path_param"),
        "shard POSTs lack {{org}}; path_param panics (use org_slug arg)"
    );
}

#[test]
fn inv_shard_reauthorizes_before_loading_docs() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/search_shard.rs"
    ));
    let normalize = src
        .find("normalize_org_slug(&org_slug)")
        .expect("normalize_org_slug(&org_slug)");
    let require = src.find("require_org(cx").expect("require_org(cx");
    let docs_read = src.find("perms.docs_read").expect("perms.docs_read");
    let load = src
        .find("load_filtered_docs(cx")
        .expect("load_filtered_docs(cx");
    assert!(
        normalize < require && require < docs_read && docs_read < load,
        "gate order: normalize_org_slug -> require_org -> docs_read -> load"
    );
}

#[test]
fn inv_shard_links_use_authorized_context_slug() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/search_shard.rs"
    ));
    assert!(
        src.contains("ctx.org.slug"),
        "result hrefs must use authorized org slug"
    );
    assert!(
        src.contains("DocsFilter::normalized"),
        "shard must share filter normalization with the page"
    );
    assert!(
        src.contains("page_slice") && src.contains("LIST_PAGE_SIZE"),
        "shard must paginate with page_slice / LIST_PAGE_SIZE"
    );
}

#[test]
fn inv_page_passes_org_slug_shard_arg() {
    let docs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org/docs.rs"));
    assert!(docs.contains("docs_search_results"));
    assert!(docs.contains("org_slug:"));
    assert!(
        docs.contains("DocsFilter::normalized") || docs.contains("normalize_query"),
        "page filter must share docs_search helpers"
    );
    assert!(
        docs.contains("page: Option<u32>"),
        "DocsQuery must include page"
    );
    assert!(
        docs.contains("filter_row"),
        "chips + pager must use filter_row"
    );
}

#[test]
fn inv_pure_helpers_module_exported() {
    let lib = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(
        lib.contains("pub mod docs_search"),
        "docs_search helpers must be a public crate module for unit/proptest"
    );
}
