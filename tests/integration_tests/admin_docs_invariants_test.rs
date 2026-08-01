//! Source-shape invariants for admin documentation editor.

use std::process::Command;

#[test]
fn inv_check_admin_docs_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_docs.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_docs.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_docs.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_admin_docs_create_is_post_and_gated() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(src.contains("docs_write"));
    assert!(src.contains("#[route(POST") || src.contains("route(POST"));
}

#[test]
fn inv_admin_docs_publish_routes_exist() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs/doc.rs"
    ));
    assert!(src.contains("/publish"));
    assert!(src.contains("/unpublish"));
    assert!(src.contains("/delete"));
    assert!(src.contains("is_delete_confirm"));
    assert!(src.contains("docs_write"));
    assert!(
        !src.contains("max-width: 720px"),
        "edit compose must be full width"
    );
}

#[test]
fn inv_client_docs_filter_published_status() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org/docs.rs"));
    assert!(
        src.contains("fields().status()"),
        "load_filtered_docs must filter via fields().status()"
    );
    assert!(src.contains("DOC_STATUS_PUBLISHED"));
}

#[test]
fn inv_client_doc_modal_uses_docs_body_parser() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/docs/doc.rs"
    ));
    assert!(
        !src.contains("quick_start_blocks"),
        "must not hardcode quick_start_blocks"
    );
    assert!(
        !src.contains("is_seed_placeholder_or_outline"),
        "must not bypass thin seed bodies"
    );
    assert!(
        src.contains("docs_body"),
        "client modal must parse dialect via docs_body"
    );
}

#[test]
fn inv_admin_docs_save_versions_and_redirects_list() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs/doc.rs"
    ));
    assert!(src.contains("bump_version"));
    assert!(src.contains("unpublish_other_published"));
    assert!(
        src.contains("Publish new version"),
        "published edit CTA must say Publish new version"
    );
    assert!(
        !src.contains("see_other(&format!(\"/{org_slug}/admin/docs/{doc_slug}\"))"),
        "must not PRG back to slug edit URL"
    );
    assert!(
        vcp::docs_version::bump_version("v1") == "v2",
        "bump_version helper must increment"
    );
}

#[test]
fn inv_admin_list_uses_id_and_sorts() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs.rs"
    ));
    assert!(src.contains("article.id"));
    assert!(src.contains("sort_by_key"));
    assert!(src.contains("Unpublish"));
    assert!(src.contains("Publish"));
    assert!(src.contains("delete="));
    assert!(src.contains("ico_trash"));
    assert!(src.contains("Delete permanently"));
    assert!(
        src.contains("doc_status_badge_class"),
        "STATUS must use doc_status_badge_class"
    );
    assert!(
        !src.contains("vb-badge soft\">(article.status"),
        "must not hardcode soft badge on status"
    );
    assert!(
        !src.contains("UPDATED"),
        "Concept list has no UPDATED column"
    );
}

#[test]
fn inv_admin_docs_list_paginates() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs.rs"
    ));
    assert!(
        src.contains("LIST_PAGE_SIZE"),
        "admin docs must use LIST_PAGE_SIZE"
    );
    assert!(
        src.contains("list_toolbar"),
        "admin docs must use list_toolbar pager"
    );
    assert!(
        src.contains("page: Option<u32>"),
        "AdminDocsQuery must include page"
    );
    assert!(
        src.contains("page_slice"),
        "admin docs must page_slice rows"
    );
}

#[test]
fn inv_admin_compose_full_width_concept_layout() {
    let new = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs/new.rs"
    ));
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/docs/doc.rs"
    ));
    assert!(new.contains("Compose article"));
    assert!(edit.contains("Compose article"));
    assert!(!new.contains("max-width: 720px"));
    assert!(!edit.contains("max-width: 720px"));
    assert!(new.contains("vb-form-grid2"));
    assert!(edit.contains("vb-form-grid2"));
    assert!(new.contains("min-height: 280px"));
    assert!(edit.contains("min-height: 280px"));
}

#[test]
fn inv_trash_icon_is_svg_helper() {
    let icons = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/_components/icons.rs"
    ));
    assert!(icons.contains("fn ico_trash"));
    assert!(!icons.contains('🗑'));
}
