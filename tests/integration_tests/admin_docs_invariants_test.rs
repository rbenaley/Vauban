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
        "/src/app/org/admin/docs/new.rs"
    ));
    assert!(src.contains("method=\"POST\""));
    assert!(src.contains("docs_write"));
    assert!(src.contains("#[route(POST") || src.contains("route(POST"));
}

#[test]
fn inv_admin_docs_publish_routes_exist() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/admin/docs/doc.rs"
    ));
    assert!(src.contains("/publish"));
    assert!(src.contains("/unpublish"));
    assert!(src.contains("docs_write"));
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
