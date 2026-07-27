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
    let idx = src
        .find("fn load_filtered_docs")
        .expect("load_filtered_docs");
    let window = &src[idx..idx.saturating_add(800).min(src.len())];
    assert!(
        window.contains("fields().status()"),
        "load_filtered_docs must filter status via fields().status()"
    );
    assert!(window.contains("DOC_STATUS_PUBLISHED"));
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
fn inv_builds_load_releases_uses_channel_filter() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/builds.rs"
    ));
    assert!(src.contains("fn load_releases"));
    assert!(src.contains("fields().channel()"));
}
