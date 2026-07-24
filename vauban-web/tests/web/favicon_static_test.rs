//! Pin: favicon referenced by `base.html` is registered in STATIC_FILES.
//!
//! REGRESSION: `templates/base.html` linked `/static/img/favicon.svg` for
//! months while the file was neither on disk nor in the Capsicum
//! whitelist, so every browser tab produced a WARN audit 404.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::common::TestApp;

const BASE_HTML: &str = include_str!("../../templates/base.html");

#[test]
fn base_html_references_svg_favicon() {
    assert!(
        BASE_HTML.contains(r#"href="/static/img/favicon.svg""#),
        "base.html must link the SVG favicon under /static/img/"
    );
}

#[test]
fn favicon_svg_is_registered_in_static_files() {
    let asset = vauban_web::static_assets::lookup("img/favicon.svg").expect(
        "`/static/img/favicon.svg` must be registered in STATIC_FILES \
         (otherwise every page load audits a 404 WARN)",
    );
    assert_eq!(asset.path, "img/favicon.svg");
    assert_eq!(asset.content_type, "image/svg+xml");
    let body = std::str::from_utf8(asset.content).expect("favicon.svg must be UTF-8 SVG");
    assert!(
        body.contains("<svg"),
        "embedded asset must be a real SVG, not a stub"
    );
    assert!(
        body.contains("#0369a1"),
        "favicon should use the VAUBAN brand tile colour"
    );
}

/// Live router: the URL the browser hits must return 200 (not audit WARN 404).
#[tokio::test]
async fn get_static_favicon_svg_returns_200() {
    let app = TestApp::spawn().await;
    let response = app.server.get("/static/img/favicon.svg").await;
    assert_eq!(
        response.status_code().as_u16(),
        200,
        "favicon must be served; got {}",
        response.status_code()
    );
    let ct = response
        .headers()
        .get("content-type")
        .expect("Content-Type")
        .to_str()
        .unwrap();
    assert!(
        ct.starts_with("image/svg+xml"),
        "unexpected Content-Type: {ct}"
    );
    assert!(!response.as_bytes().is_empty());
}
