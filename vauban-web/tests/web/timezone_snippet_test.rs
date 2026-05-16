//! Pin tests for the browser-timezone bootstrap snippet.
//!
//! The bootstrap is split into two files so the global Content
//! Security Policy (`script-src 'self'`) can stay strict:
//!
//!  * `vauban-web/static/js/vbn-tz.js` -- the actual snippet that
//!    reads `Intl.DateTimeFormat().resolvedOptions().timeZone`,
//!    posts it into the `vbn_tz` cookie, and -- on the first hit
//!    only -- triggers `location.replace()` to reload the page so
//!    the very first paint already comes localized.
//!  * `vauban-web/templates/base.html` -- a `<script src=...>` tag
//!    that pulls the snippet in synchronously inside `<head>`.
//!
//! These tests assert the CONTRACT (substring match against the
//! source files). A regression that drops one of the strings would
//! silently break the localization path on every fresh browser.

use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_static_js() -> String {
    let path = manifest_dir().join("static/js/vbn-tz.js");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {}: {}", path.display(), e))
}

fn read_base_html() -> String {
    let path = manifest_dir().join("templates/base.html");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {}: {}", path.display(), e))
}

#[test]
fn snippet_reads_intl_datetime_format() {
    let body = read_static_js();
    assert!(
        body.contains("Intl.DateTimeFormat"),
        "the bootstrap snippet must read Intl.DateTimeFormat()"
    );
    assert!(
        body.contains("resolvedOptions"),
        "the bootstrap snippet must call resolvedOptions()"
    );
    assert!(
        body.contains("timeZone"),
        "the bootstrap snippet must read .timeZone from resolvedOptions"
    );
}

#[test]
fn snippet_writes_vbn_tz_cookie() {
    let body = read_static_js();
    assert!(
        body.contains("vbn_tz="),
        "the bootstrap snippet must write the `vbn_tz` cookie"
    );
    assert!(
        body.contains("encodeURIComponent"),
        "the cookie value must be URL-encoded"
    );
    assert!(
        body.contains("Max-Age"),
        "the cookie must carry a Max-Age (one year by convention)"
    );
    assert!(
        body.contains("SameSite=Lax"),
        "the cookie must carry SameSite=Lax"
    );
    assert!(body.contains("Path=/"), "the cookie must carry Path=/");
}

#[test]
fn snippet_caps_value_at_64_bytes() {
    let body = read_static_js();
    assert!(
        body.contains("64"),
        "the bootstrap snippet must cap the cookie value at 64 chars to mirror VBN_TZ_COOKIE_MAX_LEN"
    );
}

#[test]
fn snippet_falls_back_to_utc_on_failure() {
    let body = read_static_js();
    let utc_count = body.matches("'UTC'").count() + body.matches("\"UTC\"").count();
    assert!(
        utc_count >= 2,
        "the snippet must declare a UTC fallback in BOTH the catch path and the missing-timezone path \
         (found {utc_count} occurrence(s))"
    );
}

#[test]
fn snippet_first_hit_reloads_silently() {
    let body = read_static_js();
    assert!(
        body.contains("location.replace"),
        "the snippet must use location.replace() on first hit so the back-button history is clean"
    );
}

#[test]
fn snippet_only_writes_cookie_on_change() {
    let body = read_static_js();
    assert!(
        body.contains("current === tz"),
        "the snippet must short-circuit when the resolved tz already matches the cookie"
    );
}

#[test]
fn base_html_loads_snippet_synchronously_in_head() {
    let body = read_base_html();
    let head_open = body.find("<head>").expect("base.html must have a <head>");
    let head_close = body.find("</head>").expect("base.html must have a </head>");
    let head = &body[head_open..head_close];
    assert!(
        head.contains("/static/js/vbn-tz.js"),
        "<head> must reference /static/js/vbn-tz.js"
    );
    let snippet_pos = head
        .find("/static/js/vbn-tz.js")
        .expect("snippet must be in <head>");
    let title_pos = head.find("<title>").expect("<head> must declare a <title>");
    assert!(
        snippet_pos < title_pos,
        "the snippet must load BEFORE <title> so the timezone is set on the first paint"
    );
    let snippet_line = head
        .lines()
        .find(|l| l.contains("/static/js/vbn-tz.js"))
        .expect("snippet line missing");
    assert!(
        !snippet_line.contains("async") && !snippet_line.contains("defer"),
        "the snippet MUST be synchronous (no `async`/`defer`); found: {snippet_line:?}"
    );
}

#[test]
fn base_html_does_not_inline_snippet_body() {
    let body = read_base_html();
    assert!(
        !body.contains("Intl.DateTimeFormat"),
        "the snippet must live in static/js/vbn-tz.js, not inline (CSP `script-src 'self'` forbids inline scripts)"
    );
}

/// REGRESSION (v0.7.7): the snippet was created under
/// `vauban-web/static/js/vbn-tz.js` and referenced from `base.html`,
/// but never registered in [`vauban_web::static_assets::STATIC_FILES`].
/// `STATIC_FILES` is an EXHAUSTIVE whitelist (Capsicum-compatible),
/// so the binary returned 404 on `/static/js/vbn-tz.js` and the
/// browser silently failed to set the cookie. The whole UI then fell
/// back to UTC.
///
/// This test pins the wiring: the path the template references MUST
/// also be served by `serve_static`.
#[test]
fn vbn_tz_js_is_served_under_static() {
    let asset = vauban_web::static_assets::lookup("js/vbn-tz.js").expect(
        "`/static/js/vbn-tz.js` must be registered in STATIC_FILES \
                 (otherwise the browser timezone bootstrap silently 404s \
                 and the UI collapses to UTC)",
    );
    assert_eq!(asset.path, "js/vbn-tz.js");
    assert!(
        asset.content_type.starts_with("application/javascript"),
        "vbn-tz.js must be served as JavaScript, got `{}`",
        asset.content_type
    );
    let body = std::str::from_utf8(asset.content).expect("vbn-tz.js must be valid UTF-8");
    assert!(
        body.contains("Intl.DateTimeFormat"),
        "the embedded asset must be the actual snippet (not a stub)"
    );
}

#[test]
fn extractor_constants_match_snippet() {
    use vauban_web::middleware::browser_tz::{VBN_TZ_COOKIE_MAX_LEN, VBN_TZ_COOKIE_NAME};
    let snippet = read_static_js();
    assert!(
        snippet.contains(VBN_TZ_COOKIE_NAME),
        "snippet must reference the canonical cookie name `{}`",
        VBN_TZ_COOKIE_NAME
    );
    let cap = format!("{}", VBN_TZ_COOKIE_MAX_LEN);
    assert!(
        snippet.contains(&cap),
        "snippet must cap at {} to match VBN_TZ_COOKIE_MAX_LEN",
        cap
    );
}
