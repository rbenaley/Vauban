//! CSP hardening (July 2026) — no inline DOM event handlers in
//! templates, and the 7 destructive forms that carried a dead
//! `onsubmit="return confirm(...)"` guard are HTMX-driven.
//!
//! Background. The production CSP is `script-src 'self' 'unsafe-eval'`
//! — NO `'unsafe-inline'`. Browsers therefore silently refuse to run
//! inline handler attributes: the `onsubmit=` confirm() guards on the
//! vault-secret / secret-group / secret-access-rule / access-rule
//! delete forms and the three EWS offboard forms were DEAD CODE. One
//! click destroyed the resource with no confirmation at all.
//!
//! The fix migrated all 7 forms to the BUG-12 pattern (`hx-post` +
//! `hx-confirm` fallback + styled `deleteConfirm` modal via
//! `@htmx:confirm.prevent`) and taught the 6 backing handlers the
//! HTMX dialect (`200 + HX-Redirect` when `HX-Request` is present,
//! `303 + Location` otherwise).
//!
//! This suite locks the fix on four axes:
//!
//! * **Detector invariants** — a Rust mirror of the
//!   `check_no_inline_event_handlers.sh` grep pattern, unit-tested
//!   against the battle cases (case games, whitespace games, unquoted
//!   values, attribute-position rules) and property-tested with
//!   proptest so the detector itself cannot drift silently.
//! * **Template scan** — the Rust detector walks `templates/**.html`
//!   and must find zero violations (in-process safety net when the
//!   bash lint is bypassed).
//! * **Script pin** — `scripts/check_no_inline_event_handlers.sh`
//!   exists, is executable, and passes.
//! * **E2E** — the 7 pages render the BUG-12 form contract, and the
//!   6 destructive endpoints speak both redirect dialects while
//!   actually mutating the entity.
//!
//! Native-fallback (303) coverage for vault secret delete, secret
//! access rule delete, asset access rule delete and admin offboard
//! already lives in `vault_secrets_crud_web_test.rs`,
//! `access_rules_crud_web_test.rs` and `iacs_test.rs`; this file adds
//! the missing native coverage for secret-group delete and
//! offboard-self.

use axum::http::header::{self, COOKIE};
use base64::Engine;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status, test_db, unwrap_ok};
use crate::fixtures::{
    create_admin_user, create_simple_admin_user, create_simple_user, create_test_access_rule,
    create_test_asset_group, create_test_secret_access_rule, create_test_secret_group,
    create_test_vauban_group, create_test_vault_secret, unique_name,
};

// =============================================================================
// Section A. Rust mirror of the bash detector + invariants.
// =============================================================================

/// Characters that put an `on*=` token in HTML attribute position.
/// Mirrors the `(^|[[:space:]"'/])` prefix class of the bash lint.
fn is_attr_delimiter(c: char) -> bool {
    c.is_whitespace() || c == '"' || c == '\'' || c == '/'
}

/// Detect inline DOM event-handler attributes (`onsubmit=`, `onclick=`,
/// any `on<alpha>+ <ws>* =` in attribute position, case-insensitive).
///
/// Single source of truth for the in-process scan; MUST stay in
/// lock-step with the `PATTERN` in
/// `scripts/check_no_inline_event_handlers.sh`. Returns the byte
/// offsets of each match start.
fn find_inline_event_handlers(src: &str) -> Vec<usize> {
    let bytes = src.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        let in_attr_position = if i == 0 {
            true
        } else {
            // Safe: we only step on ASCII boundaries below, and non-ASCII
            // bytes never equal ASCII delimiters.
            let prev = bytes[i - 1] as char;
            is_attr_delimiter(prev)
        };
        let on = bytes[i].eq_ignore_ascii_case(&b'o') && bytes[i + 1].eq_ignore_ascii_case(&b'n');
        if in_attr_position && on {
            // Require at least one ASCII alphabetic after `on`.
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j > i + 2 {
                // Optional whitespace, then `=`.
                let mut k = j;
                while k < bytes.len() && (bytes[k] as char).is_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'=' {
                    hits.push(i);
                    i = k + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    hits
}

fn is_clean(src: &str) -> bool {
    find_inline_event_handlers(src).is_empty()
}

#[test]
fn detector_fires_on_the_exact_production_bug() {
    // Verbatim from the pre-fix templates.
    let bug = r#"<form action="/vault/secrets/x/delete" method="POST" x-data="csrf"
                  onsubmit="return confirm('Delete this secret permanently?');">"#;
    assert_eq!(find_inline_event_handlers(bug).len(), 1);
}

#[test]
fn detector_battle_cases_that_must_fire() {
    let cases = [
        // HTML attribute names are case-insensitive.
        r#"<form ONSUBMIT="return confirm('x');">"#,
        r#"<form OnSubmit="return confirm('x');">"#,
        // Whitespace between the name and `=` is valid HTML.
        r#"<button onclick ="doIt()">"#,
        r#"<button onclick  =  "doIt()">"#,
        // Unquoted attribute values are valid HTML.
        "<img src=x onerror=alert(1)>",
        // Attribute right after a quote or a slash (packed markup).
        r#"<input value="x"onchange="sync()">"#,
        "<br/onload=hack()>",
        // Start of input.
        r#"onsubmit="x""#,
        // Multi-line tag: newline before the attribute.
        "<form\n    onsubmit=\"return confirm('x');\">",
    ];
    for case in cases {
        assert!(
            !is_clean(case),
            "detector MUST fire on: {case:?} (dead-guard regression)"
        );
    }
}

#[test]
fn detector_battle_cases_that_must_not_fire() {
    let cases = [
        // Alpine / HTMX event syntaxes are CSP-safe and allowed.
        r#"<form x-on:submit.prevent="save()">"#,
        r#"<form @submit.prevent="save()">"#,
        r#"<form @htmx:confirm.prevent="$store.deleteConfirm.openWith({})">"#,
        r#"<div hx-on::after-request="this.reset()">"#,
        // `data-*` attributes and words merely containing `on`.
        r#"<div data-online="true">"#,
        r#"<input name="session" value="abc">"#,
        r#"<a href="/vault/secrets?session=1&reason=x">"#,
        // `on` not followed by `=` (prose, Askama expressions).
        "{% if connection %}online{% endif %}",
        // `on<alpha>=` NOT in attribute position (preceded by alnum/:/-/.).
        "aonsubmit=\"x\"",
        ":onsubmit=\"x\"",
        "-onclick=\"x\"",
        ".onload=\"x\"",
        "@onclick=\"x\"",
        // `on` followed by a digit is not an event name.
        r#"<div on1="x">"#,
        // Empty remainder.
        "on",
        "",
    ];
    for case in cases {
        assert!(
            is_clean(case),
            "detector must NOT fire on: {case:?} (false positive)"
        );
    }
}

mod detector_proptests {
    use super::*;
    use proptest::prelude::*;

    /// Random casing of an ASCII string.
    fn random_case(s: &str, flips: &[bool]) -> String {
        s.chars()
            .zip(flips.iter().cycle())
            .map(|(c, upper)| {
                if *upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }

    proptest! {
        /// INVARIANT 1 — completeness: any `on<alpha>+ <ws>* =` token
        /// in attribute position is detected, whatever the casing,
        /// the event-name suffix, the whitespace gap, or the clean
        /// text around it.
        #[test]
        fn any_inline_handler_in_attr_position_is_detected(
            suffix in "[a-z]{1,12}",
            flips in proptest::collection::vec(any::<bool>(), 2..15),
            delim in prop_oneof![Just(' '), Just('\t'), Just('\n'), Just('"'), Just('\''), Just('/')],
            gap in "[ \t]{0,3}",
            // '=' and '<'/'>' excluded so the padding cannot form its
            // own match or eat the delimiter semantics.
            before in "[a-z0-9 <>/\"'-]{0,30}",
            after in "[a-z0-9 <>-]{0,30}",
        ) {
            let handler = random_case(&format!("on{suffix}"), &flips);
            let doc = format!("{before}{delim}{handler}{gap}=\"x\"{after}");
            prop_assert!(
                !is_clean(&doc),
                "handler {handler:?} embedded after delimiter {delim:?} must be detected in {doc:?}"
            );
        }

        /// INVARIANT 2 — soundness (attribute position): the same
        /// token preceded by a NON-delimiter character (Alpine `x-on:`,
        /// `hx-on::`, `data-online`, prose) never fires, provided the
        /// surroundings are clean.
        #[test]
        fn handler_not_in_attr_position_is_ignored(
            suffix in "[a-z]{1,12}",
            shield in prop_oneof![
                Just(':'), Just('-'), Just('.'), Just('@'),
                Just('a'), Just('z'), Just('0'), Just('9'),
            ],
            gap in "[ \t]{0,3}",
            before in "[a-z0-9 ]{0,30}",
        ) {
            // `before` must not end with a character that would put
            // `shield` itself in a firing sequence; `before` is clean
            // ([a-z0-9 ] only, no `=`) and `shield` breaks attribute
            // position, so the whole document is clean.
            let doc = format!("{before}{shield}on{suffix}{gap}=\"x\"");
            prop_assert!(
                is_clean(&doc),
                "shielded token must NOT fire in {doc:?}"
            );
        }

        /// INVARIANT 3 — soundness (no `=`): text that contains no `=`
        /// can never fire, whatever else it contains.
        #[test]
        fn text_without_equals_never_fires(s in "[^=]{0,200}") {
            prop_assert!(is_clean(&s), "no-equals text fired: {s:?}");
        }

        /// INVARIANT 4 — case-insensitivity: detection is invariant
        /// under ASCII case changes of the whole document.
        #[test]
        fn detection_is_case_invariant(s in "[a-zA-Z0-9 <>/\"'=:.-]{0,120}") {
            prop_assert_eq!(
                is_clean(&s.to_ascii_lowercase()),
                is_clean(&s.to_ascii_uppercase()),
                "case flip changed the verdict for {:?}", s
            );
        }
    }
}

// =============================================================================
// Section B. Template scan + script pin.
// =============================================================================

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_html_files(root: &std::path::Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_html_files(&path, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("html") {
            files.push(path);
        }
    }
}

/// In-process safety net: no template may carry an inline `on*=`
/// handler. Mirrors the bash lint so a developer who bypasses CI's
/// bash runner still trips the regression locally.
#[test]
fn no_template_carries_inline_event_handlers() {
    let dir = manifest_dir().join("templates");
    let mut files = Vec::new();
    collect_html_files(&dir, &mut files);
    assert!(!files.is_empty(), "no templates found under {dir:?}");

    let mut offenders = Vec::new();
    for file in &files {
        let body = std::fs::read_to_string(file).unwrap_or_default();
        if !is_clean(&body) {
            offenders.push(file.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "inline on*= event handlers found (dead code under the CSP, use the \
         BUG-12 hx-post + deleteConfirm modal pattern): {offenders:?}"
    );
}

#[test]
fn check_no_inline_event_handlers_script_passes() {
    let script = manifest_dir()
        .join("scripts")
        .join("check_no_inline_event_handlers.sh");
    assert!(script.exists(), "missing lint script: {}", script.display());

    let out = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", script.display(), e));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_no_inline_event_handlers.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn check_no_inline_event_handlers_script_is_executable_and_pins_pattern() {
    use std::os::unix::fs::PermissionsExt;
    let path = manifest_dir()
        .join("scripts")
        .join("check_no_inline_event_handlers.sh");
    assert!(path.exists(), "missing lint script: {}", path.display());
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "lint script not executable: {} (mode={:o})",
        path.display(),
        mode
    );

    // The bash pattern must keep its two load-bearing properties:
    // attribute-position prefix class and case-insensitive grep.
    let body = std::fs::read_to_string(&path).expect("read script");
    assert!(
        body.contains(r#"on[a-z]+[[:space:]]*="#),
        "script must keep the `on<alpha>+ ws* =` core pattern"
    );
    assert!(
        body.contains("grep -niE") || body.contains("grep -inE"),
        "script must grep case-insensitively (HTML attribute names are \
         case-insensitive; `ONSUBMIT=` is the same dead guard)"
    );
}

// =============================================================================
// Section C. E2E — HTML contract of the 7 converted forms.
// =============================================================================

/// Assert the BUG-12 contract on a rendered destructive form:
/// HTMX-driven (`hx-post`), styled-modal wiring (`data-confirm-title` +
/// `@htmx:confirm.prevent`), native fallback (`hx-confirm`), and no
/// trace of the dead legacy pattern (`onsubmit=` / native `action=`
/// on the destructive endpoint).
fn assert_bug12_form_contract(body: &str, endpoint: &str, confirm_title: &str, page: &str) {
    assert!(
        body.contains(&format!("hx-post=\"{endpoint}\"")),
        "{page}: destructive form must be HTMX-driven (hx-post=\"{endpoint}\")"
    );
    assert!(
        !body.contains(&format!("action=\"{endpoint}\"")),
        "{page}: native action= must not target {endpoint} anymore"
    );
    assert!(
        body.contains(&format!("data-confirm-title=\"{confirm_title}\"")),
        "{page}: form must carry data-confirm-title=\"{confirm_title}\" for the styled modal"
    );
    assert!(
        body.contains("@htmx:confirm.prevent"),
        "{page}: form must intercept htmx:confirm to dispatch the deleteConfirm modal"
    );
    assert!(
        body.contains("hx-confirm="),
        "{page}: hx-confirm fallback must remain (defense-in-depth if Alpine is unavailable)"
    );
    assert!(
        !body.contains("onsubmit="),
        "{page}: inline onsubmit= is dead code under the CSP and must not reappear"
    );
}

fn cookie(token: &str) -> String {
    format!("access_token={token}")
}

fn auth_csrf_cookie(token: &str, csrf: &str) -> String {
    format!("access_token={token}; __vauban_csrf={csrf}")
}

/// Form #1 — Delete vault secret, on `/vault/secrets/{uuid}`.
#[tokio::test]
#[serial]
async fn secret_detail_delete_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_sd")).await;
    let (_id, secret_uuid) = create_test_vault_secret(&mut conn, "csp-sd", "v", true).await;

    let response = app
        .server
        .get(&format!("/vault/secrets/{secret_uuid}"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/vault/secrets/{secret_uuid}/delete"),
        "Delete secret",
        "secret detail",
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #2 — Delete secret group, on `/vault/secrets/groups/{uuid}`.
#[tokio::test]
#[serial]
async fn secret_group_detail_delete_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_sg")).await;
    let (_id, group_uuid) = create_test_secret_group(&mut conn, "csp-sg").await;

    let response = app
        .server
        .get(&format!("/vault/secrets/groups/{group_uuid}"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/vault/secrets/groups/{group_uuid}/delete"),
        "Delete secret group",
        "secret group detail",
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #3 — Delete secret access rule, on `/vault/secrets/access/{uuid}`.
#[tokio::test]
#[serial]
async fn secret_access_rule_detail_delete_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_sr")).await;
    let ug_uuid = create_test_vauban_group(&mut conn, &unique_name("csp-sr-ug")).await;
    let (sg_id, _sg_uuid) = create_test_secret_group(&mut conn, "csp-sr-sg").await;
    let ag_id = crate::fixtures::all_assets_group_id(&mut conn).await;
    let rule_uuid =
        create_test_secret_access_rule(&mut conn, &ug_uuid, sg_id, ag_id, true, None, None).await;

    let response = app
        .server
        .get(&format!("/vault/secrets/access/{rule_uuid}"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/vault/secrets/access/{rule_uuid}/delete"),
        "Delete secret access rule",
        "secret access rule detail",
    );

    test_db::cleanup(&mut conn).await;
}

/// Form #4 — Delete asset access rule, on `/assets/access/{uuid}`.
#[tokio::test]
#[serial]
async fn access_rule_detail_delete_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_ar")).await;
    let ug_uuid = create_test_vauban_group(&mut conn, &unique_name("csp-ar-ug")).await;
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("csp-ar-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug_uuid, &ag_uuid, &["ssh"]).await;

    let response = app
        .server
        .get(&format!("/assets/access/{rule_uuid}"))
        .add_header(header::AUTHORIZATION, app.auth_header(&admin.token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/assets/access/{rule_uuid}/delete"),
        "Delete access rule",
        "access rule detail",
    );

    test_db::cleanup(&mut conn).await;
}

// ------------------------------------------------------------------
// IACS helpers (duplicated from iacs_admin_ux_test.rs: integration
// test files cannot import from each other in one `tests/web` crate).
// ------------------------------------------------------------------

fn make_ed25519_line_for_tag(tag: &str) -> String {
    let key_bytes = Sha256::digest(tag.as_bytes());
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&key_bytes);
    let payload = base64::engine::general_purpose::STANDARD.encode(&blob);
    format!("ssh-ed25519 {} VAUBAN", payload)
}

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

async fn spawn_iacs_user(app: &TestApp, suffix: &str) -> (i32, String, String) {
    let mut conn = app.get_conn().await;
    let username = unique_name(suffix);
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;
    (user_id, token, app.generate_csrf_token())
}

async fn spawn_iacs_admin(app: &TestApp, suffix: &str) -> (i32, String, String) {
    let mut conn = app.get_conn().await;
    let admin_name = unique_name(suffix);
    let admin_id = create_simple_admin_user(&mut conn, &admin_name).await;
    let admin_uuid = get_user_uuid(&mut conn, admin_id).await;
    let token = app
        .generate_test_token(&admin_uuid.to_string(), &admin_name, true, true)
        .await;
    (admin_id, token, app.generate_csrf_token())
}

/// Submit + approve one EWS; returns its uuid.
async fn onboard_active_ews(
    app: &TestApp,
    user_token: &str,
    admin_token: &str,
    csrf: &str,
    ews_name: &str,
    user_id: i32,
) -> Uuid {
    use vauban_web::schema::{ews, ews_onboarding_requests as r};
    let key_line = make_ed25519_line_for_tag(ews_name);
    let response = app
        .server
        .post("/iacs/onboard")
        .add_header(COOKIE, auth_csrf_cookie(user_token, csrf))
        .form(&[
            ("csrf_token", csrf),
            ("name", ews_name),
            ("public_key", key_line.as_str()),
            ("justification", "csp-hardening-test"),
        ])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "onboard submit failed (status {})",
        response.status_code().as_u16()
    );

    let mut conn = app.get_conn().await;
    let request_uuid: Uuid = unwrap_ok!(
        r::table
            .filter(r::user_id.eq(user_id))
            .filter(r::name.eq(ews_name))
            .select(r::uuid)
            .first(&mut conn)
            .await
    );

    let response = app
        .server
        .post(&format!("/iacs/admin/request/{request_uuid}/approve"))
        .add_header(COOKIE, auth_csrf_cookie(admin_token, csrf))
        .form(&[("csrf_token", csrf)])
        .await;
    assert!(
        matches!(response.status_code().as_u16(), 302 | 303),
        "approve failed (status {})",
        response.status_code().as_u16()
    );

    unwrap_ok!(
        ews::table
            .filter(ews::user_id.eq(user_id))
            .filter(ews::name.eq(ews_name))
            .select(ews::uuid)
            .first(&mut conn)
            .await
    )
}

/// Form #5 — EWS self-offboard, on `/sessions/my-requests`.
#[tokio::test]
#[serial]
async fn my_requests_self_offboard_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_so_user").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_so_admin").await;

    let ews_name = unique_name("csp_so_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .get("/sessions/my-requests")
        .add_header(COOKIE, cookie(&user_token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/iacs/{ews_uuid}/offboard-self"),
        "Offboard EWS",
        "my-requests",
    );
}

/// Form #6 — admin offboard on the landing list `/iacs/admin`.
#[tokio::test]
#[serial]
async fn iacs_admin_list_offboard_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_al_user").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_al_admin").await;

    let ews_name = unique_name("csp_al_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .get("/iacs/admin")
        .add_header(COOKIE, cookie(&admin_token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/iacs/admin/ews/{ews_uuid}/offboard"),
        "Offboard EWS",
        "iacs admin list",
    );
}

/// Form #7 — admin offboard on the EWS detail `/iacs/admin/ews/{uuid}`.
#[tokio::test]
#[serial]
async fn iacs_admin_detail_offboard_form_follows_bug12_contract() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_ad_user").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_ad_admin").await;

    let ews_name = unique_name("csp_ad_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .get(&format!("/iacs/admin/ews/{ews_uuid}"))
        .add_header(COOKIE, cookie(&admin_token))
        .await;
    assert_status(&response, 200);
    assert_bug12_form_contract(
        &response.text(),
        &format!("/iacs/admin/ews/{ews_uuid}/offboard"),
        "Offboard EWS",
        "iacs admin ews detail",
    );
}

// =============================================================================
// Section D. E2E — the endpoints speak the HTMX dialect AND mutate.
// =============================================================================

fn assert_hx_redirect(response: &axum_test::TestResponse, expected_location: &str) {
    let status = response.status_code().as_u16();
    assert_eq!(
        status, 200,
        "HTMX destructive POST must return 200 (not a 3xx), got {status}"
    );
    let hx_redirect = response
        .headers()
        .get("HX-Redirect")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        hx_redirect,
        Some(expected_location),
        "HX-Redirect must point at {expected_location}"
    );
}

fn assert_native_redirect(response: &axum_test::TestResponse, expected_location: &str) {
    let status = response.status_code().as_u16();
    assert!(
        status == 302 || status == 303,
        "native destructive POST must keep PRG (3xx), got {status}"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        location,
        Some(expected_location),
        "Location must point at {expected_location}"
    );
}

#[tokio::test]
#[serial]
async fn htmx_delete_vault_secret_returns_hx_redirect_and_deletes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_hx_s")).await;
    let (_id, secret_uuid) = create_test_vault_secret(&mut conn, "csp-hx-s", "v", true).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/vault/secrets/{secret_uuid}/delete"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/vault/secrets");

    use vauban_web::schema::vault_secrets;
    let remaining: i64 = unwrap_ok!(
        vault_secrets::table
            .filter(vault_secrets::uuid.eq(secret_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(remaining, 0, "HTMX path must actually delete the secret");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn htmx_delete_secret_group_returns_hx_redirect_and_deletes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_hx_g")).await;
    let (_id, group_uuid) = create_test_secret_group(&mut conn, "csp-hx-g").await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{group_uuid}/delete"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/vault/secrets/groups");

    use vauban_web::schema::secret_groups;
    let remaining: i64 = unwrap_ok!(
        secret_groups::table
            .filter(secret_groups::uuid.eq(group_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(remaining, 0, "HTMX path must actually delete the group");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn htmx_delete_secret_access_rule_returns_hx_redirect_and_deletes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_hx_r")).await;
    let ug_uuid = create_test_vauban_group(&mut conn, &unique_name("csp-hx-r-ug")).await;
    let (sg_id, _sg_uuid) = create_test_secret_group(&mut conn, "csp-hx-r-sg").await;
    let ag_id = crate::fixtures::all_assets_group_id(&mut conn).await;
    let rule_uuid =
        create_test_secret_access_rule(&mut conn, &ug_uuid, sg_id, ag_id, true, None, None).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/vault/secrets/access/{rule_uuid}/delete"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/vault/secrets/access");

    use vauban_web::schema::secret_access_rules;
    let remaining: i64 = unwrap_ok!(
        secret_access_rules::table
            .filter(secret_access_rules::uuid.eq(rule_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(remaining, 0, "HTMX path must actually delete the rule");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn htmx_delete_access_rule_returns_hx_redirect_and_deletes() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_hx_a")).await;
    let ug_uuid = create_test_vauban_group(&mut conn, &unique_name("csp-hx-a-ug")).await;
    let ag_uuid = create_test_asset_group(&mut conn, &unique_name("csp-hx-a-ag")).await;
    let rule_uuid = create_test_access_rule(&mut conn, &ug_uuid, &ag_uuid, &["ssh"]).await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/assets/access/{rule_uuid}/delete"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/assets/access");

    use vauban_web::schema::access_rules;
    let remaining: i64 = unwrap_ok!(
        access_rules::table
            .filter(access_rules::uuid.eq(rule_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(remaining, 0, "HTMX path must actually delete the rule");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn htmx_offboard_self_returns_hx_redirect_and_offboards() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_hx_so_u").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_hx_so_a").await;

    let ews_name = unique_name("csp_hx_so_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .post(&format!("/iacs/{ews_uuid}/offboard-self"))
        .add_header(COOKIE, auth_csrf_cookie(&user_token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/sessions/my-requests");

    use vauban_web::schema::ews;
    let mut conn = app.get_conn().await;
    let offboarded_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::offboarded_at)
            .first(&mut conn)
            .await
    );
    assert!(
        offboarded_at.is_some(),
        "HTMX offboard-self must set offboarded_at"
    );
}

#[tokio::test]
#[serial]
async fn htmx_admin_offboard_returns_hx_redirect_and_offboards() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_hx_ao_u").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_hx_ao_a").await;

    let ews_name = unique_name("csp_hx_ao_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .post(&format!("/iacs/admin/ews/{ews_uuid}/offboard"))
        .add_header(COOKIE, auth_csrf_cookie(&admin_token, &csrf))
        .add_header("HX-Request", "true")
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_hx_redirect(&response, "/iacs/admin");

    use vauban_web::schema::ews;
    let mut conn = app.get_conn().await;
    let offboarded_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::offboarded_at)
            .first(&mut conn)
            .await
    );
    assert!(
        offboarded_at.is_some(),
        "HTMX admin offboard must set offboarded_at"
    );
}

// =============================================================================
// Section E. E2E — native fallback (no HX-Request) keeps the PRG contract.
//
// Only the two endpoints without existing native coverage; the other
// four are pinned by vault_secrets_crud_web_test.rs,
// access_rules_crud_web_test.rs and iacs_test.rs.
// =============================================================================

#[tokio::test]
#[serial]
async fn native_delete_secret_group_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;
    let admin = create_admin_user(&mut conn, &app.auth_service, &unique_name("csp_nat_g")).await;
    let (_id, group_uuid) = create_test_secret_group(&mut conn, "csp-nat-g").await;
    let csrf = app.generate_csrf_token();

    let response = app
        .server
        .post(&format!("/vault/secrets/groups/{group_uuid}/delete"))
        .add_header(COOKIE, auth_csrf_cookie(&admin.token, &csrf))
        // deliberately NO HX-Request header
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_native_redirect(&response, "/vault/secrets/groups");

    use vauban_web::schema::secret_groups;
    let remaining: i64 = unwrap_ok!(
        secret_groups::table
            .filter(secret_groups::uuid.eq(group_uuid))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(remaining, 0, "native path must still delete the group");

    test_db::cleanup(&mut conn).await;
}

#[tokio::test]
#[serial]
async fn native_offboard_self_keeps_303_redirect() {
    let app = TestApp::spawn().await;
    let (user_id, user_token, csrf) = spawn_iacs_user(app, "csp_nat_so_u").await;
    let (_admin_id, admin_token, _) = spawn_iacs_admin(app, "csp_nat_so_a").await;

    let ews_name = unique_name("csp_nat_so_ews");
    let ews_uuid =
        onboard_active_ews(app, &user_token, &admin_token, &csrf, &ews_name, user_id).await;

    let response = app
        .server
        .post(&format!("/iacs/{ews_uuid}/offboard-self"))
        .add_header(COOKIE, auth_csrf_cookie(&user_token, &csrf))
        .form(&[("csrf_token", csrf.as_str())])
        .await;
    assert_native_redirect(&response, "/sessions/my-requests");

    use vauban_web::schema::ews;
    let mut conn = app.get_conn().await;
    let offboarded_at: Option<chrono::DateTime<chrono::Utc>> = unwrap_ok!(
        ews::table
            .filter(ews::uuid.eq(ews_uuid))
            .select(ews::offboarded_at)
            .first(&mut conn)
            .await
    );
    assert!(
        offboarded_at.is_some(),
        "native offboard-self must set offboarded_at"
    );
}
