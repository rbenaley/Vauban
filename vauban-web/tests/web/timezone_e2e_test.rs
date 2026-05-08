//! End-to-end tests for the browser-timezone localization stack.
//!
//! These tests drive the full Axum router (`TestApp`) and assert
//! the rendered HTML reflects the `vbn_tz` cookie value. They cover
//! the four scenarios called out by the May 2026 audit:
//!
//!  * Cookie absent -- fallback to UTC.
//!  * Cookie `Europe/Paris` -- localized to CEST/CET (DST aware).
//!  * Cookie `Foo/Bar` (invalid IANA) -- fallback to UTC, no crash.
//!  * Cookie containing an XSS probe -- fallback to UTC, payload
//!    NEVER round-trips into the body.
//!
//! The `/accounts/profile` page is targeted because it renders
//! `profile.created_at` formatted by
//! `crate::utils::format_local_with_seconds(..., browser_tz.0)`.
//! We pin the user's `created_at` to a known winter date so the
//! Paris run yields CET (deterministic across DST).

use crate::common::{TestApp, assertions::assert_status, unwrap_ok};
use crate::fixtures::{create_simple_user, unique_name};
use axum::http::header::COOKIE;
use chrono::TimeZone;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

async fn get_user_uuid(conn: &mut AsyncPgConnection, user_id: i32) -> uuid::Uuid {
    use vauban_web::schema::users;
    unwrap_ok!(
        users::table
            .filter(users::id.eq(user_id))
            .select(users::uuid)
            .first(conn)
            .await
    )
}

/// Force the user's `created_at` to a fixed UTC moment so the
/// formatted display is deterministic across runs and timezones.
/// Winter date (January) so Paris is CET (UTC+01:00) and the test
/// is DST-stable even if it runs during a DST transition window.
async fn pin_created_at(conn: &mut AsyncPgConnection, user_id: i32) -> chrono::DateTime<chrono::Utc> {
    use vauban_web::schema::users;
    let pinned = unwrap_ok!(chrono::Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).single().ok_or("bad date"));
    unwrap_ok!(
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::created_at.eq(pinned))
            .execute(conn)
            .await
    );
    pinned
}

/// Strip the bootstrap snippet `<script>` tag and the static asset
/// reference from the response body. The snippet itself contains
/// the literal `'UTC'` string (fallback), which would taint a
/// `body.contains("UTC")` assertion. Removing it yields the
/// "rendered content" view we actually care about.
fn body_without_snippet(html: &str) -> String {
    html.replace("/static/js/vbn-tz.js", "")
}

#[tokio::test]
async fn timezone_e2e_cookie_absent_falls_back_to_utc() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_utc");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    pin_created_at(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = body_without_snippet(response.text().as_str());

    // Pinned 2026-01-15 10:30:00 UTC must round-trip as
    // "2026-01-15 10:30:00 UTC" when no vbn_tz cookie is provided.
    assert!(
        body.contains("2026-01-15 10:30:00 UTC"),
        "no-cookie response must format the pinned date in UTC"
    );
    assert!(
        !body.contains("CET") && !body.contains("CEST"),
        "no-cookie response must NOT contain a Europe/Paris label"
    );
}

#[tokio::test]
async fn timezone_e2e_cookie_paris_yields_local_label() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_paris");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    pin_created_at(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(
            COOKIE,
            format!("access_token={}; vbn_tz=Europe%2FParis", token),
        )
        .await;

    assert_status(&response, 200);
    let body = body_without_snippet(response.text().as_str());

    // 2026-01-15 10:30 UTC is 2026-01-15 11:30 CET (winter).
    assert!(
        body.contains("2026-01-15 11:30:00 CET"),
        "Paris cookie must shift the formatted date by +1h and label `CET` in winter\nbody: ...{}...",
        body.lines()
            .find(|l| l.contains("2026-01-15"))
            .unwrap_or("(no matching line)")
    );
    // The snippet-stripped body must NOT carry a UTC marker on a
    // formatted timestamp anymore.
    assert!(
        !body.contains(" UTC"),
        "Paris cookie response must not leak a \" UTC\" suffix in the rendered body"
    );
}

#[tokio::test]
async fn timezone_e2e_cookie_invalid_iana_falls_back_to_utc() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_invalid");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    pin_created_at(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(
            COOKIE,
            format!("access_token={}; vbn_tz=Foo%2FBar", token),
        )
        .await;

    assert_status(&response, 200);
    let body = body_without_snippet(response.text().as_str());

    // Unknown IANA name -> extractor falls back to Tz::UTC; the
    // request MUST still succeed (no 500) and render a UTC date.
    assert!(
        body.contains("2026-01-15 10:30:00 UTC"),
        "invalid IANA cookie must collapse to UTC display"
    );
}

#[tokio::test]
async fn timezone_e2e_cookie_xss_probe_does_not_round_trip() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_xss");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    pin_created_at(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    // URL-encoded `<script>alert(1)</script>` -- payload that bypasses
    // a naive cookie reader but is rejected by the
    // `parse_browser_tz` whitelist.
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(
            COOKIE,
            format!(
                "access_token={}; vbn_tz=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                token
            ),
        )
        .await;

    assert_status(&response, 200);
    let body = response.text();

    // The probe MUST be rejected: payload absent from the response.
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "XSS payload must NEVER round-trip into the response body"
    );
    // Fallback date is UTC.
    let body_no_snippet = body_without_snippet(&body);
    assert!(
        body_no_snippet.contains("2026-01-15 10:30:00 UTC"),
        "XSS-probe cookie must collapse to UTC display"
    );
}

#[tokio::test]
async fn timezone_e2e_cookie_oversized_falls_back_to_utc() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_oversized");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;
    pin_created_at(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    // 256-byte cookie, well over the 64-byte VBN_TZ_COOKIE_MAX_LEN
    // ceiling. The extractor must NOT spend cycles parsing this; it
    // collapses to UTC.
    let big = "A".repeat(256);
    let response = app
        .server
        .get("/accounts/profile")
        .add_header(
            COOKIE,
            format!("access_token={}; vbn_tz={}", token, big),
        )
        .await;

    assert_status(&response, 200);
    let body = body_without_snippet(response.text().as_str());
    assert!(
        body.contains("2026-01-15 10:30:00 UTC"),
        "oversized cookie must collapse to UTC display (DoS-resistant)"
    );
}

#[tokio::test]
async fn timezone_e2e_html_pages_carry_the_bootstrap_snippet() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let username = unique_name("tz_e2e_snippet");
    let user_id = create_simple_user(&mut conn, &username).await;
    let user_uuid = get_user_uuid(&mut conn, user_id).await;

    let token = app
        .generate_test_token(&user_uuid.to_string(), &username, false, false)
        .await;

    let response = app
        .server
        .get("/accounts/profile")
        .add_header(COOKIE, format!("access_token={}", token))
        .await;

    assert_status(&response, 200);
    let body = response.text();
    assert!(
        body.contains("/static/js/vbn-tz.js"),
        "every HTML page must reference the timezone bootstrap script"
    );
}
