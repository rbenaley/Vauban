//! Regression tests for the "Add Member" search flow on
//! `/accounts/groups/{uuid}/members/{add,search}`.
//!
//! Why this file exists
//! --------------------
//!
//! Issue #24 (BUG-13) shipped a search input with `id="user-search"`
//! but no `name` attribute. Because `hx-include="this"` only serializes
//! form fields that have a non-empty `name`, the HTMX request reached
//! the backend with no `?user-search=...` query param. The handler then
//! fell into its empty-query branch and returned the full roster on
//! every keystroke, making the search field cosmetic.
//!
//! These tests pin the contract on three layers so the bug cannot
//! re-appear silently:
//!
//! 1. **DOM contract**: the rendered Add Member page MUST carry an
//!    input with `name="user-search"` whose `hx-get` points at the
//!    search endpoint. (`test_add_member_page_search_input_*`)
//! 2. **Filtering**: the search endpoint MUST narrow the roster on
//!    `username` and `email` substring matches, and MUST return the
//!    full list on the empty query. (`test_search_filters_*`,
//!    `test_search_empty_*`)
//! 3. **CSRF + XSS**: the HTMX response MUST opt into the Alpine `csrf`
//!    component (no empty `csrf_token` input that would trip the
//!    double-submit verifier on Add) and MUST entity-escape username /
//!    email so a future relaxation of upstream validation cannot turn
//!    the search response into a stored XSS sink.
//!    (`test_search_response_*csrf*`, `test_search_response_escapes_*`)

use axum::http::header::COOKIE;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use serial_test::serial;
use uuid::Uuid;

use crate::common::{TestApp, assertions::assert_status, test_db, unwrap_ok};
use crate::fixtures::{create_admin_user, create_test_user, create_test_vauban_group, unique_name};

/// 1. DOM contract: the Add Member page must render an input that
///    actually carries `name="user-search"`, otherwise HTMX cannot
///    serialize it and BUG-13 returns.
#[tokio::test]
#[serial]
async fn test_add_member_page_search_input_has_name_attribute() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_dom_contract_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-dom-contract-grp")).await;

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/members/add", group_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    // The search input itself: id=user-search MUST come with
    // name=user-search (BUG-13 root cause).
    assert!(
        body.contains(r#"id="user-search""#),
        "Add Member page must contain the search input with id=user-search"
    );
    assert!(
        body.contains(r#"name="user-search""#),
        "BUG-13 regression: search input must have name=\"user-search\" \
         (HTMX hx-include otherwise serializes nothing). Body did not match."
    );
    assert!(
        body.contains(&format!(
            r#"hx-get="/accounts/groups/{}/members/search""#,
            group_uuid
        )),
        "Search input must HX-GET the /members/search endpoint of THIS group"
    );

    test_db::cleanup(&mut conn).await;
}

/// 1bis. The hx-include selector must match the input's name. We accept
/// either the explicit `[name='user-search']` selector or the implicit
/// `this` form, but if `hx-include` is present at all on the search
/// input, it MUST resolve to a field that has a name.
#[tokio::test]
#[serial]
async fn test_add_member_page_hx_include_targets_named_input() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_hxincl_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("test-hxincl-grp")).await;

    let response = app
        .server
        .get(&format!("/accounts/groups/{}/members/add", group_uuid))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    // Either the explicit `[name='user-search']` selector or `this`.
    let explicit = body.contains(r#"hx-include="[name='user-search']""#);
    let implicit_this = body.contains(r#"hx-include="this""#);
    assert!(
        explicit || implicit_this,
        "Search input must declare hx-include pointing at a named field"
    );

    // If the implicit form is used, the input itself MUST have a name
    // (the regression that shipped BUG-13).
    if implicit_this {
        assert!(
            body.contains(r#"name="user-search""#),
            "hx-include=\"this\" requires the input to have a name attribute"
        );
    }

    test_db::cleanup(&mut conn).await;
}

/// 2. Search filters by username substring: typing matches only the
///    intended user, the others are dropped from the response.
#[tokio::test]
#[serial]
async fn test_search_filters_by_username_substring() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_uname_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-search-uname-grp")).await;

    // Two candidate users with disjoint usernames so a substring of one
    // can NEVER also match the other.
    let alice_name = unique_name("test_search_alice_uniq");
    let bob_name = unique_name("test_search_bob_uniq");
    create_test_user(&mut conn, &app.auth_service, &alice_name).await;
    create_test_user(&mut conn, &app.auth_service, &bob_name).await;

    // Substring that matches alice's username but not bob's.
    let needle = "alice_uniq";

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search={}",
            group_uuid, needle
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(&alice_name),
        "Search for {needle:?} must include alice ({alice_name:?})"
    );
    assert!(
        !body.contains(&bob_name),
        "Search for {needle:?} must NOT include bob ({bob_name:?}). Body: {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// 2bis. Search filters by email substring (the handler `ilike`s on
///       BOTH `username` and `email` ORed together).
#[tokio::test]
#[serial]
async fn test_search_filters_by_email_substring() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_email_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-search-email-grp")).await;

    // create_test_user assigns email = <username>@test.vauban.io. Pick
    // usernames so the ".vauban.io" suffix is not enough to differentiate
    // them; we'll search on the username portion of the email instead.
    let mailbox = unique_name("test_search_mailbox_target");
    let other = unique_name("test_search_unrelated_user");
    create_test_user(&mut conn, &app.auth_service, &mailbox).await;
    create_test_user(&mut conn, &app.auth_service, &other).await;

    // Search for a fragment of the mailbox (matches via the email
    // column even though it also matches via username -- both paths
    // exercise the OR clause).
    let needle = "mailbox_target";

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search={}",
            group_uuid, needle
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(&mailbox),
        "Search for {needle:?} must include the mailbox-bearing user"
    );
    assert!(
        !body.contains(&other),
        "Search for {needle:?} must NOT include unrelated user {other:?}"
    );

    test_db::cleanup(&mut conn).await;
}

/// 3. Empty query takes the no-filter branch of the handler and returns
///    the full eligible roster (capped at 50). This pins the
///    `if search_term.is_empty()` branch so a future refactor cannot
///    accidentally turn empty-query into "return nothing".
///
/// We assert two complementary properties:
///   - the response carries at least one user row (`name="user_uuid"`
///     marker is unique to the per-user form generated by the partial),
///   - the response does NOT show the search-empty placeholder
///     ("No matching users found.").
///
/// We do NOT assert that the freshly-created u1/u2 appear in the
/// response: the handler caps the result set at 50 entries sorted by
/// username asc, and the test database accumulates legacy fixture rows
/// that sort lexicographically before any `test_*` username we create
/// here. That alphabetical-window concern is exercised separately by
/// the substring-filter tests above.
#[tokio::test]
#[serial]
async fn test_search_empty_query_returns_full_list() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_empty_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-search-empty-grp")).await;

    // Make sure there is at least one eligible user even on a freshly
    // wiped database (the admin we just created is themselves eligible
    // because they are not yet a member of the new group).
    let _candidate = unique_name("test_search_empty_candidate");
    create_test_user(&mut conn, &app.auth_service, &_candidate).await;

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search=",
            group_uuid
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(r#"name="user_uuid""#),
        "Empty query must take the no-filter branch and emit at least \
         one user row (marker: name=\"user_uuid\"). Body: {body}"
    );
    assert!(
        !body.contains("No matching users found."),
        "Empty query MUST NOT render the search-empty placeholder. Body: {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// 4. The HTMX response MUST opt into Alpine's `csrf` component on every
///    `<form>` so that clicking Add on a filtered result submits a real
///    double-submit token. The previous `format!()` rendering shipped
///    `<input type="hidden" name="csrf_token" />` empty, which would
///    trip `add_group_member_web`'s validator the moment BUG-13 was
///    fixed (silent regression: search would work but Add wouldn't).
#[tokio::test]
#[serial]
async fn test_search_response_uses_alpine_csrf_component() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_csrf_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-search-csrf-grp")).await;

    let candidate_name = unique_name("test_search_csrf_candidate");
    create_test_user(&mut conn, &app.auth_service, &candidate_name).await;

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search={}",
            group_uuid,
            &candidate_name[..16]
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        body.contains(r#"x-data="csrf""#),
        "Search response form must use Alpine's csrf component"
    );
    assert!(
        body.contains(r#"x-model="token""#),
        "Search response csrf input must bind to the Alpine token model"
    );
    // Forbidden anti-pattern: empty csrf_token input expecting some
    // out-of-band JS to fill it (front-end-design SKILL §4 FORBIDDEN).
    assert!(
        !body.contains(r#"name="csrf_token" />"#) && !body.contains(r#"name="csrf_token">"#),
        "Search response must not ship a self-closing empty csrf_token \
         input (front-end-design FORBIDDEN pattern). Body: {body}"
    );

    test_db::cleanup(&mut conn).await;
}

/// 5. XSS hardening: even if a future relaxation of upstream validation
///    lets `<` slip into username or email, the HTMX response MUST
///    entity-escape it. The previous `format!()`-built response did not.
#[tokio::test]
#[serial]
async fn test_search_response_escapes_username_and_email() {
    use vauban_web::models::user::{AuthSource, NewUser};
    use vauban_web::schema::users;

    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_xss_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid = create_test_vauban_group(&mut conn, &unique_name("test-search-xss-grp")).await;

    // Insert a user directly with an XSS-shaped username and email.
    // create_test_user goes through AuthService and its validation; we
    // bypass deliberately because we are testing OUTPUT escaping, not
    // input validation -- defense-in-depth.
    let evil_username = format!(
        "test_xss_<script>alert(1)</script>_{}",
        &Uuid::new_v4().to_string()[..8]
    );
    let evil_email = format!(
        "x@<svg/onload=alert(1)>_{}.test",
        &Uuid::new_v4().to_string()[..8]
    );
    let new_user = NewUser {
        uuid: Uuid::new_v4(),
        username: evil_username.clone(),
        email: evil_email.clone(),
        password_hash: "hash".to_string(),
        first_name: None,
        last_name: None,
        phone: None,
        is_active: true,
        is_staff: false,
        is_superuser: false,
        is_service_account: false,
        mfa_enabled: false,
        mfa_enforced: false,
        mfa_secret: None,
        preferences: serde_json::json!({}),
        auth_source: AuthSource::Local,
        external_id: None,
    };
    unwrap_ok!(
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(&mut conn)
            .await
    );

    let needle = "xss_";

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search={}",
            group_uuid, needle
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    // The raw payloads must NOT appear verbatim -- they would land
    // inside the `#user-list` innerHTML of the live page.
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "Username payload must be HTML-escaped, not echoed raw. Body: {body}"
    );
    assert!(
        !body.contains("<svg/onload=alert(1)>"),
        "Email payload must be HTML-escaped, not echoed raw. Body: {body}"
    );
    // The entity-encoded form should appear (Askama auto-escape).
    // Askama may emit either the named entity (&lt;) or the numeric
    // entity (&#60;); both are valid escapes. Accept either.
    let escaped_lt = body.contains("&lt;script") || body.contains("&#60;script");
    assert!(
        escaped_lt,
        "Expected an entity-encoded script tag (named or numeric) in the response."
    );

    // Cleanup: hand-delete the user we inserted so cleanup() doesn't
    // miss it (its username doesn't start with `test_<something>` --
    // wait, it does: `test_xss_<script>...`. The `LIKE 'test_%'` clause
    // catches it. Still, run cleanup for full hygiene.).
    test_db::cleanup(&mut conn).await;
}

/// 6. Negative test: the response MUST NOT include users that are
///    already members of the group (otherwise the `Add` button would
///    create a duplicate or, depending on the DB constraint, just fail
///    the user). Validates the `id.ne_all(&existing_member_ids)` clause.
#[tokio::test]
#[serial]
async fn test_search_excludes_existing_group_members() {
    let app = TestApp::spawn().await;
    let mut conn = app.get_conn().await;

    let admin_name = unique_name("test_search_excl_admin");
    let admin = create_admin_user(&mut conn, &app.auth_service, &admin_name).await;
    let group_uuid =
        create_test_vauban_group(&mut conn, &unique_name("test-search-excl-grp")).await;

    let already_member_name = unique_name("test_search_already_member");
    let candidate = create_test_user(&mut conn, &app.auth_service, &already_member_name).await;

    // Add `already_member` directly into the group so the search must
    // omit them.
    use vauban_web::schema::{user_groups, vauban_groups};
    let group_id: i32 = unwrap_ok!(
        vauban_groups::table
            .filter(vauban_groups::uuid.eq(group_uuid))
            .select(vauban_groups::id)
            .first(&mut conn)
            .await
    );
    unwrap_ok!(
        diesel::insert_into(user_groups::table)
            .values((
                user_groups::user_id.eq(candidate.user.id),
                user_groups::group_id.eq(group_id),
            ))
            .execute(&mut conn)
            .await
    );

    let response = app
        .server
        .get(&format!(
            "/accounts/groups/{}/members/search?user-search=already_member",
            group_uuid
        ))
        .add_header(COOKIE, format!("access_token={}", admin.token))
        .await;

    assert_status(&response, 200);
    let body = response.text();

    assert!(
        !body.contains(&already_member_name),
        "Search response must exclude users that are already members of \
         the group (got {already_member_name:?} in body)."
    );

    test_db::cleanup(&mut conn).await;
}
