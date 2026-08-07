//! E2E: admin release create, publish/unpublish/delete, member 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{
    RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED, RELEASE_STATUS_STAGING,
    Release,
};

use crate::common::{
    MultipartFile, assert_topcoat_click_handlers_are_functions,
    assert_topcoat_submit_handlers_are_functions, cleanup, create_org_with_membership, db_lock,
    get, login_cookie, post_form, post_multipart, post_multipart_with_files, status, test_config,
    test_db, test_router, test_router_with_config, unique_email, unique_slug, urlencoding_encode,
};

/// Every create now carries its binary: the portal refuses a release row
/// without one, and rolls the row back when the upload does not complete.
fn package_part(bytes: &[u8]) -> MultipartFile<'_> {
    MultipartFile {
        field: "package",
        filename: "vauban.pkg",
        content_type: "application/octet-stream",
        bytes,
    }
}

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn expected_identity(craft_version: &str) -> vcp::release_pkg::DerivedReleaseIdentity {
    // craft_test_vauban_pkg strips one leading `v` before writing the manifeste.
    vcp::release_pkg::derive_release_identity(craft_version.trim_start_matches('v'))
        .expect("craft version must derive")
}

fn count_channel_badges(html: &str) -> usize {
    html.matches("vb-badge chan-lts").count()
        + html.matches("vb-badge chan-stable").count()
        + html.matches("vb-badge chan-eol").count()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    login_cookie(router, email).await
}

#[tokio::test]
async fn e2e_admin_creates_release() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-admin");
    let slug = unique_slug("rel-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let craft_ver = format!("{}+LTS", unique_slug("v"));
    let identity = expected_identity(&craft_ver);
    let pkg = vcp::freebsd_pkg::craft_test_vauban_pkg(&craft_ver);
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-07-01"), ("notes", "FIX: test release")],
        &[package_part(&pkg)],
    )
    .await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let found = rows
            .iter()
            .find(|r| r.version == identity.version)
            .expect("created");
        assert_eq!(found.channel, "LTS");
        assert_eq!(
            found.status, RELEASE_STATUS_PUBLISHED,
            "a completed upload publishes the release"
        );
    }

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);

    cleanup(&db).await;
}

/// A non-FreeBSD blob must never open a STAGING row or helper upload.
#[tokio::test]
async fn e2e_admin_create_rejects_non_freebsd_package() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-notpkg");
    let slug = unique_slug("rel-notpkg-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v-notpkg");
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-07-01"), ("notes", "FIX: not a pkg")],
        &[package_part(b"this-is-not-a-freebsd-package")],
    )
    .await;
    assert!(status(&create).is_redirection());
    assert_eq!(
        create
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/admin/releases/new?err=not_pkg")
    );

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        assert!(
            !rows.iter().any(|r| r.version == version),
            "invalid package must create no release row"
        );
    }

    let form = get(
        &router,
        "/admin/releases/new?err=not_pkg",
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&form), StatusCode::OK);
    let html = body_text(form).await;
    assert!(
        html.contains("vb-confirm-root")
            && html.contains("aria-modal=\"true\"")
            && html.contains("Not a FreeBSD package")
            && html.contains("nothing was created")
            && html.contains("href=\"/admin/releases/new\"")
            && html.contains("Close"),
        "compose page must raise the Concept confirm modal: {html}"
    );
    assert!(
        !html.contains("style=\"color: #b5403a"),
        "not_pkg must not fall back to the inline red banner: {html}"
    );
    assert!(
        html.contains("id=\"vcp-not-pkg-open\"")
            && html.contains("id=\"vcp-release-create\"")
            && html.contains("validate-pkg"),
        "compose page must wire submit preflight + signal bridge: {html}"
    );
    assert_topcoat_submit_handlers_are_functions(&html);
    assert_topcoat_click_handlers_are_functions(&html);

    cleanup(&db).await;
}

/// Preflight validate-pkg never stages; garbage → 422, crafted pkg → 204.
#[tokio::test]
async fn e2e_admin_validate_pkg_preflight() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-valpkg");
    let slug = unique_slug("rel-valpkg-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let before = {
        let mut conn = db.clone();
        Release::all()
            .exec(&mut conn)
            .await
            .expect("releases")
            .len()
    };

    let bad = post_multipart_with_files(
        &router,
        "/admin/releases/new/validate-pkg",
        cookie.as_deref(),
        &[],
        &[package_part(b"definitely-not-a-freebsd-pkg")],
    )
    .await;
    assert_eq!(status(&bad), StatusCode::UNPROCESSABLE_ENTITY);
    let bad_body = body_text(bad).await;
    assert!(
        bad_body.contains("\"code\":\"not_pkg\"") && bad_body.contains("\"ok\":false"),
        "stable not_pkg JSON: {bad_body}"
    );

    let pkg = vcp::freebsd_pkg::craft_test_vauban_pkg("0.1.0");
    let good = post_multipart_with_files(
        &router,
        "/admin/releases/new/validate-pkg",
        cookie.as_deref(),
        &[],
        &[package_part(&pkg)],
    )
    .await;
    assert_eq!(status(&good), StatusCode::NO_CONTENT);

    {
        let mut conn = db.clone();
        let after = Release::all()
            .exec(&mut conn)
            .await
            .expect("releases")
            .len();
        assert_eq!(
            after, before,
            "validate-pkg must never create a release row"
        );
    }

    let member_email = unique_email("rel-valpkg-member");
    let member_slug = unique_slug("rel-valpkg-member");
    let (_mu, _mo) =
        create_org_with_membership(&db, &member_email, "password", &member_slug, "member").await;
    let member_cookie = login(&router, &member_email).await;
    let denied = post_multipart_with_files(
        &router,
        "/admin/releases/new/validate-pkg",
        member_cookie.as_deref(),
        &[],
        &[package_part(&pkg)],
    )
    .await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

/// A release row is worthless without its binary: the create is refused
/// outright and leaves nothing behind.
#[tokio::test]
async fn e2e_admin_create_without_package_creates_nothing() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-nopkg");
    let slug = unique_slug("rel-nopkg-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v-nopkg");
    let create = post_multipart(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-07-01"), ("notes", "FIX: no package")],
    )
    .await;
    assert!(status(&create).is_redirection());
    assert_eq!(
        create
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/admin/releases/new?err=package")
    );

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        assert!(
            !rows.iter().any(|r| r.version == version),
            "no package must mean no release row"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_releases() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-mem");
    let slug = unique_slug("rel-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let page = get(&router, "/admin/releases/new", cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::NOT_FOUND);

    let create = post_multipart(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-07-01"), ("notes", "x")],
    )
    .await;
    assert_eq!(status(&create), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_creates_org_targeted_release() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-target");
    let slug = unique_slug("rel-target-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let craft_ver = unique_slug("v-priv");
    let identity = expected_identity(&craft_ver);
    let pkg = vcp::freebsd_pkg::craft_test_vauban_pkg(&craft_ver);
    let org_id = org.id.to_string();
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[
            ("date", "2026-07-01"),
            ("notes", "FIX: private hotfix"),
            ("organization_id", &org_id),
        ],
        &[package_part(&pkg)],
    )
    .await;
    assert!(status(&create).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let found = rows
            .iter()
            .find(|r| r.version == identity.version)
            .expect("created");
        assert_eq!(found.organization_id, org.id);
        assert_eq!(found.channel, "Stable");
    }

    cleanup(&db).await;
}

/// Regression: string `selected=""` on every `<option>` made the browser keep the
/// *last* org (often wrong). Boolean `selected=(…)` omits the attr when false.
#[tokio::test]
async fn e2e_admin_releases_edit_preserves_target_org_selection() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-org-sel");
    // Names sort as Org aaa-… then Org zzz-…; a "last selected wins" bug picks zzz.
    let (_user, target) =
        create_org_with_membership(&db, &email, "password", &unique_slug("aaa-target"), "admin")
            .await;
    let decoy = crate::common::create_test_org(&db, &unique_slug("zzz-decoy")).await;
    let decoy_id = decoy.id;

    let cookie = login(&router, &email).await;
    let version = unique_slug("v-org-sel");
    let sort = vcp::release_pkg::version_sort_fields(&version);
    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: private".to_owned(),
            organization_id: target.id,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let page = get(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    let select = select_fragment(&html, "organization_id");
    assert!(
        option_is_selected(select, &target.id.to_string()),
        "saved target org must be selected; select={select}"
    );
    assert!(
        !option_is_selected(select, &decoy_id.to_string()),
        "decoy org must not be selected; select={select}"
    );
    assert_eq!(
        select.matches("selected").count(),
        1,
        "exactly one selected option; select={select}"
    );

    let form = format!(
        "channel=LTS&notes={}&organization_id={}",
        urlencoding_encode("FIX: private"),
        target.id
    );
    let save = post_form(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(status(&save).is_redirection());
    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows[0].organization_id, target.id);
    }

    cleanup(&db).await;
}

/// Same selected-attr bug as target org: Stable/EOL must not flip to EOL (last option).
#[tokio::test]
async fn e2e_admin_releases_edit_preserves_channel_selection() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-chan-sel");
    let (_user, _org) =
        create_org_with_membership(&db, &email, "password", &unique_slug("rel-chan"), "admin")
            .await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v-chan-sel");
    let sort = vcp::release_pkg::version_sort_fields(&version);
    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: version.clone(),
            channel: "Stable".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: stable".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let page = get(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    let select = select_fragment(&html, "channel");
    assert!(
        option_is_selected(select, "Stable"),
        "saved channel must be selected; select={select}"
    );
    assert!(
        !option_is_selected(select, "EOL"),
        "EOL must not be selected; select={select}"
    );
    assert!(
        !select.contains("value=\"LTS\""),
        "Stable track must not offer LTS; select={select}"
    );
    assert_eq!(
        select.matches("selected").count(),
        1,
        "exactly one selected channel; select={select}"
    );

    cleanup(&db).await;
}

fn select_fragment<'a>(html: &'a str, id: &str) -> &'a str {
    let marker = format!("id=\"{id}\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("{id} select"));
    let rest = &html[start..];
    let end = rest.find("</select>").expect("select close");
    &rest[..end]
}

fn option_is_selected(select_html: &str, value: &str) -> bool {
    let needle = format!("value=\"{value}\"");
    let Some(pos) = select_html.find(&needle) else {
        return false;
    };
    let option_start = select_html[..pos].rfind("<option").unwrap_or(0);
    let after = &select_html[option_start..];
    let option_end = after.find('>').unwrap_or(after.len());
    after[..option_end].contains("selected")
}

#[tokio::test]
async fn e2e_admin_releases_list_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-page");
    let slug = unique_slug("rel-page-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.page.{i}");
            let _ = toasty::create!(Release {
                version: version.clone(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: admin pagination".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(&version)
                    .has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let page1 = get(&router, "/admin/releases?page=1", cookie.as_deref()).await;
    assert_eq!(status(&page1), StatusCode::OK);
    let p1 = body_text(page1).await;
    // Channel badge marks each data row (thead has none). Seed + fixtures
    // mix LTS/Stable/EOL, so count all Concept channel classes.
    let rows_p1 = count_channel_badges(&p1);
    assert_eq!(rows_p1, 10, "page 1 must show 10 rows: {p1}");
    assert!(p1.contains("vb-pager"), "pager when >10: {p1}");
    assert!(
        p1.contains("vb-chip-row") && p1.contains("vb-chip"),
        "channel chips + pager row: {p1}"
    );
    assert!(
        p1.contains("vb-rel-head") && p1.contains("vb-rel-row"),
        "catalog grid on every page: {p1}"
    );
    for label in ["All", "LTS", "Stable", "EOL"] {
        assert!(p1.contains(label), "missing channel chip {label}: {p1}");
    }
    assert!(
        p1.contains("/admin/releases?channel=LTS")
            && !p1.contains("/admin/releases?channel=LTS&page="),
        "channel chip must reset page: {p1}"
    );
    assert!(
        p1.contains("/admin/releases?page=2") || p1.contains("href=\"/admin/releases?page=2\""),
        "next page link: {p1}"
    );

    let page2 = get(&router, "/admin/releases?page=2", cookie.as_deref()).await;
    assert_eq!(status(&page2), StatusCode::OK);
    let p2 = body_text(page2).await;
    let rows_p2 = count_channel_badges(&p2);
    assert!(
        (1..=10).contains(&rows_p2),
        "page 2 row count: {rows_p2} in {p2}"
    );
    assert!(
        p2.contains("vb-rel-head") && p2.contains("vb-rel-row"),
        "page 2 must keep the same catalog grid: {p2}"
    );
    assert!(
        p2.contains("v99.page.") || p1.contains("v99.page."),
        "pagination fixtures appear across pages: p1={p1} p2={p2}"
    );

    cleanup(&db).await;
}

/// Channel chips filter SQL-side like `/{org}/builds`: Stable hides LTS rows,
/// and pager links keep the active channel without sticky `page` on chips.
#[tokio::test]
async fn e2e_admin_releases_channel_filter_hides_other_channels() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-chan");
    let slug = unique_slug("rel-chan-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let lts = "v99.chan.lts";
    let stable = "v99.chan.stable";
    let eol = "v99.chan.eol";
    {
        let mut conn = db.clone();
        for (version, channel) in [(lts, "LTS"), (stable, "Stable"), (eol, "EOL")] {
            let sort = vcp::release_pkg::version_sort_fields(version);
            let _ = toasty::create!(Release {
                version: version.to_owned(),
                channel: channel.to_owned(),
                released_on: "2026-08-01".to_owned(),
                status: RELEASE_STATUS_PUBLISHED.to_owned(),
                notes: "FIX: channel filter".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: sort.v_major,
                v_minor: sort.v_minor,
                v_patch: sort.v_patch,
                has_client_suffix: sort.has_client_suffix,
                client_suffix: sort.client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let all = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&all), StatusCode::OK);
    let all_html = body_text(all).await;
    assert!(all_html.contains(lts) && all_html.contains(stable) && all_html.contains(eol));

    let filtered = get(&router, "/admin/releases?channel=Stable", cookie.as_deref()).await;
    assert_eq!(status(&filtered), StatusCode::OK);
    let html = body_text(filtered).await;
    assert!(
        html.contains(stable),
        "Stable filter must keep Stable: {html}"
    );
    assert!(
        !html.contains(lts) && !html.contains(eol),
        "Stable filter must hide LTS/EOL: {html}"
    );
    assert!(
        html.contains("vb-chip active") || html.contains("class=\"vb-chip active\""),
        "active channel chip: {html}"
    );
    assert!(
        html.contains("/admin/releases?channel=LTS") && !html.contains("channel=LTS&page="),
        "chip hrefs omit page: {html}"
    );

    // Enough Stable rows to force a pager that must keep `channel=Stable`.
    {
        let mut conn = db.clone();
        for i in 0..11u32 {
            let version = format!("v99.chan.stable.page.{i}");
            let sort = vcp::release_pkg::version_sort_fields(&version);
            let _ = toasty::create!(Release {
                version,
                channel: "Stable".to_owned(),
                released_on: "2026-08-01".to_owned(),
                status: RELEASE_STATUS_PUBLISHED.to_owned(),
                notes: "FIX: channel page".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: sort.v_major,
                v_minor: sort.v_minor,
                v_patch: sort.v_patch,
                has_client_suffix: sort.has_client_suffix,
                client_suffix: sort.client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("stable page fixture");
        }
    }
    let paged = get(
        &router,
        "/admin/releases?channel=Stable&page=2",
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&paged), StatusCode::OK);
    let paged_html = body_text(paged).await;
    assert!(
        paged_html.contains("channel=Stable"),
        "pager under a channel filter must keep channel: {paged_html}"
    );
    assert!(
        !paged_html.contains(lts),
        "paged Stable view must still hide LTS: {paged_html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_list_shows_status_badges_and_actions() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-ui");
    let slug = unique_slug("rel-ui-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    {
        let mut conn = db.clone();
        let _ = toasty::create!(Release {
            version: "v95.ui.1".to_owned(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: ui".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields("v95.ui.1").v_major,
            v_minor: vcp::release_pkg::version_sort_fields("v95.ui.1").v_minor,
            v_patch: vcp::release_pkg::version_sort_fields("v95.ui.1").v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields("v95.ui.1").has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields("v95.ui.1").client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release");
    }

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(
        html.contains("vb-badge status-published"),
        "PUBLISHED badge: {html}"
    );
    assert!(html.contains("vb-row-actions"), "row actions: {html}");
    assert!(html.contains("+ New release"), "CTA: {html}");
    assert!(html.contains("Unpublish"), "toggle: {html}");
    assert!(html.contains("delete="), "delete query: {html}");
    assert!(
        html.contains("/admin/releases/") && html.contains(">Edit<"),
        "Edit by id: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_order_stable_across_unpublish() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-order");
    let slug = unique_slug("rel-order-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    // High unique cores so fixtures stay on page 1 above the seed catalog.
    // Insert out of version order; list must still show numeric desc + client
    // suffix above the plain twin (…-acme1 before plain …).
    let hi = "v93.order.2";
    let mid = "v93.order.1";
    let suffix = "v93.order.0-acme1";
    let plain = "v93.order.0";
    let mut mid_id = 0u64;
    {
        let mut conn = db.clone();
        for ver in [plain, mid, suffix, hi] {
            let created = toasty::create!(Release {
                version: ver.to_owned(),
                channel: "LTS".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: RELEASE_STATUS_PUBLISHED.to_owned(),
                notes: "FIX: order".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(ver).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(ver).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(ver).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(ver).has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(ver).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
            if ver == mid {
                mid_id = created.id;
            }
        }
    }

    let before = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&before), StatusCode::OK);
    let html_before = body_text(before).await;
    let pos = |html: &str, needle: &str| {
        html.find(&format!(">{needle}<"))
            .unwrap_or_else(|| panic!("missing {needle} in {html}"))
    };
    assert!(
        pos(&html_before, hi) < pos(&html_before, mid)
            && pos(&html_before, mid) < pos(&html_before, suffix)
            && pos(&html_before, suffix) < pos(&html_before, plain),
        "version order before unpublish: {html_before}"
    );

    let unpub = post_form(
        &router,
        &format!("/admin/releases/{mid_id}/unpublish"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&unpub).is_redirection());

    let after = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&after), StatusCode::OK);
    let html_after = body_text(after).await;
    assert!(
        pos(&html_after, hi) < pos(&html_after, mid)
            && pos(&html_after, mid) < pos(&html_after, suffix)
            && pos(&html_after, suffix) < pos(&html_after, plain),
        "version order must not change after unpublish: {html_after}"
    );
    assert!(
        html_after.contains("vb-badge status-hidden"),
        "unpublished row still listed with HIDDEN badge: {html_after}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_unpublish_hides_from_client_builds_publish_restores() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let staff_email = unique_email("rel-vis-staff");
    let (_staff, _home) = create_org_with_membership(
        &db,
        &staff_email,
        "password",
        &unique_slug("rel-vis-home"),
        "admin",
    )
    .await;

    let client_email = unique_email("rel-vis-client");
    let client_slug = unique_slug("rel-vis-client");
    let (_client, _client_org) =
        create_org_with_membership(&db, &client_email, "password", &client_slug, "member").await;

    let version = "v95.vis.0".to_owned();
    let release_id = {
        let mut conn = db.clone();
        let id = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: visibility toggle".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id;
        // Publish requires a storage_objects row (digest SoT).
        vcp::storage::upsert_release_object(
            &mut conn,
            id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_048_576,
        )
        .await
        .expect("storage object");
        id
    };

    let staff_cookie = login(&router, &staff_email).await;
    let client_cookie = login(&router, &client_email).await;

    let visible = get(
        &router,
        &format!("/{client_slug}/builds"),
        client_cookie.as_deref(),
    )
    .await;
    assert!(status(&visible).is_success());
    let body = body_text(visible).await;
    assert!(body.contains(&version), "client sees published: {body}");

    let unpub = post_form(
        &router,
        &format!("/admin/releases/{release_id}/unpublish"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&unpub).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows[0].status, RELEASE_STATUS_HIDDEN);
    }

    let hidden = get(
        &router,
        &format!("/{client_slug}/builds"),
        client_cookie.as_deref(),
    )
    .await;
    assert!(status(&hidden).is_success());
    let body = body_text(hidden).await;
    assert!(
        !body.contains(&version),
        "client must not see HIDDEN: {body}"
    );

    let staff_builds = get(&router, "/vauban/builds", staff_cookie.as_deref()).await;
    assert!(status(&staff_builds).is_success());
    let staff_body = body_text(staff_builds).await;
    assert!(
        !staff_body.contains(&version),
        "vauban builds must hide HIDDEN too: {staff_body}"
    );

    let staff_home = get(&router, "/vauban", staff_cookie.as_deref()).await;
    assert!(status(&staff_home).is_success());
    let home_body = body_text(staff_home).await;
    assert!(
        !home_body.contains(&version),
        "dashboard latest-build must not show HIDDEN: {home_body}"
    );

    let pub_again = post_form(
        &router,
        &format!("/admin/releases/{release_id}/publish"),
        staff_cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&pub_again).is_redirection());

    let restored = get(
        &router,
        &format!("/{client_slug}/builds"),
        client_cookie.as_deref(),
    )
    .await;
    assert!(status(&restored).is_success());
    let body = body_text(restored).await;
    assert!(body.contains(&version), "client sees after publish: {body}");

    let staff_home2 = get(&router, "/vauban", staff_cookie.as_deref()).await;
    assert!(status(&staff_home2).is_success());
    let home2 = body_text(staff_home2).await;
    assert!(
        home2.contains(&version),
        "dashboard shows latest after re-publish: {home2}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_delete_with_confirm() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-del");
    let slug = unique_slug("rel-del-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = "v95.del.0".to_owned();
    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: version.clone(),
            channel: "Stable".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: delete me".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields(&version).v_major,
            v_minor: vcp::release_pkg::version_sort_fields(&version).v_minor,
            v_patch: vcp::release_pkg::version_sort_fields(&version).v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields(&version).has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields(&version).client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let bad = post_form(
        &router,
        &format!("/admin/releases/{release_id}/delete"),
        cookie.as_deref(),
        "confirm=nope",
    )
    .await;
    assert!(status(&bad).is_redirection());
    let bad_loc = bad
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        bad_loc.contains(&format!("delete={release_id}")),
        "bad confirm should redisplay modal: {bad_loc}"
    );
    assert!(
        bad_loc.contains("err=confirm"),
        "expected err=confirm: {bad_loc}"
    );

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("still present");
        assert_eq!(rows.len(), 1, "wrong confirm must not delete");
    }

    let confirm_page = get(
        &router,
        &format!("/admin/releases?delete={release_id}&err=confirm"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&confirm_page), StatusCode::OK);
    let confirm_html = body_text(confirm_page).await;
    assert!(
        confirm_html.contains("Delete this release?")
            || confirm_html.contains("Delete permanently"),
        "confirm modal missing: {confirm_html}"
    );

    let ok = post_form(
        &router,
        &format!("/admin/releases/{release_id}/delete"),
        cookie.as_deref(),
        "confirm=delete",
    )
    .await;
    assert!(status(&ok).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert!(rows.is_empty(), "release must be deleted");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_releases_mutations() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-mem-mut");
    let slug = unique_slug("rel-mem-mut-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: "v95.mem.0".to_owned(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: member denied".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields("v95.mem.0").v_major,
            v_minor: vcp::release_pkg::version_sort_fields("v95.mem.0").v_minor,
            v_patch: vcp::release_pkg::version_sort_fields("v95.mem.0").v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields("v95.mem.0").has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields("v95.mem.0").client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    for path in [
        format!("/admin/releases/{release_id}"),
        format!("/admin/releases/{release_id}/publish"),
        format!("/admin/releases/{release_id}/unpublish"),
        format!("/admin/releases/{release_id}/delete"),
    ] {
        let resp = if path.ends_with("/delete") {
            post_form(&router, &path, cookie.as_deref(), "confirm=delete").await
        } else if path.contains("/publish") || path.contains("/unpublish") {
            post_form(&router, &path, cookie.as_deref(), "").await
        } else {
            get(&router, &path, cookie.as_deref()).await
        };
        assert_eq!(
            status(&resp),
            StatusCode::NOT_FOUND,
            "member must 404 on {path}"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_edit_updates_row() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-edit");
    let slug = unique_slug("rel-edit-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: "v95.edit.0".to_owned(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: before".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: vcp::release_pkg::version_sort_fields("v95.edit.0").v_major,
            v_minor: vcp::release_pkg::version_sort_fields("v95.edit.0").v_minor,
            v_patch: vcp::release_pkg::version_sort_fields("v95.edit.0").v_patch,
            has_client_suffix: vcp::release_pkg::version_sort_fields("v95.edit.0")
                .has_client_suffix,
            client_suffix: vcp::release_pkg::version_sort_fields("v95.edit.0").client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let page = get(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("Edit v95.edit.0")
            && !html.contains("id=\"version\"")
            && !html.contains("id=\"date\"")
            && html.contains("id=\"channel\"")
            && html.contains("id=\"organization_id\"")
            && html.contains("id=\"notes\""),
        "edit form: channel/org/notes only: {html}"
    );

    // LTS track may only move to EOL (not Stable); version gains +LTS so the
    // download basename stays LTS after EOL. Date is immutable.
    let form = format!(
        "channel=EOL&notes={}&organization_id=",
        urlencoding_encode("FEAT: after")
    );
    let save = post_form(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(status(&save).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows[0].version, "v95.edit.0+LTS");
        assert_eq!(rows[0].channel, "EOL");
        assert_eq!(rows[0].notes, "FEAT: after");
        assert_eq!(rows[0].released_on, "2026-07-01");
        assert_eq!(rows[0].v_major, 95);
        assert_eq!(rows[0].v_minor, 0);
        assert_eq!(rows[0].v_patch, 0);
    }

    cleanup(&db).await;
}

/// VERSION column and delete overlay must hide the storage `+LTS` marker.
#[tokio::test]
async fn e2e_admin_releases_list_strips_lts_marker_from_version() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-disp");
    let (_user, _org) =
        create_org_with_membership(&db, &email, "password", &unique_slug("rel-disp"), "admin")
            .await;
    let cookie = login(&router, &email).await;

    let stored = format!("{}+LTS", unique_slug("v96.disp"));
    let display = vcp::release_pkg::version_for_display(&stored).to_owned();
    let sort = vcp::release_pkg::version_sort_fields(&stored);
    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: stored.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-08-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: display".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(
        html.contains(&display) && !html.contains(&stored),
        "VERSION column must strip +LTS: display={display} stored={stored} html={html}"
    );

    let del = get(
        &router,
        &format!("/admin/releases?delete={release_id}"),
        cookie.as_deref(),
    )
    .await;
    let del_html = body_text(del).await;
    assert!(
        del_html.contains(&display) && !del_html.contains(&stored),
        "delete overlay must strip +LTS: {del_html}"
    );

    cleanup(&db).await;
}

/// Forced LTS→Stable POST must not mutate the row (track is sealed).
#[tokio::test]
async fn e2e_admin_releases_edit_rejects_lts_to_stable() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-reject");
    let (_user, _org) =
        create_org_with_membership(&db, &email, "password", &unique_slug("rel-reject"), "admin")
            .await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v96.reject");
    let sort = vcp::release_pkg::version_sort_fields(&version);
    let release_id = {
        let mut conn = db.clone();
        toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-08-01".to_owned(),
            status: RELEASE_STATUS_PUBLISHED.to_owned(),
            notes: "FIX: stay lts".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("release")
        .id
    };

    let save = post_form(
        &router,
        &format!("/admin/releases/{release_id}"),
        cookie.as_deref(),
        &format!(
            "channel=Stable&notes={}&organization_id=",
            urlencoding_encode("FIX: should not apply")
        ),
    )
    .await;
    assert!(status(&save).is_redirection());
    let expected_loc = format!("/admin/releases/{release_id}");
    assert_eq!(
        save.headers().get("location").and_then(|v| v.to_str().ok()),
        Some(expected_loc.as_str())
    );

    {
        let mut conn = db.clone();
        let rows = Release::all()
            .filter(Release::fields().id().eq(release_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows[0].channel, "LTS");
        assert_eq!(rows[0].notes, "FIX: stay lts");
        assert_eq!(rows[0].version, version);
    }

    cleanup(&db).await;
}

/// Manifeste Version that cannot derive an identity refuses create (no row).
#[tokio::test]
async fn e2e_admin_create_rejects_unusable_manifeste_version() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-ident");
    let (_user, _org) =
        create_org_with_membership(&db, &email, "password", &unique_slug("rel-ident"), "admin")
            .await;
    let cookie = login(&router, &email).await;

    // Valid FreeBSD package whose Version is only `+LTS` — inspect ok, identity no.
    let pkg = vcp::freebsd_pkg::craft_minimal_pkg(&vcp::freebsd_pkg::FreeBsdPkgInfo {
        name: "vauban".into(),
        version: "+LTS".into(),
        origin: "security/vauban".into(),
        architecture: "FreeBSD:15:amd64".into(),
        prefix: "/usr/local".into(),
        categories: vec!["security".into()],
        licenses: vec!["BSD2CLAUSE".into()],
        maintainer: "none@freebsd.org".into(),
        www: "https://vauban.sh".into(),
        comment: "bad version".into(),
        shlibs_required: vec![],
        freebsd_version: Some("1501000".into()),
        flatsize_bytes: Some(1),
    });
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-08-01"), ("notes", "FIX: identity")],
        &[package_part(&pkg)],
    )
    .await;
    assert!(status(&create).is_redirection());
    assert_eq!(
        create
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/admin/releases/new?err=identity")
    );
    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        assert!(
            !rows.iter().any(|r| r.notes.contains("identity")),
            "unusable manifeste Version must create no row"
        );
    }

    let form = get(
        &router,
        "/admin/releases/new?err=identity",
        cookie.as_deref(),
    )
    .await;
    let html = body_text(form).await;
    assert!(
        html.contains("no usable Version") || html.contains("manifeste"),
        "identity banner: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_releases_sql_semver_order_and_sort_columns() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adm-semver");
    let slug = unique_slug("adm-semver");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    // High majors stay on page 1 even if a leftover demo catalog is present
    // (`cleanup` preserves seed GA versions such as v1.0.2).
    let versions = ["v99.9.0", "v99.10.0", "v99.9.0-acme"];
    {
        let mut conn = db.clone();
        for version in versions {
            let _ = toasty::create!(Release {
                version: version.to_owned(),
                channel: "Stable".to_owned(),
                released_on: "2026-07-01".to_owned(),
                status: "PUBLISHED".to_owned(),
                notes: "FIX: admin order".to_owned(),
                organization_id: RELEASE_GA_ORG_ID,
                v_major: vcp::release_pkg::version_sort_fields(version).v_major,
                v_minor: vcp::release_pkg::version_sort_fields(version).v_minor,
                v_patch: vcp::release_pkg::version_sort_fields(version).v_patch,
                has_client_suffix: vcp::release_pkg::version_sort_fields(version).has_client_suffix,
                client_suffix: vcp::release_pkg::version_sort_fields(version).client_suffix,
            })
            .exec(&mut conn)
            .await
            .expect("release");
        }
    }

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    let i10 = html.find("v99.10.0").expect("v99.10.0");
    let i_acme = html.find("v99.9.0-acme").expect("acme");
    let i_plain = html
        .find(">v99.9.0<")
        .expect("plain v99.9.0 cell (not substring of -acme)");
    assert!(i10 < i_acme && i_acme < i_plain, "SQL semver order: {html}");

    cleanup(&db).await;
}

/// Abandoning the WebAuthn signature must publish nothing: the staged row is
/// invisible while the ceremony is in flight and disappears on cancel.
#[tokio::test]
async fn e2e_publish_cancelled_at_signature_rolls_everything_back() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = test_config().await;
    cfg.storage.webauthn_required = true;
    let router = test_router_with_config(cfg).await;

    let email = unique_email("rel-cancel");
    let slug = unique_slug("rel-cancel-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let craft_ver = unique_slug("v-cancel");
    let identity = expected_identity(&craft_ver);
    let pkg = vcp::freebsd_pkg::craft_test_vauban_pkg(&craft_ver);
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-08-01"), ("notes", "FIX: cancelled publish")],
        &[package_part(&pkg)],
    )
    .await;
    assert!(status(&create).is_redirection());
    let location = create
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("redirect")
        .to_owned();
    let token = location
        .strip_prefix("/admin/releases/confirm?token=")
        .expect("confirm redirect")
        .to_owned();

    // In flight: the row exists only to key the blob, and stays out of sight.
    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let staged = rows
            .iter()
            .find(|r| r.version == identity.version)
            .expect("staged");
        assert_eq!(staged.status, RELEASE_STATUS_STAGING);
    }
    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(
        !html.contains(&identity.version),
        "staged release must not show in the release manager: {html}"
    );

    let confirm = get(&router, &location, cookie.as_deref()).await;
    assert_eq!(status(&confirm), StatusCode::OK);
    let confirm_html = body_text(confirm).await;
    assert!(
        confirm_html.contains("/admin/releases/confirm/cancel")
            && confirm_html.contains("Cancel publish"),
        "confirm page must offer an explicit cancel: {confirm_html}"
    );
    assert!(
        confirm_html.contains("id=\"vcp-pkg-info\"")
            && confirm_html.contains("Name           : vauban")
            && confirm_html.contains("Architecture   : FreeBSD:15:amd64")
            && confirm_html.contains("Origin         : security/vauban"),
        "confirm page must show FreeBSD package metadata: {confirm_html}"
    );

    let cancel = post_form(
        &router,
        "/admin/releases/confirm/cancel",
        cookie.as_deref(),
        &format!("token={}", urlencoding_encode(&token)),
    )
    .await;
    assert!(status(&cancel).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        assert!(
            !rows.iter().any(|r| r.version == identity.version),
            "cancelled publish must leave no release row"
        );
    }

    cleanup(&db).await;
}

/// Portal restarted mid-ceremony: no reservation survives, so the staged row
/// is an orphan and the next Release manager visit rolls it back.
#[tokio::test]
async fn e2e_orphan_staged_release_is_swept_from_release_manager() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("rel-orphan");
    let slug = unique_slug("rel-orphan-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let version = unique_slug("v-orphan");
    {
        let mut conn = db.clone();
        let sort = vcp::release_pkg::version_sort_fields(&version);
        let _ = toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-08-01".to_owned(),
            status: RELEASE_STATUS_STAGING.to_owned(),
            notes: "FIX: orphan".to_owned(),
            organization_id: RELEASE_GA_ORG_ID,
            v_major: sort.v_major,
            v_minor: sort.v_minor,
            v_patch: sort.v_patch,
            has_client_suffix: sort.has_client_suffix,
            client_suffix: sort.client_suffix,
        })
        .exec(&mut conn)
        .await
        .expect("staged release");
    }

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(!html.contains(&version), "orphan must not be listed");

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        assert!(
            !rows.iter().any(|r| r.version == version),
            "orphan staged row must be swept"
        );
    }

    cleanup(&db).await;
}

/// A staged release is not an admin object: edit / publish / delete must 404
/// instead of letting an id guess promote a half-uploaded build.
#[tokio::test]
async fn e2e_staged_release_is_not_reachable_by_id() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = test_config().await;
    cfg.storage.webauthn_required = true;
    let router = test_router_with_config(cfg).await;

    let email = unique_email("rel-staged-id");
    let slug = unique_slug("rel-staged-id-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let craft_ver = unique_slug("v-staged-id");
    let identity = expected_identity(&craft_ver);
    let pkg = vcp::freebsd_pkg::craft_test_vauban_pkg(&craft_ver);
    let create = post_multipart_with_files(
        &router,
        "/admin/releases/new",
        cookie.as_deref(),
        &[("date", "2026-08-01"), ("notes", "FIX: staged id")],
        &[package_part(&pkg)],
    )
    .await;
    assert!(status(&create).is_redirection());

    let staged_id = {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        rows.iter()
            .find(|r| r.version == identity.version)
            .expect("staged")
            .id
    };

    let edit = get(
        &router,
        &format!("/admin/releases/{staged_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&edit), StatusCode::NOT_FOUND);

    let publish = post_form(
        &router,
        &format!("/admin/releases/{staged_id}/publish"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert_eq!(status(&publish), StatusCode::NOT_FOUND);

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let staged = rows
            .iter()
            .find(|r| r.id == staged_id)
            .expect("still staged");
        assert_eq!(staged.status, RELEASE_STATUS_STAGING);
    }

    cleanup(&db).await;
}
