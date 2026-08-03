//! E2E: admin release create, publish/unpublish/delete, member 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{RELEASE_GA_ORG_ID, RELEASE_STATUS_HIDDEN, RELEASE_STATUS_PUBLISHED, Release};

use crate::common::{
    cleanup, create_org_with_membership, db_lock, get, login_cookie, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
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

    let version = unique_slug("v");
    let form = format!(
        "version={}&channel=LTS&date=2026-07-01&notes={}",
        urlencoding_encode(&version),
        urlencoding_encode("FIX: test release")
    );
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), &form).await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    let list = get(&router, "/admin/releases", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);

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

    let form = "version=test-1.0.0&channel=LTS&date=2026-07-01&notes=x";
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), form).await;
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

    let version = unique_slug("v-priv");
    let form = format!(
        "version={}&channel=LTS&date=2026-07-01&notes={}&organization_id={}",
        urlencoding_encode(&version),
        urlencoding_encode("FIX: private hotfix"),
        org.id
    );
    let create = post_form(&router, "/admin/releases/new", cookie.as_deref(), &form).await;
    assert!(status(&create).is_redirection());

    {
        let mut conn = db.clone();
        let rows = Release::all().exec(&mut conn).await.expect("releases");
        let found = rows.iter().find(|r| r.version == version).expect("created");
        assert_eq!(found.organization_id, org.id);
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
        "version={}&channel=LTS&date=2026-07-01&notes={}&organization_id={}",
        urlencoding_encode(&version),
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
        !option_is_selected(select, "LTS") && !option_is_selected(select, "EOL"),
        "other channels must not be selected; select={select}"
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
                size_mb: "1.0".to_owned(),
                sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
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
        p1.contains("vb-list-toolbar"),
        "toolbar pager (no chips): {p1}"
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
        p2.contains("v99.page.") || p1.contains("v99.page."),
        "pagination fixtures appear across pages: p1={p1} p2={p2}"
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
                size_mb: "1.0".to_owned(),
                sha256: "pending".to_owned(),
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
        toasty::create!(Release {
            version: version.clone(),
            channel: "LTS".to_owned(),
            released_on: "2026-07-01".to_owned(),
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
        .id
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
            size_mb: "1.0".to_owned(),
            sha256: "pending".to_owned(),
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
    assert!(html.contains("Edit release"), "edit form: {html}");

    let form = format!(
        "version={}&channel=Stable&date=2026-08-01&notes={}&organization_id=",
        urlencoding_encode("v95.edit.1"),
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
        assert_eq!(rows[0].version, "v95.edit.1");
        assert_eq!(rows[0].channel, "Stable");
        assert_eq!(rows[0].notes, "FEAT: after");
        assert_eq!(rows[0].v_major, 95);
        assert_eq!(rows[0].v_minor, 0);
        assert_eq!(rows[0].v_patch, 1);
    }

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

    let versions = ["v0.9.0", "v0.10.0", "v0.9.0-acme"];
    {
        let mut conn = db.clone();
        for version in versions {
            let _ = toasty::create!(Release {
                version: version.to_owned(),
                channel: "Stable".to_owned(),
                released_on: "2026-07-01".to_owned(),
                size_mb: "1.0".to_owned(),
                sha256: "pending".to_owned(),
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
    let i10 = html.find("v0.10.0").expect("v0.10.0");
    let i_acme = html.find("v0.9.0-acme").expect("acme");
    let i_plain = html
        .find(">v0.9.0<")
        .expect("plain v0.9.0 cell (not substring of -acme)");
    assert!(i10 < i_acme && i_acme < i_plain, "SQL semver order: {html}");

    cleanup(&db).await;
}
