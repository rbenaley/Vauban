//! E2E: admin docs create/publish + client published-only + denials.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{db::now_unix, models::DocArticle};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_published_doc, db_lock, get,
    post_form, status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(
        status(&login).is_redirection(),
        "login should redirect, got {}",
        status(&login)
    );
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_dialect_body_renders_callout_and_pre_from_db() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-dialect");
    let slug = unique_slug("adoc-dialect-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let article_slug = unique_slug("dialect-doc");
    let body = "# Install\n\nDownload it.\n\n```\n$ curl example\n```\n\n::: callout\nNeed 2 GB RAM.\n:::\n";
    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
            title: "Dialect article".to_owned(),
            summary: "sum".to_owned(),
            category: "Getting started".to_owned(),
            slug: article_slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: body.to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create dialect article");
    }

    let client = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&client), StatusCode::OK);
    let html = body_text(client).await;
    assert!(
        html.contains("vb-callout") && html.contains("Need 2 GB RAM"),
        "callout from DB dialect missing: {html}"
    );
    assert!(
        html.contains("vb-pre") && html.contains("curl example"),
        "pre from DB dialect missing: {html}"
    );
    assert!(html.contains("Install"), "heading missing: {html}");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_create_publish_visible_on_client() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-admin");
    let slug = unique_slug("adoc-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;
    assert!(cookie.is_some());

    let title = format!("Test Admin Doc {}", unique_slug("t"));
    let form = format!(
        "title={}&category=API&summary=sum&body=Hello+body&publish=1",
        urlencoding_encode(&title)
    );
    let create = post_form(&router, "/admin/docs/new", cookie.as_deref(), &form).await;
    assert!(
        status(&create).is_redirection(),
        "create should PRG, got {}",
        status(&create)
    );

    let article_slug = vcp::slug::slugify(&title);
    let client = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&client), StatusCode::OK);
    let html = body_text(client).await;
    assert!(
        html.contains("Hello body") || html.contains(&title),
        "{html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_draft_not_visible_on_client_docs() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-draft");
    let slug = unique_slug("adoc-draft-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let title = format!("Test Draft {}", unique_slug("d"));
    let form = format!(
        "title={}&category=API&summary=sum&body=Secret+draft",
        urlencoding_encode(&title)
    );
    let create = post_form(&router, "/admin/docs/new", cookie.as_deref(), &form).await;
    assert!(status(&create).is_redirection());

    let article_slug = vcp::slug::slugify(&title);
    let detail = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(
        status(&detail),
        StatusCode::NOT_FOUND,
        "draft must not be visible on client docs"
    );

    let list = get(&router, &format!("/{slug}/docs"), cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(
        !html.contains(&title),
        "draft title must not appear on client list"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_docs() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-mem");
    let slug = unique_slug("adoc-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let admin = get(&router, "/admin/docs", cookie.as_deref()).await;
    assert_eq!(status(&admin), StatusCode::NOT_FOUND);

    let form = "title=Nope&category=API&body=x&publish=1";
    let create = post_form(&router, "/admin/docs/new", cookie.as_deref(), form).await;
    assert_eq!(status(&create), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_anonymous_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let missing = get(&router, "/admin/docs", None).await;
    assert_eq!(status(&missing), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_legacy_org_admin_docs_path_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-legacy");
    let slug = unique_slug("adoc-legacy-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    // Former `/{org}/admin/*` nest is gone — staff tools live under `/admin/*`.
    let missing = get(&router, &format!("/{slug}/admin/docs"), cookie.as_deref()).await;
    assert_eq!(status(&missing), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_publish_toggles_client_visibility() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-pub");
    let slug = unique_slug("adoc-pub-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let article_slug = unique_slug("toggle");
    let article_id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "Toggle Me".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: article_slug.clone(),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "toggle body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create draft")
        .id
    };

    let before = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&before), StatusCode::NOT_FOUND);

    let pub_resp = post_form(
        &router,
        &format!("/admin/docs/{article_id}/publish"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&pub_resp).is_redirection());
    let location = pub_resp
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        location, "/admin/docs",
        "publish must redirect to admin list"
    );

    let after = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&after), StatusCode::OK);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_list_shows_concept_actions() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-actions");
    let slug = unique_slug("adoc-actions-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
            title: "Actions Fixture".to_owned(),
            summary: "excerpt line".to_owned(),
            category: "API".to_owned(),
            slug: unique_slug("actions-doc"),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create published");
        let _ = toasty::create!(DocArticle {
            title: "Draft Fixture".to_owned(),
            summary: "draft excerpt".to_owned(),
            category: "API".to_owned(),
            slug: unique_slug("actions-draft"),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "draft body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create draft");
    }

    let list = get(&router, "/admin/docs", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(html.contains("Edit"), "missing Edit: {html}");
    assert!(html.contains("Unpublish"), "missing Unpublish: {html}");
    assert!(html.contains("delete="), "missing Delete href: {html}");
    assert!(
        html.contains("excerpt line"),
        "title cell must show summary: {html}"
    );
    assert!(
        html.contains("vb-badge status-published"),
        "PUBLISHED badge: {html}"
    );
    assert!(
        html.contains("vb-badge status-hidden"),
        "DRAFT uses unpublished amber badge: {html}"
    );
    assert!(
        html.contains("Write, version, publish or hide"),
        "Concept lead missing: {html}"
    );
    assert!(!html.contains(">UPDATED<"), "UPDATED column should be gone");

    let compose = get(&router, "/admin/docs/new", cookie.as_deref()).await;
    assert_eq!(status(&compose), StatusCode::OK);
    let compose_html = body_text(compose).await;
    assert!(compose_html.contains("Compose article"));
    assert!(compose_html.contains("vb-form-grid2"));
    assert!(!compose_html.contains("max-width: 720px"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_delete_with_confirm() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-del");
    let slug = unique_slug("adoc-del-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let article_slug = unique_slug("del-doc");
    let article_id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "Delete Me".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: article_slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "gone soon".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create")
        .id
    };

    let bad = post_form(
        &router,
        &format!("/admin/docs/{article_id}/delete"),
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
        bad_loc.contains(&format!("delete={article_id}")),
        "bad confirm should redisplay modal: {bad_loc}"
    );
    assert!(
        bad_loc.contains("err=confirm"),
        "expected err=confirm: {bad_loc}"
    );

    {
        let mut conn = db.clone();
        let rows = DocArticle::all()
            .filter(DocArticle::fields().id().eq(article_id))
            .exec(&mut conn)
            .await
            .expect("still present");
        assert_eq!(rows.len(), 1, "wrong confirm must not delete");
    }

    let confirm_page = get(
        &router,
        &format!("/admin/docs?delete={article_id}&err=confirm"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&confirm_page), StatusCode::OK);
    let confirm_html = body_text(confirm_page).await;
    assert!(
        confirm_html.contains("Delete this article?")
            || confirm_html.contains("Delete permanently"),
        "confirm modal missing: {confirm_html}"
    );

    let ok = post_form(
        &router,
        &format!("/admin/docs/{article_id}/delete"),
        cookie.as_deref(),
        "confirm=delete",
    )
    .await;
    assert!(status(&ok).is_redirection());

    {
        let mut conn = db.clone();
        let rows = DocArticle::all()
            .filter(DocArticle::fields().id().eq(article_id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert!(rows.is_empty(), "article must be deleted");
    }

    let client = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&client), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_docs_delete() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-del-mem");
    let slug = unique_slug("adoc-del-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let article_id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "Member cannot delete".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: unique_slug("mem-del"),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "x".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create")
        .id
    };

    let del = post_form(
        &router,
        &format!("/admin/docs/{article_id}/delete"),
        cookie.as_deref(),
        "confirm=delete",
    )
    .await;
    assert_eq!(status(&del), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_publish_new_version_unpublishes_previous() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-ver");
    let slug = unique_slug("adoc-ver-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let article_slug = unique_slug("versioned");
    let v1_id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "Versioned Doc".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: article_slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "body v1 content".to_owned(),
            updated_at: now_unix() - 100,
        })
        .exec(&mut conn)
        .await
        .expect("create v1")
        .id
    };

    let form = format!(
        "title={}&category=API&summary=s&body={}",
        urlencoding_encode("Versioned Doc"),
        urlencoding_encode("body v2 content")
    );
    let save = post_form(
        &router,
        &format!("/admin/docs/{v1_id}"),
        cookie.as_deref(),
        &form,
    )
    .await;
    assert!(status(&save).is_redirection(), "save should PRG");
    let location = save
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/admin/docs");

    {
        let mut conn = db.clone();
        let rows = DocArticle::all()
            .filter(DocArticle::fields().slug().eq(&article_slug))
            .include(DocArticle::fields().body())
            .exec(&mut conn)
            .await
            .expect("list versions");
        assert_eq!(rows.len(), 2, "expected v1 + v2 rows");
        let published: Vec<_> = rows.iter().filter(|a| a.status == "PUBLISHED").collect();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].version, "v2");
        assert_eq!(published[0].body.get().as_str(), "body v2 content");
        let draft = rows.iter().find(|a| a.id == v1_id).expect("v1 row");
        assert_eq!(draft.status, "DRAFT");
        assert_eq!(draft.body.get().as_str(), "body v1 content");
    }

    let client = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&client), StatusCode::OK);
    let html = body_text(client).await;
    assert!(
        html.contains("body v2 content"),
        "client must show published v2: {html}"
    );
    assert!(
        !html.contains("body v1 content"),
        "client must not show unpublished v1 body"
    );

    let admin_list = get(&router, "/admin/docs", cookie.as_deref()).await;
    assert_eq!(status(&admin_list), StatusCode::OK);
    let list_html = body_text(admin_list).await;
    let v2_pos = list_html.find("v2").expect("v2 in admin list");
    let v1_pos = list_html
        .find(">v1<")
        .or_else(|| list_html.find("v1"))
        .expect("v1 in admin list");
    assert!(
        v2_pos < v1_pos,
        "newer version should appear first in admin list"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_list_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-page");
    let slug = unique_slug("adoc-page-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let marker = unique_slug("adoc-pagefix");
    for i in 0..11u32 {
        let article_slug = unique_slug(&format!("adoc-pf-{i}"));
        create_published_doc(
            &db,
            &format!("{marker} article {i}"),
            "admin pagination fixture",
            "API",
            &article_slug,
        )
        .await;
    }

    let page1 = get(&router, "/admin/docs?page=1", cookie.as_deref()).await;
    assert_eq!(status(&page1), StatusCode::OK);
    let p1 = body_text(page1).await;
    let rows_p1 = p1.matches("vb-title-main").count();
    assert_eq!(rows_p1, 10, "page 1 must show 10 rows: {p1}");
    assert!(p1.contains("vb-pager"), "pager when >10: {p1}");
    assert!(
        p1.contains("vb-list-toolbar"),
        "toolbar pager (no chips): {p1}"
    );
    assert!(
        p1.contains("/admin/docs?page=2") || p1.contains("href=\"/admin/docs?page=2\""),
        "next page link: {p1}"
    );
    assert!(p1.contains(&marker), "page 1 shows newest fixtures: {p1}");

    let page2 = get(&router, "/admin/docs?page=2", cookie.as_deref()).await;
    assert_eq!(status(&page2), StatusCode::OK);
    let p2 = body_text(page2).await;
    let rows_p2 = p2.matches("vb-title-main").count();
    // Seed catalog may add further pages; page 2 must include the remainder.
    assert!(
        (1..=10).contains(&rows_p2),
        "page 2 row count: {rows_p2} in {p2}"
    );
    assert!(p2.contains(&marker), "page 2 keeps fixture remainder: {p2}");

    cleanup(&db).await;
}
