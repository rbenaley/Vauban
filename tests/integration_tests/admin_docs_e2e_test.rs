//! E2E: admin docs create/publish + client published-only + denials.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{db::now_unix, models::DocArticle};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, create_test_org, db_lock, get, post_form,
    status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
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
    let create = post_form(
        &router,
        &format!("/{slug}/admin/docs/new"),
        cookie.as_deref(),
        &form,
    )
    .await;
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
    let create = post_form(
        &router,
        &format!("/{slug}/admin/docs/new"),
        cookie.as_deref(),
        &form,
    )
    .await;
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

    let admin = get(&router, &format!("/{slug}/admin/docs"), cookie.as_deref()).await;
    assert_eq!(status(&admin), StatusCode::FORBIDDEN);

    let form = "title=Nope&category=API&body=x&publish=1";
    let create = post_form(
        &router,
        &format!("/{slug}/admin/docs/new"),
        cookie.as_deref(),
        form,
    )
    .await;
    assert_eq!(status(&create), StatusCode::FORBIDDEN);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_docs_wrong_org_is_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("adoc-wo");
    let slug = unique_slug("adoc-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let _other = create_test_org(&db, &unique_slug("adoc-other")).await;
    let cookie = login(&router, &email).await;

    let missing = get(
        &router,
        &format!("/{}/admin/docs", unique_slug("no-access")),
        cookie.as_deref(),
    )
    .await;
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
    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
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
        .expect("create draft");
    }

    let before = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&before), StatusCode::NOT_FOUND);

    let pub_resp = post_form(
        &router,
        &format!("/{slug}/admin/docs/{article_slug}/publish"),
        cookie.as_deref(),
        "",
    )
    .await;
    assert!(status(&pub_resp).is_redirection());

    let after = get(
        &router,
        &format!("/{slug}/docs/{article_slug}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&after), StatusCode::OK);

    cleanup(&db).await;
}
