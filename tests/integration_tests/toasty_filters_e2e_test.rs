//! E2E: docs/builds list query params; published-only docs.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::{db::now_unix, models::DocArticle};

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

#[tokio::test]
async fn e2e_docs_list_published_only_and_query_params() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("tf-docs");
    let slug = unique_slug("tf-docs-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let pub_slug = unique_slug("tf-pub");
    let draft_slug = unique_slug("tf-draft");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
            title: "Unique Published Alpha".to_owned(),
            summary: "alpha summary".to_owned(),
            category: "API".to_owned(),
            slug: pub_slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("pub");
        let _ = toasty::create!(DocArticle {
            title: "Unique Draft Hidden".to_owned(),
            summary: "draft summary".to_owned(),
            category: "API".to_owned(),
            slug: draft_slug.clone(),
            version: "v1".to_owned(),
            status: "DRAFT".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("draft");
    }

    let list = get(&router, &format!("/{slug}/docs"), cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(html.contains("Unique Published Alpha"), "{html}");
    assert!(!html.contains("Unique Draft Hidden"), "{html}");

    let q = get(
        &router,
        &format!("/{slug}/docs?q=alpha&cat=API"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&q), StatusCode::OK);

    let builds = get(
        &router,
        &format!("/{slug}/builds?channel=LTS"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&builds), StatusCode::OK);

    cleanup(&db).await;
}
