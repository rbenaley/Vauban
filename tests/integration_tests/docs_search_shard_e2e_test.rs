//! E2E: GET /docs works with search shard chrome.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;

use crate::common::{
    cleanup, cookie_header, create_org_with_membership, db_lock, get, post_form, status, test_db,
    test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_docs_page_renders_with_search() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("shard-e2e");
    let slug = unique_slug("shard-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let form = format!("email={}&password=password", urlencoding_encode(&email));
    let login = post_form(&router, "/login", None, &form).await;
    let cookie = cookie_header(&login);

    let docs = get(&router, &format!("/{slug}/docs"), cookie.as_deref()).await;
    assert_eq!(status(&docs), StatusCode::OK);
    let html = body_text(docs).await;
    assert!(
        html.contains("Documentation") || html.contains("vb-search") || html.contains("knowledge"),
        "{html}"
    );

    let q = get(&router, &format!("/{slug}/docs?q=start"), cookie.as_deref()).await;
    assert_eq!(status(&q), StatusCode::OK);

    cleanup(&db).await;
}
