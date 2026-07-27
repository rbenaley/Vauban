//! E2E: db::connect applies migrations so model CRUD works on vcp_test.

use vcp::{db::now_unix, models::DocArticle};

use crate::common::{cleanup, db_lock, test_db, unique_slug};

#[tokio::test]
async fn e2e_connect_schema_supports_doc_article_body_and_updated_at() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let slug = unique_slug("mig-doc");
    let mut conn = db.clone();
    let created = toasty::create!(DocArticle {
        title: "Migration e2e".to_owned(),
        summary: "summary".to_owned(),
        category: "API".to_owned(),
        slug: slug.clone(),
        version: "v1".to_owned(),
        status: "PUBLISHED".to_owned(),
        body: "full body".to_owned(),
        updated_at: now_unix(),
    })
    .exec(&mut conn)
    .await
    .expect("create doc with body/updated_at");

    assert_eq!(created.slug, slug);
    assert_eq!(created.body.get(), "full body");
    assert!(created.updated_at > 0);
}
