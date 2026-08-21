//! E2E: db::connect applies migrations so model CRUD works on vcp_test.

use toasty_cli::ToastyCli;
use vcp::config::Config;
use vcp::db::{self, now_unix};
use vcp::models::DocArticle;

use crate::common::{cleanup, database_url, db_lock, test_db, unique_slug};

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

#[tokio::test]
async fn e2e_second_embed_apply_skips_all() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    let expected = db::embedded_migrations().migrations().len();
    let report = db::apply_pending_migrations(&db)
        .await
        .expect("second embed apply");
    assert_eq!(report.applied(), 0, "already-applied ids must not re-run");
    assert_eq!(report.skipped(), expected);
}

#[tokio::test]
async fn e2e_cli_apply_then_embed_skips() {
    let _guard = db_lock().lock().await;
    let url = database_url();
    let db = db::open(&url).await.expect("open without auto-apply");
    let root = Config::package_root().expect("package_root");
    let cli_cfg = toasty_cli::Config::load_from(&root.join("Toasty.toml")).expect("Toasty.toml");
    ToastyCli::with_config(db.clone(), cli_cfg)
        .parse_from(["vcp", "migration", "apply"])
        .await
        .expect("CLI migration apply");

    let report = db::apply_pending_migrations(&db)
        .await
        .expect("embed after CLI");
    assert_eq!(
        report.applied(),
        0,
        "embed must skip ids the CLI already recorded"
    );
    assert_eq!(
        report.skipped(),
        db::embedded_migrations().migrations().len()
    );
}
