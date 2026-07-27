//! Contention tests for concurrent DocArticle creates / reads.

use std::sync::Arc;

use tokio::sync::Barrier;
use vcp::{db::now_unix, models::DocArticle};

use crate::common::{cleanup, db_lock, test_db, unique_slug};

#[tokio::test]
async fn battle_concurrent_doc_article_creates() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let base = unique_slug("battle-doc");

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let slug = format!("{base}-{i}");
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let created = toasty::create!(DocArticle {
                title: format!("Battle Doc {i}"),
                summary: "battle".to_owned(),
                category: "API".to_owned(),
                slug: slug.clone(),
                version: "v1".to_owned(),
                status: "DRAFT".to_owned(),
                body: format!("body {i}"),
                updated_at: now_unix(),
            })
            .exec(&mut conn)
            .await
            .expect("create doc");
            assert_eq!(created.slug, slug);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    {
        let mut conn = db.clone();
        let rows = DocArticle::all()
            .filter(DocArticle::fields().slug().eq(format!("{base}-0")))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert_eq!(rows.len(), 1);
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_doc_status_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let slug = unique_slug("battle-pub");
    {
        let mut conn = db.clone();
        let _ = toasty::create!(DocArticle {
            title: "Published battle".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "hello".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create");
    }

    let n = 10usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let slug = slug.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let rows = DocArticle::all()
                .filter(DocArticle::fields().status().eq("PUBLISHED"))
                .filter(DocArticle::fields().slug().eq(&slug))
                .exec(&mut conn)
                .await
                .expect("filter");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, "PUBLISHED");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_concurrent_doc_delete_and_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let slug = unique_slug("battle-del");
    let id = {
        let mut conn = db.clone();
        toasty::create!(DocArticle {
            title: "Delete battle".to_owned(),
            summary: "s".to_owned(),
            category: "API".to_owned(),
            slug: slug.clone(),
            version: "v1".to_owned(),
            status: "PUBLISHED".to_owned(),
            body: "body".to_owned(),
            updated_at: now_unix(),
        })
        .exec(&mut conn)
        .await
        .expect("create")
        .id
    };

    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n + 1));
    let url = crate::common::database_url();
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let _ = DocArticle::all()
                .filter(DocArticle::fields().id().eq(id))
                .exec(&mut conn)
                .await;
        }));
    }

    let del_barrier = barrier.clone();
    let del_url = url.clone();
    let delete = tokio::spawn(async move {
        del_barrier.wait().await;
        let db = vcp::db::connect(&del_url).await.expect("connect");
        let mut conn = db.clone();
        if let Ok(mut rows) = DocArticle::all()
            .filter(DocArticle::fields().id().eq(id))
            .include(DocArticle::fields().body())
            .exec(&mut conn)
            .await
            && let Some(article) = rows.pop()
        {
            article.delete().exec(&mut conn).await.expect("delete");
        }
    });

    for h in handles {
        h.await.expect("read join");
    }
    delete.await.expect("delete join");

    {
        let mut conn = db.clone();
        let rows = DocArticle::all()
            .filter(DocArticle::fields().id().eq(id))
            .exec(&mut conn)
            .await
            .expect("lookup");
        assert!(
            rows.is_empty(),
            "article must be gone after contended delete"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_docs_body_parse() {
    let src = r#"# Title

Para with <script>.

```
code <here>
```

::: callout
Need RAM.
:::
"#;
    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let barrier = barrier.clone();
        let src = src.to_owned();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let blocks = vcp::docs_body::parse(&src);
            assert!(
                blocks
                    .iter()
                    .any(|b| matches!(b, vcp::docs_body::Block::Callout(_)))
            );
            assert!(
                blocks
                    .iter()
                    .any(|b| matches!(b, vcp::docs_body::Block::Pre(_)))
            );
            assert_eq!(vcp::docs_body::escape_html("<x>"), "&lt;x&gt;");
        }));
    }
    for h in handles {
        h.await.expect("join");
    }
}
