//! Contention tests for concurrent DocArticle creates / reads.

use std::sync::Arc;

use http_body_util::BodyExt;
use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::{db::now_unix, models::DocArticle};

use crate::common::{
    cleanup, create_org_with_membership, create_published_doc, db_lock, get, login_cookie, status,
    test_db, test_router, unique_email, unique_slug,
};

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

#[tokio::test]
async fn battle_parallel_admin_docs_page_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-adoc-page");
    let slug = unique_slug("battle-adoc-page");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let marker = unique_slug("badocpage");
    for i in 0..11u32 {
        let doc_slug = unique_slug(&format!("badoc-pf-{i}"));
        create_published_doc(
            &db,
            &format!("{marker} article {i}"),
            "battle admin pagination",
            "API",
            &doc_slug,
        )
        .await;
    }

    let router = Arc::new(test_router().await);
    let cookie = login_cookie(router.as_ref(), &email).await.expect("cookie");

    let barrier = Arc::new(Barrier::new(2));
    let cookie_a = cookie.clone();
    let cookie_b = cookie;
    let router_a = router.clone();
    let router_b = router;
    let barrier_a = barrier.clone();
    let barrier_b = barrier;
    let marker_a = marker.clone();
    let marker_b = marker;

    let h1 = tokio::spawn(async move {
        barrier_a.wait().await;
        let resp = get(router_a.as_ref(), "/admin/docs?page=1", Some(&cookie_a)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let html = String::from_utf8_lossy(&body).into_owned();
        assert!(html.contains(&marker_a), "page1 marker: {html}");
        html
    });
    let h2 = tokio::spawn(async move {
        barrier_b.wait().await;
        let resp = get(router_b.as_ref(), "/admin/docs?page=2", Some(&cookie_b)).await;
        assert_eq!(status(&resp), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let html = String::from_utf8_lossy(&body).into_owned();
        assert!(html.contains(&marker_b), "page2 marker: {html}");
        html
    });

    let page1 = h1.await.expect("join page1");
    let page2 = h2.await.expect("join page2");
    assert!(page1.contains("vb-pager"), "page1 pager: {page1}");
    assert!(
        page1.contains("vb-list-toolbar"),
        "toolbar under contention: {page1}"
    );
    assert!(
        (1..=10).contains(&page2.matches("vb-title-main").count()),
        "page2 rows under contention: {page2}"
    );

    cleanup(&db).await;
}
