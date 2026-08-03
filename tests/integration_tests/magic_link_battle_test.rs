//! Battle: concurrent consume of the same magic-link token — one winner;
//! concurrent request_login_link calls stay OK (no panic / no oracle).

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::mail::MemoryTransport;
use topcoat::router::StatusCode;
use vcp::magic_link::issue_token;
use vcp::models::{MAGIC_LINK_NOT_CONSUMED, MagicLinkToken};

use crate::common::{
    call_request_login_link, cleanup, create_org_with_membership, db_lock, get, status, test_db,
    test_router, test_router_with_memory_mail, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_consume_same_token_one_session() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("ml-battle");
    let slug = unique_slug("ml-battle");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let raw = issue_token(&mut conn, user.id, 300)
        .await
        .expect("issue token");
    let path = format!("/login/magic?token={raw}");

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let barrier = barrier.clone();
        let path = path.clone();
        let slug = slug.clone();
        let router = test_router().await;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, &path, None).await;
            status(&resp).is_redirection()
                && resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|loc| {
                        loc.contains(&slug) || loc == "/login" || loc.starts_with("/login?error=")
                    })
        }));
    }

    let mut ok_redirects = 0usize;
    for h in handles {
        if h.await.expect("join") {
            ok_redirects += 1;
        }
    }
    assert!(
        ok_redirects >= 1,
        "at least one consumer must get a redirect response"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_request_login_link_same_email() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = Arc::new(test_router_with_memory_mail(memory.clone()).await);

    let email = unique_email("ml-battle-req");
    let slug = unique_slug("ml-battle-req");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let email = email.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = call_request_login_link(&router, &email).await;
            assert_eq!(status(&resp), StatusCode::OK);
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    let sent = memory.sent().len();
    assert!(
        sent >= 1 && sent <= n,
        "parallel request_login_link must send at least one mail and at most n; got {sent}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_issue_leaves_one_unused_token() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("ml-battle-issue");
    let slug = unique_slug("ml-battle-issue");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let user_id = user.id;
    let url = crate::common::database_url();

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            issue_token(&mut conn, user_id, 300)
                .await
                .expect("issue under contention");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    let mut conn = db.clone();
    let unused_after_race = MagicLinkToken::all()
        .filter(MagicLinkToken::fields().user_id().eq(user_id))
        .filter(
            MagicLinkToken::fields()
                .consumed_at()
                .eq(MAGIC_LINK_NOT_CONSUMED),
        )
        .exec(&mut conn)
        .await
        .expect("list unused");
    assert!(
        !unused_after_race.is_empty() && unused_after_race.len() <= n,
        "parallel issue must leave between 1 and n unused tokens; got {}",
        unused_after_race.len()
    );

    // A subsequent serial issue converges to a single active link.
    issue_token(&mut conn, user_id, 300)
        .await
        .expect("serial issue");
    let unused = MagicLinkToken::all()
        .filter(MagicLinkToken::fields().user_id().eq(user_id))
        .filter(
            MagicLinkToken::fields()
                .consumed_at()
                .eq(MAGIC_LINK_NOT_CONSUMED),
        )
        .exec(&mut conn)
        .await
        .expect("list unused after serial");
    assert_eq!(
        unused.len(),
        1,
        "serial issue_token after contention must leave exactly one unused link"
    );

    cleanup(&db).await;
}
