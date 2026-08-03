//! Battle: concurrent choose-org and dual-org navigation under one session.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::models::MEMBERSHIP_ROLE_ORG;

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_org, db_lock, get,
    login_cookie, status, test_db, test_router, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_parallel_choose_org_and_member_orgs() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("choose-battle");
    let slug_a = unique_slug("choose-ba");
    let slug_b = unique_slug("choose-bb");
    let (user, _org_a) =
        create_org_with_membership(&db, &email, "password", &slug_a, "member").await;
    let org_b = create_test_org(&db, &slug_b).await;
    create_membership(&db, user.id, org_b.id, MEMBERSHIP_ROLE_ORG).await;

    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let cookie = Arc::new(cookie);

    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug_a = slug_a.clone();
        let slug_b = slug_b.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = match i % 3 {
                0 => "/choose-org".to_owned(),
                1 => format!("/{slug_a}"),
                _ => format!("/{slug_b}"),
            };
            let resp = get(&router, &path, Some(cookie.as_str())).await;
            let code = status(&resp);
            assert!(
                code == StatusCode::OK || code.is_redirection(),
                "path={path} status={code:?}"
            );
            if path == "/choose-org" {
                assert_eq!(code, StatusCode::OK);
            }
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    let foreign = unique_slug("choose-bf");
    let _ = create_test_org(&db, &foreign).await;
    let denied = get(&router, &format!("/{foreign}"), Some(cookie.as_str())).await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}
