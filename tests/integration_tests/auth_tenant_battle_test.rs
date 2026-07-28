//! Contention tests for sessions and membership lookups.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::router::StatusCode;
use vcp::{
    auth::{load_user_for_token_hex, persist_session_record, resolve_home_org_slug},
    db::now_unix,
    models::{Membership, PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG},
};

use crate::common::{
    cleanup, create_org_with_membership, create_test_org, create_test_user, db_lock, get, status,
    test_db, test_router, unique_email, unique_slug,
};

#[tokio::test]
async fn battle_concurrent_session_writes() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-sess");
    let user = create_test_user(&db, &email, "password").await;
    let user_id = user.id;
    let url = crate::common::database_url();
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    for i in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            // Fresh connect per task — Toasty Db handles are not multi-task safe.
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let hex = format!("{i:064x}");
            persist_session_record(&mut conn, hex.clone(), user_id, now_unix() + 3600)
                .await
                .expect("persist");
            let loaded = load_user_for_token_hex(&mut conn, &hex).await;
            assert_eq!(loaded.expect("user").id, user_id);
            let _ = vcp::models::AuthSession::delete_by_token_hash(&mut conn, &hex).await;
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_membership_reads() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-mem");
    let slug = unique_slug("battle-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    // Sanity: membership visible before contention.
    {
        let mut conn = db.clone();
        let rows = Membership::all().exec(&mut conn).await.expect("all");
        assert!(
            rows.iter()
                .any(|m| m.user_id == user.id && m.organization_id == org.id),
            "fixture membership missing"
        );
    }

    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);

    let url = crate::common::database_url();
    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let user_id = user.id;
        let org_id = org.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let rows = Membership::all()
                .exec(&mut conn)
                .await
                .expect("memberships");
            let hit = rows
                .into_iter()
                .filter(|m| m.user_id == user_id && m.organization_id == org_id)
                .collect::<Vec<_>>();
            assert_eq!(hit.len(), 1);
            assert_eq!(hit[0].role, "org");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_org_slug_membership_lookups() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("battle-org");
    let slug = unique_slug("battle-req-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    let url = crate::common::database_url();
    let slug_owned = slug.clone();

    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let slug = slug_owned.clone();
        let user_id = user.id;
        let org_id = org.id;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("connect");
            let mut conn = db.clone();
            let found = vcp::models::Organization::all()
                .filter(vcp::models::Organization::fields().slug().eq(&slug))
                .exec(&mut conn)
                .await
                .expect("orgs");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].id, org_id);
            let memberships = Membership::all()
                .filter(Membership::fields().user_id().eq(user_id))
                .filter(Membership::fields().organization_id().eq(org_id))
                .exec(&mut conn)
                .await
                .expect("memberships");
            assert_eq!(memberships.len(), 1);
            assert_eq!(memberships[0].role, "org");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_session_root_redirects() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("battle-root");
    let slug = unique_slug("battle-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let cookie = crate::common::login_cookie(&router, &email)
        .await
        .expect("session cookie");
    let expected = format!("/{slug}");

    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let expected = expected.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let resp = get(&router, "/", Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::TEMPORARY_REDIRECT);
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .expect("location");
            assert_eq!(loc, expected);
            assert_eq!(
                resolve_home_org_slug("", Some(expected.trim_start_matches('/').to_owned()))
                    .as_deref(),
                Some(expected.trim_start_matches('/'))
            );
            assert_eq!(
                resolve_home_org_slug(PORTAL_ROLE_ADMIN, None).as_deref(),
                Some(RESERVED_ORG_SLUG)
            );
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_wrong_org_and_admin_denials_are_404() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = Arc::new(test_router().await);

    let email = unique_email("battle-deny");
    let slug = unique_slug("battle-deny-home");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let foreign = unique_slug("battle-deny-foreign");
    let _other = create_test_org(&db, &foreign).await;

    let cookie = crate::common::login_cookie(&router, &email)
        .await
        .expect("session cookie");
    let invented = unique_slug("battle-deny-missing");

    let n = 12usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let foreign = foreign.clone();
        let invented = invented.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let path = match i % 3 {
                0 => format!("/{foreign}"),
                1 => format!("/{invented}"),
                _ => "/admin/docs".to_owned(),
            };
            let resp = get(&router, &path, Some(&cookie)).await;
            assert_eq!(status(&resp), StatusCode::NOT_FOUND, "path={path}");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_login_failures_stay_redirect() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = crate::common::test_config().await;
    cfg.login.max_attempts = 100;
    cfg.login.lockout_secs = 1;
    let router = Arc::new(crate::common::test_router_with_config(cfg).await);

    let email = unique_email("battle-login-fail");
    let slug = unique_slug("battle-login-fail");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let email = email.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let enc = email.replace('@', "%40");
            let form = format!("email={enc}&password=wrong-{i}");
            let resp = crate::common::post_form(&router, "/login", None, &form).await;
            assert!(status(&resp).is_redirection());
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .expect("location");
            assert_eq!(loc, "/login");
        }));
    }

    for h in handles {
        h.await.expect("join");
    }

    cleanup(&db).await;
}
