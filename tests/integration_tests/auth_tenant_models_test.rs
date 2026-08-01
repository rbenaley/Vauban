//! Unit-style model CRUD against real Postgres (`vcp_test`).

use vcp::{
    auth::{load_user_for_token_hex, persist_session_record, session_is_expired},
    db::now_unix,
    models::{AuthSession, DocArticle, Issue, Release, User},
};

use crate::common::{
    cleanup, create_org_with_membership, create_test_org, create_test_user, db_lock, test_db,
    unique_email, unique_slug,
};

#[tokio::test]
async fn models_user_org_membership_roundtrip() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("member");
    let slug = unique_slug("org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let loaded = User::get_by_id(&mut conn, user.id).await.expect("user");
    assert_eq!(loaded.email, email);

    let orgs = vcp::models::Organization::all()
        .filter(vcp::models::Organization::fields().slug().eq(&slug))
        .exec(&mut conn)
        .await
        .expect("orgs");
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id, org.id);

    cleanup(&db).await;
}

#[tokio::test]
async fn models_reject_duplicate_email() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("dup");
    let _ = create_test_user(&db, &email, "password").await;
    let mut conn = db.clone();
    let err = toasty::create!(User {
        email: email.clone(),
        display_name: "Dup".to_owned(),
        password_hash: "x".to_owned(),
        portal_role: String::new(),
    })
    .exec(&mut conn)
    .await;
    assert!(err.is_err(), "duplicate email must fail");

    cleanup(&db).await;
}

#[tokio::test]
async fn models_reject_duplicate_org_slug() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let slug = unique_slug("dup");
    let _ = create_test_org(&db, &slug).await;
    let mut conn = db.clone();
    let err = toasty::create!(vcp::models::Organization {
        slug: slug.clone(),
        name: "Dup".to_owned(),
        address: "x".to_owned(),
        vat: "x".to_owned(),
        plan_label: "x".to_owned(),
        supported_builds: "x".to_owned(),
        lts_subscriptions: 0,
        industrial_lts_subscriptions: 0,
        technical_contact: "x".to_owned(),
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut conn)
    .await;
    assert!(err.is_err(), "duplicate slug must fail");

    cleanup(&db).await;
}

#[tokio::test]
async fn models_expired_session_not_loaded() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("sess");
    let user = create_test_user(&db, &email, "password").await;
    let expired_hex = format!("{:064x}", 0xaaaa_u128);
    let fresh_hex = format!("{:064x}", 0xbbbb_u128);

    let mut conn = db.clone();
    persist_session_record(&mut conn, expired_hex.clone(), user.id, now_unix() - 5)
        .await
        .expect("persist");

    assert!(session_is_expired(now_unix() - 5));
    let loaded = load_user_for_token_hex(&mut conn, &expired_hex).await;
    assert!(loaded.is_none());

    persist_session_record(&mut conn, fresh_hex.clone(), user.id, now_unix() + 3600)
        .await
        .expect("persist fresh");
    let loaded = load_user_for_token_hex(&mut conn, &fresh_hex).await;
    assert_eq!(loaded.expect("user").id, user.id);

    let _ = AuthSession::delete_by_token_hash(&mut conn, &expired_hex).await;
    let _ = AuthSession::delete_by_token_hash(&mut conn, &fresh_hex).await;
    cleanup(&db).await;
}

#[tokio::test]
async fn models_issue_and_stubs_create() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("issue");
    let slug = unique_slug("issue-org");
    let (user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;

    let mut conn = db.clone();
    let now = vcp::db::now_unix();
    let issue = toasty::create!(Issue {
        key: format!("TEST-{}", unique_slug("k")),
        title: "Latency".to_owned(),
        component: "SSH".to_owned(),
        severity: "Major".to_owned(),
        status: "Open".to_owned(),
        organization_id: org.id,
        details: "details here".to_owned(),
        opened_by_user_id: user.id,
        created_at: now,
        updated_at: now,
    })
    .exec(&mut conn)
    .await
    .expect("issue");
    assert_eq!(issue.organization_id, org.id);
    assert_eq!(issue.details, "details here");

    let doc = toasty::create!(DocArticle {
        title: "Test doc".to_owned(),
        summary: "Summary".to_owned(),
        category: "Test".to_owned(),
        slug: unique_slug("doc"),
        version: "v1".to_owned(),
        status: "DRAFT".to_owned(),
        body: "Body text".to_owned(),
        updated_at: vcp::db::now_unix(),
    })
    .exec(&mut conn)
    .await
    .expect("doc");
    assert!(doc.slug.starts_with("test-"));
    assert_eq!(doc.body.get(), "Body text");

    let rel = toasty::create!(Release {
        version: format!("test-{}", unique_slug("rel")),
        channel: "LTS".to_owned(),
        released_on: "2026-01-01".to_owned(),
        size_mb: "1.0".to_owned(),
        sha256: "deadbeef".to_owned(),
        status: "DRAFT".to_owned(),
        notes: "notes".to_owned(),
        organization_id: 0,
    })
    .exec(&mut conn)
    .await
    .expect("release");
    assert!(rel.version.starts_with("test-"));
    assert_eq!(rel.organization_id, 0);

    cleanup(&db).await;
}
