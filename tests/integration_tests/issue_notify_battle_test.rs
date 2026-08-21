//! Contention: unique outbox keys, drain vs sweep, circuit flood.

use std::sync::Arc;

use tokio::sync::Barrier;
use topcoat::mail::MemoryTransport;
use vcp::config::IssuesNotifyConfig;
use vcp::issue_notify::{NotifyEvent, enqueue_issue_notify};
use vcp::models::{ISSUE_MAIL_SOURCE_CREATE, Issue, IssueMailOutbox};

use crate::common::{
    cleanup, create_org_with_membership, create_test_issue, db_lock, login_cookie,
    post_multipart_with_files, status, test_config, test_db, test_router_with_memory_mail,
    test_router_with_memory_mail_circuit, unique_email, unique_slug,
};

fn count_to(sent: &[topcoat::mail::Mail], email: &str) -> usize {
    sent.iter()
        .filter(|m| m.to().iter().any(|mb| mb.address() == email))
        .count()
}

#[tokio::test]
async fn battle_double_enqueue_unique_key() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let admin = unique_email("nfy-bt-adm");
    let member = unique_email("nfy-bt-mem");
    let slug = unique_slug("nfy-bt");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("nfy-bt-adm"), "admin")
            .await;
    let (user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let issue =
        create_test_issue(&db, org.id, user.id, "TEST-nfy-uniq", "Notify uniq", "Open").await;
    let notify = IssuesNotifyConfig::default();
    let n = 8usize;
    let barrier = Arc::new(Barrier::new(n));
    let url = crate::common::database_url();
    let issue_id = issue.id;
    let actor = user.id;
    let mut handles = Vec::new();
    for _ in 0..n {
        let url = url.clone();
        let barrier = barrier.clone();
        let notify = notify.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let db = vcp::db::connect(&url).await.expect("db");
            let mut conn = db.clone();
            let rows = Issue::all()
                .filter(Issue::fields().id().eq(issue_id))
                .limit(1)
                .exec(&mut conn)
                .await
                .expect("load");
            let issue = rows.into_iter().next().expect("issue");
            enqueue_issue_notify(
                &mut conn,
                &notify,
                &issue,
                NotifyEvent::Create,
                ISSUE_MAIL_SOURCE_CREATE,
                actor,
            )
            .await
            .expect("enqueue")
        }));
    }
    let mut inserted = 0usize;
    for h in handles {
        inserted += h.await.expect("join");
    }
    assert!(inserted >= 1, "at least one insert wins");

    let mut conn = db.clone();
    let rows = IssueMailOutbox::all()
        .filter(IssueMailOutbox::fields().issue_id().eq(issue_id))
        .filter(IssueMailOutbox::fields().event().eq("create".to_owned()))
        .exec(&mut conn)
        .await
        .expect("outbox");
    let mut keys: Vec<(u64, String, u64, u64)> = rows
        .iter()
        .map(|r| {
            (
                r.issue_id,
                r.event.clone(),
                r.source_id,
                r.recipient_user_id,
            )
        })
        .collect();
    keys.sort();
    let mut dedup = keys.clone();
    dedup.dedup();
    assert_eq!(keys, dedup, "unique (issue,event,source,recipient)");

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_parallel_comments_and_fsm_no_double_mail() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = Arc::new(test_router_with_memory_mail(memory.clone()).await);

    let admin = unique_email("nfy-bt2-adm");
    let member = unique_email("nfy-bt2-mem");
    let slug = unique_slug("nfy-bt2");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-bt2-adm"),
        "admin",
    )
    .await;
    let _ = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("cookie");
    let report = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues"),
        Some(&cookie),
        &[
            ("title", "Battle notify"),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", "opener"),
        ],
        &[],
    )
    .await;
    assert!(status(&report).is_redirection());
    let loc = report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("loc")
        .to_owned();
    let key = loc
        .rsplit('/')
        .next()
        .unwrap()
        .split('?')
        .next()
        .unwrap()
        .to_owned();

    memory.clear();
    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            post_multipart_with_files(
                &router,
                &format!("/{slug}/issues/{key}/reply"),
                Some(&cookie),
                &[("body", &format!("parallel-{i}"))],
                &[],
            )
            .await
        }));
    }
    for h in handles {
        let resp = h.await.expect("join");
        assert!(status(&resp).is_redirection());
    }

    let sent = memory.sent();
    let comment_mails = sent
        .iter()
        .filter(|m| {
            m.to().iter().any(|mb| mb.address() == admin)
                && match m.text() {
                    topcoat::mail::TextBody::Text(t) => t.contains("parallel-"),
                    _ => false,
                }
        })
        .count();
    assert_eq!(
        comment_mails, n,
        "one mail per distinct comment to support, got {comment_mails}"
    );
    assert_eq!(count_to(&sent, &member), 0);

    cleanup(&db).await;
}

#[tokio::test]
async fn battle_circuit_open_under_flood_keeps_issues() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let circuit = Arc::new(vcp::mail_circuit::MailCircuitBreaker::new(
        &test_config().await.mail,
    ));
    circuit.force_open();
    let router = Arc::new(test_router_with_memory_mail_circuit(memory.clone(), circuit).await);

    let admin = unique_email("nfy-bt3-adm");
    let member = unique_email("nfy-bt3-mem");
    let slug = unique_slug("nfy-bt3");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-bt3-adm"),
        "admin",
    )
    .await;
    let _ = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("cookie");

    let n = 5usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for i in 0..n {
        let router = router.clone();
        let barrier = barrier.clone();
        let cookie = cookie.clone();
        let slug = slug.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            post_multipart_with_files(
                &router,
                &format!("/{slug}/issues"),
                Some(&cookie),
                &[
                    ("title", &format!("Flood {i}")),
                    ("component", "Portal"),
                    ("severity", "Major"),
                    ("details", "flood"),
                ],
                &[],
            )
            .await
        }));
    }
    let mut ok = 0usize;
    for h in handles {
        if status(&h.await.expect("join")).is_redirection() {
            ok += 1;
        }
    }
    assert_eq!(ok, n, "issues persist under circuit-open flood");
    assert!(memory.sent().is_empty());

    let mut conn = db.clone();
    let pending = IssueMailOutbox::all()
        .filter(IssueMailOutbox::fields().sent_at().eq(0_i64))
        .exec(&mut conn)
        .await
        .expect("pending");
    assert!(
        !pending.is_empty(),
        "outbox stays pending while circuit is open"
    );

    cleanup(&db).await;
}
