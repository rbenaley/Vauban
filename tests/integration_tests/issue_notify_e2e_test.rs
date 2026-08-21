//! E2E: issue notify outbox + MemoryTransport matrix.

use topcoat::mail::{MemoryTransport, TextBody};
use topcoat::router::StatusCode;
use vcp::db::now_unix;
use vcp::models::{
    ISSUE_MAIL_SOURCE_CREATE, Issue, IssueMailOutbox, MEMBERSHIP_ROLE_ORG, USER_NOT_DELETED, User,
};

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_user, db_lock,
    login_cookie, post_form, post_multipart_with_files, status, test_config, test_db,
    test_router_with_memory_mail, test_router_with_memory_mail_circuit,
    test_router_with_memory_mail_config, unique_email, unique_slug,
};

fn mail_to_contains(mail: &topcoat::mail::Mail, email: &str) -> bool {
    mail.to().iter().any(|mb| mb.address() == email)
}

fn mail_text(mail: &topcoat::mail::Mail) -> String {
    match mail.text() {
        TextBody::Text(t) => t.clone(),
        _ => String::new(),
    }
}

fn count_to(sent: &[topcoat::mail::Mail], email: &str) -> usize {
    sent.iter().filter(|m| mail_to_contains(m, email)).count()
}

async fn report_issue(
    router: &topcoat::router::Router,
    slug: &str,
    cookie: Option<&str>,
    title: &str,
) -> String {
    let report = post_multipart_with_files(
        router,
        &format!("/{slug}/issues"),
        cookie,
        &[
            ("title", title),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", "Repro steps for notify mail"),
        ],
        &[],
    )
    .await;
    assert!(
        status(&report).is_redirection(),
        "create should PRG, got {}",
        status(&report)
    );
    report
        .headers()
        .get(topcoat::router::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .expect("Location")
}

#[tokio::test]
async fn e2e_create_mails_other_support_not_actor() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin_a = unique_email("nfy-adm-a");
    let admin_b = unique_email("nfy-adm-b");
    let member = unique_email("nfy-mem");
    let slug = unique_slug("nfy-co");
    let _ = create_org_with_membership(
        &db,
        &admin_a,
        "password",
        &unique_slug("nfy-adm-a"),
        "admin",
    )
    .await;
    let _ = create_org_with_membership(
        &db,
        &admin_b,
        "password",
        &unique_slug("nfy-adm-b"),
        "admin",
    )
    .await;
    let (_user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("member cookie");

    memory.clear();
    let loc = report_issue(&router, &slug, Some(&cookie), "Notify create").await;
    assert!(loc.contains(&format!("/{slug}/issues/VBN-")));

    let sent = memory.sent();
    assert_eq!(count_to(&sent, &admin_a), 1, "admin A must be mailed");
    assert_eq!(count_to(&sent, &admin_b), 1, "admin B must be mailed");
    assert_eq!(count_to(&sent, &member), 0, "creator must not self-mail");
    assert!(
        sent.iter()
            .any(|m| mail_text(m).contains(&org.name) || mail_text(m).contains("VBN-")),
        "body must mention the issue"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_company_comment_is_support_only() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin = unique_email("nfy-cmt-adm");
    let member = unique_email("nfy-cmt-mem");
    let sibling = unique_email("nfy-cmt-sib");
    let slug = unique_slug("nfy-cmt");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-cmt-adm"),
        "admin",
    )
    .await;
    let (_user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let sib = create_test_user(&db, &sibling, "password").await;
    create_membership(&db, sib.id, org.id, MEMBERSHIP_ROLE_ORG).await;
    let cookie = login_cookie(&router, &member).await.expect("cookie");

    let loc = report_issue(&router, &slug, Some(&cookie), "Notify comment").await;
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();
    memory.clear();
    let reply = post_multipart_with_files(
        &router,
        &format!("/{slug}/issues/{key}/reply"),
        Some(&cookie),
        &[("body", "Company follow-up")],
        &[],
    )
    .await;
    assert!(status(&reply).is_redirection());

    let sent = memory.sent();
    assert_eq!(count_to(&sent, &admin), 1);
    assert_eq!(count_to(&sent, &sibling), 0, "sibling company account: 0");
    assert_eq!(count_to(&sent, &member), 0);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_support_comment_mails_company_and_other_support() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin_a = unique_email("nfy-sup-a");
    let admin_b = unique_email("nfy-sup-b");
    let member = unique_email("nfy-sup-mem");
    let slug = unique_slug("nfy-sup");
    let _ = create_org_with_membership(
        &db,
        &admin_a,
        "password",
        &unique_slug("nfy-sup-a"),
        "admin",
    )
    .await;
    let _ = create_org_with_membership(
        &db,
        &admin_b,
        "password",
        &unique_slug("nfy-sup-b"),
        "admin",
    )
    .await;
    let (_user, _org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let member_cookie = login_cookie(&router, &member).await.expect("member");
    let loc = report_issue(&router, &slug, Some(&member_cookie), "Notify support").await;
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();

    let admin_cookie = login_cookie(&router, &admin_a).await.expect("admin");
    memory.clear();
    let reply = post_multipart_with_files(
        &router,
        &format!("/admin/issues/{key}/reply?org={slug}"),
        Some(&admin_cookie),
        &[("body", "Support is looking")],
        &[],
    )
    .await;
    assert!(status(&reply).is_redirection());

    let sent = memory.sent();
    assert_eq!(count_to(&sent, &admin_a), 0, "commenter has 0");
    assert_eq!(count_to(&sent, &admin_b), 1);
    assert_eq!(count_to(&sent, &member), 1);
    assert!(
        sent.iter()
            .any(|m| mail_text(m).contains("Support replied") || mail_text(m).contains("looking")),
        "support comment subject/body"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_fsm_status_is_support_only() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin = unique_email("nfy-fsm-adm");
    let member = unique_email("nfy-fsm-mem");
    let slug = unique_slug("nfy-fsm");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-fsm-adm"),
        "admin",
    )
    .await;
    let (_user, _org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let member_cookie = login_cookie(&router, &member).await.expect("member");
    let loc = report_issue(&router, &slug, Some(&member_cookie), "Notify FSM").await;
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();

    let admin_cookie = login_cookie(&router, &admin).await.expect("admin");
    memory.clear();
    let posted = post_form(
        &router,
        &format!("/admin/issues/{key}/start-analysis?org={slug}"),
        Some(&admin_cookie),
        "",
    )
    .await;
    assert!(status(&posted).is_redirection());

    let sent = memory.sent();
    assert_eq!(count_to(&sent, &member), 0, "company inbox empty on FSM");
    assert_eq!(count_to(&sent, &admin), 0, "actor excluded");

    memory.clear();
    let noop = post_form(
        &router,
        &format!("/{slug}/issues/{key}/reopen"),
        Some(&member_cookie),
        "",
    )
    .await;
    assert!(status(&noop).is_redirection());
    assert!(memory.sent().is_empty(), "Noop FSM must not enqueue mail");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_soft_deleted_company_account_gets_zero() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin = unique_email("nfy-del-adm");
    let member = unique_email("nfy-del-mem");
    let gone = unique_email("nfy-del-gone");
    let slug = unique_slug("nfy-del");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-del-adm"),
        "admin",
    )
    .await;
    let (_user, org) = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let mut gone_user = create_test_user(&db, &gone, "password").await;
    create_membership(&db, gone_user.id, org.id, MEMBERSHIP_ROLE_ORG).await;
    let mut conn = db.clone();
    gone_user
        .update()
        .deleted_at(now_unix())
        .exec(&mut conn)
        .await
        .expect("soft-delete");

    let member_cookie = login_cookie(&router, &member).await.expect("member");
    let loc = report_issue(&router, &slug, Some(&member_cookie), "Notify deleted").await;
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();
    let admin_cookie = login_cookie(&router, &admin).await.expect("admin");
    memory.clear();
    let _ = post_multipart_with_files(
        &router,
        &format!("/admin/issues/{key}/reply?org={slug}"),
        Some(&admin_cookie),
        &[("body", "Ping company")],
        &[],
    )
    .await;
    assert_eq!(count_to(&memory.sent(), &gone), 0);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_notify_disabled_persists_without_mail() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let mut cfg = test_config().await;
    cfg.issues.notify.enabled = false;
    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail_config(memory.clone(), cfg).await;

    let admin = unique_email("nfy-off-adm");
    let member = unique_email("nfy-off-mem");
    let slug = unique_slug("nfy-off");
    let _ = create_org_with_membership(
        &db,
        &admin,
        "password",
        &unique_slug("nfy-off-adm"),
        "admin",
    )
    .await;
    let _ = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("cookie");
    memory.clear();
    let loc = report_issue(&router, &slug, Some(&cookie), "Notify off").await;
    assert!(loc.contains("/issues/VBN-"));
    assert!(memory.sent().is_empty());

    let mut conn = db.clone();
    let issues = Issue::all()
        .filter(Issue::fields().title().eq("Notify off".to_owned()))
        .exec(&mut conn)
        .await
        .expect("issues");
    assert_eq!(issues.len(), 1);
    let pending = IssueMailOutbox::all()
        .filter(IssueMailOutbox::fields().issue_id().eq(issues[0].id))
        .exec(&mut conn)
        .await
        .expect("outbox");
    assert!(pending.is_empty());

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_cross_org_and_denial_send_zero() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin = unique_email("nfy-xo-adm");
    let mem_a = unique_email("nfy-xo-a");
    let mem_b = unique_email("nfy-xo-b");
    let slug_a = unique_slug("nfy-xo-a");
    let slug_b = unique_slug("nfy-xo-b");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("nfy-xo-adm"), "admin")
            .await;
    let _ = create_org_with_membership(&db, &mem_a, "password", &slug_a, "member").await;
    let _ = create_org_with_membership(&db, &mem_b, "password", &slug_b, "member").await;
    let cookie_a = login_cookie(&router, &mem_a).await.expect("a");
    let loc = report_issue(&router, &slug_a, Some(&cookie_a), "Notify xo").await;
    let key = loc.rsplit('/').next().unwrap().split('?').next().unwrap();

    memory.clear();
    let cookie_b = login_cookie(&router, &mem_b).await.expect("b");
    let denied = post_multipart_with_files(
        &router,
        &format!("/{slug_a}/issues/{key}/reply"),
        Some(&cookie_b),
        &[("body", "cross org")],
        &[],
    )
    .await;
    assert_eq!(status(&denied), StatusCode::NOT_FOUND);
    assert_eq!(count_to(&memory.sent(), &mem_b), 0);
    assert_eq!(count_to(&memory.sent(), &mem_a), 0);

    let anon = post_multipart_with_files(
        &router,
        &format!("/{slug_a}/issues"),
        None,
        &[
            ("title", "anon"),
            ("component", "Portal"),
            ("severity", "Major"),
            ("details", "nope"),
        ],
        &[],
    )
    .await;
    assert!(!status(&anon).is_success() || status(&anon).is_redirection());
    assert_eq!(count_to(&memory.sent(), &mem_a), 0);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_circuit_open_leaves_pending_outbox() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let circuit = std::sync::Arc::new(vcp::mail_circuit::MailCircuitBreaker::new(
        &test_config().await.mail,
    ));
    circuit.force_open();
    let router = test_router_with_memory_mail_circuit(memory.clone(), circuit).await;

    let admin = unique_email("nfy-cb-adm");
    let member = unique_email("nfy-cb-mem");
    let slug = unique_slug("nfy-cb");
    let _ =
        create_org_with_membership(&db, &admin, "password", &unique_slug("nfy-cb-adm"), "admin")
            .await;
    let _ = create_org_with_membership(&db, &member, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &member).await.expect("cookie");
    memory.clear();
    let loc = report_issue(&router, &slug, Some(&cookie), "Notify circuit").await;
    assert!(loc.contains("/issues/VBN-"));
    assert!(memory.sent().is_empty());

    let mut conn = db.clone();
    let issues = Issue::all()
        .filter(Issue::fields().title().eq("Notify circuit".to_owned()))
        .exec(&mut conn)
        .await
        .expect("issues");
    assert_eq!(issues.len(), 1);
    let pending = IssueMailOutbox::all()
        .filter(IssueMailOutbox::fields().issue_id().eq(issues[0].id))
        .filter(IssueMailOutbox::fields().sent_at().eq(0_i64))
        .exec(&mut conn)
        .await
        .expect("pending");
    assert!(
        !pending.is_empty(),
        "circuit open must leave pending outbox (source {ISSUE_MAIL_SOURCE_CREATE})"
    );
    let _ = User::all()
        .filter(User::fields().deleted_at().eq(USER_NOT_DELETED))
        .limit(1)
        .exec(&mut conn)
        .await;

    cleanup(&db).await;
}
