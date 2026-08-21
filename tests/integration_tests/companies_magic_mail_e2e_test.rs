//! E2E: company invite / revoke / revive mails and soft-delete preserves opener.

use topcoat::context::Cx;
use topcoat::mail::{MemoryTransport, TextBody};
use vcp::models::{MEMBERSHIP_ROLE_ORG, USER_NOT_DELETED, User};

use crate::common::{
    cleanup, create_membership, create_org_with_membership, create_test_issue, create_test_org,
    db_lock, login_cookie, post_form, status, test_db, test_router_with_memory_mail, unique_email,
    unique_slug, unique_suffix, urlencoding_encode,
};

fn company_compose_form(name: &str, emails: &[&str]) -> String {
    let rows = emails.len().max(1);
    let mut parts = vec![
        format!("name={}", urlencoding_encode(name)),
        "contact_name=Ops".to_owned(),
        "contact_email=ops%40example.com".to_owned(),
        "vat=FR123".to_owned(),
        "address=1+Test".to_owned(),
        "lts_subscriptions=0".to_owned(),
        "industrial_lts_subscriptions=0".to_owned(),
        format!("account_rows={rows}"),
        "compose_action=save".to_owned(),
    ];
    if emails.is_empty() {
        parts.push("email_0=".to_owned());
    } else {
        for (i, email) in emails.iter().enumerate() {
            parts.push(format!("email_{i}={}", urlencoding_encode(email)));
        }
    }
    parts.join("&")
}

fn mail_to_contains(mail: &topcoat::mail::Mail, email: &str) -> bool {
    mail.to().iter().any(|mb| mb.address() == email)
}

fn mail_text(mail: &topcoat::mail::Mail) -> String {
    match mail.text() {
        TextBody::Text(t) => t.clone(),
        _ => String::new(),
    }
}

fn mail_html(mail: &topcoat::mail::Mail) -> String {
    let cx = Cx::default();
    mail.html()
        .map(|v| v.clone().render(&cx))
        .unwrap_or_default()
}

#[tokio::test]
async fn e2e_company_invite_revoke_revive_preserves_user_id() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin_email = unique_email("cmm-admin");
    let admin_slug = unique_slug("cmm-admin");
    let (_admin, _) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email)
        .await
        .expect("admin cookie");

    let member_email = unique_email("cmm-member");
    let org_name = format!("CMM {}", unique_slug("co"));
    memory.clear();
    let create = post_form(
        &router,
        "/admin/companies/new",
        Some(&admin_cookie),
        &company_compose_form(&org_name, &[&member_email]),
    )
    .await;
    assert!(
        status(&create).is_redirection(),
        "create company should redirect"
    );

    let sent = memory.sent();
    assert!(
        sent.iter().any(|m| {
            mail_to_contains(m, &member_email)
                && (mail_text(m).contains("invited") || mail_text(m).contains("Sign in"))
                && mail_html(m).contains(r#"src="cid:vauban-logo""#)
                && m.attachments()
                    .iter()
                    .any(|a| a.content_id() == Some("vauban-logo"))
        }),
        "create must send branded invitation mail"
    );

    assert!(
        login_cookie(&router, &member_email).await.is_some(),
        "invited member must login via magic link"
    );

    let mut conn = db.clone();
    let users = User::all()
        .filter(User::fields().email().eq(&member_email))
        .exec(&mut conn)
        .await
        .expect("users");
    let member = users.into_iter().next().expect("member");
    let orgs = vcp::models::Organization::all()
        .exec(&mut conn)
        .await
        .expect("orgs");
    let org = orgs
        .into_iter()
        .find(|o| o.name == org_name)
        .expect("created org");

    let issue_key = format!("VBN-{}", unique_suffix());
    create_test_issue(
        &db,
        org.id,
        member.id,
        &issue_key,
        "Soft-delete opener",
        "Open",
    )
    .await;

    memory.clear();
    let edit = post_form(
        &router,
        &format!("/admin/companies/{}", org.id),
        Some(&admin_cookie),
        &company_compose_form(&org_name, &[]),
    )
    .await;
    assert!(status(&edit).is_redirection());

    let revoked = memory.sent();
    assert!(
        revoked.iter().any(|m| {
            mail_to_contains(m, &member_email) && m.subject().contains("Access removed")
        }),
        "remove must send revocation mail"
    );

    let users = User::all()
        .filter(User::fields().email().eq(&member_email))
        .exec(&mut conn)
        .await
        .expect("users");
    let soft = users.into_iter().next().expect("soft-deleted user");
    assert_ne!(soft.deleted_at, USER_NOT_DELETED);
    assert!(
        login_cookie(&router, &member_email).await.is_none(),
        "soft-deleted user must not login"
    );

    // Opener row still present for issue history.
    let issues = vcp::models::Issue::all()
        .filter(vcp::models::Issue::fields().key().eq(&issue_key))
        .exec(&mut conn)
        .await
        .expect("issues");
    assert_eq!(issues[0].opened_by_user_id, soft.id);

    memory.clear();
    let revive = post_form(
        &router,
        &format!("/admin/companies/{}", org.id),
        Some(&admin_cookie),
        &company_compose_form(&org_name, &[&member_email]),
    )
    .await;
    assert!(status(&revive).is_redirection());
    assert!(
        memory
            .sent()
            .iter()
            .any(|m| mail_to_contains(m, &member_email)),
        "revive must re-invite"
    );
    let users = User::all()
        .filter(User::fields().email().eq(&member_email))
        .exec(&mut conn)
        .await
        .expect("users");
    let revived = users.into_iter().next().expect("revived");
    assert_eq!(revived.id, soft.id, "revive must keep same user_id");
    assert_eq!(revived.deleted_at, USER_NOT_DELETED);

    cleanup(&db).await;
}

/// Removing a membership from one org must send revocation mail even when the
/// user remains a member of another org (no soft-delete).
#[tokio::test]
async fn e2e_multi_org_remove_sends_revocation_without_soft_delete() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin_email = unique_email("cmm-mo-admin");
    let admin_slug = unique_slug("cmm-mo-admin");
    let (_admin, _) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email)
        .await
        .expect("admin cookie");

    let member_email = unique_email("cmm-mo-member");
    let org_a_name = format!("CMM-A {}", unique_slug("coa"));
    memory.clear();
    let create_a = post_form(
        &router,
        "/admin/companies/new",
        Some(&admin_cookie),
        &company_compose_form(&org_a_name, &[&member_email]),
    )
    .await;
    assert!(status(&create_a).is_redirection());

    let mut conn = db.clone();
    let users = User::all()
        .filter(User::fields().email().eq(&member_email))
        .exec(&mut conn)
        .await
        .expect("users");
    let member = users.into_iter().next().expect("member");
    let orgs = vcp::models::Organization::all()
        .exec(&mut conn)
        .await
        .expect("orgs");
    let org_a = orgs
        .into_iter()
        .find(|o| o.name == org_a_name)
        .expect("org A");

    // Second org membership (same user) — not via companies form so sync of A
    // leaves this membership intact.
    let org_b = create_test_org(&db, &unique_slug("cob")).await;
    create_membership(&db, member.id, org_b.id, MEMBERSHIP_ROLE_ORG).await;

    memory.clear();
    let edit = post_form(
        &router,
        &format!("/admin/companies/{}", org_a.id),
        Some(&admin_cookie),
        &company_compose_form(&org_a_name, &[]),
    )
    .await;
    assert!(status(&edit).is_redirection());

    let revoked = memory.sent();
    assert!(
        revoked.iter().any(|m| {
            mail_to_contains(m, &member_email)
                && m.subject().contains("Access removed")
                && m.subject().contains(&org_a_name)
        }),
        "multi-org remove must send org-scoped revocation mail"
    );

    let users = User::all()
        .filter(User::fields().email().eq(&member_email))
        .exec(&mut conn)
        .await
        .expect("users");
    let still = users.into_iter().next().expect("active user");
    assert_eq!(
        still.deleted_at, USER_NOT_DELETED,
        "user with remaining membership must not be soft-deleted"
    );
    assert!(
        login_cookie(&router, &member_email).await.is_some(),
        "user must still login via remaining org membership"
    );

    cleanup(&db).await;
}
