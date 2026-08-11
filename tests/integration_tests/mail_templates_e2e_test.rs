//! E2E: invite / login / revoke mails carry branded HTML + CID logo.

use topcoat::context::Cx;
use topcoat::mail::{MemoryTransport, TextBody};
use topcoat::router::StatusCode;

use crate::common::{
    call_request_login_link, cleanup, create_org_with_membership, db_lock, login_cookie, post_form,
    status, test_db, test_router_with_memory_mail, unique_email, unique_slug, urlencoding_encode,
};

fn company_compose_form(name: &str, emails: &[&str]) -> String {
    let rows = emails.len().max(1);
    let mut parts = vec![
        format!("name={}", urlencoding_encode(name)),
        "contact_name=Ops".to_owned(),
        "contact_email=ops%40example.com".to_owned(),
        "vat=FR123".to_owned(),
        "address=1+Test".to_owned(),
        "lts_subscriptions=1".to_owned(),
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
    mail.html().map(|v| v.render(&cx)).unwrap_or_default()
}

fn assert_branded(mail: &topcoat::mail::Mail) {
    let html = mail_html(mail);
    assert!(
        !html.is_empty(),
        "mail must include HTML body: subject={}",
        mail.subject()
    );
    assert!(
        html.contains(r#"src="cid:vauban-logo""#),
        "HTML must reference cid logo: {html}"
    );
    assert!(
        mail.attachments()
            .iter()
            .any(|a| a.content_id() == Some("vauban-logo") && a.content_type() == "image/png"),
        "mail must carry inline vauban-logo PNG"
    );
    assert!(
        !mail_text(mail).is_empty(),
        "mail must keep plain-text alternative"
    );
}

#[tokio::test]
async fn e2e_invite_login_revoke_mails_are_branded_html() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let admin_email = unique_email("mt-admin");
    let admin_slug = unique_slug("mt-admin");
    let (_admin, _) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login_cookie(&router, &admin_email)
        .await
        .expect("admin cookie");

    let member_email = unique_email("mt-member");
    let org_name = format!("MailTpl {}", unique_slug("co"));
    memory.clear();
    let create = post_form(
        &router,
        "/admin/companies/new",
        Some(&admin_cookie),
        &company_compose_form(&org_name, &[&member_email]),
    )
    .await;
    assert!(status(&create).is_redirection());

    let invite = memory
        .sent()
        .into_iter()
        .find(|m| mail_to_contains(m, &member_email))
        .expect("invitation mail");
    assert_branded(&invite);
    let invite_html = mail_html(&invite);
    assert!(
        invite_html.contains(&org_name),
        "invite HTML must show org name: {invite_html}"
    );
    assert!(
        invite_html.contains("/login/magic?token="),
        "invite HTML must include magic URL"
    );
    assert!(
        mail_text(&invite).contains("invited") || mail_text(&invite).contains("Sign in"),
        "invite text alternative"
    );

    memory.clear();
    let login = call_request_login_link(&router, &member_email).await;
    assert_eq!(status(&login), StatusCode::OK);
    let login_mail = memory
        .sent()
        .into_iter()
        .find(|m| mail_to_contains(m, &member_email))
        .expect("login mail");
    assert_branded(&login_mail);
    assert!(
        login_mail.subject().contains("Sign in"),
        "login subject: {}",
        login_mail.subject()
    );
    let login_html = mail_html(&login_mail);
    assert!(login_html.contains("/login/magic?token="));
    assert!(login_html.contains("minutes"));

    let mut conn = db.clone();
    let orgs = vcp::models::Organization::all()
        .exec(&mut conn)
        .await
        .expect("orgs");
    let org = orgs
        .into_iter()
        .find(|o| o.name == org_name)
        .expect("created org");

    memory.clear();
    let edit = post_form(
        &router,
        &format!("/admin/companies/{}", org.id),
        Some(&admin_cookie),
        &company_compose_form(&org_name, &[]),
    )
    .await;
    assert!(status(&edit).is_redirection());
    let revoke = memory
        .sent()
        .into_iter()
        .find(|m| mail_to_contains(m, &member_email) && m.subject().contains("Access removed"))
        .expect("revocation mail");
    assert_branded(&revoke);
    let revoke_html = mail_html(&revoke);
    assert!(
        revoke_html.contains(&org_name),
        "revoke HTML must show org: {revoke_html}"
    );
    assert!(
        !revoke_html.contains("/login/magic?token="),
        "revoke must not include a sign-in link"
    );

    cleanup(&db).await;
}
