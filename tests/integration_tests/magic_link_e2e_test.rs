//! E2E: passwordless magic-link login, JIT admin, denial paths.

use http_body_util::BodyExt;
use topcoat::mail::{MemoryTransport, TextBody};
use topcoat::router::StatusCode;
use vcp::magic_link::{hash_token, issue_token, purge_expired_tokens};
use vcp::models::{MagicLinkToken, PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG, USER_NOT_DELETED, User};

use std::sync::Arc;

use vcp::mail_circuit::MailCircuitBreaker;

use crate::common::{
    assert_topcoat_click_handlers_are_functions, assert_topcoat_submit_handlers_are_functions,
    call_request_login_link, cleanup, create_org_with_membership, db_lock, get, login_cookie,
    procedure_bool_body, procedure_path_from_html, status, test_config, test_db, test_router,
    test_router_with_memory_mail, test_router_with_memory_mail_circuit, unique_email, unique_slug,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn location(resp: &topcoat::router::Response) -> Option<&str> {
    resp.headers().get("location").and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn e2e_login_page_is_email_only_with_signal_panels() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login", None).await;
    assert_eq!(status(&resp), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("name=\"email\""));
    assert!(!html.contains("name=\"password\""));
    assert!(!html.contains("Seed:"));
    assert!(html.contains("Email me a sign-in link"));
    assert!(html.contains("Check your email"));
    assert!(html.contains("Resend in "));
    assert!(html.contains("Use a different email"));
    assert!(html.contains("vb-eph-tick"));
    assert!(
        html.contains("Resend in ")
            && html.contains("hydrate(5")
            && (html.contains("hydrate(0)") || html.contains("hydrate(0.0)")),
        "SSR cooldown seeds for token_ttl_secs=300 should hydrate mins=5 and secs=0"
    );
    assert!(
        procedure_path_from_html(&html).is_some(),
        "login SSR must embed request_login_link procedure id"
    );
    assert_topcoat_click_handlers_are_functions(&html);
    assert_topcoat_submit_handlers_are_functions(&html);
}

#[tokio::test]
async fn e2e_magic_link_login_lands_on_org() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("ml-org");
    let slug = unique_slug("ml-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login_cookie(&router, &email).await.expect("cookie");
    let home = get(&router, &format!("/{slug}"), Some(&cookie)).await;
    assert_eq!(status(&home), StatusCode::OK);
    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_vcp_admin_jit_lands_on_vauban() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;
    let admin = "support@vauban.sh";

    // Remove any leftover admin row from prior runs.
    {
        let mut conn = db.clone();
        let users = User::all()
            .filter(User::fields().email().eq(admin))
            .exec(&mut conn)
            .await
            .unwrap_or_default();
        for u in users {
            let _ = User::delete_by_id(&mut conn, u.id).await;
        }
    }

    let post = call_request_login_link(&router, admin).await;
    assert_eq!(status(&post), StatusCode::OK);

    let sent = memory.sent();
    assert_eq!(sent.len(), 1, "JIT admin must receive a magic link mail");
    let TextBody::Text(body) = sent[0].text().clone() else {
        panic!("expected plain-text magic link body");
    };
    let token = body
        .split("token=")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_hexdigit()).next())
        .expect("token in mail body");

    let consume = get(&router, &format!("/login/magic?token={token}"), None).await;
    assert!(status(&consume).is_redirection());
    let expected = format!("/{RESERVED_ORG_SLUG}");
    assert_eq!(location(&consume), Some(expected.as_str()));

    let mut conn = db.clone();
    let users = User::all()
        .filter(User::fields().email().eq(admin))
        .exec(&mut conn)
        .await
        .expect("users");
    let user = users.into_iter().next().expect("admin user");
    assert_eq!(user.portal_role, PORTAL_ROLE_ADMIN);
    assert_eq!(user.display_name, "Vauban Support");
    assert_eq!(user.deleted_at, USER_NOT_DELETED);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_expired_and_reused_token_denied() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("ml-deny");
    let slug = unique_slug("ml-deny");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let raw = issue_token(&mut conn, user.id, 300).await.expect("issue");
    // Force expiry
    let hash = hash_token(&raw);
    let mut row = vcp::models::MagicLinkToken::get_by_token_hash(&mut conn, &hash)
        .await
        .expect("token");
    row.update()
        .expires_at(1)
        .exec(&mut conn)
        .await
        .expect("expire");

    let expired = get(&router, &format!("/login/magic?token={raw}"), None).await;
    assert_eq!(location(&expired), Some("/login?error=link"));

    let raw2 = issue_token(&mut conn, user.id, 300).await.expect("issue2");
    let first = get(&router, &format!("/login/magic?token={raw2}"), None).await;
    assert!(status(&first).is_redirection());
    let second = get(&router, &format!("/login/magic?token={raw2}"), None).await;
    assert_eq!(location(&second), Some("/login?error=link"));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_reissue_invalidates_prior_unused_token() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("ml-supersede");
    let slug = unique_slug("ml-supersede");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let mut conn = db.clone();
    let older = issue_token(&mut conn, user.id, 300)
        .await
        .expect("issue older");
    let newer = issue_token(&mut conn, user.id, 300)
        .await
        .expect("issue newer");
    assert_ne!(older, newer);

    let stale = get(&router, &format!("/login/magic?token={older}"), None).await;
    assert_eq!(
        location(&stale),
        Some("/login?error=link"),
        "prior unused magic link must die when a newer one is issued"
    );

    let fresh = get(&router, &format!("/login/magic?token={newer}"), None).await;
    assert!(status(&fresh).is_redirection());
    let expected = format!("/{slug}");
    assert_eq!(location(&fresh), Some(expected.as_str()));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_unknown_email_same_ok_no_mail() {
    let _guard = db_lock().lock().await;
    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;
    let missing = unique_email("ml-unknown");
    let resp = call_request_login_link(&router, &missing).await;
    assert_eq!(status(&resp), StatusCode::OK);
    assert!(
        procedure_bool_body(resp).await,
        "closed circuit: unknown email still Check-your-email"
    );
    assert!(memory.sent().is_empty(), "unknown email must not send mail");
}

#[tokio::test]
async fn e2e_known_email_sends_mail_via_procedure() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail(memory.clone()).await;

    let email = unique_email("ml-known");
    let slug = unique_slug("ml-known");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let resp = call_request_login_link(&router, &email).await;
    assert_eq!(status(&resp), StatusCode::OK);
    assert!(
        procedure_bool_body(resp).await,
        "closed circuit: known email Check-your-email"
    );
    assert_eq!(
        memory.sent().len(),
        1,
        "known email must receive magic link"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_mail_circuit_open_same_unavailable_no_oracle() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let cfg = test_config().await;
    let circuit = Arc::new(MailCircuitBreaker::new(&cfg.mail));
    circuit.force_open();
    let memory = MemoryTransport::new();
    let router = test_router_with_memory_mail_circuit(memory.clone(), circuit).await;

    let email = unique_email("ml-circuit-known");
    let slug = unique_slug("ml-circuit-known");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let missing = unique_email("ml-circuit-missing");

    let known = call_request_login_link(&router, &email).await;
    let unknown = call_request_login_link(&router, &missing).await;
    assert_eq!(status(&known), StatusCode::OK);
    assert_eq!(status(&unknown), StatusCode::OK);
    assert!(
        !procedure_bool_body(known).await,
        "open circuit: known email must get unavailable"
    );
    assert!(
        !procedure_bool_body(unknown).await,
        "open circuit: unknown email must get same unavailable (no oracle)"
    );
    assert!(
        memory.sent().is_empty(),
        "open circuit must not send magic-link mail"
    );

    let page = get(&router, "/login", None).await;
    let html = body_text(page).await;
    assert!(
        html.contains("Sign-in is temporarily unavailable. Please try again later."),
        "login SSR must embed unavailable copy"
    );
    assert!(html.contains("Sending..."));

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_check_email_route_gone() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;
    let resp = get(&router, "/login/check-email", None).await;
    assert_eq!(status(&resp), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn e2e_failed_magic_link_shows_generic_error() {
    let _guard = db_lock().lock().await;
    let router = test_router().await;

    let clean = get(&router, "/login", None).await;
    assert_eq!(status(&clean), StatusCode::OK);
    let clean_html = body_text(clean).await;
    assert!(
        !clean_html.contains("This sign-in link is invalid or has expired"),
        "clean /login must not show the link-error banner"
    );

    let junk = get(&router, "/login/magic?token=not-a-real-token", None).await;
    assert_eq!(location(&junk), Some("/login?error=link"));

    let with_error = get(&router, "/login?error=link", None).await;
    assert_eq!(status(&with_error), StatusCode::OK);
    let err_html = body_text(with_error).await;
    assert!(err_html.contains("This sign-in link is invalid or has expired. Request a new one."));
    assert!(err_html.contains("vb-login-error"));
    assert!(err_html.contains("role=\"alert\""));

    let other = get(&router, "/login?error=other", None).await;
    let other_html = body_text(other).await;
    assert!(
        !other_html.contains("This sign-in link is invalid or has expired"),
        "unknown error= values must not show the link-error banner"
    );
}

/// Retention 0 (testing.toml): expired rows purge; still-valid tokens remain.
#[tokio::test]
async fn e2e_purge_expired_tokens_keeps_active_deletes_stale() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("ml-purge");
    let slug = unique_slug("ml-purge");
    let (user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut conn = db.clone();
    let fresh_raw = issue_token(&mut conn, user.id, 300)
        .await
        .expect("fresh issue");
    let fresh_hash = hash_token(&fresh_raw);
    let stale_hash = format!("stale-{}", unique_slug("h"));
    toasty::create!(MagicLinkToken {
        token_hash: stale_hash.clone(),
        user_id: user.id,
        expires_at: now - 120,
        consumed_at: now - 60,
        created_at: now - 3600,
    })
    .exec(&mut conn)
    .await
    .expect("stale expired row");

    let deleted = purge_expired_tokens(&mut conn, now, 0)
        .await
        .expect("purge");
    assert!(deleted >= 1, "purge must delete the expired row");

    let leftover = MagicLinkToken::all()
        .filter(MagicLinkToken::fields().user_id().eq(user.id))
        .exec(&mut conn)
        .await
        .expect("list");
    assert!(
        leftover.iter().all(|t| t.expires_at >= now),
        "no expired rows should remain; got {leftover:?}"
    );
    assert!(
        leftover.iter().any(|t| t.token_hash == fresh_hash),
        "active issued token must survive purge"
    );
    assert!(
        leftover.iter().all(|t| t.token_hash != stale_hash),
        "stale hash must be gone"
    );

    let user_again = vcp::magic_link::consume_token(&mut conn, &fresh_raw)
        .await
        .expect("consume")
        .expect("active token still valid");
    assert_eq!(user_again.id, user.id);

    cleanup(&db).await;
}
