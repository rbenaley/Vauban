//! E2E: admin company create/edit/delete + seats + member 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{MAX_USERS_PER_COMPANY, Membership, Organization, RESERVED_ORG_SLUG, User};
use vcp::seats::{can_add_member, membership_count};

use crate::common::{
    assert_topcoat_click_handlers_are_functions, cleanup, create_membership,
    create_org_with_membership, create_test_org, create_test_user, db_lock, get, login_cookie,
    post_form, status, test_db, test_router, unique_email, unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::response::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    login_cookie(router, email).await
}

struct ComposeLts {
    lts: i32,
    industrial: i32,
}

fn company_compose_form(
    name: &str,
    contact_name: &str,
    contact_email: &str,
    vat: &str,
    address: &str,
    emails: &[&str],
) -> String {
    company_compose_form_with_lts(
        name,
        contact_name,
        contact_email,
        vat,
        address,
        emails,
        ComposeLts {
            lts: 0,
            industrial: 0,
        },
    )
}

fn company_compose_form_with_lts(
    name: &str,
    contact_name: &str,
    contact_email: &str,
    vat: &str,
    address: &str,
    emails: &[&str],
    counts: ComposeLts,
) -> String {
    let mut parts = vec![
        format!("name={}", urlencoding_encode(name)),
        format!("contact_name={}", urlencoding_encode(contact_name)),
        format!("contact_email={}", urlencoding_encode(contact_email)),
        format!("vat={}", urlencoding_encode(vat)),
        format!("address={}", urlencoding_encode(address)),
        format!("lts_subscriptions={}", counts.lts),
        format!("industrial_lts_subscriptions={}", counts.industrial),
        format!("account_rows={}", emails.len().max(1)),
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

#[tokio::test]
async fn e2e_admin_creates_company_with_emails() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-admin");
    let slug = unique_slug("co-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Test Co {}", unique_slug("name"));
    let a = unique_email("co-a");
    let b = unique_email("co-b");
    let form = company_compose_form(
        &name,
        "Ops Contact",
        "ops@example.com",
        "FR123",
        "1 Test",
        &[&a, &b],
    );
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(
        status(&create),
        StatusCode::SEE_OTHER,
        "create must 303 See Other (not 307), got {}",
        status(&create)
    );

    // Filter by unique name — leftover non-test-* orgs can fill page 1 (size 3).
    let list = get(
        &router,
        &format!("/admin/companies?q={}", urlencoding_encode(&name)),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    assert!(html.contains(&a), "list should show account pill: {html}");
    assert!(html.contains(&b), "list should show second account: {html}");
    assert!(
        html.contains("Ops Contact") && html.contains("ops@example.com"),
        "list should show split technical contact: {html}"
    );
    assert!(html.contains("+ New company"));
    assert!(html.contains("USER ACCOUNTS"));

    let org = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("created org")
    };
    assert_eq!(org.technical_contact_name, "Ops Contact");
    assert_eq!(org.technical_contact_email, "ops@example.com");
    {
        let mut conn = db.clone();
        let n = membership_count(&mut conn, org.id).await.unwrap();
        assert_eq!(n, 2);
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_edit_and_delete_company() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-edit");
    let slug = unique_slug("co-edit-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Edit Co {}", unique_slug("ed"));
    let a = unique_email("edit-a");
    let form = company_compose_form(&name, "", "c@x.test", "V", "A", &[&a]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::SEE_OTHER);

    let org_id = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("org")
            .id
    };

    let edit_get = get(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&edit_get), StatusCode::OK);
    let html = body_text(edit_get).await;
    assert!(html.contains("Edit client company"));
    assert!(html.contains(&a));
    assert!(
        html.contains("aria-label=\"Remove account\"") && html.contains("value=\"remove:0\""),
        "sole filled account must keep Remove: {html}"
    );
    assert!(!html.contains("type=\"password\""));

    // add_row is a POST re-render: must keep the admin shell (CSS), not a bare View.
    let add_form = company_compose_form(&name, "", "c@x.test", "V", "A", &[&a])
        .replace("compose_action=save", "compose_action=add_row");
    let add_row = post_form(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
        &add_form,
    )
    .await;
    assert_eq!(status(&add_row), StatusCode::OK);
    let add_html = body_text(add_row).await;
    assert!(
        add_html.contains("vb-shell") && add_html.contains("vb-form"),
        "add_row must render inside admin shell with styles"
    );
    assert!(
        add_html.contains("name=\"email_1\"") || add_html.contains("account_rows\" value=\"2\""),
        "add_row should expose a second email slot"
    );

    let b = unique_email("edit-b");
    let save = post_form(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
        &company_compose_form(&name, "", "c@x.test", "V", "A", &[&a, &b]),
    )
    .await;
    assert_eq!(status(&save), StatusCode::SEE_OTHER);
    {
        let mut conn = db.clone();
        assert_eq!(membership_count(&mut conn, org_id).await.unwrap(), 2);
    }

    let del_page = get(
        &router,
        &format!("/admin/companies?delete={org_id}"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&del_page), StatusCode::OK);
    let html = body_text(del_page).await;
    assert!(html.contains("Delete this company?"));

    let deleted = post_form(
        &router,
        &format!("/admin/companies/{org_id}/delete"),
        cookie.as_deref(),
        "confirm=delete",
    )
    .await;
    assert!(status(&deleted).is_redirection());
    {
        let mut conn = db.clone();
        let still = Organization::all()
            .filter(Organization::fields().id().eq(org_id))
            .exec(&mut conn)
            .await
            .expect("orgs");
        assert!(still.is_empty());
        let mems = Membership::all()
            .filter(Membership::fields().organization_id().eq(org_id))
            .exec(&mut conn)
            .await
            .expect("mems");
        assert!(mems.is_empty());
        let orphan = User::all()
            .filter(User::fields().email().eq(&a))
            .exec(&mut conn)
            .await
            .expect("user");
        assert_eq!(orphan.len(), 1, "orphan client user should be soft-deleted");
        assert_ne!(
            orphan[0].deleted_at,
            vcp::models::USER_NOT_DELETED,
            "orphan client user must have deleted_at set"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_seat_helper_respects_max_users() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;

    let email = unique_email("co-seats");
    let slug = unique_slug("co-seats-org");
    let (_user, org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let max = MAX_USERS_PER_COMPANY;

    {
        let mut conn = db.clone();
        assert!(can_add_member(&mut conn, org.id, max).await.unwrap());
    }

    let mut conn = db.clone();
    let mut count = membership_count(&mut conn, org.id).await.unwrap();
    while count < max {
        let u = create_test_user(&db, &unique_email("fill"), "password").await;
        create_membership(&db, u.id, org.id, "member").await;
        count = membership_count(&mut conn, org.id).await.unwrap();
    }
    assert_eq!(count, max);
    assert!(!can_add_member(&mut conn, org.id, max).await.unwrap());

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_create_rejects_invalid_contact_email() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-bad-contact");
    let slug = unique_slug("co-bad-contact-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let before = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };

    let name = format!("Bad Contact Co {}", unique_slug("badc"));
    let account = unique_email("co-ok-account");
    let form = company_compose_form(&name, "Ada Lovelace", "not-an-email", "", "", &[&account]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::OK);
    let html = body_text(create).await;
    assert!(
        html.contains("Invalid email address") && html.contains("not-an-email"),
        "expected contact Mailbox validation error: {html}"
    );
    assert!(
        html.contains("Ada Lovelace") && html.contains("name=\"contact_name\""),
        "form must re-render dual contact fields: {html}"
    );

    let after = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };
    assert_eq!(
        before, after,
        "invalid contact email must not create a company"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_create_rejects_invalid_email() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-badmail");
    let slug = unique_slug("co-badmail-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let before = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };

    let name = format!("Bad Mail Co {}", unique_slug("bad"));
    let form = company_compose_form(&name, "", "", "", "", &["not-an-email"]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::OK);
    let html = body_text(create).await;
    assert!(
        html.contains("Invalid email address") && html.contains("not-an-email"),
        "expected Mailbox validation error: {html}"
    );

    let after = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };
    assert_eq!(before, after, "invalid email must not create a company");

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_edit_rejects_invalid_email_without_mutating_memberships() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-edit-bad");
    let slug = unique_slug("co-edit-bad-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Edit Bad {}", unique_slug("eb"));
    let good = unique_email("edit-good");
    let create = post_form(
        &router,
        "/admin/companies/new",
        cookie.as_deref(),
        &company_compose_form(&name, "", "c@x.test", "V", "A", &[&good]),
    )
    .await;
    assert_eq!(status(&create), StatusCode::SEE_OTHER);

    let org_id = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("org")
            .id
    };
    {
        let mut conn = db.clone();
        assert_eq!(membership_count(&mut conn, org_id).await.unwrap(), 1);
    }

    let save = post_form(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
        &company_compose_form(&name, "", "c@x.test", "V", "A", &[&good, "not-an-email"]),
    )
    .await;
    assert_eq!(status(&save), StatusCode::OK);
    let html = body_text(save).await;
    assert!(html.contains("Invalid email address"));
    {
        let mut conn = db.clone();
        assert_eq!(
            membership_count(&mut conn, org_id).await.unwrap(),
            1,
            "invalid edit must not change memberships"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_create_rejects_over_cap() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-cap");
    let slug = unique_slug("co-cap-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Cap Co {}", unique_slug("cap"));
    let emails: Vec<String> = (0..6).map(|i| unique_email(&format!("cap{i}"))).collect();
    let email_refs: Vec<&str> = emails.iter().map(String::as_str).collect();
    let form = company_compose_form(&name, "", "", "", "", &email_refs);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(
        status(&create),
        StatusCode::OK,
        "over-cap save should re-render form"
    );
    let html = body_text(create).await;
    assert!(
        html.contains("At most") || html.contains("user accounts"),
        "should show seat error: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_company_form_lts_steppers_are_client_signals() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-lts-sig");
    let slug = unique_slug("co-lts-sig-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let page = get(&router, "/admin/companies/new", cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::OK);
    let html = body_text(page).await;
    assert!(
        html.contains("data-lts-stepper-client"),
        "new form must mark client LTS steppers: {html}"
    );
    assert!(
        html.contains("data-industrial-lts-stepper-client"),
        "new form must mark client industrial steppers: {html}"
    );
    assert!(
        !html.contains("compose_action\" value=\"lts_inc\"") && !html.contains("value=\"lts_inc\""),
        "LTS + must not POST compose_action: {html}"
    );
    assert_topcoat_click_handlers_are_functions(&html);
    assert!(
        !html.contains("aria-label=\"Remove account\""),
        "new-company padded empty row must not show Remove: {html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_remove_last_company_account() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-rm-last");
    let slug = unique_slug("co-rm-last-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("Rm Last {}", unique_slug("rml"));
    let a = unique_email("rm-last-a");
    let form = company_compose_form(&name, "", "c@x.test", "V", "A", &[&a]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::SEE_OTHER);

    let org_id = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("org")
            .id
    };
    {
        let mut conn = db.clone();
        assert_eq!(membership_count(&mut conn, org_id).await.unwrap(), 1);
    }

    let remove_form = company_compose_form(&name, "", "c@x.test", "V", "A", &[&a])
        .replace("compose_action=save", "compose_action=remove:0");
    let removed = post_form(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
        &remove_form,
    )
    .await;
    assert_eq!(status(&removed), StatusCode::OK);
    let html = body_text(removed).await;
    assert!(
        !html.contains("aria-label=\"Remove account\""),
        "after removing the last account, padded empty row hides Remove: {html}"
    );

    let save_empty = company_compose_form(&name, "", "c@x.test", "V", "A", &[]);
    let saved = post_form(
        &router,
        &format!("/admin/companies/{org_id}"),
        cookie.as_deref(),
        &save_empty,
    )
    .await;
    assert_eq!(status(&saved), StatusCode::SEE_OTHER);
    {
        let mut conn = db.clone();
        assert_eq!(
            membership_count(&mut conn, org_id).await.unwrap(),
            0,
            "saving an empty account list must drop the last membership"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_member_denied_admin_companies() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-mem");
    let slug = unique_slug("co-mem-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "member").await;
    let cookie = login(&router, &email).await;

    let page = get(&router, "/admin/companies/new", cookie.as_deref()).await;
    assert_eq!(status(&page), StatusCode::NOT_FOUND);

    let form = company_compose_form("Test Denied", "", "", "", "", &[]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::NOT_FOUND);

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_reserved_org_slug_rejected_and_hidden_from_list() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-reserved");
    let slug = unique_slug("co-reserved-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let before = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };

    let form = company_compose_form("Vauban", "", "", "", "", &[]);
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(
        status(&create),
        StatusCode::OK,
        "reserved name should re-render form with error"
    );
    let html = body_text(create).await;
    assert!(
        html.contains("reserved") || html.contains("New client company"),
        "expected reserved error on form: {html}"
    );

    let after = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .len()
    };
    assert_eq!(before, after, "must not insert a reserved-slug company");

    let list = get(&router, "/admin/companies", cookie.as_deref()).await;
    assert_eq!(status(&list), StatusCode::OK);
    let html = body_text(list).await;
    let cards: Vec<&str> = html.split("vb-company-card").skip(1).collect();
    for card in cards {
        assert!(
            !card.contains(RESERVED_ORG_SLUG),
            "companies list cards must exclude reserved slug"
        );
    }

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_companies_list_pagination() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("co-page");
    let slug = unique_slug("co-page-org");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let marker = unique_slug("copagefix");
    for i in 0..4u32 {
        let org_slug = unique_slug(&format!("{marker}-{i}"));
        create_test_org(&db, &org_slug).await;
    }

    let page1 = get(
        &router,
        &format!("/admin/companies?q={marker}&page=1"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page1), StatusCode::OK);
    let p1 = body_text(page1).await;
    // Prefer exact class — `vb-company-card-head` also contains the substring.
    let cards_p1 = p1.matches("class=\"vb-company-card\"").count();
    assert_eq!(
        cards_p1, 3,
        "page 1 must show 3 cards with ≥4 fixtures: {p1}"
    );
    assert!(p1.contains("vb-pager"), "pager when >3: {p1}");
    assert!(
        p1.contains("vb-list-toolbar"),
        "toolbar pager (no chips): {p1}"
    );
    assert!(
        p1.contains("page=2") && p1.contains(&marker),
        "next page link keeps q: {p1}"
    );
    assert!(
        !pager_hrefs_contain_delete(&p1),
        "pager hrefs must omit delete=: {p1}"
    );
    assert!(
        p1.contains("data-admin-companies-search-shard"),
        "live shard container: {p1}"
    );

    let page2 = get(
        &router,
        &format!("/admin/companies?q={marker}&page=2"),
        cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&page2), StatusCode::OK);
    let p2 = body_text(page2).await;
    let cards_p2 = p2.matches("class=\"vb-company-card\"").count();
    assert!(
        (1..=3).contains(&cards_p2),
        "page 2 card count: {cards_p2} in {p2}"
    );
    assert!(p2.contains(&marker), "page 2 keeps fixture remainder: {p2}");
    assert!(
        !pager_hrefs_contain_delete(&p2),
        "page 2 pager hrefs must omit delete=: {p2}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_lts_counters_persist_and_fiche_user_can_login() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("lts-admin");
    let admin_slug = unique_slug("lts-admin-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login(&router, &admin_email).await;

    let name = format!("LTS Co {}", unique_slug("ltsname"));
    let member_email = unique_email("lts-member");
    let address = "9 Rue des Compteurs";
    let vat = "FR998877665";
    let form = company_compose_form_with_lts(
        &name,
        "LTS Contact",
        "lts-ops@example.com",
        vat,
        address,
        &[&member_email],
        ComposeLts {
            lts: 2,
            industrial: 1,
        },
    );
    let create = post_form(
        &router,
        "/admin/companies/new",
        admin_cookie.as_deref(),
        &form,
    )
    .await;
    assert_eq!(status(&create), StatusCode::SEE_OTHER);

    let org = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("created org")
    };
    assert_eq!(org.lts_subscriptions, 2);
    assert_eq!(org.industrial_lts_subscriptions, 1);
    assert_eq!(org.address, address);
    assert_eq!(org.vat, vat);

    let list = get(
        &router,
        &format!("/admin/companies?q={}", urlencoding_encode(&name)),
        admin_cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&list), StatusCode::OK);
    let list_html = body_text(list).await;
    assert!(
        list_html.contains("SUBSCRIPTIONS (VAUBAN LTS / VAUBAN INDUSTRIAL LTS)"),
        "list card LTS meta label: {list_html}"
    );
    assert!(
        list_html.contains("vb-company-meta-col subs")
            || list_html.contains("data-company-subscriptions=\"2/1\""),
        "list card must show subscriptions meta column: {list_html}"
    );
    assert!(
        list_html.contains("data-company-subscriptions=\"2/1\"") || list_html.contains("2/1"),
        "list card must show LTS ratio 2/1: {list_html}"
    );
    assert!(list_html.contains(&member_email), "{list_html}");

    let edit = get(
        &router,
        &format!("/admin/companies/{}", org.id),
        admin_cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&edit), StatusCode::OK);
    let edit_html = body_text(edit).await;
    assert!(
        edit_html.contains("data-lts-subscriptions=\"2\"") || edit_html.contains(">2<"),
        "edit form must show LTS=2: {edit_html}"
    );
    assert!(
        edit_html.contains("data-industrial-lts-subscriptions=\"1\"")
            || edit_html.contains("data-industrial-lts-stepper-client"),
        "edit form must show industrial stepper: {edit_html}"
    );
    assert!(
        edit_html.contains("data-lts-stepper-client"),
        "edit form must expose client LTS steppers: {edit_html}"
    );
    assert_topcoat_click_handlers_are_functions(&edit_html);

    // Sign out staff; login as fiche-provisioned member via magic link.
    let _ = post_form(&router, "/logout", admin_cookie.as_deref(), "").await;
    let member_cookie = login_cookie(&router, &member_email).await;
    assert!(
        member_cookie.is_some(),
        "fiche user must login via magic link"
    );

    let home = get(&router, &format!("/{}", org.slug), member_cookie.as_deref()).await;
    assert_eq!(
        status(&home),
        StatusCode::OK,
        "new org home must be accessible after company create"
    );

    let account = get(
        &router,
        &format!("/{}/account", org.slug),
        member_cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&account), StatusCode::OK);
    let account_html = body_text(account).await;
    assert!(
        account_html.contains(address),
        "account must show company address: {account_html}"
    );
    assert!(
        account_html.contains(vat),
        "account must show company VAT: {account_html}"
    );
    assert!(
        account_html.contains("data-account-lts=\"2\"") || account_html.contains(">2<"),
        "account LTS=2: {account_html}"
    );
    assert!(
        account_html.contains("data-account-industrial-lts=\"1\"")
            || account_html.contains("Industrial"),
        "account industrial LTS: {account_html}"
    );
    assert!(
        account_html.contains(&member_email),
        "account must list member email: {account_html}"
    );

    cleanup(&db).await;
}

/// Multi-line Company address displays with the technical-contact separator.
#[tokio::test]
async fn e2e_admin_companies_multiline_address_uses_display_sep() {
    use vcp::companies_accounts::{COMPANY_DISPLAY_SEP, format_company_address};

    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let admin_email = unique_email("addr-admin");
    let admin_slug = unique_slug("addr-admin-org");
    let (_admin, _aorg) =
        create_org_with_membership(&db, &admin_email, "password", &admin_slug, "admin").await;
    let admin_cookie = login(&router, &admin_email).await;

    let name = format!("Addr Co {}", unique_slug("addrco"));
    let member_email = unique_email("addr-member");
    let address = "Scalable Solutions\nChaussee de Mons 1229\n1070 Bruxelles\nBelgique";
    let displayed = format_company_address(address);
    assert!(displayed.contains(COMPANY_DISPLAY_SEP));
    assert!(!displayed.contains('\n'));

    let form = company_compose_form(
        &name,
        "Addr Contact",
        "addr-ops@example.com",
        "FR112233445",
        address,
        &[&member_email],
    );
    let create = post_form(
        &router,
        "/admin/companies/new",
        admin_cookie.as_deref(),
        &form,
    )
    .await;
    assert_eq!(status(&create), StatusCode::SEE_OTHER);

    let org = {
        let mut conn = db.clone();
        Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .find(|o| o.name == name)
            .expect("created org")
    };
    assert!(
        org.address.contains('\n'),
        "DB must keep newlines: {}",
        org.address
    );

    let list = get(
        &router,
        &format!("/admin/companies?q={}", urlencoding_encode(&name)),
        admin_cookie.as_deref(),
    )
    .await;
    assert_eq!(status(&list), StatusCode::OK);
    let list_html = body_text(list).await;
    assert!(
        list_html.contains(&displayed),
        "admin list must join address lines: {list_html}"
    );

    let _ = post_form(&router, "/logout", admin_cookie.as_deref(), "").await;
    let member_cookie = login_cookie(&router, &member_email).await.expect("cookie");
    let account = get(
        &router,
        &format!("/{}/account", org.slug),
        Some(&member_cookie),
    )
    .await;
    assert_eq!(status(&account), StatusCode::OK);
    let account_html = body_text(account).await;
    assert!(
        account_html.contains(&displayed),
        "account must join address lines: {account_html}"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn e2e_admin_rejects_out_of_range_lts_count() {
    let _guard = db_lock().lock().await;
    let db = test_db().await;
    cleanup(&db).await;
    let router = test_router().await;

    let email = unique_email("lts-oob");
    let slug = unique_slug("lts-oob");
    let (_user, _org) = create_org_with_membership(&db, &email, "password", &slug, "admin").await;
    let cookie = login(&router, &email).await;

    let name = format!("OOB Co {}", unique_slug("oob"));
    let form = company_compose_form_with_lts(
        &name,
        "Ops",
        "ops@example.com",
        "FR1",
        "1 St",
        &[],
        ComposeLts {
            lts: 100,
            industrial: 0,
        },
    );
    let create = post_form(&router, "/admin/companies/new", cookie.as_deref(), &form).await;
    assert_eq!(status(&create), StatusCode::OK);
    let html = body_text(create).await;
    assert!(
        html.contains("must be between 0 and"),
        "out-of-range LTS must error: {html}"
    );
    {
        let mut conn = db.clone();
        let found = Organization::all()
            .exec(&mut conn)
            .await
            .expect("orgs")
            .into_iter()
            .any(|o| o.name == name);
        assert!(!found, "org must not be created on OOB LTS");
    }

    cleanup(&db).await;
}

fn pager_hrefs_contain_delete(html: &str) -> bool {
    let Some(start) = html.find("vb-pager") else {
        return false;
    };
    let slice = &html[start..];
    let end = slice.find("</nav>").unwrap_or(slice.len().min(2000));
    slice[..end].contains("delete=")
}
