//! E2E: admin company create/edit/delete + seats + member 404.

use http_body_util::BodyExt;
use topcoat::router::StatusCode;
use vcp::models::{MAX_USERS_PER_COMPANY, Membership, Organization, RESERVED_ORG_SLUG, User};
use vcp::seats::{can_add_member, membership_count};

use crate::common::{
    cleanup, cookie_header, create_membership, create_org_with_membership, create_test_org,
    create_test_user, db_lock, get, post_form, status, test_db, test_router, unique_email,
    unique_slug, urlencoding_encode,
};

async fn body_text(resp: topcoat::router::Response) -> String {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn login(router: &topcoat::router::Router, email: &str) -> Option<String> {
    let form = format!("email={}&password=password", urlencoding_encode(email));
    let login = post_form(router, "/login", None, &form).await;
    assert!(status(&login).is_redirection());
    cookie_header(&login)
}

fn company_compose_form(
    name: &str,
    contact_name: &str,
    contact_email: &str,
    vat: &str,
    address: &str,
    emails: &[&str],
) -> String {
    let mut parts = vec![
        format!("name={}", urlencoding_encode(name)),
        format!("contact_name={}", urlencoding_encode(contact_name)),
        format!("contact_email={}", urlencoding_encode(contact_email)),
        format!("vat={}", urlencoding_encode(vat)),
        format!("address={}", urlencoding_encode(address)),
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
        assert!(orphan.is_empty(), "orphan client user should be removed");
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

fn pager_hrefs_contain_delete(html: &str) -> bool {
    let Some(start) = html.find("vb-pager") else {
        return false;
    };
    let slice = &html[start..];
    let end = slice.find("</nav>").unwrap_or(slice.len().min(2000));
    slice[..end].contains("delete=")
}
