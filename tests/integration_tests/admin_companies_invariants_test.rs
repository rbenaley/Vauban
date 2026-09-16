//! Source-shape invariants for admin client companies.

use std::process::Command;

use vcp::models::{MAX_LTS_SUBSCRIPTIONS_DEFAULT, MAX_USERS_PER_COMPANY};

#[test]
fn inv_check_admin_companies_script() {
    let output = Command::new("bash")
        .arg("scripts/check_admin_companies.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_admin_companies.sh");
    assert!(
        output.status.success(),
        "scripts/check_admin_companies.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_seat_cap_default_is_five() {
    assert_eq!(MAX_USERS_PER_COMPANY, 5);
    let seats = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seats.rs"));
    assert!(seats.contains("can_add_member"));
    assert!(seats.contains("membership_count"));
    let cfg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(cfg.contains("max_accounts_per_org"));
    assert!(cfg.contains("struct OrgConfig"));
}

#[test]
fn inv_lts_subscription_cap_and_steppers() {
    assert_eq!(MAX_LTS_SUBSCRIPTIONS_DEFAULT, 99);
    let cfg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(cfg.contains("max_lts_subscriptions"));
    let form = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/form.rs"
    ));
    assert!(form.contains("let lts = signal(cx"));
    assert!(form.contains("let industrial = signal(cx"));
    assert!(form.contains("data-lts-stepper-client"));
    assert!(form.contains("data-industrial-lts-stepper-client"));
    assert!(form.contains("@click=$("));
    assert!(form.contains("type=\"button\""));
    assert!(!form.contains("lts_inc"));
    assert!(!form.contains("ind_dec"));
    assert!(form.contains("Vauban LTS subscriptions"));
    assert!(form.contains("name=\"lts_subscriptions\""));
    assert!(form.contains(":value=$(lts.get())"));
    let accounts = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/companies_accounts.rs"
    ));
    assert!(accounts.contains("soft_delete_org_user"));
    assert!(accounts.contains("notify_org_access_revoked"));
    assert!(accounts.contains("invite_user"));
    assert!(accounts.contains("send_invitation_mail"));
    assert!(accounts.contains("send_revocation_mail"));
    // Revocation mail is per membership removal, not only orphan soft-delete.
    assert!(accounts.contains("notify_org_access_revoked(cx, cfg.as_ref(), user, org_name)"));
    let soft_fn = accounts
        .split("async fn soft_delete_org_user")
        .nth(1)
        .and_then(|s| s.split("async fn ").next())
        .expect("soft_delete_org_user body");
    assert!(
        !soft_fn.contains("send_revocation_mail"),
        "soft-delete must not own revocation mail"
    );
    assert!(!accounts.contains("password_hash"));
    assert!(!accounts.contains("BOOTSTRAP_LOGIN_PASSWORD"));
    let new = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/new.rs"
    ));
    assert!(new.contains("parse_lts_subscriptions"));
    assert!(
        !new.contains("apply_lts_compose_action"),
        "create POST must not re-render for LTS steppers"
    );
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    assert!(edit.contains(".lts_subscriptions("));
    assert!(edit.contains(".industrial_lts_subscriptions("));
    assert!(
        !edit.contains("apply_lts_compose_action"),
        "edit POST must not re-render for LTS steppers"
    );
    assert!(
        accounts.contains("fn apply_lts_compose_action"),
        "pure LTS stepper math must remain for unit/proptest/battle"
    );
}

/// 0.8.1: company compose POSTs are pages (`#[page(POST)]`), so the admin
/// layouts wrap validation re-renders and success leaves via `Err(see_other)`.
/// No hand-built `Response` and no re-composed shell remain.
#[test]
fn inv_company_post_handlers_are_pages_not_response_routes() {
    let new = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/new.rs"
    ));
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    let form = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/form.rs"
    ));
    let admin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/admin.rs"));
    let login = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/login.rs"));
    let choose = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/choose_org.rs"
    ));

    for (name, src) in [("new.rs", new), ("company_id.rs", edit)] {
        assert!(
            src.contains("#[page(POST)]"),
            "{name} must use #[page(POST)]"
        );
        assert!(
            src.contains("Err(see_other("),
            "{name} success must leave the POST page via Err(see_other)"
        );
        assert!(
            !src.contains("Result<Response>") && !src.contains("into_response(cx)"),
            "{name} must not hand-build a Response"
        );
    }
    assert!(!form.contains("fn company_form_response"));
    assert!(!admin.contains("fn render_admin_page"));
    assert!(
        !login.contains("choose_org_page") || !login.contains("fn choose_org_page"),
        "choose-org moved out of login.rs"
    );
    assert!(choose.contains("#[page]") && choose.contains("fn choose_org_page"));
    assert!(
        !choose.contains("root_layout(") && !choose.contains("into_response("),
        "choose-org is a module page: root_layout applies automatically"
    );
    assert!(
        choose.contains("Err(redirect(") && !choose.contains("see_other("),
        "choose-org navigational redirects stay 307"
    );
}

#[test]
fn inv_admin_companies_create_is_post_and_gated() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/new.rs"
    ));
    assert!(src.contains("method=\"POST\"") || src.contains("Form(form)"));
    assert!(src.contains("companies_manage"));
    assert!(src.contains("toasty::create!(Organization"));
    assert!(src.contains("sync_org_accounts"));
    assert!(src.contains("see_other"));
    assert!(src.contains("normalize_emails(emails_raw)?"));
    assert!(!src.contains("Err(redirect("));
    assert!(!src.contains("type=\"password\""));
}

#[test]
fn inv_mailbox_email_validation_wired() {
    let accounts = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/companies_accounts.rs"
    ));
    let cargo = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));
    assert!(accounts.contains("fn parse_portal_email"));
    assert!(accounts.contains("fn normalize_contact_email"));
    assert!(accounts.contains("fn format_technical_contact"));
    assert!(accounts.contains("fn format_company_address"));
    assert!(accounts.contains("COMPANY_DISPLAY_SEP"));
    assert!(accounts.contains("Mailbox::new"));
    assert!(accounts.contains("Result<Vec<String>, String>"));
    assert!(cargo.contains("\"mail\""));
    assert!(cargo.contains("mail-smtp"));
    assert!(app.contains("build_smtp_transport"));
    assert!(app.contains(".mail("));
    assert!(!app.contains("FileTransport"));
}

#[test]
fn inv_technical_contact_is_name_and_email() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let form = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/form.rs"
    ));
    let new = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/new.rs"
    ));
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0006_technical_contact_name_email.sql"
    ));
    assert!(models.contains("technical_contact_name"));
    assert!(models.contains("technical_contact_email"));
    assert!(!models.contains("pub technical_contact:"));
    assert!(form.contains("name=\"contact_name\""));
    assert!(form.contains("name=\"contact_email\""));
    assert!(!form.contains("name=\"contact\""));
    assert!(new.contains("normalize_contact_email"));
    assert!(edit.contains("normalize_contact_email"));
    assert!(migration.contains("technical_contact_name"));
    assert!(migration.contains("technical_contact_email"));
    assert!(
        migration.contains("RENAME COLUMN"),
        "migration must rename legacy technical_contact to preserve data"
    );
}

#[test]
fn inv_admin_companies_list_concept_and_edit_delete() {
    let list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies.rs"
    ));
    let shard = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/search_shard.rs"
    ));
    let edit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/company_id.rs"
    ));
    let form = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/form.rs"
    ));
    assert!(list.contains("+ New company"));
    assert!(list.contains("admin_companies_search_results"));
    assert!(list.contains("type=\"search\""));
    assert!(
        list.contains("COMPANIES_PAGE_SIZE"),
        "admin companies must use COMPANIES_PAGE_SIZE"
    );
    assert!(
        list.contains("list_toolbar"),
        "admin companies must use list_toolbar pager"
    );
    assert!(
        list.contains("page: Option<u32>"),
        "AdminCompaniesQuery must include page"
    );
    assert!(shard.contains("USER ACCOUNTS"));
    assert!(shard.contains("vb-account-pill"));
    assert!(shard.contains("ico_trash"));
    assert!(shard.contains("delete=") || shard.contains("DeleteSearchQ"));
    assert!(
        shard.contains("format_company_address"),
        "shard must join multi-line addresses with COMPANY_DISPLAY_SEP"
    );
    assert!(
        shard.contains("company_cards_page"),
        "shard must page via company_cards_page"
    );
    let load = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/companies/load.rs"
    ));
    assert!(
        load.contains("COMPANIES_PAGE_SIZE") && load.contains(".limit("),
        "companies load must SQL page with COMPANIES_PAGE_SIZE"
    );
    assert!(edit.contains("/delete"));
    assert!(edit.contains("sync_org_accounts"));
    assert!(edit.contains("see_other"));
    assert!(!edit.contains("Err(redirect("));
    assert!(form.contains("USER ACCOUNTS"));
    assert!(form.contains("account_rows"));
    assert!(form.contains("compose_action"));
    assert!(form.contains("email_"));
    assert!(form.contains("contact_name"));
    assert!(form.contains("contact_email"));
    assert!(!form.contains("type=\"password\""));
    assert!(
        form.contains("show_remove_account_row"),
        "Remove must stay visible for a sole filled account"
    );
    assert!(
        !form.contains("if emails.len() > 1"),
        "must not hide Remove solely on row count"
    );
    let accounts = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/companies_accounts.rs"
    ));
    assert!(accounts.contains("fn show_remove_account_row"));
    let runbook = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/runbooks/admin_companies_smoke_test.md"
    ));
    assert!(
        runbook.contains("must still show **Remove**"),
        "smoke runbook must cover Remove on a sole filled account"
    );
}
