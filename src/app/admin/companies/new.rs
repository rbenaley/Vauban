//! Admin new company at `/admin/companies/new`.

use std::collections::HashMap;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{IntoResponse, Response, content::Form, error::see_other, page, route},
};

use super::form::{CompanyFormView, company_form_response, render_company_form};
use crate::{
    auth::{capability_denied, config, db, require_staff},
    companies_accounts::{emails_from_indexed_map, normalize_emails, sync_org_accounts},
    models::{Organization, RESERVED_ORG_SLUG},
    perms::perms_for_user,
    slug::slugify,
};

#[derive(Deserialize)]
struct CompanyComposeForm {
    name: String,
    #[serde(default)]
    contact: String,
    #[serde(default)]
    vat: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    account_rows: String,
    #[serde(default)]
    compose_action: String,
    #[serde(flatten)]
    extra: HashMap<String, String>,
}

impl CompanyComposeForm {
    fn emails(&self) -> Vec<String> {
        let rows = self.account_rows.parse::<usize>().unwrap_or(1).max(1);
        emails_from_indexed_map(&self.extra, rows)
    }
}

#[page]
async fn admin_companies_new_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }
    let max = config(cx).org.max_accounts_per_org;
    render_company_form(
        cx,
        CompanyFormView {
            action: "/admin/companies/new".to_owned(),
            title: "New client company".to_owned(),
            submit_label: "Create company".to_owned(),
            name: String::new(),
            contact: String::new(),
            vat: String::new(),
            address: String::new(),
            emails: vec![String::new()],
            max_accounts: max,
            error: None,
        },
    )
    .await
}

#[route(POST "/admin/companies/new")]
async fn admin_companies_create(cx: &Cx, Form(form): Form<CompanyComposeForm>) -> Result<Response> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }

    let max = config(cx).org.max_accounts_per_org;
    let mut emails = form.emails();
    let action = form.compose_action.trim();

    if let Some(idx) = action.strip_prefix("remove:")
        && let Ok(i) = idx.parse::<usize>()
        && i < emails.len()
    {
        emails.remove(i);
    }
    if action.starts_with("remove:") {
        return company_form_response(
            cx,
            CompanyFormView {
                action: "/admin/companies/new".to_owned(),
                title: "New client company".to_owned(),
                submit_label: "Create company".to_owned(),
                name: form.name,
                contact: form.contact,
                vat: form.vat,
                address: form.address,
                emails,
                max_accounts: max,
                error: None,
            },
        )
        .await;
    }

    if action == "add_row" {
        if emails.len() < max {
            emails.push(String::new());
        }
        return company_form_response(
            cx,
            CompanyFormView {
                action: "/admin/companies/new".to_owned(),
                title: "New client company".to_owned(),
                submit_label: "Create company".to_owned(),
                name: form.name,
                contact: form.contact,
                vat: form.vat,
                address: form.address,
                emails,
                max_accounts: max,
                error: None,
            },
        )
        .await;
    }

    match save_new_company(
        cx,
        &form.name,
        &form.contact,
        &form.vat,
        &form.address,
        &emails,
        max,
    )
    .await
    {
        // 303 See Other (PRG). Do not use redirect()/307 — it re-POSTs to the
        // list URL and browsers download an empty "companies" file.
        Ok(()) => see_other("/admin/companies").into_response(cx),
        Err(msg) => {
            company_form_response(
                cx,
                CompanyFormView {
                    action: "/admin/companies/new".to_owned(),
                    title: "New client company".to_owned(),
                    submit_label: "Create company".to_owned(),
                    name: form.name,
                    contact: form.contact,
                    vat: form.vat,
                    address: form.address,
                    emails,
                    max_accounts: max,
                    error: Some(msg),
                },
            )
            .await
        }
    }
}

async fn save_new_company(
    cx: &Cx,
    name: &str,
    contact: &str,
    vat: &str,
    address: &str,
    emails_raw: &[String],
    max: usize,
) -> std::result::Result<(), String> {
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err("Company name is required.".to_owned());
    }
    let emails = normalize_emails(emails_raw);
    if emails.len() > max {
        return Err(format!("At most {max} user accounts are allowed."));
    }

    let base_slug = slugify(&name);
    if base_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Err("That company name is reserved.".to_owned());
    }
    let mut org_slug = base_slug.clone();
    let mut database = db(cx);
    let mut n = 2u32;
    loop {
        let clash = Organization::all()
            .filter(Organization::fields().slug().eq(&org_slug))
            .exec(&mut database)
            .await
            .unwrap_or_default();
        if clash.is_empty() {
            break;
        }
        org_slug = format!("{}-{n}", base_slug);
        n += 1;
        if n > 100 {
            return Err("Could not allocate a unique company slug.".to_owned());
        }
    }
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Err("That company name is reserved.".to_owned());
    }

    let created = toasty::create!(Organization {
        slug: org_slug,
        name,
        address: address.trim().to_owned(),
        vat: vat.trim().to_owned(),
        plan_label: "Standard".to_owned(),
        supported_builds: "LTS".to_owned(),
        lts_subscriptions: 0,
        industrial_lts_subscriptions: 0,
        technical_contact: contact.trim().to_owned(),
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut database)
    .await
    .map_err(|_| "Could not create company.".to_owned())?;

    sync_org_accounts(&mut database, created.id, &emails, max)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
