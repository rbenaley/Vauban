//! Admin edit / delete company at `/admin/companies/{company_id}`.

use std::collections::HashMap;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        IntoResponse, Response,
        content::Form,
        error::{SeeOther, not_found, see_other},
        page, path_param, route,
    },
};

use super::form::{CompanyFormView, company_form_response, render_company_form};
use crate::{
    auth::{capability_denied, config, db, require_staff},
    companies_accounts::{
        delete_org_with_accounts, emails_from_indexed_map, normalize_contact_email,
        normalize_emails, sync_org_accounts,
    },
    docs_version::is_delete_confirm,
    models::{Membership, Organization, RESERVED_ORG_SLUG, User},
    perms::perms_for_user,
};

#[path_param]
struct CompanyId(str);

#[derive(Deserialize)]
struct CompanyComposeForm {
    name: String,
    #[serde(default)]
    contact_name: String,
    #[serde(default)]
    contact_email: String,
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

#[derive(Deserialize)]
struct DeleteCompanyForm {
    confirm: String,
}

fn parse_company_id(raw: &str) -> Option<u64> {
    raw.parse().ok()
}

async fn load_company(cx: &Cx, id: u64) -> Option<Organization> {
    let mut database = db(cx);
    Organization::all()
        .filter(Organization::fields().id().eq(id))
        .exec(&mut database)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .filter(|o| !o.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG))
}

async fn load_org_emails(cx: &Cx, org_id: u64) -> Vec<String> {
    let mut database = db(cx);
    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().eq(org_id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let users = User::all().exec(&mut database).await.unwrap_or_default();
    let mut emails = Vec::new();
    for m in memberships {
        if let Some(u) = users.iter().find(|u| u.id == m.user_id) {
            emails.push(u.email.clone());
        }
    }
    emails.sort();
    emails
}

#[page]
async fn admin_companies_edit_page(cx: &Cx) -> Result {
    let raw = path_param::<CompanyId>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }
    let Some(id) = parse_company_id(raw) else {
        return Err(not_found().into());
    };
    let Some(org) = load_company(cx, id).await else {
        return Err(not_found().into());
    };
    let max = config(cx).org.max_accounts_per_org;
    let emails = load_org_emails(cx, org.id).await;
    render_company_form(
        cx,
        CompanyFormView {
            action: format!("/admin/companies/{id}"),
            title: "Edit client company".to_owned(),
            submit_label: "Save changes".to_owned(),
            name: org.name,
            contact_name: org.technical_contact_name,
            contact_email: org.technical_contact_email,
            vat: org.vat,
            address: org.address,
            emails,
            max_accounts: max,
            error: None,
        },
    )
    .await
}

#[route(POST "/admin/companies/{company_id}")]
async fn admin_companies_update(cx: &Cx, Form(form): Form<CompanyComposeForm>) -> Result<Response> {
    let raw = path_param::<CompanyId>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }
    let Some(id) = parse_company_id(raw) else {
        return Err(not_found().into());
    };
    let Some(org) = load_company(cx, id).await else {
        return Err(not_found().into());
    };

    let max = config(cx).org.max_accounts_per_org;
    let action_url = format!("/admin/companies/{id}");
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
                action: action_url,
                title: "Edit client company".to_owned(),
                submit_label: "Save changes".to_owned(),
                name: form.name,
                contact_name: form.contact_name,
                contact_email: form.contact_email,
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
                action: action_url,
                title: "Edit client company".to_owned(),
                submit_label: "Save changes".to_owned(),
                name: form.name,
                contact_name: form.contact_name,
                contact_email: form.contact_email,
                vat: form.vat,
                address: form.address,
                emails,
                max_accounts: max,
                error: None,
            },
        )
        .await;
    }

    let fields = CompanyFields {
        name: form.name,
        contact_name: form.contact_name,
        contact_email: form.contact_email,
        vat: form.vat,
        address: form.address,
    };
    match save_edit(cx, org, &fields, &emails, max).await {
        // 303 See Other (PRG). Do not use redirect()/307 — it re-POSTs to the
        // list URL and browsers download an empty "companies" file.
        Ok(()) => see_other("/admin/companies").into_response(cx),
        Err(msg) => {
            company_form_response(
                cx,
                CompanyFormView {
                    action: action_url,
                    title: "Edit client company".to_owned(),
                    submit_label: "Save changes".to_owned(),
                    name: fields.name,
                    contact_name: fields.contact_name,
                    contact_email: fields.contact_email,
                    vat: fields.vat,
                    address: fields.address,
                    emails,
                    max_accounts: max,
                    error: Some(msg),
                },
            )
            .await
        }
    }
}

struct CompanyFields {
    name: String,
    contact_name: String,
    contact_email: String,
    vat: String,
    address: String,
}

async fn save_edit(
    cx: &Cx,
    mut org: Organization,
    fields: &CompanyFields,
    emails_raw: &[String],
    max: usize,
) -> std::result::Result<(), String> {
    let name = fields.name.trim().to_owned();
    if name.is_empty() {
        return Err("Company name is required.".to_owned());
    }
    let contact_email = normalize_contact_email(&fields.contact_email)?;
    let emails = normalize_emails(emails_raw)?;
    if emails.len() > max {
        return Err(format!("At most {max} user accounts are allowed."));
    }

    let mut database = db(cx);
    org.update()
        .name(name)
        .technical_contact_name(fields.contact_name.trim().to_owned())
        .technical_contact_email(contact_email)
        .vat(fields.vat.trim().to_owned())
        .address(fields.address.trim().to_owned())
        .exec(&mut database)
        .await
        .map_err(|_| "Could not update company.".to_owned())?;

    sync_org_accounts(&mut database, org.id, &emails, max)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[route(POST "/admin/companies/{company_id}/delete")]
async fn admin_companies_delete(cx: &Cx, Form(form): Form<DeleteCompanyForm>) -> Result<SeeOther> {
    let raw = path_param::<CompanyId>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }
    let Some(id) = parse_company_id(raw) else {
        return Err(not_found().into());
    };
    let Some(_org) = load_company(cx, id).await else {
        return Err(not_found().into());
    };

    if !is_delete_confirm(&form.confirm) {
        return Ok(see_other(&format!(
            "/admin/companies?delete={id}&err=confirm"
        )));
    }

    let mut database = db(cx);
    let _ = delete_org_with_accounts(&mut database, id).await;

    Ok(see_other("/admin/companies"))
}
