//! Admin new company at `/admin/companies/new`.

use std::collections::HashMap;

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{content::Form, error::see_other, href, page},
    view::{View, view},
};

use super::form::{CompanyFormView, render_company_form};
use crate::app::admin::companies::admin_companies_page;
use crate::{
    auth::{capability_denied, config, db, require_staff},
    companies_accounts::{
        emails_from_indexed_map, normalize_contact_email, normalize_emails, parse_lts_field,
        parse_lts_subscriptions, sync_org_accounts,
    },
    models::{Organization, RESERVED_ORG_SLUG},
    perms::perms_for_user,
    slug::slugify,
};

#[derive(Deserialize)]
pub(crate) struct CompanyComposeForm {
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
    lts_subscriptions: String,
    #[serde(default)]
    industrial_lts_subscriptions: String,
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

    fn lts_counts(&self, max_lts: usize) -> (i32, i32) {
        let lts = parse_lts_field(&self.lts_subscriptions)
            .map(|v| crate::companies_accounts::clamp_lts_count(v, max_lts))
            .unwrap_or(0);
        let industrial = parse_lts_field(&self.industrial_lts_subscriptions)
            .map(|v| crate::companies_accounts::clamp_lts_count(v, max_lts))
            .unwrap_or(0);
        (lts, industrial)
    }
}

struct NewFormState {
    lts: i32,
    industrial: i32,
    max: usize,
    max_lts: usize,
    error: Option<String>,
}

fn form_view(
    cx: &Cx,
    form: &CompanyComposeForm,
    emails: Vec<String>,
    state: NewFormState,
) -> CompanyFormView {
    CompanyFormView {
        action: href!(admin_companies_create).resolve(cx),
        title: "New client company".to_owned(),
        submit_label: "Create company".to_owned(),
        name: form.name.clone(),
        contact_name: form.contact_name.clone(),
        contact_email: form.contact_email.clone(),
        vat: form.vat.clone(),
        address: form.address.clone(),
        lts_subscriptions: state.lts,
        industrial_lts_subscriptions: state.industrial,
        emails,
        max_accounts: state.max,
        max_lts: state.max_lts,
        error: state.error,
    }
}

#[page]
pub(crate) async fn admin_companies_new_page(cx: &Cx) -> Result<impl View> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }
    let cfg = config(cx);
    let max = cfg.org.max_accounts_per_org;
    let max_lts = cfg.org.max_lts_subscriptions;
    Ok(view! {
        cx =>
        render_company_form(
            state: CompanyFormView {
                action: href!(admin_companies_create).resolve(cx),
                title: "New client company".to_owned(),
                submit_label: "Create company".to_owned(),
                name: String::new(),
                contact_name: String::new(),
                contact_email: String::new(),
                vat: String::new(),
                address: String::new(),
                lts_subscriptions: 0,
                industrial_lts_subscriptions: 0,
                emails: vec![String::new()],
                max_accounts: max,
                max_lts,
                error: None,
            }
        )
    })
}

/// POST page (0.8.1): compose actions and validation errors re-render the form
/// under `root_layout` + `admin_layout` (chrome + staff gate); a successful
/// save leaves through `Err(see_other)`.
#[page(POST)]
pub(crate) async fn admin_companies_create(
    cx: &Cx,
    Form(form): Form<CompanyComposeForm>,
) -> Result<impl View> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }

    let cfg = config(cx);
    let max = cfg.org.max_accounts_per_org;
    let max_lts = cfg.org.max_lts_subscriptions;
    let mut emails = form.emails();
    let (lts, industrial) = form.lts_counts(max_lts);
    let action = form.compose_action.trim();

    if let Some(idx) = action.strip_prefix("remove:")
        && let Ok(i) = idx.parse::<usize>()
        && i < emails.len()
    {
        emails.remove(i);
    }

    let error = if action.starts_with("remove:") {
        None
    } else if action == "add_row" {
        if emails.len() < max {
            emails.push(String::new());
        }
        None
    } else {
        match save_new_company(cx, &form, &emails, max, max_lts).await {
            // 303 See Other (PRG). Do not use redirect()/307 — it re-POSTs to the
            // list URL and browsers download an empty "companies" file.
            Ok(()) => return Err(see_other(href!(admin_companies_page).resolve(cx)).into()),
            Err(msg) => Some(msg),
        }
    };

    let state = form_view(
        cx,
        &form,
        emails,
        NewFormState {
            lts,
            industrial,
            max,
            max_lts,
            error,
        },
    );
    Ok(view! { cx => render_company_form(state: state) })
}

async fn save_new_company(
    cx: &Cx,
    form: &CompanyComposeForm,
    emails_raw: &[String],
    max: usize,
    max_lts: usize,
) -> std::result::Result<(), String> {
    let name = form.name.trim().to_owned();
    if name.is_empty() {
        return Err("Company name is required.".to_owned());
    }
    let contact_email = normalize_contact_email(&form.contact_email)?;
    let emails = normalize_emails(emails_raw)?;
    if emails.len() > max {
        return Err(format!("At most {max} user accounts are allowed."));
    }
    let lts =
        parse_lts_subscriptions(&form.lts_subscriptions, max_lts, "Vauban LTS subscriptions")?;
    let industrial = parse_lts_subscriptions(
        &form.industrial_lts_subscriptions,
        max_lts,
        "Vauban Industrial LTS subscriptions",
    )?;

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
        address: form.address.trim().to_owned(),
        vat: form.vat.trim().to_owned(),
        plan_label: "Standard".to_owned(),
        supported_builds: "LTS".to_owned(),
        lts_subscriptions: lts,
        industrial_lts_subscriptions: industrial,
        technical_contact_name: form.contact_name.trim().to_owned(),
        technical_contact_email: contact_email,
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut database)
    .await
    .map_err(|_| "Could not create company.".to_owned())?;

    sync_org_accounts(cx, &mut database, created.id, &emails, max, &created.name)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
