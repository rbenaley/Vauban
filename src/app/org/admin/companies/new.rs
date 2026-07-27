//! Admin onboard company at `/{org}/admin/companies/new`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, forbidden, page, path_param, route, see_other},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{db, require_org},
    models::{MAX_USERS_PER_COMPANY, Organization},
    perms::perms_for_user,
    slug::slugify,
};

#[derive(Deserialize)]
struct CreateCompanyForm {
    name: String,
    #[serde(default)]
    contact: String,
    #[serde(default)]
    vat: String,
    #[serde(default)]
    address: String,
}

#[page]
async fn admin_companies_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.companies_manage {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/companies");
    let action = format!("/{slug}/admin/companies/new");

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-back"
                href=(back.clone())
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Client companies"
            </a>
            <h1 class="vb-title">"Onboard company"</h1>
            <p class="vb-lead">
                "Seat limit: "
                (MAX_USERS_PER_COMPANY.to_string())
                " user accounts per company."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(action)>
                    <label for="name">"Company name"</label>
                    <input id="name" name="name" required="">
                    <label for="contact">"Technical contact"</label>
                    <input id="contact" name="contact" type="email">
                    <label for="vat">"VAT"</label>
                    <input id="vat" name="vat">
                    <label for="address">"Address"</label>
                    <textarea id="address" name="address"></textarea>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Save"</button>
                        <a
                            class="vb-link"
                            href=(back)
                            style="margin: 0; align-self: center;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[route(POST "/{org}/admin/companies/new")]
async fn admin_companies_create(cx: &Cx, Form(form): Form<CreateCompanyForm>) -> Result<SeeOther> {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await.map_err(|_| forbidden())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.companies_manage {
        return Err(forbidden().into());
    }

    let name = form.name.trim().to_owned();
    if name.is_empty() {
        return Ok(see_other(&format!("/{slug}/admin/companies/new")));
    }
    let mut org_slug = slugify(&name);
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
        org_slug = format!("{}-{n}", slugify(&name));
        n += 1;
        if n > 100 {
            break;
        }
    }

    let contact = form.contact.trim().to_owned();
    let vat = form.vat.trim().to_owned();
    let address = form.address.trim().to_owned();

    let _ = toasty::create!(Organization {
        slug: org_slug,
        name,
        address,
        vat,
        plan_label: "Standard".to_owned(),
        supported_builds: "LTS".to_owned(),
        lts_subscriptions: 0,
        industrial_lts_subscriptions: 0,
        technical_contact: contact,
        status: "ACTIVE".to_owned(),
    })
    .exec(&mut database)
    .await;

    Ok(see_other(&format!("/{slug}/admin/companies")))
}
