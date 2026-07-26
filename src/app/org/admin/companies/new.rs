//! Admin onboard company stub at `/{org}/admin/companies/new`.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org, auth::require_org, models::MAX_USERS_PER_COMPANY, perms::perms_for_user,
};

#[page]
async fn admin_companies_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.companies_manage {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/companies");

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-link"
                href=(back.clone())
                style="display: inline-block; margin-bottom: 16px;"
            >
                "← Client companies"
            </a>
            <h1 class="vb-title">"Onboard company"</h1>
            <p class="vb-lead">
                "Seat limit: "
                (MAX_USERS_PER_COMPANY.to_string())
                " user accounts per company."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="GET" action=(back.clone())>
                    <label for="name">"Company name"</label>
                    <input id="name" name="name" required="">
                    <label for="contact">"Technical contact"</label>
                    <input id="contact" name="contact" type="email">
                    <label for="vat">"VAT"</label>
                    <input id="vat" name="vat">
                    <label for="address">"Address"</label>
                    <textarea id="address" name="address"></textarea>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Save (stub)"</button>
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
