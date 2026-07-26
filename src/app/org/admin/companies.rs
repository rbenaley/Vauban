//! Admin companies at `/{org}/admin/companies` — Concept card layout.

mod new;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    models::{MAX_USERS_PER_COMPANY, Organization},
    perms::perms_for_user,
    ui,
};

#[page]
async fn admin_companies_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.companies_manage {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let companies = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();

    view! {
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Client companies"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Tenant directory. Seat limit: "
                    (MAX_USERS_PER_COMPANY.to_string())
                    " user accounts per company."
                </p>
            </div>
            <a class="vb-btn" href=(format!("/{}/admin/companies/new", slug))>
                "+ Onboard company"
            </a>
        </div>

        <div
            style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px;"
        >
            if companies.is_empty() {
                <div class="vb-empty">"No companies."</div>
            } else {
                for company in companies {
                    let initials = ui::org_initials(&company.name);
                    <div class="vb-company-card">
                        <div
                            style="display: flex; align-items: center; gap: 12px; margin-bottom: 14px;"
                        >
                            <div
                                style="width: 40px; height: 40px; border-radius: 6px; background: color-mix(in srgb, var(--accent) 80%, #fff); color: #0c2520; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 14px;"
                            >
                                (initials)
                            </div>
                            <div style="min-width: 0;">
                                <div style="font-weight: 700;">(company.name.clone())</div>
                                <div
                                    class="vb-mono"
                                    style="font-size: 11px; color: #8a8f96;"
                                >
                                    (company.slug.clone())
                                </div>
                            </div>
                            <span class="vb-badge soft" style="margin-left: auto;">
                                (company.status.clone())
                            </span>
                        </div>
                        <div
                            style="font-size: 13px; color: #5a5f66; line-height: 1.5; margin-bottom: 10px;"
                        >
                            (company.address.clone())
                        </div>
                        <div
                            class="vb-mono"
                            style="font-size: 11px; color: #8a8f96; margin-bottom: 8px;"
                        >
                            (company.vat.clone())
                        </div>
                        <div style="font-size: 13px; margin-bottom: 12px;">
                            (company.plan_label.clone())
                        </div>
                        <div
                            class="vb-mono"
                            style="font-size: 11px; color: var(--accent);"
                        >
                            "Accounts · max "
                            (MAX_USERS_PER_COMPANY.to_string())
                        </div>
                        <a
                            class="vb-link"
                            href=(format!("/{}/admin/companies/new", slug))
                        >
                            "Edit →"
                        </a>
                    </div>
                }
            }
        </div>
    }
}
