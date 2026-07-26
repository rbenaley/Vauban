use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::{MAX_USERS_PER_COMPANY, Organization},
    perms::perms_for_user,
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

    let body = view! {
        <h1>"Client companies"</h1>
        <p class="muted">
            "Tenant directory. Seat limit: "
            (MAX_USERS_PER_COMPANY.to_string())
            " users per company."
        </p>
        <div class="card" style="margin-top: 18px; overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>"NAME"</th>
                        <th>"SLUG"</th>
                        <th>"PLAN"</th>
                        <th>"STATUS"</th>
                        <th>"VAT"</th>
                    </tr>
                </thead>
                <tbody>
                    if companies.is_empty() {
                        <tr><td colspan="5" class="muted">"No companies."</td></tr>
                    } else {
                        for company in companies {
                            <tr>
                                <td style="font-weight: 700;">(company.name.clone())</td>
                                <td style="font-family: ui-monospace, monospace;">
                                    (company.slug.clone())
                                </td>
                                <td>(company.plan_label.clone())</td>
                                <td>(company.status.clone())</td>
                                <td>(company.vat.clone())</td>
                            </tr>
                        }
                    }
                </tbody>
            </table>
        </div>
    };

    layout::shell(
        cx,
        &ctx,
        &perms,
        NavSection::AdminCompanies,
        "admin / companies",
        body,
    )
    .await
}
