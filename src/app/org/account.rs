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
    perms::perms_for_user,
};

#[page]
async fn account_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.account_read {
        return Err(forbidden().into());
    }

    let org = ctx.org.clone();

    let body = view! {
        <h1>"Account & subscription"</h1>
        <div class="card" style="margin-top: 18px; display: flex; justify-content: space-between; gap: 16px; align-items: center;">
            <div>
                <div style="font-weight: 800; font-size: 18px;">(org.name.clone())</div>
                <div class="muted">(org.plan_label.clone())</div>
            </div>
            <div style="font-family: ui-monospace, monospace; font-size: 12px; color: var(--accent); background: #e7f6f2; padding: 4px 10px; border-radius: 999px;">
                (org.status.clone())
            </div>
        </div>
        <div class="card" style="margin-top: 12px;">
            <div style="display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e8ebe6;">
                <span class="muted">"Supported builds"</span>
                <span>(org.supported_builds.clone())</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e8ebe6;">
                <span class="muted">"Vauban LTS subscriptions"</span>
                <span>(org.lts_subscriptions.to_string())</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e8ebe6;">
                <span class="muted">"Vauban Industrial LTS subscriptions"</span>
                <span>(org.industrial_lts_subscriptions.to_string())</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 10px 0;">
                <span class="muted">"Technical contact"</span>
                <span>(org.technical_contact.clone())</span>
            </div>
        </div>
        <form method="POST" action="/logout" style="margin-top: 18px;">
            <button class="btn" type="submit">"Sign out"</button>
        </form>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Account, "account", body).await
}
