use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{app::org::Org, auth::require_org, perms::perms_for_user};

#[page]
async fn account_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.account_read {
        return Err(forbidden().into());
    }

    let org = ctx.org.clone();
    let user_name = ctx.user.display_name.clone();
    let user_email = ctx.user.email.clone();

    view! {
        <h1 class="vb-title">"Account & subscription"</h1>
        <p class="vb-lead">"Organization profile and plan entitlements."</p>

        <div
            class="vb-panel"
            style="display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 12px;"
        >
            <div>
                <div style="font-weight: 800; font-size: 18px;">(org.name.clone())</div>
                <div class="vb-muted">(org.plan_label.clone())</div>
            </div>
            <span class="vb-badge soft">(org.status.clone())</span>
        </div>

        <div class="vb-panel" style="margin-bottom: 12px;">
            <div class="vb-section-label">"SUBSCRIPTION"</div>
            <div class="vb-kv">
                <span class="vb-muted">"Supported builds"</span>
                <span class="vb-mono">(org.supported_builds.clone())</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Vauban LTS subscriptions"</span>
                <span class="vb-mono">(org.lts_subscriptions.to_string())</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Vauban Industrial LTS subscriptions"</span>
                <span class="vb-mono">
                    (org.industrial_lts_subscriptions.to_string())
                </span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Technical contact"</span>
                <span>(org.technical_contact.clone())</span>
            </div>
        </div>

        <div class="vb-panel" style="margin-bottom: 18px;">
            <div class="vb-section-label">"SIGNED-IN USER"</div>
            <div class="vb-kv">
                <span class="vb-muted">"Name"</span>
                <span>(user_name)</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Email"</span>
                <span class="vb-mono">(user_email)</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Role"</span>
                <span class="vb-mono">(ctx.user.role.clone())</span>
            </div>
        </div>

        <form method="POST" action="/logout">
            <button class="vb-btn ghost" type="submit">"Sign out"</button>
        </form>
    }
}
