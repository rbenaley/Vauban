use topcoat::{
    Result,
    context::Cx,
    router::{page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::{capability_denied, db, require_org},
    companies_accounts::{
        account_member_pill_class, format_company_address, format_technical_contact,
    },
    models::Membership,
    perms::perms_for_user,
};

#[page]
async fn account_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.account_read {
        return Err(capability_denied().into());
    }

    let org = ctx.org.clone();
    let signed_in_email = ctx.user.email.clone();
    let technical_contact =
        format_technical_contact(&org.technical_contact_name, &org.technical_contact_email);

    let mut database = db(cx);
    let memberships = Membership::all()
        .filter(Membership::fields().organization_id().eq(org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let user_ids: Vec<u64> = memberships.iter().map(|m| m.user_id).collect();
    let users = crate::id_lookups::users_by_ids(&mut database, &user_ids)
        .await
        .unwrap_or_default();
    let mut member_emails = Vec::new();
    for m in memberships {
        if let Some(u) = users.iter().find(|u| u.id == m.user_id) {
            member_emails.push(u.email.clone());
        }
    }
    member_emails.sort();

    let address = format_company_address(&org.address);
    let vat = if org.vat.trim().is_empty() {
        "—".to_owned()
    } else {
        org.vat.clone()
    };

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
            <div class="vb-section-label">"COMPANY"</div>
            <div class="vb-kv">
                <span class="vb-muted">"Address"</span>
                <span>(address)</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"VAT"</span>
                <span class="vb-mono">(vat)</span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Technical contact"</span>
                <span>(technical_contact)</span>
            </div>
        </div>

        <div class="vb-panel" style="margin-bottom: 12px;">
            <div class="vb-section-label">"SUBSCRIPTION"</div>
            <div class="vb-kv">
                <span class="vb-muted">"Vauban LTS subscriptions"</span>
                <span
                    class="vb-mono"
                    data-account-lts=(org.lts_subscriptions.to_string())
                >
                    (org.lts_subscriptions.to_string())
                </span>
            </div>
            <div class="vb-kv">
                <span class="vb-muted">"Vauban Industrial LTS subscriptions"</span>
                <span
                    class="vb-mono"
                    data-account-industrial-lts=(org.industrial_lts_subscriptions.to_string())
                >
                    (org.industrial_lts_subscriptions.to_string())
                </span>
            </div>
        </div>

        <div class="vb-panel" style="margin-bottom: 18px;">
            <div class="vb-section-label">"USER ACCOUNTS"</div>
            <div class="vb-account-pills">
                if member_emails.is_empty() {
                    <span style="font-size: 13px; color: #8a8f96;">"None"</span>
                } else {
                    for email in member_emails {
                        let pill_class = account_member_pill_class(&email, &signed_in_email)
                            .to_owned();
                        <span class=(pill_class)>(email)</span>
                    }
                }
            </div>
        </div>

        <form method="POST" action="/logout">
            <button class="vb-btn ghost" type="submit">"Sign out"</button>
        </form>
    }
}
