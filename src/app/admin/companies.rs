//! Admin companies at `/admin/companies` — Concept card layout.

mod company_id;
mod form;
mod new;

use std::collections::HashMap;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::ico_trash,
    auth::{capability_denied, config, require_staff},
    models::{Membership, Organization, RESERVED_ORG_SLUG, User},
    perms::perms_for_user,
};

#[query_params]
struct AdminCompaniesQuery {
    delete: Option<String>,
    err: Option<String>,
}

#[derive(Clone)]
struct CompanyCard {
    org: Organization,
    emails: Vec<String>,
}

#[page]
async fn admin_companies_page(cx: &Cx) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }

    let max = config(cx).org.max_accounts_per_org;
    let max_label = max.to_string();

    let mut database = crate::auth::db(cx);
    let companies: Vec<_> = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !c.slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG))
        .collect();

    let memberships = Membership::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let users = User::all().exec(&mut database).await.unwrap_or_default();
    let user_by_id: HashMap<u64, &User> = users.iter().map(|u| (u.id, u)).collect();

    let mut cards: Vec<CompanyCard> = companies
        .into_iter()
        .map(|org| {
            let mut emails: Vec<String> = memberships
                .iter()
                .filter(|m| m.organization_id == org.id)
                .filter_map(|m| user_by_id.get(&m.user_id).map(|u| u.email.clone()))
                .collect();
            emails.sort();
            CompanyCard { org, emails }
        })
        .collect();
    cards.sort_by_key(|c| c.org.name.to_lowercase());

    let q = query_params::<AdminCompaniesQuery>(cx).ok();
    let delete_id = q
        .as_ref()
        .and_then(|q| q.delete.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let delete_err = q
        .as_ref()
        .and_then(|q| q.err.as_deref())
        .is_some_and(|e| e == "confirm");
    let delete_target = delete_id.and_then(|id| cards.iter().find(|c| c.org.id == id).cloned());

    view! {
        <div
            style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; margin-bottom: 18px;"
        >
            <div>
                <h1 class="vb-title">"Client companies"</h1>
                <p class="vb-lead" style="margin-bottom: 0;">
                    "Onboard a client organization and provision up to "
                    (max_label)
                    " user accounts."
                </p>
            </div>
            <a class="vb-btn" href="/admin/companies/new">"+ New company"</a>
        </div>

        <div
            class="vb-company-list"
            style="display: flex; flex-direction: column; gap: 16px; width: 100%;"
        >
            if cards.is_empty() {
                <div class="vb-empty">"No companies."</div>
            } else {
                for card in cards {
                    let edit_href = format!("/admin/companies/{}", card.org.id);
                    let delete_href = format!("/admin/companies?delete={}", card.org.id);
                    let count = card.emails.len();
                    let count_label = if count == 1 {
                        "1 account".to_owned()
                    } else {
                        format!("{count} accounts")
                    };
                    let contact = if card.org.technical_contact.trim().is_empty() {
                        "—".to_owned()
                    } else {
                        card.org.technical_contact.clone()
                    };
                    <div class="vb-company-card">
                        <div class="vb-company-card-head">
                            <div style="min-width: 0;">
                                <div style="font-weight: 700; font-size: 16px;">
                                    (card.org.name.clone())
                                </div>
                                <div
                                    style="font-size: 13px; color: #5a5f66; margin-top: 4px;"
                                >
                                    (contact)
                                </div>
                            </div>
                            <div
                                style="display: flex; align-items: center; gap: 8px; flex: none;"
                            >
                                <span class="vb-badge soft">(count_label)</span>
                                <a class="vb-btn muted compact" href=(edit_href)>"Edit"</a>
                                <a
                                    class="vb-btn muted compact vb-btn-ico"
                                    href=(delete_href)
                                    aria-label="Delete company"
                                >
                                    (ico_trash(cx, 14).await?)
                                </a>
                            </div>
                        </div>

                        <div class="vb-company-meta">
                            <div class="vb-company-meta-col">
                                <div class="vb-company-meta-label">"ADDRESS"</div>
                                <div class="vb-company-meta-value">
                                    (card.org.address.clone())
                                </div>
                            </div>
                            <div class="vb-company-meta-col vat">
                                <div class="vb-company-meta-label">"VAT"</div>
                                <div class="vb-company-meta-value mono">
                                    (card.org.vat.clone())
                                </div>
                            </div>
                        </div>

                        <div class="vb-company-meta-label" style="margin-bottom: 8px;">
                            "USER ACCOUNTS"
                        </div>
                        <div class="vb-account-pills">
                            if card.emails.is_empty() {
                                <span style="font-size: 13px; color: #8a8f96;">
                                    "None"
                                </span>
                            } else {
                                for email in card.emails {
                                    <span class="vb-account-pill">(email)</span>
                                }
                            }
                        </div>
                    </div>
                }
            }
        </div>

        if let Some(target) = delete_target {
            let cancel = "/admin/companies".to_owned();
            let action = format!("/admin/companies/{}/delete", target.org.id);
            <div
                class="vb-confirm-root"
                role="dialog"
                aria-modal="true"
                aria-label="Delete company"
            >
                <div class="vb-confirm">
                    <h2>"Delete this company?"</h2>
                    <p>
                        "This permanently removes "
                        <strong>(target.org.name.clone())</strong>
                        " and its portal memberships. Type "
                        <span class="vb-mono">"delete"</span>
                        " to confirm."
                    </p>
                    if delete_err {
                        <p style="color: #b5403a; margin-bottom: 14px;">
                            "Confirmation text must be exactly "
                            <span class="vb-mono">"delete"</span>
                            "."
                        </p>
                    }
                    <form class="vb-form" method="POST" action=(action)>
                        <label for="confirm">"Confirm"</label>
                        <input
                            id="confirm"
                            name="confirm"
                            required=""
                            placeholder="delete"
                            autocomplete="off"
                        >
                        <div class="vb-confirm-actions">
                            <a class="vb-btn muted compact" href=(cancel)>"Cancel"</a>
                            <button
                                class="vb-btn danger"
                                type="submit"
                                style="padding: 10px 18px; font-size: 13px;"
                            >
                                "Delete permanently"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        }
    }
}
