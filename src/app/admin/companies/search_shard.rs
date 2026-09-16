//! Live admin companies search shard — re-checks staff + companies_manage.
//!
//! Shard POSTs hit `/_topcoat/runtime/shards/{id}` — admin layout does not run.
//! Always re-authorize with `require_staff` before loading data.

use topcoat::{
    Result,
    context::Cx,
    router::href,
    runtime::shard,
    view::{View, view},
};

use super::load::company_cards_page;
use crate::{
    app::_components::ico_trash,
    app::admin::companies::admin_companies_page,
    app::admin::companies::company_id::{CompanyId, admin_companies_edit_page},
    auth::{capability_denied, require_staff},
    companies_accounts::{format_company_address, format_technical_contact},
    companies_search::normalize_query,
    list_page::parse_page,
    perms::perms_for_user,
    ui::row_dom_id,
};

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn admin_companies_search_results(cx: &Cx, q: String, page: String) -> Result<impl View> {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }

    let q = normalize_query(&q);
    let page = parse_page(page.parse().ok());

    let (page_cards, total) = company_cards_page(cx, &q, page).await;
    let empty_label = if q.is_empty() {
        "No companies."
    } else {
        "No matching companies."
    };

    Ok(view! {
        cx =>
        <div
            class="vb-company-list"
            data-admin-companies-search-shard="1"
            style="display: flex; flex-direction: column; gap: 16px; width: 100%;"
        >
            if total == 0 {
                <div class="vb-empty">(empty_label)</div>
            } else {
                for card in page_cards {
                    let edit_href = href!(
                        admin_companies_edit_page,
                        CompanyId(card.org.id),
                    ).resolve(cx);
                    let delete_href = href!(admin_companies_page)
                        .query(
                            crate::app::hrefs::DeleteSearchQ {
                                q: &q,
                                delete: card.org.id,
                            },
                        )
                        .resolve(cx);
                    let count = card.emails.len();
                    let count_label = if count == 1 {
                        "1 account".to_owned()
                    } else {
                        format!("{count} accounts")
                    };
                    let contact = format_technical_contact(
                        &card.org.technical_contact_name,
                        &card.org.technical_contact_email,
                    );
                    let emails = card.emails.clone();
                    let subs_ratio = format!(
                        "{}/{}",
                        card.org.lts_subscriptions,
                        card.org.industrial_lts_subscriptions,
                    );
                    <div
                        id=(row_dom_id("company", &card.org.id.to_string()))
                        class="vb-company-card"
                    >
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
                                    ico_trash(size: 14)
                                </a>
                            </div>
                        </div>

                        <div class="vb-company-meta">
                            <div class="vb-company-meta-col">
                                <div class="vb-company-meta-label">"ADDRESS"</div>
                                <div class="vb-company-meta-value">
                                    (format_company_address(&card.org.address))
                                </div>
                            </div>
                            <div class="vb-company-meta-col vat">
                                <div class="vb-company-meta-label">"VAT"</div>
                                <div class="vb-company-meta-value mono">
                                    (card.org.vat.clone())
                                </div>
                            </div>
                            <div class="vb-company-meta-col subs">
                                <div class="vb-company-meta-label">
                                    "SUBSCRIPTIONS (VAUBAN LTS / VAUBAN INDUSTRIAL LTS)"
                                </div>
                                <div
                                    class="vb-company-meta-value mono"
                                    data-company-subscriptions=(subs_ratio.clone())
                                >
                                    (subs_ratio.clone())
                                </div>
                            </div>
                        </div>

                        <div class="vb-company-meta-label" style="margin-bottom: 8px;">
                            "USER ACCOUNTS"
                        </div>
                        <div class="vb-account-pills">
                            if emails.is_empty() {
                                <span style="font-size: 13px; color: #8a8f96;">
                                    "None"
                                </span>
                            } else {
                                for email in emails {
                                    <span class="vb-account-pill">(email)</span>
                                }
                            }
                        </div>
                    </div>
                }
            }
        </div>
    })
}
