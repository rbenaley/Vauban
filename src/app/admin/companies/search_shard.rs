//! Live admin companies search shard — re-checks staff + companies_manage.
//!
//! Shard POSTs hit `/_topcoat/shards/{id}` — admin layout does not run.
//! Always re-authorize with `require_staff` before loading data.

use std::collections::HashMap;

use topcoat::{Result, context::Cx, runtime::shard, view::view};

use crate::{
    app::_components::ico_trash,
    auth::{capability_denied, require_staff},
    companies_accounts::format_technical_contact,
    companies_search::{CompanyMatchFields, company_matches_query, normalize_query},
    list_page::{COMPANIES_PAGE_SIZE, page_slice, parse_page},
    models::{Membership, Organization, RESERVED_ORG_SLUG, User},
    perms::perms_for_user,
};

#[derive(Clone)]
struct CompanyCard {
    org: Organization,
    emails: Vec<String>,
}

/// Shard args are attacker-controlled — always re-authorize.
#[shard]
pub async fn admin_companies_search_results(cx: &Cx, q: String, page: String) -> Result {
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.companies_manage {
        return Err(capability_denied().into());
    }

    let q = normalize_query(&q);
    let page = parse_page(page.parse().ok());

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
        .filter(|c| {
            company_matches_query(
                &q,
                &CompanyMatchFields {
                    name: &c.org.name,
                    slug: &c.org.slug,
                    contact_name: &c.org.technical_contact_name,
                    contact_email: &c.org.technical_contact_email,
                    vat: &c.org.vat,
                    address: &c.org.address,
                    emails: &c.emails,
                },
            )
        })
        .collect();
    cards.sort_by_key(|c| c.org.name.to_lowercase());

    let page_cards = page_slice(&cards, page, COMPANIES_PAGE_SIZE);
    let empty_label = if q.is_empty() {
        "No companies."
    } else {
        "No matching companies."
    };

    view! {
        cx =>
        <div
            class="vb-company-list"
            data-admin-companies-search-shard="1"
            style="display: flex; flex-direction: column; gap: 16px; width: 100%;"
        >
            if cards.is_empty() {
                <div class="vb-empty">(empty_label)</div>
            } else {
                for card in page_cards {
                    let edit_href = format!("/admin/companies/{}", card.org.id);
                    let delete_href = if q.is_empty() {
                        format!("/admin/companies?delete={}", card.org.id)
                    } else {
                        format!(
                            "/admin/companies?q={}&delete={}",
                            urlencoding_encode(&q),
                            card.org.id
                        )
                    };
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
    }
}

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
