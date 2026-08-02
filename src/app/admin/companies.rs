//! Admin companies at `/admin/companies` — Concept card layout.

mod company_id;
mod form;
mod new;
mod search_shard;

pub(super) use search_shard::admin_companies_search_results;

use std::collections::HashMap;

use topcoat::{
    Result,
    context::Cx,
    router::{page, query_params},
    view::view,
};

use crate::{
    app::_components::list_toolbar,
    auth::{capability_denied, config, require_staff},
    companies_search::{CompanyMatchFields, company_matches_query, normalize_query},
    list_page::{
        COMPANIES_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, parse_page,
        with_page_param,
    },
    models::{Membership, Organization, RESERVED_ORG_SLUG, User},
    perms::perms_for_user,
};

#[query_params]
struct AdminCompaniesQuery {
    q: Option<String>,
    delete: Option<String>,
    err: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
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

    let query = query_params::<AdminCompaniesQuery>(cx).ok();
    let q = normalize_query(query.as_ref().and_then(|q| q.q.as_deref()).unwrap_or(""));
    let delete_id = query
        .as_ref()
        .and_then(|q| q.delete.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let delete_err = query
        .as_ref()
        .and_then(|q| q.err.as_deref())
        .is_some_and(|e| e == "confirm");
    // Resolve delete target against the full list (before filter / page slice).
    let delete_target = delete_id.and_then(|id| cards.iter().find(|c| c.org.id == id).cloned());

    let filtered_total = cards
        .iter()
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
        .count();
    let mut page = parse_page(query.as_ref().and_then(|q| q.page));
    let pages = page_count(filtered_total, COMPANIES_PAGE_SIZE);
    page = clamp_page(page, pages);
    let page_init = page.to_string();
    let q_value = query.and_then(|q| q.q.clone()).unwrap_or_default();

    // Pager keeps `q` + `page` — never sticky `delete` / `err` (overlay query).
    let q_for_pager = q.clone();
    let pager = PagerLinks::from_hrefs(page, pages, |n| list_href(&q_for_pager, n));

    let cancel = if q.is_empty() {
        "/admin/companies".to_owned()
    } else {
        format!("/admin/companies?q={}", urlencoding_encode(&q))
    };

    view! {
        cx =>
        signal query = q_value.clone();
        signal page = page_init.clone();

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

        // Filter only (shareable ?q=); live results use the shard. Not a mutation.
        <form method="GET" action="/admin/companies" style="margin-bottom: 16px;">
            <input
                class="vb-search"
                type="search"
                name="q"
                value=(q_value.clone())
                placeholder="Search companies…"
                @input=$(|e: topcoat::runtime::Event| {
                    page.set("1".to_owned());
                    query.set(e.target.value);
                })
            >
        </form>

        list_toolbar(links: &pager)

        admin_companies_search_results(q: $(query.get()), page: $(page.get()))

        if let Some(target) = delete_target {
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
                            <a class="vb-btn muted compact" href=(cancel.clone())>
                                "Cancel"
                            </a>
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

fn list_href(q: &str, page: usize) -> String {
    let mut parts = Vec::new();
    if !q.is_empty() {
        parts.push(format!("q={}", urlencoding_encode(q)));
    }
    with_page_param(&mut parts, page);
    href_with_query("/admin/companies", &parts)
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
