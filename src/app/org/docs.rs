//! Documentation list at `/{org}/docs`.

mod doc;
mod search_shard;

pub(super) use search_shard::docs_search_results;

use topcoat::{
    Result,
    context::Cx,
    router::{page, path_param, query_params},
    view::view,
};

use crate::{
    app::_components::filter_row,
    app::org::Org,
    auth::{capability_denied, require_org},
    docs_search::{normalize_category, normalize_query},
    list_page::{
        LIST_PAGE_SIZE, PagerLinks, clamp_page, href_with_query, page_count, page_offset,
        parse_page, with_page_param,
    },
    models::{DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
    sql_search::ilike_contains,
};

const CATEGORIES: &[&str] = &[
    "Getting started",
    "Deployment",
    "Security",
    "API",
    "Operations",
];

#[query_params]
struct DocsQuery {
    q: Option<String>,
    cat: Option<String>,
    /// 1-based page index; omitted means page 1.
    page: Option<u32>,
}

/// Shareable docs list URL (`page=1` and empty filters omitted).
pub(super) fn docs_list_href(org: &str, q: &str, cat: &str, page: usize) -> String {
    let mut parts = Vec::new();
    if !q.is_empty() {
        parts.push(format!("q={}", urlencoding_encode(q)));
    }
    if !cat.is_empty() {
        parts.push(format!("cat={}", urlencoding_encode(cat)));
    }
    with_page_param(&mut parts, page);
    href_with_query(&format!("/{org}/docs"), &parts)
}

#[page]
async fn docs_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.docs_read {
        return Err(capability_denied().into());
    }

    let filter = DocsFilter::from_cx(cx);
    let page = DocsFilter::page_from_cx(cx);
    docs_list_view(cx, slug, &filter.q, &filter.cat, page).await
}

pub(super) struct DocsFilter {
    pub(super) q: String,
    pub(super) cat: String,
}

impl DocsFilter {
    pub(super) fn normalized(q: &str, cat: &str) -> Self {
        Self {
            q: normalize_query(q),
            cat: normalize_category(cat),
        }
    }

    pub(super) fn from_cx(cx: &Cx) -> Self {
        let query = query_params::<DocsQuery>(cx).ok();
        let q = query.as_ref().and_then(|q| q.q.as_deref()).unwrap_or("");
        let cat = query.as_ref().and_then(|q| q.cat.as_deref()).unwrap_or("");
        Self::normalized(q, cat)
    }

    pub(super) fn page_from_cx(cx: &Cx) -> usize {
        let query = query_params::<DocsQuery>(cx).ok();
        parse_page(query.and_then(|q| q.page))
    }
}

/// Build the shared published (+ category / search) docs query.
macro_rules! docs_filtered_query {
    ($filter:expr) => {{
        let filter = $filter;
        let mut query =
            DocArticle::all().filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED));
        if !filter.cat.is_empty() {
            query = query.filter(DocArticle::fields().category().eq(filter.cat.clone()));
        }
        if let Some(pat) = ilike_contains(&filter.q) {
            query = query.filter(
                DocArticle::fields()
                    .title()
                    .ilike_with_escape(pat.clone(), '\\')
                    .or(DocArticle::fields().summary().ilike_with_escape(pat, '\\')),
            );
        }
        query
    }};
}

/// Count matching published docs (SQL).
pub(super) async fn count_filtered_docs(cx: &Cx, filter: &DocsFilter) -> usize {
    let mut database = crate::auth::db(cx);
    docs_filtered_query!(filter)
        .count()
        .exec(&mut database)
        .await
        .unwrap_or(0) as usize
}

/// One page of matching docs (SQL `ORDER BY updated_at DESC` + limit/offset).
pub(super) async fn load_filtered_docs_page(
    cx: &Cx,
    filter: &DocsFilter,
    page: usize,
) -> Vec<DocArticle> {
    let total = count_filtered_docs(cx, filter).await;
    let pages = page_count(total, LIST_PAGE_SIZE);
    let page = clamp_page(page, pages);
    let mut database = crate::auth::db(cx);
    docs_filtered_query!(filter)
        .order_by(DocArticle::fields().updated_at().desc())
        .limit(LIST_PAGE_SIZE)
        .offset(page_offset(page, LIST_PAGE_SIZE))
        .exec(&mut database)
        .await
        .unwrap_or_default()
}

pub(super) async fn docs_list_view(
    cx: &Cx,
    org_slug: &str,
    q: &str,
    cat: &str,
    page: usize,
) -> Result {
    let filter = DocsFilter::normalized(q, cat);
    let total = count_filtered_docs(cx, &filter).await;
    let pages = page_count(total, LIST_PAGE_SIZE);
    let page = clamp_page(page, pages);

    let q_value = q.to_owned();
    let cat_owned = cat.to_owned();
    let org = org_slug.to_owned();
    let org_for_pager = org.clone();
    let q_for_pager = q_value.clone();
    let cat_for_pager = cat_owned.clone();
    let pager = PagerLinks::from_hrefs(page, pages, |n| {
        docs_list_href(&org_for_pager, &q_for_pager, &cat_for_pager, n)
    });
    let pager_opt = if pager.show() { Some(pager) } else { None };

    let base = format!("/{org_slug}/docs");
    // Chip hrefs omit `page` (reset). All clears filters; category chips keep q.
    let mut chips: Vec<(String, String, bool)> =
        vec![("All".to_owned(), base.clone(), cat.is_empty())];
    for c in CATEGORIES {
        chips.push((
            (*c).to_owned(),
            docs_list_href(&org, q, c, 1),
            cat.eq_ignore_ascii_case(c),
        ));
    }

    let page_init = page.to_string();

    view! {
        cx =>
        signal query = q_value.clone();
        signal page = page_init.clone();

        <h1 class="vb-title">"Documentation & knowledge base"</h1>
        <p class="vb-lead">"Operations, security, API, and deployment runbooks."</p>

        // Filter only (shareable ?q=); live results use the shard. Not a mutation.
        <form method="GET" action=(base.clone())>
            <input
                class="vb-search"
                type="search"
                name="q"
                value=(q_value.clone())
                placeholder="Search the documentation…"
                @input=$(|e: topcoat::runtime::Event| {
                    page.set("1".to_owned());
                    query.set(e.target.value);
                })
            >
            if !cat_owned.is_empty() {
                <input type="hidden" name="cat" value=(cat_owned.clone())>
            }
        </form>

        filter_row(chips: &chips, pager: &pager_opt)

        docs_search_results(
            org_slug: $(org.clone()),
            q: $(query.get()),
            cat: $(cat_owned.clone()),
            page: $(page.get())
        )
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

#[cfg(test)]
mod docs_list_href_tests {
    use super::docs_list_href;

    #[test]
    fn docs_list_href_omits_page_one_and_empty_filters() {
        assert_eq!(docs_list_href("acme", "", "", 1), "/acme/docs");
        assert_eq!(docs_list_href("acme", "ssh", "", 1), "/acme/docs?q=ssh");
        assert_eq!(
            docs_list_href("acme", "ssh", "API", 2),
            "/acme/docs?q=ssh&cat=API&page=2"
        );
    }
}
