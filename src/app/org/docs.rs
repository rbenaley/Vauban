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
    app::_components::chip_row,
    app::org::Org,
    auth::{capability_denied, require_org},
    docs_search::{normalize_category, normalize_query, text_matches_query},
    models::{DOC_STATUS_PUBLISHED, DocArticle},
    perms::perms_for_user,
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
    docs_list_view(cx, slug, &filter.q, &filter.cat).await
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
        let q = query.and_then(|q| q.q.as_deref()).unwrap_or("");
        let cat = query.and_then(|q| q.cat.as_deref()).unwrap_or("");
        Self::normalized(q, cat)
    }
}

pub(super) async fn load_filtered_docs(
    cx: &Cx,
    filter: &DocsFilter,
) -> (String, String, Vec<DocArticle>) {
    let mut database = crate::auth::db(cx);
    let mut query =
        DocArticle::all().filter(DocArticle::fields().status().eq(DOC_STATUS_PUBLISHED));
    if !filter.cat.is_empty() {
        query = query.filter(DocArticle::fields().category().eq(&filter.cat));
    }
    let articles = query.exec(&mut database).await.unwrap_or_default();
    let mut filtered: Vec<_> = articles
        .into_iter()
        .filter(|a| text_matches_query(&filter.q, &a.title, &a.summary))
        .collect();
    filtered.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    (filter.q.clone(), filter.cat.clone(), filtered)
}

pub(super) async fn docs_list_view(cx: &Cx, org_slug: &str, q: &str, cat: &str) -> Result {
    let base = format!("/{org_slug}/docs");
    let q_value = q.to_owned();
    let cat_owned = cat.to_owned();
    let org = org_slug.to_owned();
    let mut chips: Vec<(String, String, bool)> =
        vec![("All".to_owned(), base.clone(), cat.is_empty())];
    for c in CATEGORIES {
        let href = if q.is_empty() {
            format!("{base}?cat={}", urlencoding_encode(c))
        } else {
            format!(
                "{base}?q={}&cat={}",
                urlencoding_encode(q),
                urlencoding_encode(c)
            )
        };
        chips.push(((*c).to_owned(), href, cat.eq_ignore_ascii_case(c)));
    }

    view! {
        cx =>
        signal query = q_value.clone();

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
                @input=$(|e: topcoat::runtime::Event| query.set(e.target.value))
            >
            if !cat_owned.is_empty() {
                <input type="hidden" name="cat" value=(cat_owned.clone())>
            }
        </form>

        chip_row(chips: &chips)

        docs_search_results(
            org_slug: $(org.clone()),
            q: $(query.get()),
            cat: $(cat_owned.clone())
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
