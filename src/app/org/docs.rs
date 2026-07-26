//! Documentation list at `/{org}/docs`.

mod doc;

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param, query_params},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::DocArticle,
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
        return Err(forbidden().into());
    }

    let (q, cat, filtered) = load_filtered_docs(cx, &DocsFilter::from_cx(cx)).await;
    let body = docs_list_view(cx, slug, &q, &cat, &filtered).await;
    layout::shell(cx, &ctx, &perms, NavSection::Docs, "documentation", body).await
}

pub(super) struct DocsFilter {
    q: String,
    cat: String,
}

impl DocsFilter {
    pub(super) fn from_cx(cx: &Cx) -> Self {
        let query = query_params::<DocsQuery>(cx).ok();
        let q = query
            .and_then(|q| q.q.as_deref())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let cat = query
            .and_then(|q| q.cat.as_deref())
            .unwrap_or("")
            .trim()
            .to_owned();
        Self { q, cat }
    }
}

pub(super) async fn load_filtered_docs(
    cx: &Cx,
    filter: &DocsFilter,
) -> (String, String, Vec<DocArticle>) {
    let mut database = crate::auth::db(cx);
    let articles = DocArticle::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let filtered: Vec<_> = articles
        .into_iter()
        .filter(|a| {
            let cat_ok = filter.cat.is_empty() || a.category.eq_ignore_ascii_case(&filter.cat);
            let q_ok = filter.q.is_empty()
                || a.title.to_lowercase().contains(&filter.q)
                || a.summary.to_lowercase().contains(&filter.q);
            cat_ok && q_ok
        })
        .collect();
    (filter.q.clone(), filter.cat.clone(), filtered)
}

pub(super) async fn docs_list_view(
    cx: &Cx,
    org_slug: &str,
    q: &str,
    cat: &str,
    filtered: &[DocArticle],
) -> Result {
    let all_active = if cat.is_empty() {
        "vb-chip active"
    } else {
        "vb-chip"
    };
    let base = format!("/{org_slug}/docs");
    let q_value = q.to_owned();
    let cat_owned = cat.to_owned();
    let org = org_slug.to_owned();

    view! { cx =>
        <h1 class="vb-title">"Documentation & knowledge base"</h1>
        <p class="vb-lead">"Operations, security, API, and deployment runbooks."</p>

        <form method="GET" action=(base.clone())>
            <input
                class="vb-search"
                type="search"
                name="q"
                value=(q_value)
                placeholder="Search the documentation…"
            >
            if !cat_owned.is_empty() {
                <input type="hidden" name="cat" value=(cat_owned.clone())>
            }
        </form>

        <div class="vb-chip-row">
            <a class=(all_active) href=(base.clone())>"All"</a>
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
                let class = if cat.eq_ignore_ascii_case(c) {
                    "vb-chip active"
                } else {
                    "vb-chip"
                };
                <a class=(class) href=(href)>(*c)</a>
            }
        </div>

        <div class="vb-list">
            if filtered.is_empty() {
                <div class="vb-empty">"No matching articles."</div>
            } else {
                for article in filtered {
                    <a class="vb-row" href=(format!("/{}/docs/{}", org, article.slug))>
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-weight: 700;">(article.title.clone())</div>
                            <div style="font-size: 12.5px; color: var(--muted); margin-top: 2px;">
                                (article.summary.clone())
                            </div>
                        </div>
                        <div style="text-align: right; flex: none;">
                            <div class="vb-mono" style="font-size: 10px; color: var(--accent);">
                                (article.category.clone())
                            </div>
                            <div class="vb-mono" style="font-size: 10px; color: #9aa0a6; margin-top: 3px;">
                                "Updated "
                                (article.version.clone())
                            </div>
                        </div>
                        <span style="font-size: 16px; color: #c2c6cb; flex: none;">"→"</span>
                    </a>
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
