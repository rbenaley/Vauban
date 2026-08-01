//! SSR list pager (Prev / page numbers / Next).

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::list_page::PagerLinks;

/// Chip-height pager; render only when `links.show()`.
#[component]
pub async fn vb_pager(cx: &Cx, links: &PagerLinks) -> Result {
    if !links.show() {
        return view! { cx => };
    }
    let page = links.page;
    let pages = links.pages.clone();
    let prev = links.prev_href.clone();
    let next = links.next_href.clone();

    view! {
        cx =>
        <nav class="vb-pager" aria-label="List pages">
            if let Some(href) = prev {
                <a class="vb-pager-link" href=(href)>"Prev"</a>
            } else {
                <a class="vb-pager-link disabled" aria-disabled="true" tabindex="-1">
                    "Prev"
                </a>
            }
            for (n, href) in pages {
                let class = if n == page {
                    "vb-pager-link active"
                } else {
                    "vb-pager-link"
                };
                <a class=(class) href=(href)>(n.to_string())</a>
            }
            if let Some(href) = next {
                <a class="vb-pager-link" href=(href)>"Next"</a>
            } else {
                <a class="vb-pager-link disabled" aria-disabled="true" tabindex="-1">
                    "Next"
                </a>
            }
        </nav>
    }
}

/// Right-aligned toolbar for lists without filter chips.
#[component]
pub async fn list_toolbar(cx: &Cx, links: &PagerLinks) -> Result {
    let show = links.show();
    let links = links.clone();
    view! {
        cx =>
        if show {
            <div class="vb-list-toolbar">vb_pager(links: &links)</div>
        }
    }
}
