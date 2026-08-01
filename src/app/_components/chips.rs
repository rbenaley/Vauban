use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::list_page::PagerLinks;

use super::pager::vb_pager;

/// Chip filter row: `(label, href, active)` triples (no pager).
#[allow(dead_code)] // available for chip-only rows; lists with pager use `filter_row`.
#[component]
pub async fn chip_row(cx: &Cx, chips: &[(String, String, bool)]) -> Result {
    view! {
        cx =>
        <div class="vb-chip-row">
            <div class="vb-chip-group">
                for (label, href, active) in chips {
                    let class = if *active { "vb-chip active" } else { "vb-chip" };
                    <a class=(class) href=(href.clone())>(label.clone())</a>
                }
            </div>
        </div>
    }
}

/// Filter chips (left) + optional SSR pager (right) on one row.
#[component]
pub async fn filter_row(
    cx: &Cx,
    chips: &[(String, String, bool)],
    pager: &Option<PagerLinks>,
) -> Result {
    let show_pager = pager.as_ref().is_some_and(|p| p.show());
    view! {
        cx =>
        <div class="vb-chip-row">
            <div class="vb-chip-group">
                for (label, href, active) in chips {
                    let class = if *active { "vb-chip active" } else { "vb-chip" };
                    <a class=(class) href=(href.clone())>(label.clone())</a>
                }
            </div>
            if show_pager {
                if let Some(links) = pager {
                    vb_pager(links: links)
                }
            }
        </div>
    }
}
