use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

/// Chip filter row: `(label, href, active)` triples.
#[component]
pub async fn chip_row(cx: &Cx, chips: &[(String, String, bool)]) -> Result {
    view! {
        cx =>
        <div class="vb-chip-row">
            for (label, href, active) in chips {
                let class = if *active { "vb-chip active" } else { "vb-chip" };
                <a class=(class) href=(href.clone())>(label.clone())</a>
            }
        </div>
    }
}
