//! Render paired `` `code` `` as mono chips (release notes + KB article prose).

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::release_notes::{InlineSegment, parse_inline_code};

/// Changelog body fragment: plain text + light gray monospace chips.
#[component]
pub async fn note_inline_text(cx: &Cx, text: &str) -> Result {
    let segs = parse_inline_code(text);
    view! {
        cx =>
        for seg in segs {
            (render_seg(cx, seg).await?)
        }
    }
}

async fn render_seg(cx: &Cx, seg: InlineSegment) -> Result {
    match seg {
        InlineSegment::Text(t) => {
            view! { cx => (t) }
        }
        InlineSegment::Code(c) => {
            view! { cx => <code class="vb-inline-code">(c)</code> }
        }
    }
}
