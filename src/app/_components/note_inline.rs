//! Render paired `` `code` `` as mono chips (release notes + KB article prose).

use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

use crate::release_notes::{InlineSegment, parse_inline_code};

/// Changelog body fragment: plain text + light gray monospace chips.
#[component]
pub async fn note_inline_text(cx: &Cx, text: &str) -> Result<impl View> {
    let segs = parse_inline_code(text);
    Ok(view! {
        cx =>
        for seg in segs {
            render_seg(seg: seg)
        }
    })
}

#[component]
async fn render_seg(cx: &Cx, seg: InlineSegment) -> Result<impl View> {
    Ok(view! {
        cx =>
        match seg {
            InlineSegment::Text(t) => {
                (t)
            }
            InlineSegment::Code(c) => {
                <code class="vb-inline-code">(c)</code>
            }
        }
    })
}
