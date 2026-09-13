//! Shared docs-dialect renderer (KB articles + issue comment bodies).

use topcoat::{
    Result,
    context::Cx,
    view::{View, component, view},
};

use crate::{
    app::_components::{ico_issues, note_inline_text},
    docs_body::{self, Block},
};

/// Parse [`docs_body`] and render the same blocks as `/admin/docs` / `/{org}/docs`.
#[component]
pub async fn docs_formatted_body(cx: &Cx, body: &str) -> Result<impl View> {
    let blocks = docs_body::parse(body);
    Ok(view! {
        cx =>
        <div class="vb-docs-body">
            for block in blocks {
                render_docs_block(block: block)
            }
        </div>
    })
}

#[component]
async fn render_docs_block(cx: &Cx, block: Block) -> Result<impl View> {
    Ok(view! {
        cx =>
        match block {
            Block::Heading(text) => {
                <h3>note_inline_text(text: &text)</h3>
            }
            Block::Paragraph(text) => {
                <p style="white-space: pre-wrap;">note_inline_text(text: &text)</p>
            }
            Block::Pre(text) => {
                <pre class="vb-pre">(text)</pre>
            }
            Block::Callout(text) => {
                <div class="vb-callout">
                    ico_issues(size: 16)
                    <span style="white-space: pre-wrap;">
                        note_inline_text(text: &text)
                    </span>
                </div>
            }
            Block::List(items) => {
                <ul>
                    for item in items {
                        <li>note_inline_text(text: &item)</li>
                    }
                </ul>
            }
        }
    })
}
