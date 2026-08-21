//! Shared docs-dialect renderer (KB articles + issue comment bodies).

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::{
    app::_components::{ico_issues, note_inline_text},
    docs_body::{self, Block},
};

/// Parse [`docs_body`] and render the same blocks as `/admin/docs` / `/{org}/docs`.
#[component]
pub async fn docs_formatted_body(cx: &Cx, body: &str) -> Result {
    let blocks = docs_body::parse(body);
    view! {
        cx =>
        <div class="vb-docs-body">
            for block in blocks {
                (render_docs_block(cx, block).await?)
            }
        </div>
    }
}

async fn render_docs_block(cx: &Cx, block: Block) -> Result {
    match block {
        Block::Heading(text) => {
            view! { cx => <h3>note_inline_text(text: &text)</h3> }
        }
        Block::Paragraph(text) => {
            view! {
                cx =>
                <p style="white-space: pre-wrap;">note_inline_text(text: &text)</p>
            }
        }
        Block::Pre(text) => {
            view! { cx => <pre class="vb-pre">(text)</pre> }
        }
        Block::Callout(text) => {
            view! {
                cx =>
                <div class="vb-callout">
                    (ico_issues(cx, 16).await?)
                    <span style="white-space: pre-wrap;">
                        note_inline_text(text: &text)
                    </span>
                </div>
            }
        }
        Block::List(items) => {
            view! {
                cx =>
                <ul>
                    for item in items {
                        <li>note_inline_text(text: &item)</li>
                    }
                </ul>
            }
        }
    }
}
