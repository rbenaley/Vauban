//! Light dialect for `DocArticle.body` (plain text, no raw HTML).
//!
//! Markers:
//! - `#` / `##` headings -> h3 in the Concept modal
//! - blank-line paragraphs
//! - fenced code with triple backticks (literal `<pre>`; no inline chips)
//! - `::: callout` … `:::` callout boxes
//! - `- ` list items (consecutive)
//! - paired `` `code` `` in headings / paragraphs / lists / callouts — rendered
//!   by the page via [`crate::release_notes::parse_inline_code`] (not here)

use std::fmt;

/// Parsed document block ready for server-side `view!` rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Heading(String),
    Paragraph(String),
    Pre(String),
    Callout(String),
    List(Vec<String>),
}

/// Escape text for safe interpolation into HTML text nodes / attributes.
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Parse dialect source into blocks. Text is stored raw; callers must render
/// via escaped HTML text nodes (Topcoat `view!` interpolation) — never as raw HTML.
/// Use [`escape_html`] when building HTML strings outside `view!`.
pub fn parse(src: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut lines = src.lines().peekable();
    let mut para: Vec<String> = Vec::new();
    let mut list: Vec<String> = Vec::new();

    let flush_para = |para: &mut Vec<String>, blocks: &mut Vec<Block>| {
        if para.is_empty() {
            return;
        }
        let text = para.join("\n");
        para.clear();
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            blocks.push(Block::Paragraph(trimmed.to_owned()));
        }
    };

    let flush_list = |list: &mut Vec<String>, blocks: &mut Vec<Block>| {
        if list.is_empty() {
            return;
        }
        let items = std::mem::take(list);
        blocks.push(Block::List(items));
    };

    while let Some(line) = lines.next() {
        let trimmed = line.trim_end();

        if trimmed == "```" || trimmed.starts_with("```") {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            let mut code = Vec::new();
            for code_line in lines.by_ref() {
                if code_line.trim_end() == "```" {
                    break;
                }
                code.push(code_line.to_owned());
            }
            blocks.push(Block::Pre(code.join("\n")));
            continue;
        }

        if trimmed == "::: callout" {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            let mut body = Vec::new();
            for callout_line in lines.by_ref() {
                if callout_line.trim_end() == ":::" {
                    break;
                }
                body.push(callout_line.to_owned());
            }
            let text = body.join("\n");
            blocks.push(Block::Callout(text.trim().to_owned()));
            continue;
        }

        if trimmed.starts_with("::: ") {
            // Unknown fence opener: treat the opener line as paragraph text.
            flush_list(&mut list, &mut blocks);
            para.push(trimmed.to_owned());
            continue;
        }

        if trimmed.is_empty() {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("# ") {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            blocks.push(Block::Heading(rest.trim().to_owned()));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("## ") {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            blocks.push(Block::Heading(rest.trim().to_owned()));
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("- ") {
            flush_para(&mut para, &mut blocks);
            list.push(rest.trim().to_owned());
            continue;
        }

        flush_list(&mut list, &mut blocks);
        para.push(trimmed.to_owned());
    }

    flush_para(&mut para, &mut blocks);
    flush_list(&mut list, &mut blocks);
    blocks
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Block::Heading(t) => write!(f, "Heading({t})"),
            Block::Paragraph(t) => write!(f, "Paragraph({t})"),
            Block::Pre(t) => write!(f, "Pre({t})"),
            Block::Callout(t) => write!(f, "Callout({t})"),
            Block::List(items) => write!(f, "List({})", items.len()),
        }
    }
}

/// True when body still looks like the pre-dialect thin seed (for refresh).
pub fn is_thin_seed_body(body: &str, summary: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed == summary.trim() {
        return true;
    }
    if trimmed.starts_with(summary.trim())
        && trimmed.contains("Full article body will expand as the knowledge base grows.")
    {
        return true;
    }
    // Pre-dialect quick-start outline (no fences / callouts).
    trimmed.starts_with("Vauban ships as a single signed binary.")
        && trimmed.contains("1. Install the binary")
        && !trimmed.contains("::: callout")
        && !trimmed.contains("```")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_heading_paragraph_pre_callout_list() {
        let src = r#"# Install

Download the binary.

```
$ curl example
```

::: callout
Need 2 GB RAM.
:::

## Next

- First item
- Second item
"#;
        let blocks = parse(src);
        assert_eq!(
            blocks,
            vec![
                Block::Heading("Install".into()),
                Block::Paragraph("Download the binary.".into()),
                Block::Pre("$ curl example".into()),
                Block::Callout("Need 2 GB RAM.".into()),
                Block::Heading("Next".into()),
                Block::List(vec!["First item".into(), "Second item".into()]),
            ]
        );
    }

    #[test]
    fn escape_html_neutralizes_markup() {
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape_html("A < B & \"c\""), "A &lt; B &amp; &quot;c&quot;");
    }

    #[test]
    fn parse_preserves_raw_text_for_view_escaping() {
        let blocks = parse("<script>alert(1)</script>\n\n# A < B");
        assert_eq!(
            blocks[0],
            Block::Paragraph("<script>alert(1)</script>".into())
        );
        assert_eq!(blocks[1], Block::Heading("A < B".into()));
        // Rendering path must use text nodes or escape_html — never raw HTML concat.
        assert_eq!(
            escape_html(&match &blocks[0] {
                Block::Paragraph(t) => t.clone(),
                _ => panic!("expected paragraph"),
            }),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    #[test]
    fn unknown_fence_becomes_paragraph() {
        let blocks = parse("::: warning\nnope\n");
        assert!(matches!(&blocks[0], Block::Paragraph(p) if p.contains("::: warning")));
    }

    #[test]
    fn thin_seed_detection() {
        assert!(is_thin_seed_body(
            "Summary here.\n\nFull article body will expand as the knowledge base grows.",
            "Summary here."
        ));
        assert!(!is_thin_seed_body(
            "# Overview\n\nReal dialect body with content.",
            "Summary here."
        ));
    }

    #[test]
    fn parse_keeps_paired_backticks_in_prose_for_inline_renderer() {
        // Block parse must not strip `` `…` ``; the page turns them into chips.
        let blocks = parse(
            "Only non-deleted assets with `auth_type = ssh_key` are included.\n\n- Use `user@host`\n",
        );
        assert_eq!(
            blocks[0],
            Block::Paragraph(
                "Only non-deleted assets with `auth_type = ssh_key` are included.".into()
            )
        );
        assert_eq!(blocks[1], Block::List(vec!["Use `user@host`".into()]));
    }

    #[test]
    fn fenced_triple_backticks_still_become_pre() {
        let blocks = parse("See:\n\n```\nvauban-supervisor asset-pubkeys\n```\n");
        assert!(matches!(&blocks[0], Block::Paragraph(p) if p == "See:"));
        assert_eq!(
            blocks[1],
            Block::Pre("vauban-supervisor asset-pubkeys".into())
        );
    }
}
