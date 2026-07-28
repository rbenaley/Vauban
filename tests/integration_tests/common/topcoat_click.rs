//! Contract checks for Topcoat `data-topcoat-on:*` attribute values.
//!
//! The browser runtime binds handlers as:
//! `s = new Function("cx", "return " + attr)(cx); el.addEventListener(type, e => s(event))`
//! so the attribute must *evaluate to a function*. Statement forms such as
//! `navigator.clipboard.writeText(this.getAttribute(...))` run at bind time,
//! can throw, and abort the document scan (leaving later tabs inert).

/// Decode the HTML entities Topcoat emits inside attribute / comment payloads.
pub fn decode_topcoat_js(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&amp;", "&")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Collect decoded `data-topcoat-on:click` attribute values from SSR HTML.
pub fn data_topcoat_on_click_values(html: &str) -> Vec<String> {
    let needle = "data-topcoat-on:click=\"";
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(needle) {
        let start = i + needle.len();
        let tail = &rest[start..];
        let Some(end) = tail.find('"') else {
            break;
        };
        out.push(decode_topcoat_js(&tail[..end]));
        rest = &tail[end + 1..];
    }
    out
}

/// True when `js` is a function expression under Topcoat's `return ${js}` bind.
pub fn is_topcoat_function_handler(js: &str) -> bool {
    let t = js.trim_start();
    t.starts_with('(') || t.starts_with("function") || t.starts_with("async ")
}

/// Assert every `data-topcoat-on:click` in `html` is a function expression.
pub fn assert_topcoat_click_handlers_are_functions(html: &str) {
    let values = data_topcoat_on_click_values(html);
    assert!(
        !values.is_empty(),
        "expected at least one data-topcoat-on:click handler in SSR HTML"
    );
    for v in &values {
        assert!(
            is_topcoat_function_handler(v),
            "Topcoat click handler must be a function expression \
             (runtime does `return <js>` at bind time); got: {v}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_expr_and_iife_pass() {
        assert!(is_topcoat_function_handler(
            "(e) => { navigator.clipboard.writeText('x'); }"
        ));
        assert!(is_topcoat_function_handler(
            "(() => { const [__external0] = []; return (__local0) => __external0.set(true); })()"
        ));
        assert!(is_topcoat_function_handler("function (e) { return; }"));
    }

    #[test]
    fn bind_time_statement_fails() {
        assert!(!is_topcoat_function_handler(
            "navigator.clipboard.writeText(this.getAttribute('data-copy')); this.textContent='Copied';"
        ));
    }

    #[test]
    fn extracts_and_decodes_handlers() {
        let html = r#"
            <button data-topcoat-on:click="(e) =&gt; { const x = &quot;a&quot;; }"></button>
            <button data-topcoat-on:click="navigator.clipboard.writeText('x')"></button>
        "#;
        let vals = data_topcoat_on_click_values(html);
        assert_eq!(vals.len(), 2);
        assert!(vals[0].contains("=>"));
        assert!(vals[0].contains("\"a\""));
        assert!(is_topcoat_function_handler(&vals[0]));
        assert!(!is_topcoat_function_handler(&vals[1]));
    }
}
