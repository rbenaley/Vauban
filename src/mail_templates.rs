//! Compile-time transactional email HTML templates (`email/*.html`).

/// Invitation when a company account is created or revived.
pub const USER_JOIN_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/email/user-join.html"));

/// Sign-in magic link (login form request).
pub const USER_LOGIN_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user-login.html"
));

/// Access revoked when a company membership is removed.
pub const USER_LEAVE_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user-leave.html"
));

/// Star-fort logo for `cid:vauban-logo` inline attachments.
pub const VAUBAN_LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/vauban-logo.png"
));

pub const LOGO_CONTENT_ID: &str = "vauban-logo";

const PH_ORG: &str = "__ORG_NAME__";
const PH_URL: &str = "__MAGIC_URL__";
const PH_FROM: &str = "__FROM_ADDRESS__";
const PH_TTL: &str = "__TTL_MINUTES__";

/// Values injected into HTML templates before send.
#[derive(Debug, Clone, Copy)]
pub struct TemplateVars<'a> {
    pub org_name: Option<&'a str>,
    pub magic_url: Option<&'a str>,
    pub from_address: &'a str,
    pub ttl_minutes: Option<u64>,
}

/// Escape text for HTML element / attribute content.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Substitute placeholders in a template. `org_name` / URL are HTML-escaped.
pub fn render_html(template: &str, vars: TemplateVars<'_>) -> String {
    let mut out = template.to_owned();
    if let Some(org) = vars.org_name {
        out = out.replace(PH_ORG, &html_escape(org));
    }
    if let Some(url) = vars.magic_url {
        out = out.replace(PH_URL, &html_escape(url));
    }
    out = out.replace(PH_FROM, &html_escape(vars.from_address));
    if let Some(mins) = vars.ttl_minutes {
        out = out.replace(PH_TTL, &mins.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_ship_cid_and_placeholders() {
        for (name, html) in [
            ("join", USER_JOIN_HTML),
            ("login", USER_LOGIN_HTML),
            ("leave", USER_LEAVE_HTML),
        ] {
            assert!(
                html.contains(r#"src="cid:vauban-logo""#),
                "{name} must use cid logo"
            );
            assert!(
                !html.contains("data:image"),
                "{name} must not embed base64 logo"
            );
            assert!(
                html.contains(PH_FROM),
                "{name} must carry from-address placeholder"
            );
        }
        assert!(USER_JOIN_HTML.contains(PH_ORG));
        assert!(USER_JOIN_HTML.contains(PH_URL));
        assert!(USER_JOIN_HTML.contains(PH_TTL));
        assert!(USER_LOGIN_HTML.contains(PH_URL));
        assert!(USER_LOGIN_HTML.contains(PH_TTL));
        assert!(!USER_LOGIN_HTML.contains(PH_ORG));
        assert!(USER_LEAVE_HTML.contains(PH_ORG));
        assert!(!USER_LEAVE_HTML.contains(PH_URL));
        assert!(!USER_LEAVE_HTML.contains(PH_TTL));
        assert!(!VAUBAN_LOGO_PNG.is_empty());
        assert_eq!(&VAUBAN_LOGO_PNG[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn render_escapes_org_and_url() {
        let html = render_html(
            USER_JOIN_HTML,
            TemplateVars {
                org_name: Some(r#"Acme <script>"#),
                magic_url: Some("https://x.test/login/magic?token=ab&c=1"),
                from_address: "no-reply@vauban.sh",
                ttl_minutes: Some(5),
            },
        );
        assert!(html.contains("Acme &lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("token=ab&amp;c=1"));
        assert!(html.contains(">5 minutes<"));
        assert!(html.contains("no-reply@vauban.sh"));
        assert!(!html.contains(PH_ORG));
        assert!(!html.contains(PH_URL));
        assert!(!html.contains(PH_TTL));
        assert!(!html.contains(PH_FROM));
    }

    #[test]
    fn html_escape_covers_entities() {
        assert_eq!(
            html_escape(r#"a&b<c>"d'e"#),
            "a&amp;b&lt;c&gt;&quot;d&#39;e"
        );
    }
}
