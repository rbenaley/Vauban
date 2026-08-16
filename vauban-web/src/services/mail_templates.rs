//! Compile-time transactional email HTML templates (`email/*.html`).
//!
//! Placeholders are substituted by [`render_html`]. Caller-controlled
//! field values are HTML-escaped. Optional blocks (`__FACTS_BLOCK__`,
//! `__NOTICE_BLOCK__`, `__INFO_BLOCK__`, `__DANGER_BLOCK__`,
//! `__CTA_BLOCK__`) are pre-composed by the fragment builders in this
//! module -- that is the only path that injects markup.

use shared::smtp::EMAIL_LOGO_CID;

pub const ACCESS_REQUEST_SUBMITTED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/access_request_submitted.html"
));
pub const ACCESS_REQUEST_APPROVED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/access_request_approved.html"
));
pub const ACCESS_REQUEST_REJECTED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/access_request_rejected.html"
));
pub const ACCESS_REQUEST_REVOKED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/access_request_revoked.html"
));
pub const ACCESS_REQUEST_EXPIRED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/access_request_expired.html"
));
pub const USER_CREATED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user_created.html"
));
pub const USER_PASSWORD_RESET_REQUESTED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user_password_reset_requested.html"
));
pub const USER_LOCKED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user_locked.html"
));
pub const USER_MFA_RESET_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/user_mfa_reset.html"
));
pub const SECURITY_MONO_ADMIN_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/security_mono_admin.html"
));
pub const IACS_ONBOARD_SUBMITTED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/iacs_onboard_submitted.html"
));
pub const IACS_ONBOARD_APPROVED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/iacs_onboard_approved.html"
));
pub const IACS_ONBOARD_REJECTED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/iacs_onboard_rejected.html"
));
pub const IACS_OFFBOARDED_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/email/iacs_offboarded.html"
));

/// Catalogue of `(event_kind, template)` used by drift tests.
pub const CATALOGUE: &[(&str, &str)] = &[
    ("access_request.submitted", ACCESS_REQUEST_SUBMITTED_HTML),
    ("access_request.approved", ACCESS_REQUEST_APPROVED_HTML),
    ("access_request.rejected", ACCESS_REQUEST_REJECTED_HTML),
    ("access_request.revoked", ACCESS_REQUEST_REVOKED_HTML),
    ("access_request.expired", ACCESS_REQUEST_EXPIRED_HTML),
    ("user.created", USER_CREATED_HTML),
    (
        "user.password_reset_requested",
        USER_PASSWORD_RESET_REQUESTED_HTML,
    ),
    ("user.locked_after_failed_attempts", USER_LOCKED_HTML),
    ("user.mfa_reset_by_admin", USER_MFA_RESET_HTML),
    ("security.mono_admin_detected", SECURITY_MONO_ADMIN_HTML),
    ("iacs.onboard_submitted", IACS_ONBOARD_SUBMITTED_HTML),
    ("iacs.onboard_approved", IACS_ONBOARD_APPROVED_HTML),
    ("iacs.onboard_rejected", IACS_ONBOARD_REJECTED_HTML),
    ("iacs.offboarded", IACS_OFFBOARDED_HTML),
];

const PH_BRAND: &str = "__BRAND__";
const PH_BASE_URL: &str = "__BASE_URL__";
const PH_FACTS: &str = "__FACTS_BLOCK__";
const PH_NOTICE: &str = "__NOTICE_BLOCK__";
const PH_INFO: &str = "__INFO_BLOCK__";
const PH_DANGER: &str = "__DANGER_BLOCK__";
const PH_CTA: &str = "__CTA_BLOCK__";

/// Values injected into an HTML template before send.
#[derive(Debug, Clone)]
pub struct TemplateVars<'a> {
    pub brand: &'a str,
    pub base_url: &'a str,
    /// Already-escaped field substitutions (`__ASSET__` -> value).
    pub fields: &'a [(&'a str, String)],
    pub facts_block: String,
    pub notice_block: String,
    pub info_block: String,
    pub danger_block: String,
    pub cta_block: String,
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

/// Label/value table. Both sides are escaped.
pub fn facts_block(rows: &[(&str, &str)]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut inner = String::new();
    for (i, (label, value)) in rows.iter().enumerate() {
        let border = if i + 1 < rows.len() {
            " border-bottom:1px solid #e8e7e2;"
        } else {
            ""
        };
        inner.push_str("<tr>\n<td width=\"150\" style=\"width:150px; padding:12px 14px;");
        inner.push_str(border);
        inner.push_str(" font-family:Arial,Helvetica,sans-serif; font-size:12px; line-height:19px; mso-line-height-rule:exactly; color:#6b7684;\">");
        inner.push_str(&html_escape(label));
        inner.push_str("</td>\n<td style=\"padding:12px 14px;");
        inner.push_str(border);
        inner.push_str(" font-family:'Courier New',Courier,monospace; font-size:13px; line-height:20px; mso-line-height-rule:exactly; color:#16202c; word-break:break-all;\">");
        inner.push_str(&html_escape(value));
        inner.push_str("</td>\n</tr>\n");
    }
    wrap_facts_table(&inner)
}

/// Gold notice callout. `inner` is escaped.
pub fn notice_block(inner: &str) -> String {
    callout(inner, "#fdf9f0", "#e0c68c", "#6f5417")
}

/// Blue info callout. `inner` is escaped.
pub fn info_block(inner: &str) -> String {
    callout(inner, "#f4f9fd", "#bcd3e6", "#1d5c96")
}

/// Red danger callout. `inner` is escaped.
pub fn danger_block(inner: &str) -> String {
    callout(inner, "#f6e9e9", "#e4c4c4", "#8c2f2f")
}

fn callout(inner: &str, bg: &str, border: &str, color: &str) -> String {
    if inner.is_empty() {
        return String::new();
    }
    wrap_callout(&html_escape(inner), bg, border, color)
}

/// Bulletproof button plus raw-URL fallback. URL and label are escaped.
pub fn cta_block(url: &str, label: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let url_esc = html_escape(url);
    let label_esc = html_escape(label);
    format!(
        "<tr>\n\
         <td style=\"padding:28px 40px 0 40px;\">\n\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n\
         <tr>\n\
         <td bgcolor=\"#16202c\" style=\"background-color:#16202c; border-radius:6px;\">\n\
         <a href=\"{url_esc}\" style=\"display:block; padding:15px 30px; font-family:Arial,Helvetica,sans-serif; font-size:15px; font-weight:bold; line-height:18px; mso-line-height-rule:exactly; color:#ffffff; text-decoration:none;\">{label_esc}</a>\n\
         </td>\n\
         </tr>\n\
         </table>\n\
         </td>\n\
         </tr>\n\
         <tr>\n\
         <td style=\"padding:26px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:12px; line-height:19px; mso-line-height-rule:exactly; color:#6b7684;\">\n\
         If the button does not work, copy this address into your browser:\n\
         </td>\n\
         </tr>\n\
         <tr>\n\
         <td style=\"padding:10px 40px 0 40px;\">\n\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"width:100%;\">\n\
         <tr>\n\
         <td bgcolor=\"#f7f6f2\" style=\"background-color:#f7f6f2; border:1px solid #e6e4dd; border-radius:6px; padding:12px 14px; font-family:'Courier New',Courier,monospace; font-size:11px; line-height:17px; mso-line-height-rule:exactly; color:#4a4f55; word-break:break-all;\">\n\
         <a href=\"{url_esc}\" style=\"color:#b07f2e; text-decoration:none; word-break:break-all;\">{url_esc}</a>\n\
         </td>\n\
         </tr>\n\
         </table>\n\
         </td>\n\
         </tr>\n"
    )
}

fn wrap_facts_table(inner: &str) -> String {
    format!(
        "<tr>\n<td style=\"padding:24px 40px 0 40px;\">\n\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"width:100%; border:1px solid #e6e4dd; border-radius:6px;\">\n\
         {inner}\
         </table>\n</td>\n</tr>\n"
    )
}

fn wrap_callout(inner: &str, bg: &str, border: &str, color: &str) -> String {
    format!(
        "<tr>\n<td style=\"padding:26px 40px 0 40px;\">\n\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"width:100%;\">\n\
         <tr>\n\
         <td bgcolor=\"{bg}\" style=\"background-color:{bg}; border:1px solid {border}; border-radius:6px; padding:14px 16px; font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:20px; mso-line-height-rule:exactly; color:{color};\">\n\
         {inner}\n\
         </td>\n</tr>\n</table>\n</td>\n</tr>\n"
    )
}

/// Inputs for [`render_event`] (avoids a 9-argument helper).
#[derive(Debug, Clone)]
pub struct RenderSpec<'a> {
    pub brand: &'a str,
    pub base_url: &'a str,
    pub fields: &'a [(&'a str, String)],
    pub facts: &'a [(&'a str, &'a str)],
    pub notice: Option<&'a str>,
    pub info: Option<&'a str>,
    pub danger: Option<&'a str>,
    pub cta: Option<(&'a str, &'a str)>,
}

/// Render a catalogue template with escaped fields and optional blocks.
pub fn render_event(template: &str, spec: RenderSpec<'_>) -> String {
    render_html(
        template,
        TemplateVars {
            brand: spec.brand,
            base_url: spec.base_url,
            fields: spec.fields,
            facts_block: facts_block(spec.facts),
            notice_block: spec.notice.map(notice_block).unwrap_or_default(),
            info_block: spec.info.map(info_block).unwrap_or_default(),
            danger_block: spec.danger.map(danger_block).unwrap_or_default(),
            cta_block: spec
                .cta
                .map(|(url, label)| cta_block(url, label))
                .unwrap_or_default(),
        },
    )
}

/// Substitute placeholders. Field values in `vars.fields` are already escaped.
pub fn render_html(template: &str, vars: TemplateVars<'_>) -> String {
    let mut out = template.to_owned();
    out = out.replace(PH_BRAND, &html_escape(vars.brand));
    out = out.replace(PH_BASE_URL, &html_escape(vars.base_url));
    out = out.replace(PH_FACTS, &vars.facts_block);
    out = out.replace(PH_NOTICE, &vars.notice_block);
    out = out.replace(PH_INFO, &vars.info_block);
    out = out.replace(PH_DANGER, &vars.danger_block);
    out = out.replace(PH_CTA, &vars.cta_block);
    for (ph, value) in vars.fields {
        out = out.replace(ph, value);
    }
    out
}

/// Convenience: escape a field pair.
pub fn field(placeholder: &'static str, value: &str) -> (&'static str, String) {
    (placeholder, html_escape(value))
}

/// `cid:` href used by every template (no angle brackets).
pub fn logo_cid_href() -> String {
    format!("cid:{EMAIL_LOGO_CID}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_covers_fourteen_kinds() {
        assert_eq!(CATALOGUE.len(), 14);
        let mut kinds: Vec<&str> = CATALOGUE.iter().map(|(k, _)| *k).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), 14);
    }

    #[test]
    fn every_template_ships_brand_cid_and_no_scripts() {
        for (kind, html) in CATALOGUE {
            assert!(html.contains(PH_BRAND), "{kind} must carry __BRAND__");
            assert!(!html.contains("VAUBAN"), "{kind} must not hard-code VAUBAN");
            assert!(
                html.contains(&format!("cid:{EMAIL_LOGO_CID}")),
                "{kind} must reference the shared CID"
            );
            assert!(
                !html.contains("data:image"),
                "{kind} must not embed data URIs"
            );
            assert!(!html.contains("<script"), "{kind} must not carry script");
            let without_mso = html.replace(
                "<!--[if mso]><style>body,table,td,a{font-family:Arial,Helvetica,sans-serif !important;}</style><![endif]-->",
                "",
            );
            assert!(
                !without_mso.contains("<style"),
                "{kind} must not carry a style block outside the mso conditional"
            );
            for (i, line) in html.lines().enumerate() {
                assert!(
                    line.len() <= 998,
                    "{kind} line {} is {} chars",
                    i + 1,
                    line.len()
                );
            }
        }
    }

    #[test]
    fn html_escape_covers_entities() {
        assert_eq!(
            html_escape(r#"a&b<c>"d'e"#),
            "a&amp;b&lt;c&gt;&quot;d&#39;e"
        );
    }

    #[test]
    fn render_escapes_fields_and_clears_placeholders() {
        let html = render_html(
            ACCESS_REQUEST_REJECTED_HTML,
            TemplateVars {
                brand: "Acme <script>",
                base_url: "https://x.test/?a=1&b=2",
                fields: &[
                    field("__APPROVER__", "eve<script>"),
                    field("__ASSET__", "db&1"),
                    field("__PROTOCOL__", "ssh"),
                ],
                facts_block: facts_block(&[("Asset", "db&1")]),
                notice_block: String::new(),
                info_block: String::new(),
                danger_block: danger_block("no <script>"),
                cta_block: String::new(),
            },
        );
        assert!(html.contains("Acme &lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("db&amp;1"));
        assert!(html.contains("no &lt;script&gt;"));
        assert!(html.contains("https://x.test/?a=1&amp;b=2"));
        assert!(!html.contains(PH_BRAND));
        assert!(!html.contains(PH_FACTS));
        assert!(!html.contains(PH_DANGER));
        assert!(!html.contains("__APPROVER__"));
    }

    #[test]
    fn empty_optional_blocks_are_empty_strings() {
        assert!(facts_block(&[]).is_empty());
        assert!(notice_block("").is_empty());
        assert!(info_block("").is_empty());
        assert!(danger_block("").is_empty());
        assert!(cta_block("", "x").is_empty());
    }

    #[test]
    fn logo_cid_href_matches_shared_constant() {
        assert_eq!(logo_cid_href(), format!("cid:{EMAIL_LOGO_CID}"));
        assert!(!logo_cid_href().contains('<'));
    }
}
