//! Property tests for email HTML placeholder rendering.

use proptest::prelude::*;
use vcp::mail_templates::{
    TemplateVars, USER_JOIN_HTML, USER_LEAVE_HTML, USER_LOGIN_HTML, html_escape, render_html,
};

proptest! {
    #[test]
    fn prop_render_escapes_org_and_never_leaves_placeholders(
        org in "[A-Za-z0-9 <>&\"']{1,40}",
        token in "[a-f0-9]{16,64}",
        ttl in 1u64..120,
    ) {
        let url = format!("https://access.example/login/magic?token={token}&x=1");
        let from = "no-reply@vauban.sh";
        let join = render_html(
            USER_JOIN_HTML,
            TemplateVars {
                org_name: Some(&org),
                magic_url: Some(&url),
                from_address: from,
                ttl_minutes: Some(ttl),
            },
        );
        let login = render_html(
            USER_LOGIN_HTML,
            TemplateVars {
                org_name: None,
                magic_url: Some(&url),
                from_address: from,
                ttl_minutes: Some(ttl),
            },
        );
        let leave = render_html(
            USER_LEAVE_HTML,
            TemplateVars {
                org_name: Some(&org),
                magic_url: None,
                from_address: from,
                ttl_minutes: None,
            },
        );
        for html in [&join, &login, &leave] {
            prop_assert!(!html.contains("__ORG_NAME__"));
            prop_assert!(!html.contains("__MAGIC_URL__"));
            prop_assert!(!html.contains("__FROM_ADDRESS__"));
            prop_assert!(!html.contains("__TTL_MINUTES__"));
            prop_assert!(html.contains(r#"src="cid:vauban-logo""#));
            prop_assert!(html.contains(from));
        }
        let esc = html_escape(&org);
        prop_assert!(join.contains(&esc));
        prop_assert!(leave.contains(&esc));
        prop_assert!(join.contains(&html_escape(&url)));
        prop_assert!(login.contains(&html_escape(&url)));
        let ttl_label = format!("{ttl} minutes");
        prop_assert!(join.contains(&ttl_label));
        prop_assert!(login.contains(&ttl_label));
        let raw_org_cell = format!(">{org}<");
        prop_assert!(!join.contains(&raw_org_cell));
    }
}
