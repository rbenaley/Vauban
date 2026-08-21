//! Shared `href!` query items. Paths come from page/route markers, not string tables.

use serde::Serialize;

#[derive(Serialize)]
pub struct ErrQ<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<&'a str>,
}

#[derive(Serialize)]
pub struct LoginErrorQ {
    pub error: &'static str,
}

#[derive(Serialize)]
pub struct TokenQ<'a> {
    pub token: &'a str,
}

#[derive(Serialize)]
pub struct PageQ {
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

pub fn page_one(page: &usize) -> bool {
    *page <= 1
}

#[derive(Serialize)]
pub struct ChannelPageQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub channel: &'a str,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

#[derive(Serialize)]
pub struct BuildsListQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub channel: &'a str,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<&'static str>,
}

#[derive(Serialize)]
pub struct DownloadErrorQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub channel: &'a str,
    pub dl_error: &'a str,
}

#[derive(Serialize)]
pub struct EnrolledQ<'a> {
    pub enrolled: &'a str,
}

#[derive(Serialize)]
pub struct KeyRevokeQ<'a> {
    pub revoke: &'a str,
    pub err: &'a str,
}

#[derive(Serialize)]
pub struct AdminIssueOrgQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub org: &'a str,
}

#[derive(Serialize)]
pub struct SearchQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub q: &'a str,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

#[derive(Serialize)]
pub struct AdminIssuesListQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub q: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub org: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub status: &'a str,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

#[derive(Serialize)]
pub struct DeleteQ {
    pub delete: u64,
}

#[derive(Serialize)]
pub struct DeleteErrQ {
    pub delete: u64,
    pub err: &'static str,
}

#[derive(Serialize)]
pub struct DeleteSearchQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub q: &'a str,
    pub delete: u64,
}

#[derive(Serialize)]
pub struct DeleteChannelPageQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub channel: &'a str,
    pub delete: u64,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

#[derive(Serialize)]
pub struct ChannelQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub channel: &'a str,
}

#[derive(Serialize)]
pub struct KeyPagesQ {
    #[serde(skip_serializing_if = "page_one")]
    pub pending_page: usize,
    #[serde(skip_serializing_if = "page_one")]
    pub active_page: usize,
}

#[derive(Serialize)]
pub struct KeyRevokeListQ<'a> {
    #[serde(skip_serializing_if = "page_one")]
    pub pending_page: usize,
    #[serde(skip_serializing_if = "page_one")]
    pub active_page: usize,
    pub revoke: &'a str,
}

#[derive(Serialize)]
pub struct EditCommentQ {
    pub edit: u64,
}

#[derive(Serialize)]
pub struct SearchListQ<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    pub q: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub status: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub cat: &'a str,
    #[serde(skip_serializing_if = "page_one")]
    pub page: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use topcoat::{context::Cx, router::href};

    #[test]
    fn href_login_and_query_error() {
        let cx = Cx::default();
        assert_eq!(href!("/login").resolve(&cx), "/login");
        assert_eq!(
            href!("/login")
                .query(LoginErrorQ { error: "link" })
                .resolve(&cx),
            "/login?error=link"
        );
        assert_eq!(href!("/choose-org").resolve(&cx), "/choose-org");
        assert_eq!(href!("/logout").resolve(&cx), "/logout");
    }

    #[test]
    fn href_org_admin_and_mail_paths() {
        use crate::app::org::Org;
        let cx = Cx::default();
        assert_eq!(href!("/{org}", Org("acme")).resolve(&cx), "/acme");
        assert_eq!(
            href!("/{org}/issues", Org("acme"))
                .query(PageQ { page: 2 })
                .resolve(&cx),
            "/acme/issues?page=2"
        );
        assert_eq!(
            href!("/{org}/issues", Org("acme"))
                .query(PageQ { page: 1 })
                .resolve(&cx),
            "/acme/issues"
        );
        assert_eq!(href!("/admin/releases").resolve(&cx), "/admin/releases");
        assert_eq!(
            href!("/admin/releases")
                .query(ErrQ {
                    err: Some("upload")
                })
                .resolve(&cx),
            "/admin/releases?err=upload"
        );
        assert_eq!(
            href!("/login/magic")
                .query(TokenQ { token: "abc" })
                .resolve(&cx),
            "/login/magic?token=abc"
        );
        assert_eq!(
            href!("/{org}/issues", Org("acme"))
                .query(SearchListQ {
                    q: "ssh",
                    status: "Open",
                    cat: "",
                    page: 2,
                })
                .resolve(&cx),
            "/acme/issues?q=ssh&status=Open&page=2"
        );
        assert_eq!(
            href!("/admin/issues/ISS-1")
                .query(AdminIssueOrgQ { org: "vauban" })
                .resolve(&cx),
            "/admin/issues/ISS-1?org=vauban"
        );
    }

    #[test]
    fn href_encodes_slug_segment() {
        use crate::app::org::Org;
        let cx = Cx::default();
        assert_eq!(
            href!("/{org}/docs", Org("acme/prod")).resolve(&cx),
            "/acme%2Fprod/docs"
        );
        assert_eq!(
            href!("/admin/docs")
                .query(DeleteErrQ {
                    delete: 9,
                    err: "confirm"
                })
                .resolve(&cx),
            "/admin/docs?delete=9&err=confirm"
        );
        assert_eq!(
            href!("/admin/companies")
                .query(DeleteSearchQ {
                    q: "acme",
                    delete: 3
                })
                .resolve(&cx),
            "/admin/companies?q=acme&delete=3"
        );
        assert_eq!(
            href!("/admin/releases")
                .query(DeleteChannelPageQ {
                    channel: "LTS",
                    delete: 4,
                    page: 2
                })
                .resolve(&cx),
            "/admin/releases?channel=LTS&delete=4&page=2"
        );
    }
}
