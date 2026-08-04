//! Org chrome navigation: active section + crumb derived from the request path.

use topcoat::{context::Cx, router::uri};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavSection {
    Home,
    Docs,
    Builds,
    Issues,
    Account,
    AdminHome,
    AdminIssues,
    AdminDocs,
    AdminReleases,
    AdminCompanies,
    AdminCtap2,
}

/// Derive rail highlight and topbar crumb from the request path.
pub fn nav_from_cx(cx: &Cx) -> (NavSection, String) {
    nav_from_path(uri(cx).path())
}

/// Pure path → (section, crumb) mapping used by org / admin chrome.
pub fn nav_from_path(path: &str) -> (NavSection, String) {
    let mut parts = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty());
    let first = parts.next().unwrap_or("");

    // Global admin tools under `/admin/*`.
    if first == "admin" {
        let rest: Vec<&str> = parts.collect();
        return match rest.first().copied() {
            None => (NavSection::AdminHome, "admin".to_owned()),
            Some("issues") => (NavSection::AdminIssues, "admin / issues".to_owned()),
            Some("docs") => {
                if rest.get(1).copied() == Some("new") {
                    (NavSection::AdminDocs, "admin / docs / edit".to_owned())
                } else {
                    (NavSection::AdminDocs, "admin / docs".to_owned())
                }
            }
            Some("releases") => {
                if rest.get(1).copied() == Some("new") {
                    (
                        NavSection::AdminReleases,
                        "admin / releases / new".to_owned(),
                    )
                } else {
                    (NavSection::AdminReleases, "admin / releases".to_owned())
                }
            }
            Some("companies") => {
                if rest.get(1).copied() == Some("new") {
                    (
                        NavSection::AdminCompanies,
                        "admin / companies / new".to_owned(),
                    )
                } else if rest.get(1).is_some() {
                    (
                        NavSection::AdminCompanies,
                        "admin / companies / edit".to_owned(),
                    )
                } else {
                    (NavSection::AdminCompanies, "admin / companies".to_owned())
                }
            }
            Some("ctap2") => (NavSection::AdminCtap2, "admin / ctap2".to_owned()),
            _ => (NavSection::AdminHome, "admin".to_owned()),
        };
    }

    // Org-scoped: `/{org}/…`.
    let section = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();

    match section {
        "" => (NavSection::Home, "dashboard".to_owned()),
        "docs" => (NavSection::Docs, "documentation".to_owned()),
        "builds" => (NavSection::Builds, "builds".to_owned()),
        "issues" => {
            if rest.first().copied() == Some("new") {
                (NavSection::Issues, "issues / new".to_owned())
            } else {
                (NavSection::Issues, "issues".to_owned())
            }
        }
        "account" => (NavSection::Account, "account".to_owned()),
        _ => (NavSection::Home, "dashboard".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nav_home_and_unknown() {
        assert_eq!(
            nav_from_path("/acme"),
            (NavSection::Home, "dashboard".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/"),
            (NavSection::Home, "dashboard".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/nope"),
            (NavSection::Home, "dashboard".to_owned())
        );
        assert_eq!(
            nav_from_path(""),
            (NavSection::Home, "dashboard".to_owned())
        );
    }

    #[test]
    fn nav_member_sections() {
        assert_eq!(
            nav_from_path("/acme/docs"),
            (NavSection::Docs, "documentation".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/builds"),
            (NavSection::Builds, "builds".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/issues"),
            (NavSection::Issues, "issues".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/issues/new"),
            (NavSection::Issues, "issues / new".to_owned())
        );
        assert_eq!(
            nav_from_path("/acme/account"),
            (NavSection::Account, "account".to_owned())
        );
    }

    #[test]
    fn nav_admin_sections() {
        assert_eq!(
            nav_from_path("/admin"),
            (NavSection::AdminHome, "admin".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/issues"),
            (NavSection::AdminIssues, "admin / issues".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/docs"),
            (NavSection::AdminDocs, "admin / docs".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/docs/new"),
            (NavSection::AdminDocs, "admin / docs / edit".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/releases"),
            (NavSection::AdminReleases, "admin / releases".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/releases/new"),
            (
                NavSection::AdminReleases,
                "admin / releases / new".to_owned()
            )
        );
        assert_eq!(
            nav_from_path("/admin/companies"),
            (NavSection::AdminCompanies, "admin / companies".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/companies/new"),
            (
                NavSection::AdminCompanies,
                "admin / companies / new".to_owned()
            )
        );
        assert_eq!(
            nav_from_path("/admin/ctap2"),
            (NavSection::AdminCtap2, "admin / ctap2".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/unknown"),
            (NavSection::AdminHome, "admin".to_owned())
        );
    }
}
