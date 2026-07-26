//! Org chrome navigation: active section + crumb derived from the request path.

use topcoat::{context::Cx, router::uri};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NavSection {
    Home,
    Docs,
    Builds,
    Issues,
    Account,
    AdminHome,
    AdminDocs,
    AdminReleases,
    AdminCompanies,
}

/// Derive rail highlight and topbar crumb from `/{org}/…` path segments.
pub fn nav_from_cx(cx: &Cx) -> (NavSection, String) {
    let path = uri(cx).path();
    let mut parts = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty());
    let _org = parts.next();
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
        "admin" => match rest.first().copied() {
            None => (NavSection::AdminHome, "admin".to_owned()),
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
                } else {
                    (NavSection::AdminCompanies, "admin / companies".to_owned())
                }
            }
            _ => (NavSection::AdminHome, "admin".to_owned()),
        },
        _ => (NavSection::Home, "dashboard".to_owned()),
    }
}
