//! Org chrome navigation: active section + crumb derived from the matched
//! route pattern (`/{org}/docs/{doc}`), falling back to the request path.

use topcoat::{
    context::Cx,
    router::{request::uri, try_endpoint},
};

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
    AdminKey,
}

/// Derive rail highlight and topbar crumb for the current request.
///
/// Prefers the matched endpoint pattern (Topcoat 0.6+ `try_endpoint`):
/// parameters keep their `{name}` form, so a slug or key value can never be
/// mistaken for a static segment (`/acme/docs/new` is still the Docs section
/// even though its last segment reads "new"). Unmatched URLs (404) carry no
/// endpoint and fall back to the request path.
pub fn nav_from_cx(cx: &Cx) -> (NavSection, String) {
    match try_endpoint(cx) {
        Some(endpoint) => nav_from_pattern(endpoint.path().as_str()),
        None => nav_from_path(uri(cx).path()),
    }
}

/// Route pattern → (section, crumb): `/{org}/docs/{doc}` is Docs,
/// `/admin/companies/{company_id}` is the companies edit crumb, a catch-all
/// (`/admin/{*rest}`) lands on the section home.
pub fn nav_from_pattern(pattern: &str) -> (NavSection, String) {
    nav_from_segments(pattern)
}

/// Concrete request path → (section, crumb). Used when no endpoint matched
/// (404 chrome) and by tests; shares the segment table with the pattern form.
pub fn nav_from_path(path: &str) -> (NavSection, String) {
    nav_from_segments(path)
}

/// Segment table shared by patterns and concrete paths. A `{param}` or
/// `{*catch_all}` placeholder is an opaque segment, like a real slug.
fn nav_from_segments(path: &str) -> (NavSection, String) {
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
            Some("key") => (NavSection::AdminKey, "admin / key".to_owned()),
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

    /// Every registered route pattern maps to the section its layout expects.
    #[test]
    fn nav_from_pattern_table() {
        let table: &[(&str, NavSection, &str)] = &[
            ("/{org}", NavSection::Home, "dashboard"),
            ("/{org}/docs", NavSection::Docs, "documentation"),
            ("/{org}/docs/{doc}", NavSection::Docs, "documentation"),
            ("/{org}/builds", NavSection::Builds, "builds"),
            ("/{org}/builds/{release_ver}", NavSection::Builds, "builds"),
            ("/{org}/issues", NavSection::Issues, "issues"),
            ("/{org}/issues/new", NavSection::Issues, "issues / new"),
            ("/{org}/issues/{issue_key}", NavSection::Issues, "issues"),
            ("/vauban/issues/{issue_key}", NavSection::Issues, "issues"),
            ("/{org}/account", NavSection::Account, "account"),
            ("/admin", NavSection::AdminHome, "admin"),
            (
                "/admin/issues/{issue_key}",
                NavSection::AdminIssues,
                "admin / issues",
            ),
            (
                "/admin/docs/new",
                NavSection::AdminDocs,
                "admin / docs / edit",
            ),
            ("/admin/docs/{doc}", NavSection::AdminDocs, "admin / docs"),
            (
                "/admin/releases/new",
                NavSection::AdminReleases,
                "admin / releases / new",
            ),
            (
                "/admin/releases/confirm",
                NavSection::AdminReleases,
                "admin / releases",
            ),
            (
                "/admin/releases/{release_id}",
                NavSection::AdminReleases,
                "admin / releases",
            ),
            (
                "/admin/companies/new",
                NavSection::AdminCompanies,
                "admin / companies / new",
            ),
            (
                "/admin/companies/{company_id}",
                NavSection::AdminCompanies,
                "admin / companies / edit",
            ),
            ("/admin/key", NavSection::AdminKey, "admin / key"),
            ("/admin/{*rest}", NavSection::AdminHome, "admin"),
        ];
        for (pattern, section, crumb) in table {
            assert_eq!(
                nav_from_pattern(pattern),
                (*section, (*crumb).to_owned()),
                "pattern {pattern}"
            );
        }
    }

    /// A doc slug that reads like a static segment does not change the
    /// section when the pattern is used (`{doc}` stays opaque).
    #[test]
    fn nav_pattern_keeps_params_opaque() {
        assert_eq!(
            nav_from_pattern("/{org}/docs/{doc}"),
            nav_from_path("/acme/docs/new")
        );
        assert_eq!(nav_from_pattern("/admin/docs/{doc}").1, "admin / docs");
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
            nav_from_path("/admin/key"),
            (NavSection::AdminKey, "admin / key".to_owned())
        );
        assert_eq!(
            nav_from_path("/admin/unknown"),
            (NavSection::AdminHome, "admin".to_owned())
        );
    }
}
