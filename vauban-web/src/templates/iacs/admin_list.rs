//! Admin-zone IACS landing page (`GET /iacs/admin`).
//!
//! Aggregates two distinct collections in a single page so an admin
//! can review the entire IACS surface at a glance:
//!
//! 1. Pending onboarding requests -- the operationally hot section,
//!    rendered with Approve / Reject controls (separation of duties
//!    not enforced for IACS today: the requester can be the admin
//!    of last resort, but a future iteration may add an `is_own`
//!    flag analogous to the JIT approval flow). Paginated, 3 rows
//!    per page (`PENDING_PAGE_SIZE`); query parameter `pending_page`.
//! 2. Engineering Workstations -- two tabs:
//!     - **Active** (default): rows whose `offboarded_at IS NULL`
//!       (covers `active` AND `disabled`).
//!     - **Offboarded**: rows whose `offboarded_at IS NOT NULL`.
//!
//!    Each tab has independent pagination (5 rows per page,
//!    `EWS_PAGE_SIZE`) and a single HTMX-driven `search` input
//!    that filters on `users.username` OR `ews.name`. The query
//!    parameters are: `tab=active|offboarded`, `ews_page`,
//!    `search`. The handler resolves the `tab` value and only
//!    paginates the active tab when `tab=active`, mirroring the
//!    pattern used by `/accounts/users` for HTMX-driven listings.
//!
//! A small "history" tab is intentionally NOT rendered here -- the
//! detail page already shows all decision-related fields, and the
//! audit log is queried separately in the runbook tooling.

use askama::Template;

use crate::templates::accounts::user_list::Pagination;
use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Minimal RFC 3986 unreserved-only percent-encoder used for the
/// `search` query-string parameter when the template builds links
/// like `?ews_page=2&search=...`. We deliberately do NOT pull in
/// `urlencoding` / `percent-encoding`: this code path only encodes
/// already-sanitized search strings (`sanitize()` strips control
/// chars in the handler), and adding a new transitive dependency
/// for a 10-char helper is wasteful. Spaces become `%20` (NOT `+`),
/// which is what query-string consumers (`Query<HashMap<...>>`) and
/// the `<input value="...">` round-trip expect.
fn percent_encode_qs(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        // Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

/// Pending onboarding-request row.
#[derive(Debug, Clone)]
pub struct AdminPendingRequest {
    pub request_uuid: String,
    pub requester_username: String,
    pub ews_name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    pub justification: String,
    pub created_at: String,
}

/// Active / disabled / offboarded EWS row.
#[derive(Debug, Clone)]
pub struct AdminEwsRow {
    pub ews_uuid: String,
    pub owner_username: String,
    pub name: String,
    pub key_algo: String,
    pub fingerprint_short: String,
    /// `active` | `disabled` | `offboarded`. Pinned as a string so
    /// the template can branch with simple equality checks.
    pub state: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
    pub offboarded_at: Option<String>,
}

impl AdminEwsRow {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
    pub fn is_disabled(&self) -> bool {
        self.state == "disabled"
    }
    pub fn is_offboarded(&self) -> bool {
        self.state == "offboarded"
    }
    pub fn state_class(&self) -> &'static str {
        match self.state.as_str() {
            "active" => "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300",
            "disabled" => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
            "offboarded" => {
                "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-300"
            }
            _ => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
        }
    }
}

/// 3 pending requests per page (UX signal: "more than 3 pending
/// onboards is unusual, paginate so the operator notices").
pub const PENDING_PAGE_SIZE: i64 = 3;

/// 5 EWS per page (Active and Offboarded tabs share the same size).
pub const EWS_PAGE_SIZE: i64 = 5;

/// Active EWS tab key (default).
pub const TAB_ACTIVE: &str = "active";

/// Offboarded EWS tab key.
pub const TAB_OFFBOARDED: &str = "offboarded";

#[derive(Template)]
#[template(path = "iacs/admin_list.html")]
pub struct AdminListTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<crate::templates::base::UserContext>,
    pub csrf_token: String,
    pub pending_requests: Vec<AdminPendingRequest>,
    /// Pagination of the pending-requests section. `None` when
    /// `pending_requests.is_empty()` (no controls, no "Showing 0
    /// of 0" line). Reuses the shared `Pagination` shape used
    /// across `/accounts/users`, `/assets`, etc.
    pub pending_pagination: Option<Pagination>,
    /// Active tab key: `"active"` (default) or `"offboarded"`. Read
    /// from `?tab=...` and clamped to one of the two valid values
    /// in the handler so the template can branch with a simple
    /// equality check (no "unknown tab" arm).
    pub ews_tab: String,
    pub ews_rows: Vec<AdminEwsRow>,
    /// Pagination of the EWS section. `None` when the current
    /// tab (matching `ews_tab`) has no rows.
    pub ews_pagination: Option<Pagination>,
    /// Current value of the EWS search box (mirrored back so the
    /// field stays populated after an HTMX swap and shows up in
    /// the address bar via `hx-push-url`).
    pub ews_search: Option<String>,
}

impl AdminListTemplate {
    /// True iff the rendered tab is the Active tab.
    pub fn is_active_tab(&self) -> bool {
        self.ews_tab == TAB_ACTIVE
    }

    /// True iff the rendered tab is the Offboarded tab.
    pub fn is_offboarded_tab(&self) -> bool {
        self.ews_tab == TAB_OFFBOARDED
    }

    /// Build the `?tab=&search=` query suffix used by the pagination
    /// links in the EWS section so a click on "page 2" preserves the
    /// current tab AND the active search filter. The leading `&`
    /// is intentional -- the caller already emits `?ews_page=N`.
    pub fn ews_qs(&self) -> String {
        let mut out = String::new();
        out.push_str("&tab=");
        out.push_str(&self.ews_tab);
        if let Some(s) = self.ews_search.as_ref()
            && !s.is_empty()
        {
            out.push_str("&search=");
            out.push_str(&percent_encode_qs(s));
        }
        out
    }

    /// Build the `?pending_page=&...` query suffix used by the
    /// pending-requests pagination so the EWS tab/search are not
    /// reset when the operator paginates the pending section.
    pub fn pending_qs(&self) -> String {
        let mut out = String::new();
        if !self.ews_tab.is_empty() && self.ews_tab != TAB_ACTIVE {
            out.push_str("&tab=");
            out.push_str(&self.ews_tab);
        }
        if let Some(s) = self.ews_search.as_ref()
            && !s.is_empty()
        {
            out.push_str("&search=");
            out.push_str(&percent_encode_qs(s));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pagination(current: i32, total: i32, total_items: i32, per_page: i32) -> Pagination {
        Pagination {
            current_page: current,
            total_pages: total,
            total_items,
            items_per_page: per_page,
            has_previous: current > 1,
            has_next: current < total,
            start_index: (current - 1) * per_page + 1,
            end_index: (current * per_page).min(total_items),
        }
    }

    fn fixture() -> AdminListTemplate {
        AdminListTemplate {
            title: "IACS".into(),
            user: Some(UserContext {
                uuid: "u".into(),
                username: "admin".into(),
                display_name: "Admin".into(),
                is_superuser: true,
                is_staff: true,
            }),
            vauban: VaubanConfig::default(),
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            csrf_token: "tk".into(),
            pending_requests: vec![AdminPendingRequest {
                request_uuid: "00000000-0000-0000-0000-000000000001".into(),
                requester_username: "alice".into(),
                ews_name: "factory-ews-01".into(),
                key_algo: "ssh-ed25519".into(),
                fingerprint_short: "abcdef0123456789".into(),
                justification: "New onboarding for factory line 7".into(),
                created_at: "May 6, 2026 10:00".into(),
            }],
            pending_pagination: Some(pagination(1, 1, 1, PENDING_PAGE_SIZE as i32)),
            ews_tab: TAB_ACTIVE.into(),
            ews_rows: vec![
                AdminEwsRow {
                    ews_uuid: "00000000-0000-0000-0000-000000000002".into(),
                    owner_username: "bob".into(),
                    name: "factory-ews-02".into(),
                    key_algo: "ssh-ed25519".into(),
                    fingerprint_short: "1111222233334444".into(),
                    state: "active".into(),
                    created_at: "May 1, 2026 09:00".into(),
                    disabled_at: None,
                    offboarded_at: None,
                },
                AdminEwsRow {
                    ews_uuid: "00000000-0000-0000-0000-000000000003".into(),
                    owner_username: "carol".into(),
                    name: "factory-ews-03".into(),
                    key_algo: "ssh-ed25519".into(),
                    fingerprint_short: "5555666677778888".into(),
                    state: "disabled".into(),
                    created_at: "Apr 14, 2026 09:00".into(),
                    disabled_at: Some("May 2, 2026 12:00".into()),
                    offboarded_at: None,
                },
            ],
            ews_pagination: Some(pagination(1, 1, 2, EWS_PAGE_SIZE as i32)),
            ews_search: None,
        }
    }

    #[test]
    fn admin_list_renders() {
        let html = fixture().render().expect("render");
        assert!(html.contains("Pending onboarding requests"));
        assert!(html.contains("alice"));
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/approve"));
        assert!(html.contains("/iacs/admin/request/00000000-0000-0000-0000-000000000001/reject"));
    }

    #[test]
    fn ews_active_renders_disable_and_offboard() {
        let html = fixture().render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/disable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000002/enable"));
    }

    #[test]
    fn ews_disabled_renders_enable_only() {
        let html = fixture().render().expect("render");
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/enable"));
        assert!(html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/offboard"));
        assert!(!html.contains("/iacs/admin/ews/00000000-0000-0000-0000-000000000003/disable"));
    }

    #[test]
    fn empty_state_renders() {
        let mut tpl = fixture();
        tpl.pending_requests.clear();
        tpl.pending_pagination = None;
        tpl.ews_rows.clear();
        tpl.ews_pagination = None;
        let html = tpl.render().expect("render");
        assert!(html.contains("No pending requests"));
        assert!(html.contains("No EWS"));
    }

    #[test]
    fn helpers_match_state() {
        let row = AdminEwsRow {
            ews_uuid: "x".into(),
            owner_username: "y".into(),
            name: "z".into(),
            key_algo: "ssh-ed25519".into(),
            fingerprint_short: "fp".into(),
            state: "active".into(),
            created_at: "now".into(),
            disabled_at: None,
            offboarded_at: None,
        };
        assert!(row.is_active());
        assert!(!row.is_disabled());
        assert!(!row.is_offboarded());
        assert!(row.state_class().contains("green"));
    }

    #[test]
    fn renders_tab_navigation_with_search_input() {
        let html = fixture().render().expect("render");
        // Two tab buttons (Active default + Offboarded).
        assert!(
            html.contains("data-testid=\"iacs-tab-active\""),
            "Active tab anchor missing: {}",
            html.lines().take(50).collect::<Vec<_>>().join("\n")
        );
        assert!(html.contains("data-testid=\"iacs-tab-offboarded\""));
        // HTMX-driven search input.
        assert!(html.contains("data-testid=\"iacs-ews-search\""));
        assert!(html.contains("hx-get=\"/iacs/admin\""));
    }

    #[test]
    fn renders_pending_pagination_block() {
        let mut tpl = fixture();
        // Force a multi-page pending section.
        tpl.pending_pagination = Some(pagination(1, 2, 4, PENDING_PAGE_SIZE as i32));
        let html = tpl.render().expect("render");
        assert!(
            html.contains("data-testid=\"iacs-pending-pagination\""),
            "pending pagination block must render when total_pages > 1"
        );
        assert!(
            html.contains("?pending_page=2"),
            "next-page link to pending_page=2 must be present"
        );
    }

    #[test]
    fn renders_ews_pagination_preserves_tab_and_search() {
        let mut tpl = fixture();
        tpl.ews_search = Some("bob".to_string());
        tpl.ews_pagination = Some(pagination(1, 2, 7, EWS_PAGE_SIZE as i32));
        let html = tpl.render().expect("render");
        assert!(html.contains("data-testid=\"iacs-ews-pagination\""));
        // The next-page link must preserve tab + search via ews_qs().
        // Askama HTML-escapes `&` to `&#38;` (or `&amp;`); both are
        // valid query separators per RFC 3986 / HTML5.
        let has_link = html.contains("?ews_page=2&tab=active&search=bob")
            || html.contains("?ews_page=2&#38;tab=active&#38;search=bob")
            || html.contains("?ews_page=2&amp;tab=active&amp;search=bob");
        assert!(
            has_link,
            "next-page link must preserve tab and search; html sample: {}",
            html.lines()
                .filter(|l| l.contains("ews_page="))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn offboarded_tab_active_when_requested() {
        let mut tpl = fixture();
        tpl.ews_tab = TAB_OFFBOARDED.into();
        let html = tpl.render().expect("render");
        // Offboarded tab anchor is the *active* one (no link href -- it's
        // the current page). The Active tab in turn becomes a link.
        assert!(html.contains("data-testid=\"iacs-tab-offboarded\""));
        assert!(tpl.is_offboarded_tab());
        assert!(!tpl.is_active_tab());
    }

    #[test]
    fn ews_qs_includes_search_when_present() {
        let mut tpl = fixture();
        tpl.ews_search = Some("alice ews".to_string());
        let qs = tpl.ews_qs();
        assert!(qs.contains("&tab=active"));
        // urlencoding turns the space into %20.
        assert!(qs.contains("&search=alice%20ews"), "got {qs}");
    }
}
