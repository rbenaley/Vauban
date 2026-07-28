/// VAUBAN Web - Base template.
///
/// Base template struct for Askama that wraps all page templates.
use askama::Template;

/// Flash message for displaying notifications.
#[derive(Debug, Clone)]
pub struct FlashMessage {
    pub level: String, // "success", "error", "warning", "info"
    pub message: String,
}

/// Process-wide cache for the configured brand name.
///
/// Populated exactly once at startup by [`set_brand_name`] (called from
/// `main::main` after the TOML config has been loaded). Every
/// [`VaubanConfig::default`] -- and therefore every Askama page rendered
/// by [`BaseTemplate::new`] -- reads through this cell so the wordmark
/// in the top-left of the sidebar matches the operator's
/// `[product.brand].name` directive without each handler having to
/// thread the brand explicitly.
///
/// The cell is intentionally write-once: the brand is part of the
/// boot configuration and changing it at runtime would create a
/// confusing "half-rebranded" UI for in-flight requests. A second
/// call to `set_brand_name` is a no-op (the first value wins).
static BRAND_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Install the brand name read from `[product.brand].name`. Called
/// exactly once at startup. Subsequent calls are no-ops -- the first
/// caller wins, which matches the boot-config-only contract.
pub fn set_brand_name(name: String) {
    let _ = BRAND_NAME.set(name);
}

/// Read the configured brand, falling back to `"VAUBAN"` if the cell
/// has not been initialized (e.g. unit tests that build a
/// [`VaubanConfig`] without going through `main`). Public so the
/// templates module can also expose it through context structs that
/// don't carry a full [`VaubanConfig`] (no current consumer needs
/// that yet, but the helper is the canonical read accessor).
pub fn brand_name() -> String {
    BRAND_NAME
        .get()
        .cloned()
        .unwrap_or_else(|| "VAUBAN".to_string())
}

/// Vauban configuration for templates.
///
/// `tz` carries the operator's browser-resolved IANA timezone (see
/// [`crate::middleware::browser_tz`]). It is set by every handler
/// through [`BaseTemplate::new`] and propagates automatically to
/// every page template via [`BaseTemplate::into_fields`]. Templates
/// then format `DateTime<Utc>` values via the
/// `|local(vauban.tz) / |local_seconds(vauban.tz)` filters.
/// `Tz::UTC` is the well-defined fallback (no cookie posted yet).
#[derive(Debug, Clone)]
pub struct VaubanConfig {
    pub brand_name: String,
    pub brand_logo: Option<String>,
    pub theme: String, // "light" or "dark"
    pub version: String,
    pub tz: chrono_tz::Tz,
}

impl Default for VaubanConfig {
    fn default() -> Self {
        Self {
            // Read through the process-wide cell so every page picks
            // up the operator-configured brand. Tests that construct
            // a `VaubanConfig` directly (without booting the cell)
            // see the canonical `"VAUBAN"` fallback.
            brand_name: brand_name(),
            brand_logo: None,
            theme: "dark".to_string(),
            version: format!(
                "v{} [{}]",
                env!("CARGO_PKG_VERSION"),
                env!("VAUBAN_GIT_HASH")
            ),
            // Default to UTC: the per-request override comes through
            // `BaseTemplate::new(title, user, browser_tz)` and through
            // the `with_tz` builder on `VaubanConfig` itself.
            tz: chrono_tz::Tz::UTC,
        }
    }
}

impl VaubanConfig {
    /// Override the timezone carried by this `VaubanConfig`.
    /// Used by tests and by `BaseTemplate::new(...)` to seed the
    /// browser-resolved Tz.
    pub fn with_tz(mut self, tz: chrono_tz::Tz) -> Self {
        self.tz = tz;
        self
    }
}

use crate::auth::PermissionContext;
use crate::templates::partials::SidebarContentTemplate;

/// Base template that all pages extend.
#[derive(Template)]
#[template(path = "base.html")]
pub struct BaseTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content: Option<SidebarContentTemplate>, // Sidebar content for include
    pub header_user: Option<UserContext>,                // Header user for include
}

/// User context for templates (simplified from `AuthUser`).
///
/// **Authorization policy.** `is_superuser` and `is_staff` are exposed for
/// **display purposes only** (e.g. role badges, account management forms).
/// They MUST NOT be used to gate UI elements: every authorization check in a
/// template must read from the Casbin-backed
/// [`crate::auth::PermissionContext`] published as `sc.perms.*` on the
/// sidebar (or as `perms.*` on per-page templates that opt in). Patterns
/// such as `{% if user.is_staff %}` for hiding/showing actionable controls
/// silently bypass custom Casbin policies (see issue #1) and are forbidden.
#[derive(Debug, Clone)]
pub struct UserContext {
    pub uuid: String,
    pub username: String,
    pub display_name: String,
    /// Display-only: do not gate UI on this; use `PermissionContext` instead.
    pub is_superuser: bool,
    /// Display-only: do not gate UI on this; use `PermissionContext` instead.
    pub is_staff: bool,
}

impl UserContext {
    pub fn is_authenticated(&self) -> bool {
        true
    }
}

impl BaseTemplate {
    /// Construct a `BaseTemplate` carrying the operator's
    /// browser-resolved timezone. Handlers extract a
    /// [`crate::middleware::BrowserTz`] from the request and pass
    /// `browser_tz.0` here so every page template renders dates in
    /// the operator's local timezone (DB / logs / IPC remain UTC,
    /// see `docs/runbooks/timezone_localization.md`).
    ///
    /// `Tz::UTC` is the safe fallback (no `vbn_tz` cookie posted
    /// yet, e.g. first hit before the bootstrap script runs).
    pub fn new(title: String, user: Option<UserContext>, tz: chrono_tz::Tz) -> Self {
        let header_user = user.clone();
        let sidebar_content = user.as_ref().map(|u| SidebarContentTemplate {
            user: u.clone(),
            is_dashboard: false,
            is_assets: false,
            is_manage_assets: false,
            is_sessions: false,
            is_recordings: false,
            is_users: false,
            is_groups: false,
            is_approvals: false,
            is_access_rules: false,
            is_vault_secrets: false,
            is_my_requests: false,
            is_iacs: false,
            pending_approval_count: 0,
            pending_iacs_count: 0,
            perms: PermissionContext::default(),
        });

        Self {
            title,
            user,
            vauban: VaubanConfig::default().with_tz(tz),
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content,
            header_user,
        }
    }

    pub fn with_messages(mut self, messages: Vec<FlashMessage>) -> Self {
        self.messages = messages;
        self
    }

    pub fn with_current_path(mut self, path: &str) -> Self {
        // Update sidebar with current path if user exists
        if let Some(ref user) = self.user {
            // Preserve any perms already injected by an earlier
            // `apply_sidebar_rbac`/`with_perms` call so that calling
            // `with_current_path` after the RBAC pre-load does not regress to
            // the deny-everything default. In practice handlers call this
            // before `apply_sidebar_rbac`, but we stay defensive.
            let preserved_perms = self
                .sidebar_content
                .as_ref()
                .map(|s| s.perms.clone())
                .unwrap_or_default();
            // Issue #27: differentiate the user-facing `/assets` page
            // (Connect / Request) from the admin `/assets/manage/*`
            // sub-tree (CRUD). The two highlight different sidebar
            // entries and the regex is intentionally narrow so adding a
            // new admin asset path under `/assets/manage` does not
            // bleed back into the user-zone highlight.
            let on_manage_assets = path.starts_with("/assets/manage");
            self.sidebar_content = Some(SidebarContentTemplate {
                user: user.clone(),
                is_dashboard: path == "/",
                is_assets: path.starts_with("/assets")
                    && !path.contains("/access")
                    && !on_manage_assets
                    && !path.contains("/groups"),
                is_manage_assets: on_manage_assets,
                is_sessions: path.contains("/sessions")
                    && !path.contains("/recordings")
                    && !path.contains("/approvals")
                    && !path.contains("/my-requests"),
                is_recordings: path.contains("/recordings"),
                is_users: path.contains("/users") && !path.contains("/groups"),
                // `/vault/secrets/groups` and `/vault/secrets/access`
                // belong to the self-contained Vault Secrets section:
                // they must highlight the "Vault Secrets" entry, not
                // the PAM "Groups" / "Access Rules" ones. Same for
                // `/assets/manage/groups` (asset groups), which lives
                // in the admin Assets section (`is_manage_assets`).
                is_groups: path.contains("/groups")
                    && !path.starts_with("/vault")
                    && !on_manage_assets,
                is_approvals: path.contains("/approvals"),
                is_access_rules: path.contains("/access") && !path.starts_with("/vault"),
                is_vault_secrets: path.starts_with("/vault/secrets"),
                is_my_requests: path.contains("/my-requests"),
                // The IACS sidebar entry covers BOTH the user-zone
                // onboarding form (`/iacs/onboard`) and the admin
                // landing page (`/iacs/admin`). The form is only ever
                // reached via "Onboard EWS" from `/assets`, so
                // highlighting the IACS entry on either path keeps
                // the navigation context intuitive for users while
                // also flagging the admin section to operators.
                is_iacs: path.starts_with("/iacs"),
                pending_approval_count: 0,
                pending_iacs_count: 0,
                perms: preserved_perms,
            });
        }
        self
    }

    /// Inject the canonical Casbin [`PermissionContext`] into the sidebar so
    /// templates can gate UI on `sc.perms.*` instead of `is_staff`/`is_superuser`.
    /// This is the only supported way to populate sidebar RBAC; handlers must
    /// call it (typically via [`crate::handlers::web::apply_sidebar_rbac`]).
    pub fn with_perms(mut self, perms: PermissionContext) -> Self {
        if let Some(ref mut sidebar) = self.sidebar_content {
            sidebar.perms = perms;
        }
        self
    }

    /// Set the count of pending approval requests (displayed as badge in sidebar).
    pub fn with_pending_approval_count(mut self, count: i64) -> Self {
        if let Some(ref mut sidebar) = self.sidebar_content {
            sidebar.pending_approval_count = count;
        }
        self
    }

    /// Set the count of pending IACS / EWS onboarding requests
    /// (rendered as a badge next to the IACS sidebar entry).
    pub fn with_pending_iacs_count(mut self, count: i64) -> Self {
        if let Some(ref mut sidebar) = self.sidebar_content {
            sidebar.pending_iacs_count = count;
        }
        self
    }

    /// Decompose BaseTemplate into individual fields for child templates.
    #[allow(clippy::type_complexity)]
    pub fn into_fields(
        self,
    ) -> (
        String,
        Option<UserContext>,
        VaubanConfig,
        Vec<FlashMessage>,
        String,
        Option<SidebarContentTemplate>,
        Option<UserContext>,
    ) {
        (
            self.title,
            self.user,
            self.vauban,
            self.messages,
            self.language_code,
            self.sidebar_content,
            self.header_user,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FlashMessage Tests ====================

    #[test]
    fn test_flash_message_success() {
        let msg = FlashMessage {
            level: "success".to_string(),
            message: "Operation completed".to_string(),
        };

        assert_eq!(msg.level, "success");
        assert_eq!(msg.message, "Operation completed");
    }

    #[test]
    fn test_flash_message_error() {
        let msg = FlashMessage {
            level: "error".to_string(),
            message: "Something went wrong".to_string(),
        };

        assert_eq!(msg.level, "error");
    }

    #[test]
    fn test_flash_message_clone() {
        let msg = FlashMessage {
            level: "warning".to_string(),
            message: "Be careful".to_string(),
        };
        let cloned = msg.clone();

        assert_eq!(msg.level, cloned.level);
        assert_eq!(msg.message, cloned.message);
    }

    #[test]
    fn test_flash_message_debug() {
        let msg = FlashMessage {
            level: "info".to_string(),
            message: "FYI".to_string(),
        };
        let debug_str = format!("{:?}", msg);

        assert!(debug_str.contains("FlashMessage"));
        assert!(debug_str.contains("info"));
    }

    // ==================== VaubanConfig Tests ====================

    #[test]
    fn test_vauban_config_default() {
        let config = VaubanConfig {
            brand_name: "VAUBAN".to_string(),
            brand_logo: None,
            theme: "dark".to_string(),
            ..Default::default()
        };

        assert_eq!(config.brand_name, "VAUBAN");
        assert!(config.brand_logo.is_none());
        assert_eq!(config.theme, "dark");
    }

    #[test]
    fn test_vauban_config_with_logo() {
        let config = VaubanConfig {
            brand_name: "Custom Brand".to_string(),
            brand_logo: Some("/static/logo.png".to_string()),
            theme: "light".to_string(),
            ..Default::default()
        };

        assert_eq!(config.brand_name, "Custom Brand");
        assert_eq!(config.brand_logo, Some("/static/logo.png".to_string()));
        assert_eq!(config.theme, "light");
    }

    #[test]
    fn test_vauban_config_clone() {
        let config = VaubanConfig {
            brand_name: "Test".to_string(),
            brand_logo: Some("logo.svg".to_string()),
            theme: "dark".to_string(),
            ..Default::default()
        };
        let cloned = config.clone();

        assert_eq!(config.brand_name, cloned.brand_name);
        assert_eq!(config.brand_logo, cloned.brand_logo);
    }

    // ==================== UserContext Tests ====================

    fn create_test_user() -> UserContext {
        UserContext {
            uuid: "test-uuid-123".to_string(),
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            is_superuser: false,
            is_staff: false,
        }
    }

    #[test]
    fn test_user_context_is_authenticated() {
        let user = create_test_user();
        assert!(user.is_authenticated());
    }

    #[test]
    fn test_user_context_superuser() {
        let user = UserContext {
            uuid: "admin-uuid".to_string(),
            username: "admin".to_string(),
            display_name: "Administrator".to_string(),
            is_superuser: true,
            is_staff: true,
        };

        assert!(user.is_superuser);
        assert!(user.is_staff);
        assert!(user.is_authenticated());
    }

    #[test]
    fn test_user_context_clone() {
        let user = create_test_user();
        let cloned = user.clone();

        assert_eq!(user.uuid, cloned.uuid);
        assert_eq!(user.username, cloned.username);
        assert_eq!(user.display_name, cloned.display_name);
    }

    #[test]
    fn test_user_context_debug() {
        let user = create_test_user();
        let debug_str = format!("{:?}", user);

        assert!(debug_str.contains("UserContext"));
        assert!(debug_str.contains("testuser"));
    }

    // ==================== BaseTemplate Tests ====================

    #[test]
    fn test_base_template_new_without_user() {
        let base = BaseTemplate::new("Login".to_string(), None, chrono_tz::Tz::UTC);

        assert_eq!(base.title, "Login");
        assert!(base.user.is_none());
        assert!(base.sidebar_content.is_none());
        assert!(base.header_user.is_none());
        assert_eq!(base.vauban.brand_name, "VAUBAN");
        assert_eq!(base.language_code, "en");
        assert_eq!(base.vauban.tz, chrono_tz::Tz::UTC);
    }

    #[test]
    fn test_base_template_new_with_user() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC);

        assert_eq!(base.title, "Dashboard");
        assert!(base.user.is_some());
        assert!(base.sidebar_content.is_some());
        assert!(base.header_user.is_some());
    }

    /// Browser-resolved Tz threads through to `vauban.tz` so every
    /// page template can format dates via `|local(vauban.tz)`.
    #[test]
    fn test_base_template_propagates_browser_tz() {
        let base = BaseTemplate::new("X".to_string(), None, chrono_tz::Tz::Europe__Paris);
        assert_eq!(base.vauban.tz, chrono_tz::Tz::Europe__Paris);
    }

    #[test]
    fn test_base_template_with_messages() {
        let base =
            BaseTemplate::new("Test".to_string(), None, chrono_tz::Tz::UTC).with_messages(vec![
                FlashMessage {
                    level: "success".to_string(),
                    message: "Done".to_string(),
                },
                FlashMessage {
                    level: "error".to_string(),
                    message: "Failed".to_string(),
                },
            ]);

        assert_eq!(base.messages.len(), 2);
        assert_eq!(base.messages[0].level, "success");
        assert_eq!(base.messages[1].level, "error");
    }

    #[test]
    fn test_base_template_with_current_path_dashboard() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_current_path("/");

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(sidebar.is_dashboard);
        assert!(!sidebar.is_assets);
        assert!(!sidebar.is_sessions);
    }

    #[test]
    fn test_base_template_with_current_path_assets() {
        let user = create_test_user();
        let base = BaseTemplate::new("Assets".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_current_path("/assets");

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(!sidebar.is_dashboard);
        assert!(sidebar.is_assets);
    }

    #[test]
    fn test_base_template_with_current_path_sessions() {
        let user = create_test_user();
        let base = BaseTemplate::new("Sessions".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_current_path("/sessions");

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(sidebar.is_sessions);
        assert!(!sidebar.is_recordings);
    }

    #[test]
    fn test_base_template_with_current_path_recordings() {
        let user = create_test_user();
        let base = BaseTemplate::new("Recordings".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_current_path("/sessions/recordings");

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(sidebar.is_recordings);
    }

    #[test]
    fn test_base_template_perms_default_until_injected() {
        let user = UserContext {
            uuid: "admin".to_string(),
            username: "admin".to_string(),
            display_name: "Admin".to_string(),
            is_superuser: true,
            is_staff: true,
        };
        let base = BaseTemplate::new("Admin".to_string(), Some(user), chrono_tz::Tz::UTC);

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(
            !sidebar.perms.admin_view,
            "PermissionContext must default to deny until apply_sidebar_rbac runs"
        );
    }

    #[test]
    fn test_base_template_with_perms_injects_casbin_view() {
        let user = create_test_user();
        let perms = PermissionContext {
            admin_view: true,
            groups_read: true,
            access_rules_read: true,
            ..PermissionContext::default()
        };
        let base = BaseTemplate::new("Admin".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_perms(perms);

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(sidebar.perms.admin_view);
        assert!(sidebar.perms.groups_read);
        assert!(sidebar.perms.access_rules_read);
    }

    #[test]
    fn test_with_current_path_preserves_injected_perms() {
        let user = create_test_user();
        let perms = PermissionContext {
            admin_view: true,
            ..PermissionContext::default()
        };
        let base = BaseTemplate::new("Admin".to_string(), Some(user), chrono_tz::Tz::UTC)
            .with_perms(perms)
            .with_current_path("/sessions");

        let sidebar = unwrap_some!(base.sidebar_content);
        assert!(
            sidebar.perms.admin_view,
            "with_current_path must preserve previously injected PermissionContext"
        );
    }

    #[test]
    fn test_base_template_into_fields() {
        let user = create_test_user();
        let base = BaseTemplate::new("Test".to_string(), Some(user), chrono_tz::Tz::UTC);
        let (title, user_ctx, vauban, messages, lang, sidebar, header) = base.into_fields();

        assert_eq!(title, "Test");
        assert!(user_ctx.is_some());
        assert_eq!(vauban.brand_name, "VAUBAN");
        assert!(messages.is_empty());
        assert_eq!(lang, "en");
        assert!(sidebar.is_some());
        assert!(header.is_some());
    }

    #[test]
    fn test_base_template_renders() {
        let base = BaseTemplate::new("Test Page".to_string(), None, chrono_tz::Tz::UTC);
        let result = base.render();
        assert!(result.is_ok(), "BaseTemplate should render successfully");
        let html = unwrap_ok!(result);
        // Template renders successfully - content verification depends on HTML structure
        assert!(!html.is_empty(), "Rendered HTML should not be empty");
    }

    #[test]
    fn test_base_template_renders_with_user() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC);
        let result = base.render();
        assert!(result.is_ok(), "BaseTemplate with user should render");
    }

    // ==================== Brand sidebar wordmark ====================
    //
    // The sidebar renders a different top-left visual depending on
    // `vauban.brand_name`:
    //   - "VAUBAN" (default) -> the wordmark `<span>VAUBAN</span>`.
    //   - "BAŞKESEN"          -> an embedded SVG of the Turkish flag.
    //   - any other value     -> falls back to the wordmark.
    // The three tests below pin each branch by rendering a real
    // `BaseTemplate` (with a user, so the sidebar partial is
    // included) and grepping the produced HTML.

    #[test]
    fn brand_default_vauban_renders_wordmark_in_sidebar() {
        let user = create_test_user();
        let base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC);
        let html = unwrap_ok!(base.render());
        assert!(
            html.contains(">VAUBAN<"),
            "default brand must render the canonical <span>VAUBAN</span> wordmark in the \
             sidebar; got HTML missing the literal '>VAUBAN<'"
        );
        assert!(
            !html.contains("BAŞKESEN"),
            "default brand must NOT leak the BAŞKESEN white-label key into the rendered HTML"
        );
        // Anti-leak: the Turkish-flag SVG title must only appear
        // when the BAŞKESEN brand is active.
        assert!(
            !html.contains("Turkish flag"),
            "default brand must NOT render the Turkish-flag SVG"
        );
    }

    #[test]
    fn brand_baskesen_renders_turkish_flag_svg_in_sidebar() {
        let user = create_test_user();
        let mut base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC);
        // The OnceLock cache may not be initialized in this test
        // process, so we set the field directly on the struct --
        // exercising the same code path the production renderer hits
        // after `set_brand_name` has populated the cache.
        base.vauban.brand_name = "BAŞKESEN".to_string();
        let html = unwrap_ok!(base.render());

        // Must render the flag artefacts: the canonical fill colour
        // (#E30A17 -- the Turkish-flag red), the SVG <title> the
        // template carries for screen readers, and the BAŞKESEN
        // string in the aria-label of the <a> element.
        assert!(
            html.contains("#E30A17"),
            "BAŞKESEN brand must render the SVG with the Turkish-flag red (#E30A17)"
        );
        assert!(
            html.contains("Turkish flag"),
            "BAŞKESEN brand must render the SVG <title>'BAŞKESEN (Turkish flag)'"
        );
        assert!(
            html.contains(r#"aria-label="BAŞKESEN""#),
            "BAŞKESEN brand must surface the brand string on the wordmark anchor"
        );

        // Must NOT render the wordmark fallback. The grep is
        // anchored on `>VAUBAN<` (the literal `<span>VAUBAN</span>`
        // text-node) so unrelated mentions of "VAUBAN" elsewhere in
        // the page (meta description, helper anchors) don't false-
        // positive the negative assertion.
        assert!(
            !html.contains(">VAUBAN<"),
            "BAŞKESEN brand must NOT render the <span>VAUBAN</span> wordmark fallback"
        );
    }

    #[test]
    fn brand_unknown_value_falls_back_to_vauban_wordmark() {
        // Pin: a value that is neither "VAUBAN" nor a recognised
        // white-label key (here a plausible-looking but unsupported
        // brand) MUST render the canonical wordmark, not the SVG.
        // This protects operators from a typo in their config -- the
        // sidebar never ends up visually broken.
        let user = create_test_user();
        let mut base = BaseTemplate::new("Dashboard".to_string(), Some(user), chrono_tz::Tz::UTC);
        base.vauban.brand_name = "Acme Corp".to_string();
        let html = unwrap_ok!(base.render());
        assert!(
            html.contains(">VAUBAN<"),
            "unknown brand must fall back to the <span>VAUBAN</span> wordmark"
        );
        assert!(
            !html.contains("Turkish flag"),
            "unknown brand must NOT trigger the Turkish-flag SVG"
        );
    }

    // ==================== Brand cell (set_brand_name / brand_name) ====================

    #[test]
    fn brand_name_helper_falls_back_to_vauban_when_uninitialized() {
        // Defensive: code paths that build a `VaubanConfig::default()`
        // before `main` has had a chance to install the brand (early
        // boot, unit tests, embedded smoke checks) must still see
        // the canonical wordmark. The OnceLock cell may already be
        // populated by another test in the same binary, in which
        // case we simply assert that the value is non-empty -- the
        // contract we care about is "no panics, no empty string".
        let value = brand_name();
        assert!(
            !value.is_empty(),
            "brand_name() must never return an empty string"
        );
    }
}
