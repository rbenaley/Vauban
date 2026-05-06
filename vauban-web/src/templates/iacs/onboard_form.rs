//! IACS / EWS onboarding form template.
//!
//! Reused for both `GET /iacs/onboard` (new request -- `prefill` has
//! all empty fields) and the edit-pending flow (`prefill` re-hydrates
//! the existing request UUID + name + key + justification).

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Form data prefilled into the onboarding form.
///
/// On the new-request flow these are all empty. On the edit-pending
/// flow they hold the current values of the row (so the user can fix
/// a typo without re-pasting their whole `id_VAUBAN.pub`).
#[derive(Debug, Clone, Default)]
pub struct OnboardFormPrefill {
    /// `Some(request_uuid)` on the edit flow, `None` on the new flow.
    /// Drives the form action: `/iacs/onboard` for None,
    /// `/iacs/onboard/{uuid}/edit` for Some.
    pub request_uuid: Option<String>,
    pub name: String,
    pub public_key: String,
    pub justification: String,
}

/// Onboarding form template.
///
/// `max_ews_per_user`:
/// * `0` is the "unlimited" sentinel mirroring `[industrial]`.
/// * Any non-zero value is shown verbatim in the form to set
///   expectations before submit.
#[derive(Template)]
#[template(path = "iacs/onboard_form.html")]
pub struct OnboardFormTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    pub csrf_token: String,
    pub prefill: OnboardFormPrefill,
    pub max_ews_per_user: u32,
}

impl OnboardFormTemplate {
    /// True when the form is in edit mode.
    pub fn is_edit(&self) -> bool {
        self.prefill.request_uuid.is_some()
    }

    /// Form `action=` URL.
    pub fn form_action(&self) -> String {
        match &self.prefill.request_uuid {
            Some(uuid) => format!("/iacs/onboard/{}/edit", uuid),
            None => "/iacs/onboard".to_string(),
        }
    }

    /// Friendly form heading.
    pub fn heading(&self) -> &'static str {
        if self.is_edit() {
            "Edit pending EWS request"
        } else {
            "Onboard a new Engineering Workstation"
        }
    }

    /// "Unlimited" or the integer cap, ready for verbatim render.
    pub fn cap_label(&self) -> String {
        if self.max_ews_per_user == 0 {
            "Unlimited".to_string()
        } else {
            self.max_ews_per_user.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(prefill: OnboardFormPrefill, cap: u32) -> OnboardFormTemplate {
        OnboardFormTemplate {
            title: "Onboard EWS".into(),
            user: Some(UserContext {
                uuid: "u".into(),
                username: "alice".into(),
                display_name: "Alice".into(),
                is_superuser: false,
                is_staff: false,
            }),
            vauban: VaubanConfig {
                brand_name: "VAUBAN".into(),
                brand_logo: None,
                theme: "dark".into(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".into(),
            sidebar_content: None,
            header_user: None,
            csrf_token: "tk".into(),
            prefill,
            max_ews_per_user: cap,
        }
    }

    #[test]
    fn form_action_new_path() {
        let t = fixture(OnboardFormPrefill::default(), 0);
        assert!(!t.is_edit());
        assert_eq!(t.form_action(), "/iacs/onboard");
        assert_eq!(t.heading(), "Onboard a new Engineering Workstation");
    }

    #[test]
    fn form_action_edit_path() {
        let t = fixture(
            OnboardFormPrefill {
                request_uuid: Some("abc-123".into()),
                ..Default::default()
            },
            0,
        );
        assert!(t.is_edit());
        assert_eq!(t.form_action(), "/iacs/onboard/abc-123/edit");
        assert_eq!(t.heading(), "Edit pending EWS request");
    }

    #[test]
    fn cap_zero_renders_unlimited() {
        let t = fixture(OnboardFormPrefill::default(), 0);
        assert_eq!(t.cap_label(), "Unlimited");
    }

    #[test]
    fn cap_non_zero_renders_number() {
        let t = fixture(OnboardFormPrefill::default(), 5);
        assert_eq!(t.cap_label(), "5");
    }

    #[test]
    fn template_renders_new_with_unix_and_windows_tabs() {
        let t = fixture(OnboardFormPrefill::default(), 0);
        let html = t.render().expect("render");
        assert!(html.contains("ssh-keygen -t ed25519"));
        assert!(html.contains("id_VAUBAN"));
        assert!(html.contains("USERPROFILE"));
        assert!(html.contains("/iacs/onboard"));
        assert!(html.contains("Onboard"));
    }

    #[test]
    fn template_renders_edit_with_prefilled_fields() {
        let prefill = OnboardFormPrefill {
            request_uuid: Some("abc-123".into()),
            name: "factory-ews-01".into(),
            public_key: "ssh-ed25519 AAAA...".into(),
            justification: "Plant rollout".into(),
        };
        let t = fixture(prefill, 0);
        let html = t.render().expect("render");
        assert!(html.contains("factory-ews-01"));
        assert!(html.contains("ssh-ed25519 AAAA..."));
        assert!(html.contains("Plant rollout"));
        assert!(html.contains("/iacs/onboard/abc-123/edit"));
        assert!(html.contains("Edit"));
    }

    #[test]
    fn template_advertises_cap_when_finite() {
        let t = fixture(OnboardFormPrefill::default(), 3);
        let html = t.render().expect("render");
        assert!(html.contains("3"));
    }

    #[test]
    fn template_carries_csrf_token_in_hidden_input() {
        let t = fixture(OnboardFormPrefill::default(), 0);
        let html = t.render().expect("render");
        assert!(html.contains("name=\"csrf_token\""));
    }
}
