//! IACS tunnel status page (lot L2: UI only, lot L5: live updates).
//!
//! Renders a single-page status view for an in-flight IACS tunnel
//! session. The page is deliberately minimal:
//!
//!   * the `ssh -L ...` command the operator must run from their EWS
//!     to bind the local port-forward (with a copy-to-clipboard
//!     button),
//!   * the current tunnel state pill (`waiting_client` -> `tunnel_active`
//!     -> `terminated`),
//!   * lifecycle metadata: peer IP (filled in once the EWS handshakes),
//!     connection time, byte counters, and the EWS UUID,
//!   * a Disconnect button that posts to the existing
//!     `/api/v1/sessions/{uuid}/terminate` endpoint.
//!
//! L2 ships the page **without** the WebSocket subscription that
//! drives the byte counters and the state pill in real time -- L5
//! wires it up. The template is structured so that adding the
//! Alpine `x-data` block in L5 requires no Rust-side change.

use askama::Template;

use crate::templates::base::{FlashMessage, UserContext, VaubanConfig};

/// Pre-resolved page context. Field semantics are documented inline
/// because the template renders them verbatim and a typo in either
/// place is a regression.
#[derive(Template)]
#[template(path = "sessions/iacs_tunnel_status.html")]
pub struct IacsTunnelStatusTemplate {
    pub title: String,
    pub user: Option<UserContext>,
    pub vauban: VaubanConfig,
    pub messages: Vec<FlashMessage>,
    pub language_code: String,
    pub sidebar_content:
        Option<crate::templates::partials::sidebar_content::SidebarContentTemplate>,
    pub header_user: Option<UserContext>,
    /// Session UUID -- becomes the SSH username on the EWS side.
    pub session_uuid: String,
    /// Asset display name.
    pub asset_name: String,
    /// Industrial protocol label (`modbus`, `opcua`, ...). Empty
    /// string for unsupported / generic TCP rows.
    pub industrial_protocol: String,
    /// Bastion host the EWS connects to (typically the same hostname
    /// as the web UI, but the IACS sshd may run on a different
    /// interface so we expose it explicitly via the configured
    /// `[industrial.iacs_tunnel].advertise_hostname`).
    pub bastion_hostname: String,
    /// Bastion port the IACS sshd is bound to (default 22322).
    pub bastion_port: u16,
    /// Local port the EWS will forward FROM (e.g. 4321) -- pulled from
    /// the asset row at session creation time.
    pub local_forward_port: u16,
    /// Target host:port the bastion will tunnel TO. Today always
    /// `127.0.0.1:4321` (config-driven), tomorrow derived from
    /// `assets.hostname:assets.port`.
    pub tunnel_target_addr: String,
    /// Current session status (`waiting_client`, `tunnel_active`,
    /// `terminated`). Used for the initial state pill; L5 mutates
    /// it client-side via the WebSocket push.
    pub session_status: String,
    /// CSRF token for the Disconnect form.
    pub csrf_token: String,
}

impl IacsTunnelStatusTemplate {
    /// Build the canonical
    /// `ssh -i ~/.ssh/id_VAUBAN -L LP:127.0.0.1:LP <session_uuid>@<bastion> -p <port> -N`
    /// command line as a String.
    ///
    /// `-i ~/.ssh/id_VAUBAN` is required: without it OpenSSH offers
    /// `~/.ssh/id_rsa` / `id_ed25519` / agent keys, none of which are
    /// registered as an EWS, and the IACS sshd rejects with
    /// "Permission denied (publickey)" -- see
    /// `services::iacs_tunnel::auth::verify_pubkey` (`EwsNotFound`).
    /// The path matches the canonical filename produced by the
    /// onboarding flow (`templates/iacs/onboard_form.html`).
    ///
    /// The format is consumed both by the template (rendered as
    /// `<code>`) and by the unit tests below.
    pub fn ssh_command(&self) -> String {
        format!(
            "ssh -i ~/.ssh/id_VAUBAN -L {lp}:127.0.0.1:{lp} {sess}@{host} -p {port} -N",
            lp = self.local_forward_port,
            sess = self.session_uuid,
            host = self.bastion_hostname,
            port = self.bastion_port,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_template() -> IacsTunnelStatusTemplate {
        IacsTunnelStatusTemplate {
            title: "IACS tunnel".to_string(),
            user: None,
            vauban: VaubanConfig {
                brand_name: "VAUBAN".to_string(),
                brand_logo: None,
                theme: "dark".to_string(),
                ..Default::default()
            },
            messages: Vec::new(),
            language_code: "en".to_string(),
            sidebar_content: None,
            header_user: None,
            session_uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            asset_name: "PLC-Modbus-A1".to_string(),
            industrial_protocol: "modbus".to_string(),
            bastion_hostname: "bastion.example.com".to_string(),
            bastion_port: 22322,
            local_forward_port: 4321,
            tunnel_target_addr: "127.0.0.1:4321".to_string(),
            session_status: "waiting_client".to_string(),
            csrf_token: "csrf-token".to_string(),
        }
    }

    #[test]
    fn ssh_command_format_is_canonical() {
        let t = make_template();
        assert_eq!(
            t.ssh_command(),
            "ssh -i ~/.ssh/id_VAUBAN -L 4321:127.0.0.1:4321 \
             11111111-1111-1111-1111-111111111111@bastion.example.com -p 22322 -N"
        );
    }

    /// Regression pin: the `-i ~/.ssh/id_VAUBAN` flag is mandatory.
    /// Without it OpenSSH offers default keys (none are registered as
    /// an EWS) and the IACS sshd rejects with "Permission denied
    /// (publickey)". The path mirrors the onboarding flow
    /// (`templates/iacs/onboard_form.html`).
    #[test]
    fn ssh_command_carries_explicit_identity_file() {
        let t = make_template();
        let cmd = t.ssh_command();
        assert!(
            cmd.contains("-i ~/.ssh/id_VAUBAN"),
            "ssh command must explicitly point at the EWS private key -- got {}",
            cmd
        );
    }

    #[test]
    fn ssh_command_uses_local_forward_port_on_both_sides() {
        let mut t = make_template();
        t.local_forward_port = 502;
        assert!(t.ssh_command().contains("-L 502:127.0.0.1:502"));
    }

    #[test]
    fn ssh_command_carries_session_uuid_as_username() {
        let t = make_template();
        let cmd = t.ssh_command();
        assert!(
            cmd.contains(&format!("{}@", t.session_uuid)),
            "ssh username must be the session UUID -- got {}",
            cmd
        );
    }

    #[test]
    fn template_renders_with_status_pill_and_command() {
        let t = make_template();
        let html = t.render().expect("render must succeed");
        assert!(html.contains("PLC-Modbus-A1"));
        assert!(html.contains("waiting_client"));
        assert!(html.contains("ssh -i ~/.ssh/id_VAUBAN -L 4321:127.0.0.1:4321"));
        assert!(html.contains("Disconnect"));
    }

    #[test]
    fn template_renders_iacs_protocol_label_when_set() {
        let t = make_template();
        let html = t.render().expect("render must succeed");
        assert!(
            html.contains("modbus"),
            "industrial protocol label must surface in the template"
        );
    }

    #[test]
    fn template_renders_when_protocol_empty() {
        let mut t = make_template();
        t.industrial_protocol = String::new();
        let html = t.render().expect("render must succeed");
        // Sanity: the page still renders, the modbus badge just
        // disappears (the iacs_tcp catch-all has no protocol label).
        assert!(html.contains("PLC-Modbus-A1"));
    }

    #[test]
    fn template_carries_csrf_token_on_disconnect_form() {
        let t = make_template();
        let html = t.render().expect("render must succeed");
        // The token itself is hydrated client-side via the Alpine
        // `csrf` store (x-model="token" + hidden input named
        // csrf_token). The template renders the wiring; the
        // double-submit value comes from the cookie.
        assert!(
            html.contains("x-data=\"csrf\""),
            "Disconnect form must hydrate the CSRF token via Alpine `csrf` store"
        );
        assert!(html.contains("name=\"csrf_token\""));
        assert!(html.contains("/sessions/"));
        assert!(html.contains("/terminate"));
    }
}
