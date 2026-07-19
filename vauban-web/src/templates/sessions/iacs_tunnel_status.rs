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
    /// Local TCP port the EWS will bind via `ssh -L LP:...`. Computed
    /// by [`crate::services::iacs_tunnel::derive_local_forward_port`]
    /// so that privileged asset ports (Modbus 502, MMS 102, ...) are
    /// shifted into the user range (50502, 50102, ...) -- the
    /// operator never needs root to bind locally.
    pub local_forward_port: u16,
    /// Asset upstream hostname (RHS of the `ssh -L` command's
    /// `<local>:<host>:<port>` triplet). The bastion's `validate_target`
    /// pins this exact value on the per-session entry, so the
    /// rendered command MUST carry it verbatim.
    pub target_host: String,
    /// Asset upstream port (the third element of the `-L` triplet).
    /// Stays equal to `assets.port` end-to-end -- the privileged-port
    /// rewrite is purely an EWS-side concern.
    pub target_port: u16,
    /// Display label for the upstream `host:port`. Rendered as a hint
    /// alongside the SSH command so the operator can map "what I'm
    /// reaching" to "what I configured in my IACS client".
    pub tunnel_target_addr: String,
    /// Current session status (`waiting_client`, `tunnel_active`,
    /// `terminated`). Used for the initial state pill; L5 mutates
    /// it client-side via the WebSocket push.
    pub session_status: String,
    /// Seconds left before the revocation watchdog flips this
    /// `waiting_client` row to `expired`, computed by
    /// [`crate::services::iacs_tunnel::remaining_waiting_seconds`]
    /// from the SAME reference the watchdog uses
    /// (`proxy_sessions.created_at + waiting_client_ttl_seconds`).
    /// `None` when the countdown must not render: TTL disabled
    /// (`waiting_client_ttl_seconds == 0`) or session no longer in
    /// `waiting_client`. The Alpine component ticks the value down
    /// client-side and flips the pill to `expired` at zero.
    pub waiting_countdown_seconds: Option<i64>,
    /// CSRF token for the Disconnect form.
    pub csrf_token: String,
}

impl IacsTunnelStatusTemplate {
    /// Build the canonical
    /// `ssh -i ~/.ssh/id_VAUBAN -L <local>:<asset_host>:<asset_port> <session_uuid>@<bastion> -p <port> -N`
    /// command line as a String.
    ///
    /// Three independent fields drive the `-L` triplet:
    ///
    /// - `local_forward_port` (LHS): the port the EWS binds locally.
    ///   Derived from the asset port via
    ///   [`crate::services::iacs_tunnel::derive_local_forward_port`]
    ///   so that privileged asset ports (Modbus 502, MMS 102, ...)
    ///   are shifted out of the kernel-restricted range. The operator
    ///   never needs root on their EWS.
    /// - `target_host` (middle): the asset's hostname / IP. The
    ///   bastion's `validate_target` pins this value on the
    ///   per-session entry, so a rendered command that hardcodes
    ///   `127.0.0.1` here would only ever work in a dev fixture
    ///   where the asset is on loopback.
    /// - `target_port` (RHS): the asset's true upstream port. Stays
    ///   equal to `assets.port` end-to-end.
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
            "ssh -i ~/.ssh/id_VAUBAN -L {lp}:{th}:{tp} {sess}@{host} -p {port} -N",
            lp = self.local_forward_port,
            th = self.target_host,
            tp = self.target_port,
            sess = self.session_uuid,
            host = self.bastion_hostname,
            port = self.bastion_port,
        )
    }

    /// Display string rendered next to the `ssh -L` block so the
    /// operator immediately sees both ports and the asset.
    /// Format: `127.0.0.1:50502  ->  10.42.0.7:502 (asset)`
    pub fn local_to_upstream_label(&self) -> String {
        format!(
            "127.0.0.1:{lp}  ->  {th}:{tp}",
            lp = self.local_forward_port,
            th = self.target_host,
            tp = self.target_port,
        )
    }

    /// Numeric seed handed to the Alpine `iacsTunnelStatus`
    /// component. `-1` is the "no countdown" sentinel (TTL disabled
    /// or non-`waiting_client` status): the client never starts the
    /// timer nor renders the label for a negative seed.
    pub fn countdown_seed(&self) -> i64 {
        self.waiting_countdown_seconds.unwrap_or(-1)
    }

    /// Server-rendered initial countdown label (`M:SS` / `H:MM:SS`)
    /// so the value is meaningful before the first client-side tick.
    /// Empty when no countdown renders.
    pub fn countdown_initial_label(&self) -> String {
        self.waiting_countdown_seconds
            .map(crate::services::iacs_tunnel::format_countdown_label)
            .unwrap_or_default()
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
            local_forward_port: 50_502,
            target_host: "10.42.0.7".to_string(),
            target_port: 502,
            tunnel_target_addr: "10.42.0.7:502".to_string(),
            session_status: "waiting_client".to_string(),
            waiting_countdown_seconds: Some(272),
            csrf_token: "csrf-token".to_string(),
        }
    }

    #[test]
    fn ssh_command_format_is_canonical() {
        let t = make_template();
        assert_eq!(
            t.ssh_command(),
            "ssh -i ~/.ssh/id_VAUBAN -L 50502:10.42.0.7:502 \
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

    /// The privileged-port rewrite contract: an asset on Modbus 502
    /// renders as `-L 50502:<host>:502` so the EWS binds 50502
    /// (unprivileged) but the bastion still tunnels to the real
    /// asset port 502. A regression that re-coupled the LHS to the
    /// asset port would break every Linux/macOS/Windows operator
    /// who does not run `ssh` as root.
    #[test]
    fn ssh_command_decouples_local_port_from_upstream_for_modbus() {
        let mut t = make_template();
        t.local_forward_port = 50_502;
        t.target_host = "10.42.0.7".to_string();
        t.target_port = 502;
        let cmd = t.ssh_command();
        assert!(
            cmd.contains("-L 50502:10.42.0.7:502"),
            "Modbus must render as -L 50502:<host>:502 (got {cmd})"
        );
        assert!(
            !cmd.contains(":127.0.0.1:"),
            "the legacy hardcoded 127.0.0.1 RHS must NOT leak into \
             the rendered command for a non-loopback asset (got {cmd})"
        );
    }

    /// For a non-privileged asset port (OPC-UA 4840) the LHS equals
    /// the upstream port -- no rewrite, the contract is a no-op
    /// when no privilege is required.
    #[test]
    fn ssh_command_does_not_rewrite_unprivileged_asset_port() {
        let mut t = make_template();
        t.local_forward_port = 4_840;
        t.target_host = "opcua.factory.local".to_string();
        t.target_port = 4_840;
        assert!(t.ssh_command().contains("-L 4840:opcua.factory.local:4840"),);
    }

    /// Loopback assets (dev / E2E fixtures) keep working: the
    /// rendered RHS reflects whatever `target_host` was pinned on
    /// the per-session entry, including `127.0.0.1`.
    #[test]
    fn ssh_command_supports_loopback_asset_in_dev_fixtures() {
        let mut t = make_template();
        t.local_forward_port = 50_502;
        t.target_host = "127.0.0.1".to_string();
        t.target_port = 502;
        assert!(t.ssh_command().contains("-L 50502:127.0.0.1:502"),);
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
        assert!(html.contains("ssh -i ~/.ssh/id_VAUBAN -L 50502:10.42.0.7:502"));
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
    fn countdown_seed_maps_none_to_negative_sentinel() {
        let mut t = make_template();
        t.waiting_countdown_seconds = None;
        assert_eq!(t.countdown_seed(), -1);
        assert_eq!(t.countdown_initial_label(), "");
        t.waiting_countdown_seconds = Some(0);
        assert_eq!(t.countdown_seed(), 0);
        assert_eq!(t.countdown_initial_label(), "0:00");
    }

    #[test]
    fn template_renders_countdown_when_waiting_with_ttl() {
        let t = make_template();
        let html = t.render().expect("render must succeed");
        assert!(
            html.contains("data-testid=\"iacs-tunnel-countdown\""),
            "waiting_client with an enabled TTL must render the countdown slot"
        );
        assert!(
            html.contains("remainingSeconds: 272"),
            "Alpine seed must carry the server-computed remaining seconds"
        );
        assert!(
            html.contains("4:32"),
            "initial label must be server-rendered so the first paint is meaningful"
        );
    }

    #[test]
    fn template_seeds_negative_sentinel_when_countdown_disabled() {
        let mut t = make_template();
        t.waiting_countdown_seconds = None;
        let html = t.render().expect("render must succeed");
        assert!(
            html.contains("remainingSeconds: -1"),
            "disabled countdown must seed the -1 sentinel so the client never starts the timer"
        );
        assert!(
            !html.contains("data-testid=\"iacs-tunnel-countdown\""),
            "no countdown slot must render when the TTL is disabled or the tunnel is past waiting_client"
        );
    }

    /// A row the watchdog is about to reap (remaining == 0) still
    /// renders: the client flips the pill to `expired` on first tick.
    #[test]
    fn template_renders_zero_countdown_for_reapable_row() {
        let mut t = make_template();
        t.waiting_countdown_seconds = Some(0);
        let html = t.render().expect("render must succeed");
        assert!(html.contains("remainingSeconds: 0"));
        assert!(html.contains("0:00"));
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
