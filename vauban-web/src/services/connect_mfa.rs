//! Second factor at session open, for a rule marked "Require MFA".
//!
//! A rule that requires MFA without requiring approval used to be
//! opened by the direct Connect button with no second factor: only the
//! approval request checked the code. Every direct open (SSH, RDP, IACS
//! tunnel) now goes through [`enforce`], which asks for a TOTP code and
//! consumes it with [`crate::auth::enforce_totp_step_up`] (single use,
//! audited on refusal).

use axum::response::{IntoResponse, Response};

use crate::AppState;

/// `HX-Trigger` event that opens the connection modal with its code field.
pub const PROMPT_TRIGGER: &str = "show-connect-mfa-modal";

/// Message when a code is needed and the caller cannot be prompted.
pub const CODE_REQUIRED_MESSAGE: &str = "This asset requires your authenticator code to connect.";

type Conn = diesel_async::pooled_connection::deadpool::Object<diesel_async::AsyncPgConnection>;

/// Outcome of the second-factor check for one session open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectMfa {
    /// Not required, or the code was verified and consumed.
    Passed,
    /// Required and no code was submitted: ask for one.
    Prompt,
    /// A code was submitted and refused; the message is safe to display.
    Refused(&'static str),
}

/// What to do with a submitted code, before any verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step<'a> {
    Pass,
    Prompt,
    Verify(&'a str),
}

fn step(required: bool, code: Option<&str>) -> Step<'_> {
    if !required {
        return Step::Pass;
    }
    match code.map(str::trim) {
        Some(code) if !code.is_empty() => Step::Verify(code),
        _ => Step::Prompt,
    }
}

/// Check the second factor for a session open. `required` is the
/// `require_mfa` flag returned by vauban-access for this user, asset
/// and protocol. A code submitted when none is required is ignored and
/// not consumed.
pub async fn enforce(
    state: &AppState,
    conn: &mut Conn,
    user_uuid: &str,
    required: bool,
    code: Option<&str>,
) -> ConnectMfa {
    match step(required, code) {
        Step::Pass => ConnectMfa::Passed,
        Step::Prompt => ConnectMfa::Prompt,
        Step::Verify(code) => {
            match crate::auth::enforce_totp_step_up(state, conn, user_uuid, code).await {
                Ok(()) => ConnectMfa::Passed,
                Err(err) => ConnectMfa::Refused(err.flash_message()),
            }
        }
    }
}

/// Answer an HTMX request by opening the connection modal with the code
/// field. `asset_type` selects the endpoint the modal posts to.
pub fn prompt_response(asset_uuid: &str, asset_type: &str, need_justification: bool) -> Response {
    let payload = serde_json::json!({
        PROMPT_TRIGGER: {
            "asset_uuid": asset_uuid,
            "asset_type": asset_type,
            "need_justification": need_justification,
        }
    })
    .to_string();
    let value = axum::http::HeaderValue::from_str(&payload).unwrap_or_else(|_| {
        axum::http::HeaderValue::from_static(r#"{"show-connect-mfa-modal":{}}"#)
    });
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            value,
        )],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_without_mfa_asks_for_nothing() {
        assert_eq!(step(false, None), Step::Pass);
        assert_eq!(step(false, Some("123456")), Step::Pass);
    }

    #[test]
    fn attack_required_mfa_is_never_passed_without_a_code() {
        assert_eq!(step(true, None), Step::Prompt);
        assert_eq!(step(true, Some("")), Step::Prompt);
        assert_eq!(step(true, Some("   ")), Step::Prompt);
    }

    #[test]
    fn a_submitted_code_is_verified_not_trusted() {
        assert_eq!(step(true, Some(" 123456 ")), Step::Verify("123456"));
    }

    /// Every direct session-open handler must pass through `enforce`
    /// with the flag vauban-access returned and the submitted code.
    #[test]
    fn attack_every_direct_open_path_enforces_the_rule_mfa() {
        for (name, src) in [
            ("ssh", include_str!("../handlers/web/ssh.rs")),
            ("rdp", include_str!("../handlers/web/rdp.rs")),
            ("iacs", include_str!("../handlers/web/iacs_tunnel.rs")),
        ] {
            let call = src
                .split("connect_mfa::enforce(")
                .nth(1)
                .unwrap_or_else(|| panic!("{name}: no connect_mfa::enforce call"));
            let args = call.split(".await").next().unwrap_or_default();
            assert!(
                args.contains("issued.require_mfa"),
                "{name}: flag not passed"
            );
            assert!(args.contains("form.totp_code"), "{name}: code not passed");
        }
    }

    #[test]
    fn prompt_names_the_asset_and_the_endpoint_kind() {
        let response = prompt_response("a-b", "rdp", true);
        let header = response
            .headers()
            .get("hx-trigger")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let json: serde_json::Value = serde_json::from_str(&header).unwrap_or_default();
        assert_eq!(json[PROMPT_TRIGGER]["asset_uuid"], "a-b");
        assert_eq!(json[PROMPT_TRIGGER]["asset_type"], "rdp");
        assert_eq!(json[PROMPT_TRIGGER]["need_justification"], true);
    }
}
