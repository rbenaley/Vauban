//! What vauban-web says, and records, when the NLA leg of an RDP session
//! fails with a classified reason ([`RdpAuthFailure`]).
//!
//! The proxy sends a closed-set reason and no text. This module is the
//! only place that turns a reason into words:
//!
//! * a holder of `assets:manage` gets the cause and the expected action
//!   (NTP, SPN, registry value, supervisor configuration);
//! * anyone else gets one generic sentence. The cause of a failed logon
//!   describes the directory (which accounts exist, which are locked):
//!   it is not shown to a user who cannot manage the asset.
//!
//! Every message is a constant. Nothing from the KDC, the target or the
//! request is interpolated.

use shared::messages::{RdpAuthFailure, RdpAuthMode};

/// The only sentence shown to a user without `assets:manage`.
pub const GENERIC_MESSAGE: &str =
    "The target refused the authentication. Contact an administrator of this asset.";

/// Cause and expected action, for a holder of `assets:manage`.
///
/// EXHAUSTIVE match (no `_` arm): a new reason does not compile until it
/// has a message.
pub const fn operator_message(reason: RdpAuthFailure) -> &'static str {
    match reason {
        RdpAuthFailure::KdcUnreachable => {
            "Kerberos: no domain controller (KDC) of the realm answered. Check the KDC hosts and port of the realm in [auth.kerberos] and the network path from the bastion."
        }
        RdpAuthFailure::ClockSkew => {
            "Kerberos: the clocks of the bastion, the KDC and the target differ too much. Synchronize all three with NTP (the default tolerance is 5 minutes)."
        }
        RdpAuthFailure::PreAuthFailed => {
            "Kerberos: the KDC rejected the password of the account. Update the credential stored on the asset."
        }
        RdpAuthFailure::ClientPrincipalUnknown => {
            "Kerberos: the KDC does not know this account in the realm. Check the username and the DNS domain of the asset."
        }
        RdpAuthFailure::ServicePrincipalUnknown => {
            "Kerberos: the KDC has no service principal TERMSRV/<hostname> for this target. The asset hostname must be the FQDN under which the target is registered in the domain (check with setspn -Q TERMSRV/<fqdn>)."
        }
        RdpAuthFailure::RestrictedAdminRefused => {
            "The target refused the Restricted Admin logon. Check that DisableRestrictedAdmin is 0 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa on the target and that the account is a local administrator there. For another account, use the Kerberos mode."
        }
        RdpAuthFailure::KerberosPackageRefused => {
            "The target did not complete a Kerberos-only negotiation. It may not be joined to the domain, or it may only accept NTLM. No NTLM fallback is attempted."
        }
        RdpAuthFailure::RealmNotConfigured => {
            "Kerberos: the realm of this asset's domain is not configured on the bastion. Add it under [[auth.kerberos.realms]] in the supervisor configuration."
        }
        RdpAuthFailure::NtlmForbidden => {
            "NTLM sessions are forbidden on this bastion ([rdp] ntlm_policy = \"deny\"). Switch the asset to a Kerberos authentication mode."
        }
        RdpAuthFailure::Other => {
            "The RDP authentication failed for a reason the proxy could not classify. See the vauban-proxy-rdp log for this session."
        }
        RdpAuthFailure::PreAuthNotRequired => {
            "Kerberos: the account is exempt from pre-authentication (\"Do not require Kerberos preauthentication\"). Clear that option on the account: the bastion does not support it."
        }
        RdpAuthFailure::RealmInvalid => {
            "Kerberos: the domain of the asset is missing, is not the DNS name of the domain (corp.example.com, not CORP), or is not the realm of the KDC. Fix the Domain field of the asset."
        }
        RdpAuthFailure::AccountDisabledOrLocked => {
            "Kerberos: the account is disabled, locked out, expired or outside its logon hours in the domain."
        }
        RdpAuthFailure::PasswordExpired => {
            "Kerberos: the password of the account has expired. Change it in the domain, then update the credential stored on the asset."
        }
        RdpAuthFailure::EncryptionTypeUnsupported => {
            "Kerberos: the KDC offers no AES encryption type for this account or service. Enable AES128 or AES256: the bastion uses neither RC4 nor DES."
        }
        RdpAuthFailure::KerberosBrokerUnavailable => {
            "Kerberos is not enabled on this bastion. Set enabled = true and at least one realm under [auth.kerberos] in the supervisor configuration."
        }
        RdpAuthFailure::NegotiationRefused => {
            "The target did not negotiate Network Level Authentication: it refused the security negotiation, selected TLS-only security, or does not support Restricted Admin. No credential was sent. The bastion requires NLA in every mode: enable it on the target. If it is already enabled, the negotiation may have been altered on the network path."
        }
        RdpAuthFailure::CredentialsRejected => {
            "The target refused the credentials. Check the username, password and domain stored on the asset, and that the account may log on through Remote Desktop."
        }
    }
}

/// The message for this viewer. `can_manage_assets` is the caller's
/// `PermissionContext::assets_manage`.
pub const fn message_for(reason: RdpAuthFailure, can_manage_assets: bool) -> &'static str {
    if can_manage_assets {
        operator_message(reason)
    } else {
        GENERIC_MESSAGE
    }
}

/// Details of the `RdpAuthFailed` audit event. Built with `serde_json`,
/// from a UUID and two closed-set names: no free text.
pub fn audit_details(asset_uuid: uuid::Uuid, reason: RdpAuthFailure, mode: RdpAuthMode) -> String {
    serde_json::json!({
        "protocol": "rdp",
        "asset": asset_uuid.to_string(),
        "reason": reason.as_str(),
        "auth_mode": mode.as_str(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_every_reason_has_its_own_operator_message() {
        let mut seen = HashSet::new();
        for reason in RdpAuthFailure::ALL {
            let message = operator_message(reason);
            assert!(message.len() > 40, "{reason:?}: message too short");
            assert!(message.ends_with('.'), "{reason:?}");
            assert!(seen.insert(message), "{reason:?}: duplicate message");
            assert_ne!(message, GENERIC_MESSAGE, "{reason:?}");
        }
    }

    /// The messages that name an action name the right knob.
    #[test]
    fn test_operator_messages_name_the_expected_action() {
        for (reason, needle) in [
            (RdpAuthFailure::ClockSkew, "NTP"),
            (RdpAuthFailure::ServicePrincipalUnknown, "TERMSRV/"),
            (
                RdpAuthFailure::RestrictedAdminRefused,
                "DisableRestrictedAdmin",
            ),
            (RdpAuthFailure::RealmInvalid, "DNS name"),
            (
                RdpAuthFailure::RealmNotConfigured,
                "[[auth.kerberos.realms]]",
            ),
            (RdpAuthFailure::KdcUnreachable, "[auth.kerberos]"),
            (RdpAuthFailure::KerberosBrokerUnavailable, "enabled = true"),
            (RdpAuthFailure::EncryptionTypeUnsupported, "AES"),
            (RdpAuthFailure::KerberosPackageRefused, "No NTLM fallback"),
            (RdpAuthFailure::Other, "vauban-proxy-rdp log"),
        ] {
            assert!(
                operator_message(reason).contains(needle),
                "{reason:?} must mention {needle}"
            );
        }
    }

    /// A user who cannot manage the asset gets the same sentence for
    /// every reason: the cause is not disclosed.
    #[test]
    fn attack_reason_disclosure_to_non_operator_is_rejected() {
        for reason in RdpAuthFailure::ALL {
            assert_eq!(message_for(reason, false), GENERIC_MESSAGE, "{reason:?}");
            assert_eq!(message_for(reason, true), operator_message(reason));
        }
        // The generic sentence names no cause.
        for word in [
            "Kerberos", "KDC", "password", "account", "NTLM", "realm", "locked",
        ] {
            assert!(
                !GENERIC_MESSAGE.contains(word),
                "generic message says {word}"
            );
        }
    }

    #[test]
    fn test_audit_details_are_json_with_closed_set_values() {
        let asset = uuid::Uuid::nil();
        for reason in RdpAuthFailure::ALL {
            for mode in RdpAuthMode::ALL {
                let details = audit_details(asset, reason, mode);
                let value: serde_json::Value =
                    serde_json::from_str(&details).unwrap_or(serde_json::Value::Null);
                assert_eq!(value["protocol"], "rdp");
                assert_eq!(value["asset"], asset.to_string());
                assert_eq!(value["reason"], reason.as_str());
                assert_eq!(value["auth_mode"], mode.as_str());
                assert_eq!(value.as_object().map(serde_json::Map::len), Some(4));
            }
        }
    }
}
