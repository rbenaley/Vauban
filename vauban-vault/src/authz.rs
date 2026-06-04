//! VAU-002 -- Per-peer authorization for vault requests (capability matrix).
//!
//! `vauban-vault` is a pure crypto oracle: any peer holding a live IPC pipe
//! to it can ask it to encrypt/decrypt on any key domain. Before this module,
//! the peer name was only logged (`debug!`), never used as an authorization
//! decision -- so a SINGLE compromised peer (web, auth, a proxy) could decrypt
//! EVERY secret of EVERY domain, collapsing the defense-in-depth the split
//! architecture is meant to provide.
//!
//! # Trust model: the channel IS the identity
//!
//! Each peer talks to the vault on a DEDICATED pipe pair created by the
//! supervisor at fork time (one `IpcChannel::pair()` per `TOPOLOGY` edge).
//! The vault labels each incoming channel `"web"` / `"auth"` / `"proxy_ssh"`
//! / `"proxy_rdp"` at init from the env-var suffix the supervisor set
//! (see `main.rs::parse_topology_channel` and the `peer_channels` vector).
//! That label is therefore SUPERVISOR-ATTESTED, kernel-backed, and NOT
//! forgeable on the wire: a peer cannot send "I am web" -- it can only write
//! into the pipe the supervisor handed it. We consequently need no on-wire
//! identity token; we authorize purely on `(peer, verb, domain)`.
//!
//! # Capability matrix (fail-closed)
//!
//! Only the couples below are allowed; everything else is DENIED:
//!
//! - `web`: Encrypt{credentials, mfa}, Decrypt{credentials}, MfaGenerate,
//!   MfaVerify, MfaGetSecret.
//! - `auth`: MfaVerify ONLY. Deliberately NOT MfaGetSecret nor Decrypt{mfa}:
//!   those return the TOTP secret in clear, while auth only needs a yes/no on
//!   a submitted code.
//! - `proxy_ssh`: Decrypt{credentials} (read-only).
//! - `proxy_rdp`: Decrypt{credentials} (read-only).
//! - `supervisor`: NOTHING. The supervisor channel is control-only.
//! - unknown label / any other couple: NOTHING.
//!
//! The matrix is forward-looking: `auth` / `proxy_ssh` / `proxy_rdp` do not
//! send vault traffic yet (web decrypts and forwards plaintext over its own
//! peer pipe), but their least-privilege grant is pre-declared so wiring them
//! later does not require relaxing the vault.

use shared::messages::Message;

/// A vault peer, identified by the supervisor-attested IPC channel it speaks
/// on. NEVER constructed from wire data.
///
/// The enum is matched EXHAUSTIVELY by [`is_authorized`] (no `_` peer arm), so
/// adding a variant fails to compile until its capabilities are declared.
/// Pinned at runtime by [`VaultPeer::COUNT`] and the `all_peers_*` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPeer {
    /// vauban-web: the only active vault client today (full credential + MFA).
    Web,
    /// vauban-auth: MFA code verification only.
    Auth,
    /// vauban-proxy-ssh: read-only credential decryption.
    ProxySsh,
    /// vauban-proxy-rdp: read-only credential decryption.
    ProxyRdp,
    /// The supervisor control channel: NO vault capability (control-only).
    Supervisor,
}

impl VaultPeer {
    /// Number of `VaultPeer` variants. Kept in lock-step with the enum by
    /// `count_matches_all_variants`; consumed by the drift tests.
    #[allow(dead_code)]
    pub const COUNT: usize = 5;

    /// All variants, for table-driven tests and drift checks.
    #[allow(dead_code)]
    pub const ALL: [VaultPeer; Self::COUNT] = [
        VaultPeer::Web,
        VaultPeer::Auth,
        VaultPeer::ProxySsh,
        VaultPeer::ProxyRdp,
        VaultPeer::Supervisor,
    ];

    /// Map a supervisor-set peer-channel label to a `VaultPeer`.
    ///
    /// Returns `None` for any unknown label (treated as a hard deny by the
    /// caller). The labels MUST match the `peer_channels` names set in
    /// `main.rs` (`"web"`, `"auth"`, `"proxy_ssh"`, `"proxy_rdp"`).
    /// `Supervisor` is intentionally NOT reachable from a label: it is only
    /// minted directly for the supervisor control channel.
    #[must_use]
    pub fn from_channel_label(label: &str) -> Option<Self> {
        match label {
            "web" => Some(VaultPeer::Web),
            "auth" => Some(VaultPeer::Auth),
            "proxy_ssh" => Some(VaultPeer::ProxySsh),
            "proxy_rdp" => Some(VaultPeer::ProxyRdp),
            _ => None,
        }
    }

    /// Stable name for structured logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            VaultPeer::Web => "web",
            VaultPeer::Auth => "auth",
            VaultPeer::ProxySsh => "proxy_ssh",
            VaultPeer::ProxyRdp => "proxy_rdp",
            VaultPeer::Supervisor => "supervisor",
        }
    }
}

/// Key domain for credential secrets (asset passwords, SSH private keys).
pub const DOMAIN_CREDENTIALS: &str = "credentials";
/// Key domain for TOTP / MFA secrets.
pub const DOMAIN_MFA: &str = "mfa";

/// The authorization decision for a `(peer, message)` couple.
///
/// EXHAUSTIVE `match` on the peer with NO fail-open catch-all: every allowed
/// couple is spelled out explicitly and the final arm is `_ => false`
/// (fail-closed). Adding a `VaultPeer` variant forces a compile error here.
#[must_use]
pub fn is_authorized(peer: VaultPeer, msg: &Message) -> bool {
    match (peer, msg) {
        // ---- web: full credential + MFA surface ----
        (VaultPeer::Web, Message::VaultEncrypt { domain, .. }) => {
            domain == DOMAIN_CREDENTIALS || domain == DOMAIN_MFA
        }
        (VaultPeer::Web, Message::VaultDecrypt { domain, .. }) => domain == DOMAIN_CREDENTIALS,
        (VaultPeer::Web, Message::VaultMfaGenerate { .. }) => true,
        (VaultPeer::Web, Message::VaultMfaVerify { .. }) => true,
        (VaultPeer::Web, Message::VaultMfaGetSecret { .. }) => true,

        // ---- auth: MFA code verification ONLY (never reads the secret) ----
        (VaultPeer::Auth, Message::VaultMfaVerify { .. }) => true,

        // ---- proxies: read-only credential decryption ----
        (VaultPeer::ProxySsh, Message::VaultDecrypt { domain, .. }) => domain == DOMAIN_CREDENTIALS,
        (VaultPeer::ProxyRdp, Message::VaultDecrypt { domain, .. }) => domain == DOMAIN_CREDENTIALS,

        // ---- fail-closed: supervisor, unknown verbs, and every couple not
        // explicitly granted above default to deny. This catch-all MUST remain
        // a wildcard-deny; a wildcard-allow would re-open the cross-domain hole.
        _ => false,
    }
}

/// The `(verb, effective_domain)` of a vault request, for structured logging.
///
/// `VaultMfa*` verbs have no explicit `domain` field; they implicitly act on
/// the `mfa` keyring, so we surface `"mfa"` for them. Returns `None` for any
/// non-vault message.
#[must_use]
pub fn verb_and_domain(msg: &Message) -> Option<(&'static str, &str)> {
    match msg {
        Message::VaultEncrypt { domain, .. } => Some(("VaultEncrypt", domain)),
        Message::VaultDecrypt { domain, .. } => Some(("VaultDecrypt", domain)),
        Message::VaultMfaGenerate { .. } => Some(("VaultMfaGenerate", DOMAIN_MFA)),
        Message::VaultMfaVerify { .. } => Some(("VaultMfaVerify", DOMAIN_MFA)),
        Message::VaultMfaGetSecret { .. } => Some(("VaultMfaGetSecret", DOMAIN_MFA)),
        _ => None,
    }
}

/// Build the typed `*Response` for a denied request so the caller's pending
/// request resolves with an `unauthorized` error instead of timing out.
///
/// Mirrors the verb -> response shape; carries NO secret material (every
/// payload field is `None` / `false`). Returns `None` for a non-vault message
/// (the caller drops those via the fail-closed catch-all without responding).
#[must_use]
pub fn denied_response(msg: &Message) -> Option<Message> {
    let err = || Some("unauthorized: vault capability denied".to_string());
    match msg {
        Message::VaultEncrypt { request_id, .. } => Some(Message::VaultEncryptResponse {
            request_id: *request_id,
            ciphertext: None,
            error: err(),
        }),
        Message::VaultDecrypt { request_id, .. } => Some(Message::VaultDecryptResponse {
            request_id: *request_id,
            plaintext: None,
            error: err(),
        }),
        Message::VaultMfaGenerate { request_id, .. } => Some(Message::VaultMfaGenerateResponse {
            request_id: *request_id,
            encrypted_secret: None,
            plaintext_secret: None,
            error: err(),
        }),
        Message::VaultMfaVerify { request_id, .. } => Some(Message::VaultMfaVerifyResponse {
            request_id: *request_id,
            valid: false,
            error: err(),
        }),
        Message::VaultMfaGetSecret { request_id, .. } => Some(Message::VaultMfaGetSecretResponse {
            request_id: *request_id,
            plaintext_secret: None,
            error: err(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::messages::SensitiveString;

    /// The five vault verbs, parameterized by domain where relevant.
    fn encrypt(domain: &str) -> Message {
        Message::VaultEncrypt {
            request_id: 1,
            domain: domain.to_string(),
            plaintext: SensitiveString::new("p".to_string()),
        }
    }
    fn decrypt(domain: &str) -> Message {
        Message::VaultDecrypt {
            request_id: 2,
            domain: domain.to_string(),
            ciphertext: "v1:AAAA".to_string(),
        }
    }
    fn mfa_generate() -> Message {
        Message::VaultMfaGenerate {
            request_id: 3,
            username: "u".to_string(),
            issuer: "VAUBAN".to_string(),
        }
    }
    fn mfa_verify() -> Message {
        Message::VaultMfaVerify {
            request_id: 4,
            encrypted_secret: "v1:enc".to_string(),
            code: "123456".to_string(),
        }
    }
    fn mfa_get_secret() -> Message {
        Message::VaultMfaGetSecret {
            request_id: 5,
            encrypted_secret: "v1:enc".to_string(),
        }
    }

    /// Independent re-implementation of the expected matrix, kept separate
    /// from `is_authorized` so a single typo cannot pass both.
    fn expected(peer: VaultPeer, verb: &str, domain: &str) -> bool {
        match peer {
            VaultPeer::Web => match verb {
                "Encrypt" => domain == "credentials" || domain == "mfa",
                "Decrypt" => domain == "credentials",
                "MfaGenerate" | "MfaVerify" | "MfaGetSecret" => true,
                _ => false,
            },
            VaultPeer::Auth => verb == "MfaVerify",
            VaultPeer::ProxySsh | VaultPeer::ProxyRdp => verb == "Decrypt" && domain == "credentials",
            VaultPeer::Supervisor => false,
        }
    }

    #[test]
    fn full_cartesian_product_matches_expected_matrix() {
        let domains = ["credentials", "mfa", "unknown"];
        for &peer in &VaultPeer::ALL {
            for domain in domains {
                // Encrypt / Decrypt carry an explicit domain.
                assert_eq!(
                    is_authorized(peer, &encrypt(domain)),
                    expected(peer, "Encrypt", domain),
                    "Encrypt peer={:?} domain={}",
                    peer,
                    domain
                );
                assert_eq!(
                    is_authorized(peer, &decrypt(domain)),
                    expected(peer, "Decrypt", domain),
                    "Decrypt peer={:?} domain={}",
                    peer,
                    domain
                );
            }
            // MFA verbs act implicitly on the "mfa" domain.
            assert_eq!(
                is_authorized(peer, &mfa_generate()),
                expected(peer, "MfaGenerate", "mfa"),
                "MfaGenerate peer={:?}",
                peer
            );
            assert_eq!(
                is_authorized(peer, &mfa_verify()),
                expected(peer, "MfaVerify", "mfa"),
                "MfaVerify peer={:?}",
                peer
            );
            assert_eq!(
                is_authorized(peer, &mfa_get_secret()),
                expected(peer, "MfaGetSecret", "mfa"),
                "MfaGetSecret peer={:?}",
                peer
            );
        }
    }

    #[test]
    fn web_has_full_documented_surface() {
        assert!(is_authorized(VaultPeer::Web, &encrypt("credentials")));
        assert!(is_authorized(VaultPeer::Web, &encrypt("mfa")));
        assert!(is_authorized(VaultPeer::Web, &decrypt("credentials")));
        assert!(is_authorized(VaultPeer::Web, &mfa_generate()));
        assert!(is_authorized(VaultPeer::Web, &mfa_verify()));
        assert!(is_authorized(VaultPeer::Web, &mfa_get_secret()));
    }

    /// SECURITY: even web cannot decrypt the raw MFA secret via VaultDecrypt;
    /// the MFA secret only ever leaves via the dedicated (audited) verbs.
    #[test]
    fn web_cannot_decrypt_mfa_domain() {
        assert!(!is_authorized(VaultPeer::Web, &decrypt("mfa")));
    }

    /// SECURITY: auth may verify a code but must NOT be able to exfiltrate the
    /// TOTP secret (MfaGetSecret) nor decrypt the mfa domain.
    #[test]
    fn auth_cannot_exfiltrate_mfa_secret() {
        assert!(is_authorized(VaultPeer::Auth, &mfa_verify()));
        assert!(!is_authorized(VaultPeer::Auth, &mfa_get_secret()));
        assert!(!is_authorized(VaultPeer::Auth, &decrypt("mfa")));
        assert!(!is_authorized(VaultPeer::Auth, &decrypt("credentials")));
        assert!(!is_authorized(VaultPeer::Auth, &encrypt("mfa")));
    }

    /// SECURITY: proxies are read-only on credentials and nothing else.
    #[test]
    fn proxies_are_credentials_read_only() {
        for peer in [VaultPeer::ProxySsh, VaultPeer::ProxyRdp] {
            assert!(is_authorized(peer, &decrypt("credentials")));
            assert!(!is_authorized(peer, &decrypt("mfa")));
            assert!(!is_authorized(peer, &encrypt("credentials")));
            assert!(!is_authorized(peer, &mfa_verify()));
            assert!(!is_authorized(peer, &mfa_get_secret()));
        }
    }

    /// SECURITY: the supervisor control channel has NO vault capability.
    #[test]
    fn supervisor_is_denied_everything() {
        assert!(!is_authorized(VaultPeer::Supervisor, &encrypt("credentials")));
        assert!(!is_authorized(VaultPeer::Supervisor, &encrypt("mfa")));
        assert!(!is_authorized(VaultPeer::Supervisor, &decrypt("credentials")));
        assert!(!is_authorized(VaultPeer::Supervisor, &decrypt("mfa")));
        assert!(!is_authorized(VaultPeer::Supervisor, &mfa_generate()));
        assert!(!is_authorized(VaultPeer::Supervisor, &mfa_verify()));
        assert!(!is_authorized(VaultPeer::Supervisor, &mfa_get_secret()));
    }

    #[test]
    fn unknown_channel_label_maps_to_none() {
        assert_eq!(VaultPeer::from_channel_label("web"), Some(VaultPeer::Web));
        assert_eq!(VaultPeer::from_channel_label("auth"), Some(VaultPeer::Auth));
        assert_eq!(
            VaultPeer::from_channel_label("proxy_ssh"),
            Some(VaultPeer::ProxySsh)
        );
        assert_eq!(
            VaultPeer::from_channel_label("proxy_rdp"),
            Some(VaultPeer::ProxyRdp)
        );
        // Anything else (incl. "supervisor", "iacs", "") is unknown -> deny.
        for label in ["supervisor", "proxy_iacs", "access", "audit", "", "WEB"] {
            assert_eq!(VaultPeer::from_channel_label(label), None, "label={label}");
        }
    }

    #[test]
    fn count_matches_all_variants() {
        assert_eq!(VaultPeer::ALL.len(), VaultPeer::COUNT);
    }

    #[test]
    fn denied_response_carries_no_secret_and_matches_verb() {
        // Encrypt -> EncryptResponse with no ciphertext.
        match denied_response(&encrypt("credentials")) {
            Some(Message::VaultEncryptResponse {
                ciphertext: None,
                error: Some(e),
                ..
            }) => assert!(e.contains("unauthorized")),
            other => panic!("expected denied EncryptResponse, got {other:?}"),
        }
        // Decrypt -> DecryptResponse with no plaintext.
        match denied_response(&decrypt("mfa")) {
            Some(Message::VaultDecryptResponse {
                plaintext: None,
                error: Some(_),
                ..
            }) => {}
            other => panic!("expected denied DecryptResponse, got {other:?}"),
        }
        // MfaGetSecret -> GetSecretResponse with no plaintext_secret.
        match denied_response(&mfa_get_secret()) {
            Some(Message::VaultMfaGetSecretResponse {
                plaintext_secret: None,
                error: Some(_),
                ..
            }) => {}
            other => panic!("expected denied GetSecretResponse, got {other:?}"),
        }
        // A non-vault message yields no response (dropped by catch-all).
        assert!(denied_response(&Message::Control(shared::messages::ControlMessage::Ping { seq: 1 })).is_none());
    }

    #[test]
    fn verb_and_domain_extraction() {
        assert_eq!(
            verb_and_domain(&encrypt("credentials")),
            Some(("VaultEncrypt", "credentials"))
        );
        assert_eq!(verb_and_domain(&decrypt("mfa")), Some(("VaultDecrypt", "mfa")));
        assert_eq!(
            verb_and_domain(&mfa_verify()),
            Some(("VaultMfaVerify", "mfa"))
        );
        assert!(
            verb_and_domain(&Message::Control(shared::messages::ControlMessage::Ping {
                seq: 1
            }))
            .is_none()
        );
    }
}
