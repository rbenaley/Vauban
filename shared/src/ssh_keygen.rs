//! Ed25519 SSH key-pair generation for asset key-based authentication.
//!
//! Single source of truth for the "Vauban generates the key-pair"
//! branch of the SSH asset key-auth flow (see
//! `docs/technical` and the asset create/edit handlers in
//! `vauban-web`). When an administrator chooses
//! `Generate public/private key`, vauban-web calls
//! [`generate_ed25519_keypair`] to mint a fresh Ed25519 pair:
//!
//!   * the **public** half is stored in clear on the asset row
//!     (`connection_config.ssh_public_key`) and is the only half ever
//!     shown back in the UI;
//!   * the **private** half is sealed in vauban-vault
//!     (`connection_config.private_key` = vault ciphertext) and never
//!     leaves the vault address space in clear except inside
//!     vauban-proxy-ssh at session-open time.
//!
//! This module is deliberately tiny and dependency-light (russh +
//! getrandom only) so it can live in `shared` behind the `ssh-keygen`
//! feature and be unit-tested in isolation. It mirrors the keygen
//! hygiene of [`crate::iacs_host_key`]: the private PEM is held in a
//! `Zeroizing<String>` so it is wiped from the heap on drop.

use std::io;

use russh::keys::ssh_key::{Algorithm, LineEnding};
use russh::keys::{HashAlg, PrivateKey, PublicKey, decode_secret_key};
use zeroize::Zeroizing;

/// A freshly-generated Ed25519 key-pair, ready to be persisted.
///
/// `private_openssh` is the OpenSSH PEM (`-----BEGIN OPENSSH PRIVATE
/// KEY-----`), wrapped in [`Zeroizing`] so the secret is wiped from the
/// heap when the value is dropped. The caller MUST encrypt it via the
/// vault before storing and MUST NOT log or echo it.
///
/// `public_openssh` is the single-line OpenSSH public key
/// (`ssh-ed25519 AAAA... <comment>`) and is NOT secret.
pub struct GeneratedKeyPair {
    /// OpenSSH PEM private key (secret, zeroized on drop).
    pub private_openssh: Zeroizing<String>,
    /// Single-line OpenSSH public key (`ssh-ed25519 AAAA... comment`).
    pub public_openssh: String,
    /// OpenSSH-style fingerprint of the public key (`SHA256:...`).
    pub fingerprint: String,
}

/// Generate a fresh Ed25519 SSH key-pair.
///
/// `comment` is appended to the public key line (the conventional
/// trailing `user@host` field); pass an empty string for no comment.
///
/// # Errors
///
/// Returns an [`io::Error`] if the OS CSPRNG fails or the key cannot be
/// encoded to OpenSSH form (both are effectively unreachable on a
/// healthy host, but we surface them instead of panicking so the web
/// handler can render a clean error fragment).
pub fn generate_ed25519_keypair(comment: &str) -> io::Result<GeneratedKeyPair> {
    // ssh-key 0.7 (russh 0.61) requires a `rand_core` 0.10 `CryptoRng`.
    // getrandom's `SysRng` is the OS entropy source but only implements
    // the fallible `TryCryptoRng`; `UnwrapErr` adapts it to the
    // infallible `CryptoRng` the `random` bound demands. Mirrors
    // `iacs_host_key::load_or_generate_host_key`.
    let key = PrivateKey::random(
        &mut russh::keys::ssh_key::rand_core::UnwrapErr(getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .map_err(|e| io::Error::other(format!("ed25519 keygen: {e}")))?;

    // `to_openssh` returns `Zeroizing<String>`; re-wrap to keep the
    // explicit `Zeroizing` type in our public API even if russh's return
    // type ever changes.
    let private_pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| io::Error::other(format!("encode private key: {e}")))?;
    let private_openssh = Zeroizing::new(private_pem.to_string());

    let public_base = key
        .public_key()
        .to_openssh()
        .map_err(|e| io::Error::other(format!("encode public key: {e}")))?;
    let trimmed_comment = comment.trim();
    let public_openssh = if trimmed_comment.is_empty() {
        public_base
    } else {
        format!("{} {}", public_base.trim_end(), trimmed_comment)
    };

    let fingerprint = key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();

    Ok(GeneratedKeyPair {
        private_openssh,
        public_openssh,
        fingerprint,
    })
}

/// Derive the OpenSSH public key (and its SHA256 fingerprint) from an
/// OpenSSH PEM private key.
///
/// Used by the `existing` key-source branch of the asset create/edit
/// flow: the administrator pastes a private key (optionally
/// passphrase-protected) and Vauban derives the matching public half
/// itself rather than trusting a separately-pasted public key. The
/// OpenSSH private-key format always embeds the public key in clear,
/// so derivation works even when the key body is encrypted (no
/// passphrase required here).
///
/// `comment` is appended to the public-key line exactly as in
/// [`generate_ed25519_keypair`]; pass an empty string for none.
///
/// # Errors
///
/// Returns an [`io::Error`] if the private key cannot be parsed as
/// OpenSSH or the public half cannot be re-encoded.
pub fn public_key_from_private_openssh(
    private_openssh: &str,
    comment: &str,
) -> io::Result<(String, String)> {
    let key = PrivateKey::from_openssh(private_openssh.trim())
        .map_err(|e| io::Error::other(format!("parse private key: {e}")))?;

    let public_base = key
        .public_key()
        .to_openssh()
        .map_err(|e| io::Error::other(format!("encode public key: {e}")))?;
    let trimmed_comment = comment.trim();
    let public_openssh = if trimmed_comment.is_empty() {
        public_base
    } else {
        format!("{} {}", public_base.trim_end(), trimmed_comment)
    };

    let fingerprint = key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();

    Ok((public_openssh, fingerprint))
}

/// Strictly verify that a pasted OpenSSH **public** key matches a pasted
/// **private** key, for the `existing` key-source branch of the asset
/// create/edit flow (the administrator pastes BOTH halves).
///
/// Decoding goes through [`russh::keys::decode_secret_key`] -- the SAME
/// decoder vauban-proxy-ssh uses at session-open / authentication time
/// (`session.rs`). This guarantees no creation/auth drift: any private
/// key Vauban accepts here is decodable later for `authenticate_publickey`,
/// and any key it cannot decode is rejected at creation rather than
/// failing confusingly on the first connection. Multiple PEM encodings
/// (OpenSSH, PKCS#8, ...) and encrypted keys (via `passphrase`) are
/// supported to the same extent as the proxy.
///
/// On success returns `(public_openssh, fingerprint)` where
/// `public_openssh` is the pasted public-key line, trimmed (the
/// operator's comment is preserved), and `fingerprint` is the SHA256
/// OpenSSH fingerprint of the verified key.
///
/// # Errors
///
/// - the public key is not a valid single-line OpenSSH public key;
/// - the private key cannot be decoded (bad format, or missing/wrong
///   passphrase for an encrypted key);
/// - the public and private keys do not form a matching pair (strict:
///   the SHA256 fingerprints of the pasted public key and the public
///   half derived from the private key must be identical).
pub fn verify_public_private_pair(
    public_openssh: &str,
    private_openssh: &str,
    passphrase: Option<&str>,
) -> io::Result<(String, String)> {
    let pasted_pub = PublicKey::from_openssh(public_openssh.trim()).map_err(|e| {
        io::Error::other(format!(
            "the public key is not a valid OpenSSH public key (expected `ssh-ed25519 AAAA...` \
             or `ssh-rsa AAAA...`): {e}"
        ))
    })?;

    let passphrase = passphrase.map(str::trim).filter(|s| !s.is_empty());
    let private = decode_secret_key(private_openssh.trim(), passphrase).map_err(|e| {
        io::Error::other(format!(
            "the private key could not be decoded (check the format and, for an encrypted key, \
             the passphrase): {e}"
        ))
    })?;

    let derived_pub = private.public_key();
    let derived_fp = derived_pub.fingerprint(HashAlg::Sha256);
    let pasted_fp = pasted_pub.fingerprint(HashAlg::Sha256);

    if derived_fp != pasted_fp {
        return Err(io::Error::other(
            "the public key does not match the private key (their fingerprints differ). \
             Paste the public key that corresponds to this private key."
                .to_string(),
        ));
    }

    Ok((public_openssh.trim().to_string(), derived_fp.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_openssh_private_key() {
        let kp = generate_ed25519_keypair("VAUBAN").expect("keygen");
        assert!(
            kp.private_openssh
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "private key must be OpenSSH PEM, got: {}",
            &kp.private_openssh[..kp.private_openssh.len().min(40)]
        );
        // The private PEM must round-trip back into a russh PrivateKey.
        let parsed = PrivateKey::from_openssh(kp.private_openssh.as_str());
        assert!(parsed.is_ok(), "generated private key must re-parse");
    }

    #[test]
    fn public_key_is_ed25519_with_comment() {
        let kp = generate_ed25519_keypair("alice@asset").expect("keygen");
        assert!(
            kp.public_openssh.starts_with("ssh-ed25519 "),
            "public key must be an ssh-ed25519 line, got: {}",
            kp.public_openssh
        );
        assert!(
            kp.public_openssh.ends_with(" alice@asset"),
            "public key must carry the trailing comment, got: {}",
            kp.public_openssh
        );
        // Exactly three whitespace-separated fields: algo, payload, comment.
        let fields: Vec<&str> = kp.public_openssh.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "expected `algo b64 comment`");
        assert_eq!(fields[0], "ssh-ed25519");
    }

    #[test]
    fn empty_comment_yields_two_field_public_key() {
        let kp = generate_ed25519_keypair("").expect("keygen");
        let fields: Vec<&str> = kp.public_openssh.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            2,
            "no comment must yield `algo b64` only, got: {}",
            kp.public_openssh
        );
        assert_eq!(fields[0], "ssh-ed25519");
    }

    #[test]
    fn fingerprint_is_sha256_openssh_form() {
        let kp = generate_ed25519_keypair("VAUBAN").expect("keygen");
        assert!(
            kp.fingerprint.starts_with("SHA256:"),
            "fingerprint must be the OpenSSH SHA256 form, got: {}",
            kp.fingerprint
        );
    }

    #[test]
    fn derive_public_key_matches_generated_pair() {
        let kp = generate_ed25519_keypair("alice@asset").expect("keygen");
        let (derived_pub, derived_fp) =
            public_key_from_private_openssh(&kp.private_openssh, "alice@asset")
                .expect("derive public key");
        assert_eq!(
            derived_pub, kp.public_openssh,
            "derived public key must match the generated one"
        );
        assert_eq!(derived_fp, kp.fingerprint);
    }

    #[test]
    fn derive_public_key_rejects_garbage() {
        let err = public_key_from_private_openssh("not a key", "");
        assert!(err.is_err(), "garbage private key must be rejected");
    }

    #[test]
    fn derive_public_key_empty_comment_two_fields() {
        let kp = generate_ed25519_keypair("VAUBAN").expect("keygen");
        let (derived_pub, _) =
            public_key_from_private_openssh(&kp.private_openssh, "").expect("derive");
        let fields: Vec<&str> = derived_pub.split_whitespace().collect();
        assert_eq!(fields.len(), 2, "no comment must yield `algo b64`");
    }

    #[test]
    fn verify_pair_accepts_matching_pasted_halves() {
        let kp = generate_ed25519_keypair("alice@asset").expect("keygen");
        let (stored_pub, fp) =
            verify_public_private_pair(&kp.public_openssh, &kp.private_openssh, None)
                .expect("matching pair must verify");
        // The pasted public key is stored verbatim (comment preserved).
        assert_eq!(stored_pub, kp.public_openssh.trim());
        assert_eq!(fp, kp.fingerprint);
    }

    #[test]
    fn verify_pair_rejects_mismatched_halves() {
        let a = generate_ed25519_keypair("a@asset").expect("keygen a");
        let b = generate_ed25519_keypair("b@asset").expect("keygen b");
        // Pair a-public with b-private: fingerprints differ -> reject.
        let err = verify_public_private_pair(&a.public_openssh, &b.private_openssh, None);
        assert!(
            err.is_err(),
            "a public key that does not match the private key must be rejected"
        );
    }

    #[test]
    fn verify_pair_rejects_garbage_public_key() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let err = verify_public_private_pair("not-a-public-key", &kp.private_openssh, None);
        assert!(err.is_err(), "garbage public key must be rejected");
    }

    #[test]
    fn verify_pair_rejects_garbage_private_key() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let err = verify_public_private_pair(&kp.public_openssh, "not-a-private-key", None);
        assert!(err.is_err(), "garbage private key must be rejected");
    }

    // --- Adversarial battery ------------------------------------------------

    /// Encrypt a freshly-minted Ed25519 key with `passphrase`, returning
    /// `(public_openssh, encrypted_private_openssh)`. Used to exercise the
    /// passphrase-protected import path the same way an operator would
    /// paste a passphrase-locked `id_ed25519`.
    fn make_encrypted_pair(passphrase: &str) -> (String, String) {
        let key = PrivateKey::random(
            &mut russh::keys::ssh_key::rand_core::UnwrapErr(getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let public_openssh = key.public_key().to_openssh().expect("encode pub");
        let encrypted = key
            .encrypt(
                &mut russh::keys::ssh_key::rand_core::UnwrapErr(getrandom::SysRng),
                passphrase.as_bytes(),
            )
            .expect("encrypt private key");
        let private_pem = encrypted
            .to_openssh(LineEnding::LF)
            .expect("encode encrypted private")
            .to_string();
        (public_openssh, private_pem)
    }

    #[test]
    fn verify_pair_accepts_encrypted_private_with_correct_passphrase() {
        let (public_openssh, encrypted_priv) = make_encrypted_pair("s3cr3t-passphrase");
        let res =
            verify_public_private_pair(&public_openssh, &encrypted_priv, Some("s3cr3t-passphrase"));
        assert!(
            res.is_ok(),
            "an encrypted private key with the right passphrase must verify: {res:?}"
        );
    }

    #[test]
    fn verify_pair_rejects_encrypted_private_with_wrong_passphrase() {
        let (public_openssh, encrypted_priv) = make_encrypted_pair("correct-horse");
        let err = verify_public_private_pair(&public_openssh, &encrypted_priv, Some("wrong-pass"));
        assert!(
            err.is_err(),
            "an encrypted private key with the wrong passphrase must be rejected"
        );
    }

    #[test]
    fn verify_pair_rejects_encrypted_private_without_passphrase() {
        let (public_openssh, encrypted_priv) = make_encrypted_pair("locked");
        let err = verify_public_private_pair(&public_openssh, &encrypted_priv, None);
        assert!(
            err.is_err(),
            "an encrypted private key with no passphrase must be rejected (cannot decode)"
        );
    }

    #[test]
    fn verify_pair_treats_blank_passphrase_as_none() {
        // A non-encrypted key paired with a stray blank passphrase (the UI
        // submits "" when the operator leaves the field empty) must still
        // verify: the helper trims+filters the passphrase to None.
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let res = verify_public_private_pair(&kp.public_openssh, &kp.private_openssh, Some("   "));
        assert!(
            res.is_ok(),
            "blank passphrase must be treated as None: {res:?}"
        );
    }

    #[test]
    fn verify_pair_trims_surrounding_whitespace() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let padded_pub = format!("  \n {}  \n", kp.public_openssh.trim());
        let padded_priv = format!("\n\n{}\n\n", kp.private_openssh.as_str());
        let (stored, _) = verify_public_private_pair(&padded_pub, &padded_priv, None)
            .expect("whitespace-padded pair must verify after trimming");
        assert_eq!(
            stored,
            kp.public_openssh.trim(),
            "stored public key must be trimmed"
        );
    }

    #[test]
    fn verify_pair_rejects_swapped_halves() {
        // Public field carries a PRIVATE key, private field carries a
        // PUBLIC key: both decoders must reject their wrong input.
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let err = verify_public_private_pair(&kp.private_openssh, &kp.public_openssh, None);
        assert!(err.is_err(), "swapped halves must be rejected");
    }

    #[test]
    fn verify_pair_rejects_public_key_in_private_field() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        // Private field is actually a public key line -> decode fails.
        let err = verify_public_private_pair(&kp.public_openssh, &kp.public_openssh, None);
        assert!(
            err.is_err(),
            "a public key pasted into the private field must be rejected"
        );
    }

    #[test]
    fn verify_pair_rejects_empty_inputs() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        assert!(verify_public_private_pair("", &kp.private_openssh, None).is_err());
        assert!(verify_public_private_pair(&kp.public_openssh, "", None).is_err());
        assert!(verify_public_private_pair("", "", None).is_err());
    }

    #[test]
    fn verify_pair_preserves_comment_verbatim_including_markup() {
        // A malicious comment must NOT prevent verification (the
        // fingerprint ignores the comment) and must round-trip verbatim so
        // the rendering layer (askama auto-escape / html_escape) is the
        // single XSS chokepoint -- not silent mangling here.
        let kp = generate_ed25519_keypair("").expect("keygen");
        let evil = format!("{} <script>alert(1)</script>", kp.public_openssh.trim());
        let (stored, fp) = verify_public_private_pair(&evil, &kp.private_openssh, None)
            .expect("a valid key with a hostile comment must still verify");
        assert_eq!(
            stored, evil,
            "the pasted public key must be stored verbatim"
        );
        assert!(stored.contains("<script>"));
        assert_eq!(fp, kp.fingerprint);
    }

    #[test]
    fn verify_pair_rejects_truncated_public_key() {
        let kp = generate_ed25519_keypair("a@asset").expect("keygen");
        let body = kp.public_openssh.split_whitespace().nth(1).unwrap();
        // Drop the last 8 base64 chars: still "looks" like a key but is
        // structurally invalid.
        let truncated = format!("ssh-ed25519 {}", &body[..body.len().saturating_sub(8)]);
        let err = verify_public_private_pair(&truncated, &kp.private_openssh, None);
        assert!(err.is_err(), "a truncated public key must be rejected");
    }

    #[test]
    fn two_calls_yield_distinct_keys() {
        let a = generate_ed25519_keypair("VAUBAN").expect("keygen a");
        let b = generate_ed25519_keypair("VAUBAN").expect("keygen b");
        assert_ne!(
            *a.private_openssh, *b.private_openssh,
            "each generation must produce a fresh private key"
        );
        assert_ne!(
            a.public_openssh, b.public_openssh,
            "each generation must produce a fresh public key"
        );
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
