//! Shape checks on what a proxy returns when it fetches a trust anchor.
//!
//! The SSH and RDP proxies fetch a host key or a server certificate and
//! answer with a key, an SPKI and a fingerprint. vauban-web stores them
//! on the asset and shows them in the admin pages. A proxy is a separate,
//! sandboxed process: what it returns is input, checked here before it is
//! stored or shown. A value that is not shaped like what it claims to be
//! is refused.
//!
//! These checks are about shape only. Whether the key is the right one is
//! the administrator's decision when pinning.

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// `SHA256:` followed by base64 characters.
pub fn is_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|rest| {
        !rest.is_empty() && rest.len() <= 128 && rest.bytes().all(is_base64_byte)
    })
}

/// Base64 text of a plausible size (an SPKI).
pub fn is_base64(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8192 && value.bytes().all(is_base64_byte)
}

/// An OpenSSH public key line: `<algorithm> <base64>`, nothing else.
pub fn is_openssh_public_key(value: &str) -> bool {
    // A trailing line break is how some encoders end the line.
    let value = value.trim_end_matches(['\r', '\n']);
    let mut parts = value.split(' ');
    let (Some(algorithm), Some(key), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !algorithm.is_empty()
        && algorithm.len() <= 64
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.'))
        && is_base64(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_shapes_are_accepted() {
        assert!(is_fingerprint(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));
        assert!(is_fingerprint(
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        ));
        assert!(is_base64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
        assert!(is_openssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        ));
        assert!(is_openssh_public_key(
            "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t"
        ));
    }

    #[test]
    fn attack_markup_in_a_fingerprint_is_rejected() {
        for value in [
            "SHA256:x\"><div x-data x-init=\"fetch('/x')\">",
            "SHA256:<script>alert(1)</script>",
            "SHA256:abc def",
            "SHA256:abc\n",
            "SHA256:",
            "sha256:abc",
            "MD5:abc",
            "",
            "SHA256:abc&amp;",
        ] {
            assert!(!is_fingerprint(value), "{value:?}");
        }
        assert!(!is_fingerprint(&format!("SHA256:{}", "A".repeat(129))));
    }

    #[test]
    fn attack_markup_in_a_key_or_spki_is_rejected() {
        for value in ["", "abc def", "abc<", "abc\"", "abc\n", "a'b"] {
            assert!(!is_base64(value), "{value:?}");
        }
        assert!(!is_base64(&"A".repeat(8193)));
        for value in [
            "ssh-ed25519",
            "ssh-ed25519 AAAA comment",
            "ssh-ed25519 AAAA\"><img src=x>",
            "<b> AAAA",
            " AAAA",
            "ssh-ed25519  AAAA",
            "ssh-ed25519 ",
        ] {
            assert!(!is_openssh_public_key(value), "{value:?}");
        }
    }
}
