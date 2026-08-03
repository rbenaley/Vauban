//! Capsicum hooks (FreeBSD) with soft-containment WARN elsewhere.

#[cfg(target_os = "freebsd")]
use tracing::info;
use tracing::warn;

/// Display name for log lines (`macOS`, `FreeBSD`, `Linux`, …).
fn os_display_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "freebsd" => "FreeBSD",
        "linux" => "Linux",
        "ios" => "iOS",
        "android" => "Android",
        "windows" => "Windows",
        other => other,
    }
}

/// Enter capability mode after pre-opening FDs.
///
/// On FreeBSD, attempts real `cap_enter(2)`. Elsewhere (and when the
/// syscall is unavailable), logs a soft-containment WARN and continues
/// with dirfd + path policy + UID permissions only.
pub fn enter_capability_mode(production: bool) {
    #[cfg(target_os = "freebsd")]
    {
        // SAFETY: `cap_enter` is process-wide and irreversible. Callers must
        // pre-open blob dirfd, listen socket, and any other needed FDs first.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::cap_enter() };
        if rc == 0 {
            info!("Capsicum: entered capability mode via cap_enter");
        } else {
            let err = std::io::Error::last_os_error();
            warn!(
                error = %err,
                "Capsicum: cap_enter unavailable or failed; soft containment only (dirfd + uid)"
            );
            if production {
                warn!("production deployment without kernel capability mode");
            }
        }
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        warn!(
            "Capsicum unavailable on {}; storage helper running with soft containment only (dirfd + RESOLVE_BENEATH + uid/permissions)",
            os_display_name()
        );
        if production {
            warn!("production deployment without kernel sandbox");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_capability_mode_does_not_panic_on_host_os() {
        enter_capability_mode(false);
        enter_capability_mode(true);
    }

    #[test]
    fn os_display_name_uses_product_casing() {
        let name = os_display_name();
        match std::env::consts::OS {
            "macos" => assert_eq!(name, "macOS"),
            "freebsd" => assert_eq!(name, "FreeBSD"),
            "linux" => assert_eq!(name, "Linux"),
            _ => assert!(!name.is_empty()),
        }
    }
}
