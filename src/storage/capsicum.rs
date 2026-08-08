//! Capsicum hooks (FreeBSD) with soft-containment WARN elsewhere.
//!
//! On FreeBSD, capability mode is entered via the `capsicum` crate
//! (`capsicum::enter` → `cap_enter(2)`). Unsafe FFI stays in that dependency;
//! this module keeps `unsafe_code = "deny"`.

#[cfg(target_os = "freebsd")]
use tracing::info;
use tracing::warn;

use super::STORE_LOG_TARGET;

/// Display name for log lines (`macOS`, `Linux`, …). FreeBSD uses the
/// `capsicum::enter` path and never formats this helper.
#[cfg(not(target_os = "freebsd"))]
fn os_display_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "linux" => "Linux",
        "ios" => "iOS",
        "android" => "Android",
        "windows" => "Windows",
        other => other,
    }
}

/// Enter capability mode after pre-opening FDs.
///
/// On FreeBSD, attempts real `cap_enter(2)` via [`capsicum::enter`]. Elsewhere
/// (and when the syscall is unavailable), logs a soft-containment WARN and
/// continues with dirfd + path policy + UID permissions only.
pub fn enter_capability_mode(production: bool) {
    #[cfg(target_os = "freebsd")]
    {
        // Callers must pre-open blob dirfd, listen socket, and any other
        // needed FDs first — `cap_enter` is process-wide and irreversible.
        match capsicum::enter() {
            Ok(()) => {
                info!(
                    target: STORE_LOG_TARGET,
                    "Capsicum: entered capability mode via cap_enter"
                );
            }
            Err(err) => {
                warn!(
                    target: STORE_LOG_TARGET,
                    error = %err,
                    "Capsicum: cap_enter unavailable or failed; soft containment only (dirfd + uid)"
                );
                if production {
                    warn!(
                        target: STORE_LOG_TARGET,
                        "production deployment without kernel capability mode"
                    );
                }
            }
        }
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        warn!(
            target: STORE_LOG_TARGET,
            "Capsicum unavailable on {}; storage helper running with soft containment only",
            os_display_name()
        );
        if production {
            warn!(
                target: STORE_LOG_TARGET,
                "production deployment without kernel sandbox"
            );
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

    #[cfg(not(target_os = "freebsd"))]
    #[test]
    fn os_display_name_uses_product_casing() {
        let name = os_display_name();
        match std::env::consts::OS {
            "macos" => assert_eq!(name, "macOS"),
            "linux" => assert_eq!(name, "Linux"),
            _ => assert!(!name.is_empty()),
        }
    }
}
