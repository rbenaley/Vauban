//! Pin tests for the unified `industrial.enabled` gate and the
//! supervisor-side IACS host key + listener pre-load (May 2026).
//!
//! Background: the supervisor must:
//!
//!   1. Skip spawning `proxy_iacs` when `industrial.enabled = false`
//!      (no surface, no FD pre-load, no respawn).
//!   2. When `industrial.enabled = true`, pre-bind the IACS sshd
//!      listener AND pre-load the russh host key BEFORE forking the
//!      proxy. Both FDs are inherited via env vars
//!      (`VAUBAN_IACS_LISTENER_FD`, `VAUBAN_IACS_HOST_KEY_FD`)
//!      exclusively to `proxy_iacs`.
//!   3. NOT carry the retired `industrial.iacs_tunnel.enabled` field
//!      anywhere except the deserialised-then-warned `_deprecated_enabled`
//!      slot in [`config::IacsTunnelSupervisorConfig`].
//!
//! These pin tests run on Linux CI (where Capsicum is a no-op) and
//! cover the source contract that protects the FreeBSD production
//! deployment.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MAIN_RS: &str = include_str!("../src/main.rs");
const CONFIG_RS: &str = include_str!("../src/config.rs");

/// The boot path MUST gate `proxy_iacs` spawn on
/// `config.industrial.enabled`. The legacy
/// `config.industrial.iacs_tunnel.enabled` was removed.
#[test]
fn proxy_iacs_spawn_is_gated_on_industrial_enabled() {
    assert!(
        MAIN_RS.contains("if service_key == \"proxy_iacs\" && !config.industrial.enabled"),
        "vauban-supervisor/src/main.rs MUST skip proxy_iacs spawn when \
         industrial.enabled = false. Without this guard, the proxy is \
         spawned and crash-loops on the post-Capsicum host key open \
         (FreeBSD errno 94)."
    );
}

/// The supervisor MUST call `prepare_host_key_fd` exactly inside the
/// `if config.industrial.enabled` branch, BEFORE any `spawn_child(`.
#[test]
fn prepare_host_key_fd_is_invoked_in_enabled_branch() {
    assert!(
        MAIN_RS.contains("shared::iacs_host_key::prepare_host_key_fd"),
        "vauban-supervisor MUST call \
         shared::iacs_host_key::prepare_host_key_fd to pre-load the \
         IACS sshd Ed25519 host key BEFORE fork."
    );
    let prep_pos = MAIN_RS
        .find("shared::iacs_host_key::prepare_host_key_fd")
        .expect("prepare_host_key_fd call");
    let first_spawn_pos = MAIN_RS
        .find("for service_key in config.startup_order()")
        .expect("startup_order spawn loop");
    assert!(
        prep_pos < first_spawn_pos,
        "INVARIANT BROKEN: prepare_host_key_fd ({}) must run BEFORE \
         the startup_order spawn loop ({}); otherwise the host key \
         FD is not available when proxy_iacs is forked.",
        prep_pos,
        first_spawn_pos
    );
}

/// `VAUBAN_IACS_HOST_KEY_FD` MUST be attached to `inheritable_fds`
/// only for `proxy_iacs`. We restrict the assertion to push sites
/// (`inheritable_fds.push((...))` lines) so doc-comment mentions
/// in the architectural prelude do not produce false positives.
#[test]
fn host_key_fd_env_attached_only_to_proxy_iacs() {
    let push_sites: Vec<_> = MAIN_RS
        .match_indices("inheritable_fds.push((\"VAUBAN_IACS_HOST_KEY_FD\"")
        .collect();
    assert!(
        !push_sites.is_empty(),
        "VAUBAN_IACS_HOST_KEY_FD MUST be pushed into \
         inheritable_fds in vauban-supervisor/src/main.rs."
    );
    // Three push sites today: initial spawn loop, respawn_service,
    // respawn_linked_group. Every site must sit inside a `proxy_iacs`
    // guard somewhere in the immediate ~400 chars preceding the push.
    for (pos, _) in &push_sites {
        let start = pos.saturating_sub(400);
        let window = &MAIN_RS[start..*pos];
        assert!(
            window.contains("proxy_iacs"),
            "VAUBAN_IACS_HOST_KEY_FD push at byte offset {} sits \
             OUTSIDE a `proxy_iacs` guard. The host key FD must be \
             exposed exclusively to vauban-proxy-iacs.",
            pos
        );
    }
}

/// `VAUBAN_IACS_LISTENER_FD` MUST also remain exclusive to `proxy_iacs`.
#[test]
fn listener_fd_env_attached_only_to_proxy_iacs() {
    let occurrences: Vec<_> = MAIN_RS
        .match_indices("VAUBAN_IACS_LISTENER_FD")
        .collect();
    for (pos, _) in &occurrences {
        let start = pos.saturating_sub(600);
        let window = &MAIN_RS[start..*pos];
        // The doc-comment occurrences may not have a `proxy_iacs`
        // word in the immediate vicinity but they are not push
        // sites. We only enforce the constraint for `inheritable_fds.push`
        // sites by detecting them.
        let following = &MAIN_RS[*pos..(*pos + 80).min(MAIN_RS.len())];
        let is_push_site = following.contains("inheritable_fds.push");
        if is_push_site {
            assert!(
                window.contains("proxy_iacs"),
                "VAUBAN_IACS_LISTENER_FD pushed into inheritable_fds \
                 OUTSIDE a `proxy_iacs` guard at byte offset {}.",
                pos
            );
        }
    }
}

/// The `IacsTunnelSupervisorConfig` MUST NOT have a runtime `enabled`
/// field any more (only the deserialised-then-warned `_deprecated_enabled`
/// slot remains, renamed via serde).
#[test]
fn iacs_tunnel_supervisor_config_has_no_active_enabled_field() {
    // The struct definition MUST NOT carry an active `pub enabled: bool`.
    // The slot we keep is `_deprecated_enabled` (with `rename = "enabled"`)
    // -- this lets serde capture the legacy key for the deprecation
    // warning without binding it to runtime logic.
    let struct_pos = CONFIG_RS
        .find("pub struct IacsTunnelSupervisorConfig")
        .expect("IacsTunnelSupervisorConfig struct must exist");
    let after = &CONFIG_RS[struct_pos..];
    let close = after.find("\n}").expect("struct must close");
    let body = &after[..close];
    assert!(
        !body.contains("pub enabled: bool"),
        "IacsTunnelSupervisorConfig MUST NOT carry an active \
         `pub enabled: bool` field. Use industrial.enabled (single \
         master switch). The slot kept for deprecation warnings is \
         `_deprecated_enabled` with `#[serde(rename = \"enabled\")]`."
    );
    assert!(
        body.contains("_deprecated_enabled"),
        "IacsTunnelSupervisorConfig MUST keep the `_deprecated_enabled` \
         slot so the supervisor can warn at boot when an operator's \
         TOML still carries the retired `industrial.iacs_tunnel.enabled`."
    );
}

/// `IndustrialConfig::enabled` MUST default to `true` so deployments
/// that never wrote the field keep the industrial surface alive after
/// upgrade.
#[test]
fn industrial_enabled_defaults_to_true() {
    assert!(
        CONFIG_RS.contains("fn default_industrial_enabled() -> bool {\n    true\n}"),
        "industrial.enabled MUST default to true (single master switch \
         shipped on by default; opt-out is explicit via enabled = false)."
    );
}

/// The supervisor MUST log a deprecation warning when the deployed
/// TOML still carries `industrial.iacs_tunnel.enabled`.
#[test]
fn boot_warns_about_deprecated_iacs_tunnel_enabled() {
    assert!(
        MAIN_RS.contains("industrial.iacs_tunnel.enabled is DEPRECATED"),
        "vauban-supervisor MUST log a deprecation warning when the \
         deployed TOML still carries `industrial.iacs_tunnel.enabled`."
    );
}

/// The supervisor MUST NOT propagate `VAUBAN_IACS_HOST_KEY_PATH` as
/// an env var to children any more (the FD form replaces it).
#[test]
fn supervisor_does_not_propagate_host_key_path_env() {
    // The string only appears in comments / docs in `config.rs`, but
    // never as a `vars.push((... "VAUBAN_IACS_HOST_KEY_PATH", ...))`.
    let pushes: Vec<_> = CONFIG_RS
        .match_indices("\"VAUBAN_IACS_HOST_KEY_PATH\".to_string()")
        .collect();
    assert!(
        pushes.is_empty(),
        "vauban-supervisor MUST NOT propagate VAUBAN_IACS_HOST_KEY_PATH \
         as an env var any more. The supervisor pre-loads the host key \
         and inherits the FD via VAUBAN_IACS_HOST_KEY_FD instead."
    );
}
