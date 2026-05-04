//! Issue #34 -- pin tests on the inlined Request Access /
//! Justification modal data flow.
//!
//! These tests grep the source of:
//!
//! - `templates/sessions/access_request_modal.html`
//! - `templates/sessions/justification_modal.html`
//! - `templates/assets/asset_list.html`
//! - `static/js/vauban-components.js`
//!
//! to verify, at compile time, that the per-row buttons on `/assets`
//! correctly populate the Alpine stores and that the modal forms
//! read from those stores instead of from server-rendered template
//! variables.  The legacy `/assets/{uuid}` detail page has been
//! removed (information leak: description / dates / ssh-host-key
//! fingerprint were rendered for any caller with `assets:read`,
//! including users awaiting JIT approval), so any regression that
//! reintroduces the per-asset hash navigation pattern (`<a
//! href=".../#request-access">`) is a P1 bug.

const ACCESS_MODAL: &str = include_str!("../../templates/sessions/access_request_modal.html");
const JUSTIFY_MODAL: &str = include_str!("../../templates/sessions/justification_modal.html");
const ASSET_LIST: &str = include_str!("../../templates/assets/asset_list.html");
const COMPONENTS_JS: &str = include_str!("../../static/js/vauban-components.js");

/// The access request modal MUST read the asset uuid / asset_type /
/// require_mfa flag from the Alpine store, NOT from a server-side
/// `{{ asset.* }}` interpolation.  The per-row buttons on /assets
/// open the modal via `$store.accessModal.open(uuid, type, mfa)`,
/// which is the ONLY path that populates these fields.
#[test]
fn access_modal_form_uses_alpine_store_bindings() {
    assert!(
        ACCESS_MODAL.contains(":value=\"$store.accessModal.asset_uuid\""),
        "access_request_modal.html must bind asset_uuid via :value to \
         $store.accessModal.asset_uuid (issue #34)"
    );
    assert!(
        ACCESS_MODAL.contains(":value=\"$store.accessModal.asset_type\""),
        "access_request_modal.html must bind session_type via :value to \
         $store.accessModal.asset_type (issue #34)"
    );
    assert!(
        ACCESS_MODAL.contains("x-if=\"$store.accessModal.require_mfa\""),
        "access_request_modal.html must conditionally render the TOTP \
         input via <template x-if> against \
         $store.accessModal.require_mfa (issue #34)"
    );
    // Modal must NOT fall back to the legacy server-rendered
    // `{{ asset.uuid }}` interpolation -- that pattern bound the
    // form to a single page-loaded asset and required the detail
    // page that we just deleted.
    assert!(
        !ACCESS_MODAL.contains("{{ asset.uuid }}"),
        "access_request_modal.html must NOT use server-side \
         `{{{{ asset.uuid }}}}` interpolation; the modal is now \
         inlined on /assets and reads from the Alpine store"
    );
    assert!(
        !ACCESS_MODAL.contains("{{ asset.asset_type }}"),
        "access_request_modal.html must NOT use server-side \
         `{{{{ asset.asset_type }}}}`; switch to the Alpine store"
    );
    assert!(
        !ACCESS_MODAL.contains("{% if asset.require_mfa %}"),
        "access_request_modal.html must NOT branch on the server-side \
         `asset.require_mfa`; the TOTP block is rendered via \
         `<template x-if=\"$store.accessModal.require_mfa\">`"
    );
}

/// The justification modal MUST submit via `htmx.ajax(...)` from a
/// `@submit.prevent` handler, with the URL computed by
/// `$store.justificationModal.connectUrl()`.  Alpine `:hx-post`
/// bindings don't compose reliably with the cached HTMX form
/// submit handler, so the programmatic `htmx.ajax()` path is the
/// battle-tested pattern.
#[test]
fn justify_modal_uses_htmx_ajax_with_connect_url_from_store() {
    assert!(
        JUSTIFY_MODAL.contains("htmx.ajax('POST', $store.justificationModal.connectUrl()"),
        "justification_modal.html must POST via htmx.ajax with the URL \
         computed by $store.justificationModal.connectUrl() (issue #34)"
    );
    assert!(
        JUSTIFY_MODAL.contains("@submit.prevent="),
        "justification_modal.html must intercept the form submit with \
         @submit.prevent so Alpine can dispatch the htmx.ajax call \
         instead of the static hx-post path"
    );
    // No static hx-post fallback: that would race with the
    // programmatic ajax call and could double-submit.
    assert!(
        !JUSTIFY_MODAL.contains("hx-post=\""),
        "justification_modal.html must NOT carry a static `hx-post` \
         attribute; the URL is computed at click time from the \
         Alpine store"
    );
    // Must NOT use the legacy `{{ asset.uuid }}` server-side
    // interpolation either.
    assert!(
        !JUSTIFY_MODAL.contains("{{ asset.uuid }}"),
        "justification_modal.html must NOT use server-side \
         `{{{{ asset.uuid }}}}` interpolation (issue #34)"
    );
}

/// `asset_list.html` MUST drive the modaux via per-row Alpine
/// `@click` bindings (NOT via `<a href=".../#request-access">`
/// anchor navigation, which forced the user through the now-removed
/// detail page).  Each button MUST pass `asset.uuid` and
/// `asset.asset_type` literally; the Request button additionally
/// passes `asset.require_mfa` so the TOTP block is conditionally
/// rendered.
#[test]
fn asset_list_buttons_call_open_with_per_row_data() {
    assert!(
        ASSET_LIST.contains(
            "$store.accessModal.open('{{ asset.uuid }}', \
             '{{ asset.asset_type }}', {{ asset.require_mfa }})"
        ),
        "asset_list.html must open the access modal with per-row \
         (asset.uuid, asset.asset_type, asset.require_mfa) (issue #34)"
    );
    assert!(
        ASSET_LIST.contains(
            "$store.justificationModal.open('{{ asset.uuid }}', \
             '{{ asset.asset_type }}')"
        ),
        "asset_list.html must open the justification modal with \
         per-row (asset.uuid, asset.asset_type) (issue #34)"
    );
    // Forbidden legacy patterns:
    assert!(
        !ASSET_LIST.contains("#request-access"),
        "asset_list.html must NOT contain the legacy \
         `#request-access` hash (the /assets/{{uuid}} detail page \
         is gone, issue #34)"
    );
    assert!(
        !ASSET_LIST.contains("#justify"),
        "asset_list.html must NOT contain the legacy `#justify` \
         hash (the /assets/{{uuid}} detail page is gone, issue #34)"
    );
    // Modaux must be included exactly once at the bottom.
    let access_includes = ASSET_LIST.matches("access_request_modal.html").count();
    let justify_includes = ASSET_LIST.matches("justification_modal.html").count();
    assert_eq!(
        access_includes, 1,
        "asset_list.html must include access_request_modal.html exactly \
         once (issue #34); found {} occurrences",
        access_includes
    );
    assert_eq!(
        justify_includes, 1,
        "asset_list.html must include justification_modal.html exactly \
         once (issue #34); found {} occurrences",
        justify_includes
    );
}

/// The Alpine stores MUST expose an `open(...)` function that is the
/// single entry point for populating the per-asset fields.  The
/// `connectUrl()` method on `justificationModal` MUST switch on
/// `asset_type === 'rdp'` to return the right backend route.  The
/// legacy hash router (`#request-access` / `#justify`) MUST NOT be
/// re-introduced.
#[test]
fn alpine_stores_expose_open_and_connect_url() {
    assert!(
        COMPONENTS_JS.contains("Alpine.store('accessModal'"),
        "vauban-components.js must register the accessModal Alpine store"
    );
    assert!(
        COMPONENTS_JS.contains("Alpine.store('justificationModal'"),
        "vauban-components.js must register the justificationModal Alpine store"
    );
    assert!(
        COMPONENTS_JS.contains("open: function (uuid, type, requireMfa)"),
        "accessModal store must expose open(uuid, type, requireMfa) (issue #34)"
    );
    assert!(
        COMPONENTS_JS.contains("open: function (uuid, type)"),
        "justificationModal store must expose open(uuid, type) (issue #34)"
    );
    assert!(
        COMPONENTS_JS.contains("connectUrl: function ()"),
        "justificationModal store must expose connectUrl() (issue #34)"
    );
    assert!(
        COMPONENTS_JS.contains("'connect-rdp'"),
        "connectUrl() must select 'connect-rdp' for RDP assets"
    );
    // Legacy hash router MUST be gone.
    assert!(
        !COMPONENTS_JS.contains("window.location.hash === '#request-access'"),
        "vauban-components.js must NOT contain the legacy \
         `#request-access` hash auto-opener (issue #34): the modal \
         is now opened by per-row buttons on /assets"
    );
    assert!(
        !COMPONENTS_JS.contains("window.location.hash === '#justify'"),
        "vauban-components.js must NOT contain the legacy `#justify` \
         hash auto-opener (issue #34)"
    );
    assert!(
        !COMPONENTS_JS.contains("asset-policy-state"),
        "vauban-components.js must NOT consume the `asset-policy-state` \
         data island (the detail page that emitted it is gone, issue #34)"
    );
}

/// SSH/RDP connect handlers MUST emit `HX-Trigger:
/// show-access-request-modal` (with payload) instead of the legacy
/// `HX-Redirect: /assets/{uuid}#request-access` so the modal opens
/// in-place on /assets.  The 410 Gone served by
/// `gone_asset_user_view` would otherwise interrupt the JIT request
/// flow.
#[test]
fn connect_handlers_emit_hx_trigger_not_hx_redirect_to_detail() {
    let ssh = include_str!("../../src/handlers/web/ssh.rs");
    let rdp = include_str!("../../src/handlers/web/rdp.rs");

    for (name, src) in [("ssh.rs", ssh), ("rdp.rs", rdp)] {
        assert!(
            !src.contains("/assets/{}#request-access"),
            "{name} must NOT format `/assets/{{}}#request-access`: \
             the detail page is gone (issue #34); use HX-Trigger \
             show-access-request-modal instead"
        );
        assert!(
            src.contains("show-access-request-modal"),
            "{name} must emit HX-Trigger `show-access-request-modal` \
             with the asset_uuid / asset_type / require_mfa payload \
             when approval is required (issue #34)"
        );
        assert!(
            src.contains("\"asset_uuid\""),
            "{name} HX-Trigger payload must carry asset_uuid"
        );
        assert!(
            src.contains("\"require_mfa\""),
            "{name} HX-Trigger payload must carry require_mfa so the \
             inlined modal renders the TOTP field correctly"
        );
    }
}

/// `gone_asset_user_view` MUST exist and the route MUST point at it.
/// The function body MUST NOT echo the asset uuid, name, or any DB
/// field (anti-enumeration: a 410 is the same for every input).
#[test]
fn gone_asset_user_view_is_constant_and_anti_enum() {
    let assets = include_str!("../../src/handlers/web/assets.rs");
    let main = include_str!("../../src/main.rs");

    assert!(
        assets.contains("pub async fn gone_asset_user_view("),
        "handlers/web/assets.rs must define `gone_asset_user_view`"
    );
    assert!(
        main.contains("handlers::web::gone_asset_user_view"),
        "main.rs must route GET /assets/{{uuid}} to gone_asset_user_view"
    );
    // Body must not interpolate any path / DB data.
    let body_start = assets
        .find("pub async fn gone_asset_user_view(")
        .expect("gone handler must exist");
    let body_end = assets[body_start..]
        .find("\n}\n")
        .map(|p| body_start + p)
        .unwrap_or(assets.len());
    let body = &assets[body_start..body_end];
    assert!(
        !body.contains("format!"),
        "gone_asset_user_view body must NOT use format! (anti-enum: \
         the response is constant)"
    );
    assert!(
        !body.contains("asset_uuid_str.as_str"),
        "gone_asset_user_view body must NOT echo the input uuid"
    );
    assert!(
        body.contains("StatusCode::GONE"),
        "gone_asset_user_view must return 410 Gone, not 404 / redirect"
    );
}

/// The legacy `asset_detail.html` template MUST be gone from disk.
/// Askama would compile-fail anyway if the file existed without a
/// matching `Template` derive, but a stale template is a footgun for
/// future maintainers who could be tempted to mount a new handler
/// against it.
#[test]
fn asset_detail_template_was_removed() {
    let path = std::path::Path::new("templates/assets/asset_detail.html");
    assert!(
        !path.exists(),
        "templates/assets/asset_detail.html must NOT exist (issue #34): \
         the user-zone detail page was an information-leak surface and \
         has been replaced by inlined modaux on /assets"
    );
    // Same goes for the Rust template module.
    let module = std::path::Path::new("src/templates/assets/asset_detail.rs");
    assert!(
        !module.exists(),
        "src/templates/assets/asset_detail.rs must NOT exist (issue #34)"
    );
}
