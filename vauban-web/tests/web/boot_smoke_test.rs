//! Issue #27 — boot smoke test.
//!
//! Pin the high-level shape of `vauban-web/src/main.rs` for the
//! asset-zone split: the production binary MUST mount the admin
//! sub-trees and layer them with `require_assets_manage`. v1.0
//! has not shipped, so there are intentionally NO legacy-URL
//! redirects to preserve compatibility for; clients (UI, CLI,
//! IaC) target the canonical `/assets/manage/*` and
//! `/api/v1/assets/manage/*` URLs directly.
//!
//! Most route-shape invariants are pinned by other tests; this
//! file is the *single boot-time checklist*. Tests in this file
//! are deliberately simple and source-level so they cannot be
//! disabled by a runtime regression (e.g. a database outage).

/// `main.rs` MUST keep both nest declarations (web + API), each
/// followed by a `route_layer` carrying the gate. This is the
/// bootstrap-time signature of the asset zone split.
#[test]
fn main_rs_contains_both_nests_and_both_gates() {
    let body = include_str!("../../src/main.rs");
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");

    let web_nest = format!(".nest( \"{}\"", "/assets/manage");
    let api_nest = format!(".nest( \"{}\"", "/api/v1/assets/manage");

    assert!(
        collapsed.contains(web_nest.as_str())
            || collapsed.contains(format!(".nest(\"{}\"", "/assets/manage").as_str()),
        "main.rs MUST mount the web admin sub-tree via Router::nest"
    );
    assert!(
        collapsed.contains(api_nest.as_str())
            || collapsed.contains(format!(".nest(\"{}\"", "/api/v1/assets/manage").as_str()),
        "main.rs MUST mount the API admin sub-tree via Router::nest"
    );

    let gate = "require_assets_manage::require_assets_manage";
    let gate_count = body.matches(gate).count();
    assert!(
        gate_count >= 2,
        "main.rs MUST wire `{}` on BOTH the web and the API admin nest \
         (found {} occurrence(s))",
        gate,
        gate_count
    );
}

/// Anti-regression: now that v1.0 has not shipped, NO legacy
/// `redirect_legacy_*` helpers and NO legacy admin routes (e.g.
/// `/assets/new`, `/assets/{uuid}/edit`, `/api/v1/assets/groups`)
/// should remain in `main.rs`. The cleanup commit removed them
/// because there are no bookmarks or external clients to preserve
/// compatibility for; reintroducing them would silently re-create
/// a parallel surface that bypasses the canonical
/// `/assets/manage/*` (web) and `/api/v1/assets/manage/*` (API)
/// URLs. If a future v1.x release needs migration redirects,
/// reintroduce them with a fresh boot-time test, not by undoing
/// this guard.
#[test]
fn main_rs_does_not_carry_legacy_asset_redirects() {
    let body = include_str!("../../src/main.rs");

    let needle = "async fn redirect_legacy_";
    let count = body.matches(needle).count();
    assert_eq!(
        count, 0,
        "main.rs MUST NOT declare any `async fn redirect_legacy_*` \
         helper (found {count}). The pre-v1.0 cleanup removed them \
         because there are no shipped clients to support."
    );

    let forbidden_paths: &[&str] = &[
        "\"/assets/new\"",
        "\"/assets/deleted\"",
        "\"/assets/{uuid}/edit\"",
        "\"/assets/{uuid}/delete\"",
        "\"/assets/{uuid}/fetch-host-key\"",
        "\"/api/v1/assets/{uuid}/ssh-host-key\"",
        "\"/api/v1/assets/groups\"",
        "\"/api/v1/assets/groups/{uuid}/assets\"",
        // BAC hardening: asset groups moved under
        // `/assets/manage/groups/*`. The flat pre-move web paths must
        // never come back (they lived OUTSIDE the
        // `require_assets_manage` nest and leaked the catalogue to
        // any authenticated user).
        "\"/assets/groups\"",
        "\"/assets/groups/new\"",
        "\"/assets/groups/{uuid}\"",
        "\"/assets/groups/{uuid}/edit\"",
        "\"/assets/groups/{uuid}/delete\"",
        "\"/assets/groups/{uuid}/add-asset\"",
        "\"/assets/groups/{uuid}/remove-asset\"",
    ];
    for p in forbidden_paths {
        assert!(
            !body.contains(p),
            "main.rs MUST NOT register the legacy admin path {} as a \
             route. CRUD now lives exclusively under \
             `/assets/manage/*` (web) and `/api/v1/assets/manage/*` \
             (API).",
            p
        );
    }
}

/// The middleware module MUST export `require_assets_manage` so
/// `main.rs` can wire it via `from_fn`. A regression in the public
/// path would compile-fail the binary, but pinning it here makes
/// the failure point obvious in CI logs.
#[test]
fn middleware_module_exports_require_assets_manage() {
    let body = include_str!("../../src/middleware/mod.rs");
    let module_decl = "pub mod require_assets_manage";
    assert!(
        body.contains(module_decl),
        "vauban-web/src/middleware/mod.rs MUST declare `{}` so \
         main.rs can reference `middleware::require_assets_manage::\
         require_assets_manage` in the route_layer.",
        module_decl
    );
}

/// The `manage_assets` web and API modules MUST be re-exported from
/// `handlers/{web,api}/mod.rs` so `main.rs` can call e.g.
/// `handlers::web::manage_asset_list` directly.
#[test]
fn handlers_modules_re_export_manage_assets() {
    let web_mod = include_str!("../../src/handlers/web/mod.rs");
    let api_mod = include_str!("../../src/handlers/api/mod.rs");

    assert!(
        web_mod.contains("manage_assets"),
        "vauban-web/src/handlers/web/mod.rs MUST register the \
         `manage_assets` submodule (or re-export from it)."
    );
    assert!(
        api_mod.contains("manage_assets"),
        "vauban-web/src/handlers/api/mod.rs MUST register the \
         `manage_assets` submodule (or re-export from it)."
    );
}

/// The `templates::assets::manage` Askama module MUST export both
/// the list and the detail templates so the admin handlers can
/// instantiate them. Compile-time check; pinned here as a
/// boot-checklist item.
#[test]
fn manage_assets_templates_module_exports_both_templates() {
    let body = include_str!("../../src/templates/assets/manage/mod.rs");
    assert!(
        body.contains("ManageAssetListTemplate"),
        "templates/assets/manage/mod.rs MUST export ManageAssetListTemplate"
    );
    assert!(
        body.contains("ManageAssetDetailTemplate"),
        "templates/assets/manage/mod.rs MUST export ManageAssetDetailTemplate"
    );
}
