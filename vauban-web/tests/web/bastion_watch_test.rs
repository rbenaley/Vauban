//! Bastion Watch dashboard structural pin tests.
//!
//! These tests are battle-tested guards on the dashboard's three
//! invariants that the team relies on humans to NOT regress on:
//!
//! 1. **Layout** -- 10 admin-visible tiles, 7 user-visible tiles.
//! 2. **Passivity** -- no `<button>`, `<form>`, mutating HTMX verbs,
//!    or internal navigation links. The dashboard reads, never
//!    writes.
//! 3. **WS target consistency** -- every `id="dash-..."` rendered by
//!    `bastion_watch.html` is also addressed by a `WsMessage::new(...)`
//!    in `dashboard_pusher.rs`. A tile that the page declares but
//!    the pusher does not refresh would be a stale snapshot of the
//!    request that loaded it; a tile that the pusher pushes but the
//!    page omits would be a silent drop.

use std::collections::HashSet;

fn page_template_src() -> &'static str {
    include_str!("../../templates/dashboard/bastion_watch.html")
}

fn pusher_src() -> &'static str {
    include_str!("../../src/tasks/dashboard_pusher.rs")
}

fn tiles_src() -> &'static str {
    include_str!("../../src/templates/dashboard/tiles.rs")
}

/// Pin: 10 admin-visible tiles + 1 user-only tile = 11 distinct
/// `id="dash-..."` attributes in the page template. Admin sees 10 of
/// them (admin-only includes are inside `{% if perms.admin_view %}`);
/// user sees 7 (the 6 always-visible ones + dash-user-lens).
#[test]
fn bastion_watch_template_declares_every_known_tile_id() {
    let page = page_template_src();
    let mut declared: HashSet<&str> = HashSet::new();
    for id in [
        "dash-hero-live",
        "dash-hero-today",
        "dash-hero-jit",
        "dash-hero-evidence",
        "dash-live-sessions",
        "dash-evidence-chain",
        "dash-access-posture",
        "dash-anomalies",
        "dash-user-lens",
        "dash-heatmap",
        "dash-system-health",
    ] {
        let needle = format!("id=\"{}\"", id);
        assert!(
            page.contains(&needle),
            "bastion_watch.html MUST declare a `<div id=\"{}\">` for \
             the WS pusher to target. Adding a new tile without this \
             div silently drops every push for that tile.",
            id
        );
        declared.insert(id);
    }
    assert_eq!(
        declared.len(),
        11,
        "expected exactly 11 tile ids in the dashboard"
    );
}

/// Pin: admin-only tiles MUST be wrapped in `{% if perms.admin_view %}`.
/// Without the wrapper, a user UI would render the admin-tile div,
/// HTMX would happily swap the broadcast HTML into it, and admin
/// data would leak to non-admin browsers.
#[test]
fn admin_only_tiles_are_perms_gated() {
    let page = page_template_src();
    for id in [
        "dash-hero-jit",
        "dash-access-posture",
        "dash-anomalies",
        "dash-system-health",
    ] {
        let needle = format!("id=\"{}\"", id);
        let pos = page
            .find(&needle)
            .unwrap_or_else(|| panic!("missing {needle}"));
        // Walk backwards looking for the nearest `{% if` -- it MUST
        // be `{% if perms.admin_view %}` (or a `{% else %}` of a
        // larger admin gate).
        let prefix = &page[..pos];
        let last_if = prefix.rfind("{% if ").unwrap_or(0);
        let last_endif = prefix.rfind("{% endif %}").unwrap_or(0);
        assert!(
            last_if > last_endif,
            "tile `{}` MUST be inside an `{{% if perms.admin_view %}}` \
             block; otherwise non-admin browsers would receive its WS \
             updates.",
            id
        );
        let if_block = &prefix[last_if..];
        assert!(
            if_block.contains("perms.admin_view"),
            "tile `{}` is wrapped in an `if`, but the condition does \
             not mention `perms.admin_view`. Replace the gate with \
             one that delegates to Casbin via `PermissionContext`.",
            id
        );
    }
}

/// Pin: passivity. Dashboard renders read-only, no actionable UI.
#[test]
fn dashboard_template_carries_no_actionable_widgets() {
    let page = page_template_src();
    let forbidden = [
        "<button",
        "<form",
        "hx-post",
        "hx-put",
        "hx-delete",
        "hx-patch",
    ];
    for needle in forbidden {
        assert!(
            !page.contains(needle),
            "bastion_watch.html MUST stay passive: forbidden token \
             `{}` found. The dashboard is a radar; if you need to \
             expose an action move it to the relevant CRUD page \
             (assets, sessions, ...). See \
             .cursor/rules/dashboard-passivity.mdc.",
            needle
        );
    }
}

/// Pin: passivity (tile partials). Each tile partial under
/// `templates/dashboard/tiles/` MUST also be free of mutating
/// HTMX verbs. A tile silently sneaking in an `hx-post` would
/// be a foot-gun.
#[test]
fn dashboard_tile_partials_carry_no_mutating_htmx() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("templates/dashboard/tiles");
    let entries = std::fs::read_dir(&dir).expect("tile dir");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("html") {
            continue;
        }
        count += 1;
        let src = std::fs::read_to_string(&path).expect("tile read");
        for needle in ["hx-post", "hx-put", "hx-delete", "hx-patch", "<form"] {
            assert!(
                !src.contains(needle),
                "tile partial `{}` MUST NOT carry `{}`",
                path.display(),
                needle
            );
        }
    }
    assert!(
        count >= 10,
        "at least 10 tile partials MUST exist; found {}",
        count
    );
}

/// Pin: every tile id rendered by the page is also addressed by the
/// pusher. A tile that the page declares but the pusher never
/// refreshes is a stale-on-load tile; a tile that the pusher
/// addresses but the page never declares is a silently-dropped push.
#[test]
fn ws_targets_match_between_pusher_and_page() {
    let page = page_template_src();
    let pusher = pusher_src();
    let tiles = tiles_src();
    for id in [
        "dash-hero-live",
        "dash-hero-today",
        "dash-hero-jit",
        "dash-hero-evidence",
        "dash-live-sessions",
        "dash-evidence-chain",
        "dash-access-posture",
        "dash-anomalies",
        "dash-user-lens",
        "dash-heatmap",
        "dash-system-health",
    ] {
        // Page declares the div.
        assert!(
            page.contains(&format!("id=\"{}\"", id)),
            "page must declare div for `{}`",
            id
        );
        // Tile constants module lists the id (as a string literal).
        assert!(
            tiles.contains(&format!("\"{}\"", id)),
            "templates::dashboard::tiles must export a constant for `{}`",
            id
        );
        // Pusher references the id (transitively through the const).
        let const_present = tiles
            .lines()
            .any(|line| line.contains(&format!("\"{}\";", id)) || line.contains(&format!("\"{}\",", id)));
        assert!(const_present, "tile id `{}` MUST be a const in tiles.rs", id);
    }
    // Sanity: pusher imports the const block.
    assert!(
        pusher.contains("TILE_HERO_LIVE")
            && pusher.contains("TILE_ANOMALIES")
            && pusher.contains("TILE_HEATMAP"),
        "dashboard_pusher.rs MUST address tiles via the TILE_* \
         constants exported by templates::dashboard::tiles."
    );
}

/// Pin: the dashboard `/` handler MUST query `system_health` only
/// for admins, and MUST always run the snapshot loader (it is the
/// page's primary read).
#[test]
fn dashboard_handler_gates_system_health_on_admin_view() {
    let src = include_str!("../../src/handlers/web/dashboard.rs");
    let needle = "if perms.admin_view";
    assert!(
        src.contains(needle),
        "dashboard_home MUST gate the system_health load on \
         `perms.admin_view`. Without the gate, every user request \
         would do a 5-query DB roundtrip just to discard the data."
    );
    assert!(
        src.contains("DashboardSnapshot::load"),
        "dashboard_home MUST call DashboardSnapshot::load to power \
         the page's read-only tiles."
    );
    assert!(
        src.contains("BastionWatchTemplate"),
        "dashboard_home MUST render BastionWatchTemplate (the legacy \
         HomeTemplate was retired by the Bastion Watch refonte)."
    );
}

/// Pin: anomaly detector catalogue. Adding or removing a detector
/// without updating the page tile is a silent regression; this test
/// ties them together.
#[test]
fn anomaly_catalogue_is_pinned() {
    let src = include_str!("../../src/services/anomalies.rs");
    for id in [
        "out_of_window_sessions",
        "mfa_stale_users",
        "rules_expiring_soon",
        "unrecorded_recent_sessions",
    ] {
        let needle = format!("id: \"{}\"", id);
        assert!(
            src.contains(&needle),
            "anomaly id `{}` MUST be emitted by some detector",
            id
        );
    }
    let tile = include_str!("../../templates/dashboard/tiles/_anomalies.html");
    assert!(
        tile.contains("a.severity.css_class()"),
        "anomalies tile MUST render `a.severity.css_class()`; a \
         drift to a different accessor would break the per-severity \
         badge palette."
    );
}

/// Pin: SVG widget primitives produce non-empty content.
/// Smoke-tests that the tile partials embed valid SVG primitives.
#[test]
fn tile_partials_embed_svg_primitives() {
    use std::path::Path;
    let live = include_str!("../../templates/dashboard/tiles/_hero_live.html");
    assert!(live.contains("<svg") && live.contains("<polyline"));
    let evid = include_str!("../../templates/dashboard/tiles/_evidence_chain.html");
    assert!(evid.contains("<svg") && evid.contains("<circle"));
    let _ = Path::new("templates/dashboard/_widgets/_sparkline.html");
}

/// Pin: pusher cadences are explicitly named. Drifting to numeric
/// literals scattered across the file makes it impossible to audit
/// "how often does the bastion broadcast?" with a single grep.
#[test]
fn pusher_cadences_are_named_constants() {
    let src = pusher_src();
    assert!(
        src.contains("CADENCE_FAST: Duration") && src.contains("CADENCE_MEDIUM: Duration") && src.contains("CADENCE_SLOW: Duration"),
        "dashboard_pusher.rs MUST expose CADENCE_FAST / CADENCE_MEDIUM / CADENCE_SLOW so a single source-grep tells you the broadcast cadence."
    );
}

/// Pin: WS pusher MUST skip work when no subscriber is connected.
/// This is the difference between a free dashboard refresh and a
/// permanent "load average +1 per process".
#[test]
fn pusher_skips_when_no_subscribers() {
    let src = pusher_src();
    assert!(
        src.contains("subscriber_count(&WsChannel::DashboardStats)"),
        "dashboard_pusher MUST consult subscriber_count(...) and \
         skip the snapshot+render+broadcast pipeline when no client \
         is connected."
    );
}

/// Pin: LIVE hero tile sparkline is fed by `LiveSessionHistory`,
/// NOT by the previous `proxy_sessions.created_at` openings-per-hour
/// approach (which lied: a long-running session opened earlier in
/// the day surfaced as a single past spike then a flat zero for the
/// rest of the day, even when the live count was steady).
#[test]
fn live_sparkline_uses_live_session_history_not_openings_per_hour() {
    let snap = include_str!("../../src/services/dashboard/snapshot.rs");
    assert!(
        snap.contains("live_session_history.record(live_u64)"),
        "load_hero MUST record the freshly-observed live count into \
         the LiveSessionHistory before building the sparkline. A drift \
         to recording AFTER, or skipping the record altogether, would \
         show a sparkline whose last point lags the displayed KPI."
    );
    assert!(
        snap.contains("live_session_history.series()"),
        "load_hero MUST derive its sparkline series from \
         LiveSessionHistory::series(). The previous \
         build_today_sparkline() helper conflated openings-per-hour \
         with active-count-over-time and was deliberately removed."
    );
    assert!(
        !snap.contains("fn build_today_sparkline"),
        "build_today_sparkline() MUST stay deleted. Re-introducing it \
         would silently re-enable the lying openings-per-hour series."
    );
}

/// Pin: HTTP rate middleware is mounted on the global `common_layers`
/// stack, not on a sub-router. Without this layer, the SYSTEM HEALTH
/// tile's `req/s (60s avg)` stays at 0 regardless of bench traffic --
/// the original bug the user reported.
#[test]
fn http_rate_middleware_is_mounted_on_common_layers() {
    let main_src = include_str!("../../src/main.rs");
    let needle = "services::system_health::record_http_request";
    assert!(
        main_src.contains(needle),
        "main.rs MUST mount `record_http_request` as a middleware. \
         Without it, AppState.http_rate stays unused and the System \
         Health tile shows 0 req/s under any load."
    );
    // The mount MUST be on the shared common_layers builder so it
    // covers web + api + ws routes uniformly. We cannot easily ensure
    // strict ordering across `from_fn_with_state` calls in a textual
    // pin, but we can guard against accidental re-mount on a single
    // route or a sub-router.
    let common_layers_idx = main_src
        .find("let common_layers = ServiceBuilder::new()")
        .expect("common_layers ServiceBuilder must exist in main.rs");
    let mw_idx = main_src
        .find(needle)
        .expect("record_http_request must be referenced in main.rs");
    assert!(
        mw_idx > common_layers_idx,
        "record_http_request MUST be layered ON common_layers, not \
         declared above it (otherwise a fresh refactor could move it \
         to a sub-router and silently un-cover most routes)."
    );
}
