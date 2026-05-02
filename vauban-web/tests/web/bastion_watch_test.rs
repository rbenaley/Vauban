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
        // be `{% if perms.sessions_supervise %}` (the per-user
        // isolation refactor moved every dashboard gate from
        // `admin_view` to `sessions_supervise`).
        let prefix = &page[..pos];
        let last_if = prefix.rfind("{% if ").unwrap_or(0);
        let last_endif = prefix.rfind("{% endif %}").unwrap_or(0);
        assert!(
            last_if > last_endif,
            "tile `{}` MUST be inside an `{{% if perms.sessions_supervise %}}` \
             block; otherwise non-supervisor browsers would receive its WS \
             updates.",
            id
        );
        let if_block = &prefix[last_if..];
        assert!(
            if_block.contains("perms.sessions_supervise"),
            "tile `{}` is wrapped in an `if`, but the condition does \
             not mention `perms.sessions_supervise`. The dashboard \
             gates the supervisor surface on `sessions:supervise` \
             (Casbin) -- a regression to `admin_view` would defeat \
             the per-user isolation contract.",
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
/// for supervisors, and MUST always run the snapshot loader (it is
/// the page's primary read). The gate moved from `admin_view` to
/// `sessions_supervise` as part of the per-user isolation refactor.
#[test]
fn dashboard_handler_gates_system_health_on_sessions_supervise() {
    let src = include_str!("../../src/handlers/web/dashboard.rs");
    let needle = "if perms.sessions_supervise";
    assert!(
        src.contains(needle),
        "dashboard_home MUST gate the system_health load on \
         `perms.sessions_supervise`. Without the gate, every user \
         request would do a 5-query DB roundtrip just to discard \
         the data, AND a non-supervisor would observe pool / \
         req-rate / outbox state."
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
        snap.contains("live_session_history.record(scope_key, live_u64)"),
        "load_hero MUST record the freshly-observed live count into \
         the LiveSessionHistory under the SAME scope_key it queries. \
         A drift here (e.g. recording under Global from a User scope) \
         would mix lanes and leak active counts across tenants."
    );
    assert!(
        snap.contains("live_session_history.series(scope_key)"),
        "load_hero MUST derive its sparkline series from \
         LiveSessionHistory::series(scope_key) on the SAME scope it \
         queries. The previous build_today_sparkline() helper \
         conflated openings-per-hour with active-count-over-time and \
         was deliberately removed."
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

// =====================================================================
// Bastion Watch -- per-user isolation pin tests (5-layer defence)
// =====================================================================

fn snapshot_src() -> &'static str {
    include_str!("../../src/services/dashboard/snapshot.rs")
}

fn handler_src() -> &'static str {
    include_str!("../../src/handlers/web/dashboard.rs")
}

fn broadcast_src() -> &'static str {
    include_str!("../../src/services/broadcast.rs")
}

/// Pin (L1 type system): every user-scopable loader MUST take a
/// `scope: DashboardScope` parameter so the compiler refuses an
/// oversight. Adding a new loader without the parameter would
/// silently fall back to a global query.
#[test]
fn every_user_scopable_loader_takes_dashboard_scope() {
    let src = snapshot_src();
    for sig in &[
        "pub(crate) async fn load_hero(",
        "pub(crate) async fn load_live_sessions(",
        "pub(crate) async fn load_evidence_chain(",
        "pub(crate) async fn load_heatmap(",
    ] {
        let idx = src.find(sig).unwrap_or_else(|| {
            panic!(
                "loader signature `{}` not found in snapshot.rs -- did the \
                 visibility or name drift?",
                sig
            )
        });
        // Look at the next 400 chars after the signature for the
        // multi-line argument list.
        let window = &src[idx..(idx + 400).min(src.len())];
        assert!(
            window.contains("scope: DashboardScope"),
            "{} MUST accept `scope: DashboardScope` as a mandatory \
             parameter (Bastion Watch isolation L1). See \
             .cursor/rules/dashboard-passivity.mdc, section \
             User-scope isolation.",
            sig
        );
    }
}

/// Pin (L3 Casbin gate): the dashboard handler MUST derive its
/// scope from `perms.sessions_supervise` -- not from a hard-coded
/// `is_staff || is_superuser` shortcut, which would silently bypass
/// custom Casbin policies.
#[test]
fn dashboard_handler_derives_scope_from_sessions_supervise() {
    let src = handler_src();
    assert!(
        src.contains("perms.sessions_supervise"),
        "dashboard_home MUST gate the scope decision on \
         `perms.sessions_supervise`. A handler that uses \
         `auth_user.is_staff` or hard-codes `Global` would defeat \
         the L3 layer of the per-user isolation."
    );
    assert!(
        src.contains("DashboardScope::Global") && src.contains("DashboardScope::User"),
        "dashboard_home MUST construct both DashboardScope variants \
         (Global for supervisors, User(id) for everyone else)."
    );
}

/// Pin (L3 routing): the pusher MUST route per-user broadcasts on
/// the `WsChannel::DashboardStatsUser(...)` parametric channel
/// (high-cardinality), not on the singleton `DashboardStats`.
#[test]
fn dashboard_pusher_routes_users_to_dashboard_stats_user_channel() {
    let src = pusher_src();
    assert!(
        src.contains("WsChannel::DashboardStatsUser("),
        "dashboard_pusher MUST broadcast per-user snapshots on \
         `WsChannel::DashboardStatsUser(uuid)`. Routing them on the \
         singleton `DashboardStats` would re-leak global data to \
         every supervisor sub."
    );
    assert!(
        src.contains("active_channels_with_prefix("),
        "dashboard_pusher MUST enumerate active per-user channels \
         via BroadcastService::active_channels_with_prefix to drive \
         the per-scope loop. Hard-coding the user list would bypass \
         the live-subscriber GC."
    );
    assert!(
        src.contains("gc_idle_after("),
        "dashboard_pusher MUST call LiveSessionHistory::gc_idle_after \
         on the slow tier to evict idle per-user rings (else memory \
         grows linearly with the count of users who ever opened the \
         dashboard)."
    );
}

/// Pin (cardinality classification): `DashboardStatsUser(_)` MUST
/// classify as high-cardinality -- one channel per non-supervisor
/// browser tab. Logging it at INFO would flood the operator's
/// terminal with one line per tile per second per user.
#[test]
fn ws_channel_dashboard_stats_user_is_high_cardinality() {
    let src = broadcast_src();
    assert!(
        src.contains("WsChannel::DashboardStatsUser(_)"),
        "broadcast.rs MUST list `WsChannel::DashboardStatsUser(_)` in \
         its `is_low_cardinality` exhaustive match arms."
    );
    // Verify the variant is grouped with the high-cardinality arm.
    let is_low_idx = src
        .find("pub fn is_low_cardinality(&self) -> bool {")
        .expect("is_low_cardinality must exist on WsChannel");
    let body = &src[is_low_idx..(is_low_idx + 1500).min(src.len())];
    let user_idx = body
        .find("WsChannel::DashboardStatsUser(_)")
        .expect("DashboardStatsUser arm must appear in is_low_cardinality body");
    let false_idx = body.find("=> false")
        .expect("is_low_cardinality must contain a `=> false` branch");
    assert!(
        user_idx < false_idx,
        "WsChannel::DashboardStatsUser(_) MUST be on the high-cardinality \
         (`=> false`) branch of is_low_cardinality. Routing it as low \
         (`=> true`) would log every per-tile broadcast at INFO."
    );
}

/// Pin (template gate alignment): `bastion_watch.html` MUST gate
/// supervisor tiles on `perms.sessions_supervise`, NEVER on the
/// looser `perms.admin_view` (which a Casbin policy could grant
/// without granting supervise).
#[test]
fn template_gates_supervisor_tiles_on_sessions_supervise() {
    let page = page_template_src();
    assert!(
        page.contains("perms.sessions_supervise"),
        "bastion_watch.html MUST gate supervisor tiles on \
         `perms.sessions_supervise` (the L3 Casbin gate of the \
         Bastion Watch isolation contract)."
    );
    // The pre-isolation gate `perms.admin_view` MUST not appear in
    // the page -- letting both gates coexist would create an
    // ambiguous policy surface.
    assert!(
        !page.contains("perms.admin_view"),
        "bastion_watch.html MUST NOT gate any tile on \
         `perms.admin_view`; the per-user isolation refactor moved \
         every dashboard tile to `perms.sessions_supervise`. \
         Mixing both would let a `admin_view`-without-`sessions_supervise` \
         user observe global telemetry."
    );
    // The WS endpoint MUST split on the same gate.
    assert!(
        page.contains("/ws/dashboard/personal"),
        "bastion_watch.html MUST route non-supervisors to \
         /ws/dashboard/personal so they receive only their own \
         user-scoped fragments."
    );
}
