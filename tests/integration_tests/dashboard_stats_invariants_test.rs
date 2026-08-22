//! Source-shape invariants for org dashboard issue stats aggregation.

use std::process::Command;

#[test]
fn inv_check_dashboard_stats_script() {
    let output = Command::new("bash")
        .arg("scripts/check_dashboard_stats.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_dashboard_stats.sh");
    assert!(
        output.status.success(),
        "scripts/check_dashboard_stats.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_dashboard_uses_single_issue_load_and_summarize() {
    let dash = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/dashboard_tiles.rs"
    ));
    let page = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(dash.contains("summarize_issue_stats"));
    assert!(dash.contains("DASHBOARD_ISSUES_CAP"));
    assert!(dash.contains("latest_issue_by_updated_at"));
    assert!(dash.contains("#[memoize]"));
    assert_eq!(
        dash.matches("Issue::all()").count(),
        1,
        "dashboard must call Issue::all() exactly once"
    );
    assert!(
        !dash.contains("ISSUE_STATUS_RESOLVED") && !dash.contains("ISSUE_STATUS_CLOSED"),
        "dashboard must not multi-COUNT by status constants"
    );
    assert!(
        page.contains("dash_stat_build")
            && page.contains("dash_stat_open")
            && page.contains("dash_stat_analysis")
            && page.contains("dash_card_docs")
            && page.contains("dash_activity"),
        "dashboard page must compose sibling tile components"
    );
}

#[test]
fn inv_dashboard_stats_module_exported() {
    let lib = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(lib.contains("pub mod dashboard_stats"));
    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/dashboard_stats.rs"
    ));
    assert!(helpers.contains("pub const DASHBOARD_ISSUES_CAP"));
    assert!(helpers.contains("pub fn summarize_issue_stats"));
    assert!(helpers.contains("pub fn latest_issue_by_updated_at"));
    assert!(helpers.contains("pub fn issue_activity_copy"));
}

/// Pins the contract that OPEN ISSUES is FSM `Open`, not `!issue_is_closed`.
#[test]
fn inv_dashboard_open_tile_counts_fsm_open_not_non_closed() {
    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/dashboard_stats.rs"
    ));
    assert!(
        helpers.contains("ISSUE_STATUS_OPEN"),
        "open tile must key off ISSUE_STATUS_OPEN"
    );
    assert!(
        helpers.contains("ISSUE_STATUS_IN_ANALYSIS"),
        "analysis tile must key off ISSUE_STATUS_IN_ANALYSIS"
    );
    assert!(
        !helpers.contains("issue_is_closed"),
        "dashboard_stats must not reuse issue_is_closed (would fold In analysis into Open)"
    );
    assert!(
        helpers.contains("summarize_open_excludes_in_analysis_and_terminal"),
        "must keep the 16/3/1/1 Open-vs-In-analysis regression unit"
    );
    let script = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/check_dashboard_stats.sh"
    ));
    assert!(
        script.contains("issue_is_closed") && script.contains("ISSUE_STATUS_OPEN"),
        "check_dashboard_stats.sh must pin FSM open counting"
    );
}

#[test]
fn inv_toasty_filters_pins_dashboard_single_load() {
    let script = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/check_toasty_filters.sh"
    ));
    assert!(
        script.contains("summarize_issue_stats") || script.contains("DASHBOARD_ISSUES_CAP"),
        "check_toasty_filters must pin dashboard_stats aggregation"
    );
}

#[test]
fn inv_dashboard_activity_is_dateless_equal_panels() {
    let dash = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/dashboard_tiles.rs"
    ));
    let page = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    let script = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/check_dashboard_stats.sh"
    ));
    assert!(
        dash.contains("issue_activity_copy") && page.contains("vb-grid-2"),
        "dashboard must wire dateless activity + vb-grid-2"
    );
    assert!(
        !dash.contains("format_relative")
            && !dash.contains("format_unix_local")
            && !dash.contains("build_released_on")
            && !page.contains("format_relative")
            && !page.contains("format_unix_local")
            && !page.contains("build_released_on"),
        "dashboard must not format activity clocks"
    );
    assert!(
        css.contains(".vb-grid-2 { display: grid; grid-template-columns: 1fr 1fr;"),
        "vb-grid-2 must split activity / latest-build 50/50"
    );
    assert!(
        !css.contains("1.3fr 1fr"),
        "vb-grid-2 must not keep the old 1.3fr/1fr split"
    );
    assert!(
        script.contains("issue_activity_copy") && script.contains("1fr 1fr"),
        "check_dashboard_stats.sh must pin dateless activity + equal columns"
    );
}
