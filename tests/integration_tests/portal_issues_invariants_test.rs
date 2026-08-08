//! Source-shape invariants for portal issue tracker.

use std::process::Command;

#[test]
fn inv_check_portal_issues_script() {
    let output = Command::new("bash")
        .arg("scripts/check_portal_issues.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run check_portal_issues.sh");
    assert!(
        output.status.success(),
        "scripts/check_portal_issues.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inv_report_issue_persists_details() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    assert!(src.contains("details"));
    assert!(src.contains("issues_write"));
    assert!(src.contains("organization_id"));
}

#[test]
fn inv_report_issue_safe_key_allocation() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    let helper = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_key.rs"));
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0009_issue_org_key_unique.sql"
    ));
    assert!(
        src.contains("allocate_issue_key"),
        "report_issue must call allocate_issue_key"
    );
    assert!(
        src.contains("err=create"),
        "failed create must redirect with err=create"
    );
    assert!(
        !src.contains("existing.len() + 200") && !src.contains("len() + 200"),
        "must not forge keys via len() + 200"
    );
    assert!(
        !src.contains("let _ = toasty::create!(Issue"),
        "must not swallow create!(Issue) errors"
    );
    assert!(helper.contains("fn allocate_issue_key"));
    assert!(helper.contains("fn next_issue_key_from_keys"));
    assert!(history.contains("0009_issue_org_key_unique.sql"));
    assert!(migration.contains("index_issues_by_organization_id_and_key"));
    assert!(migration.contains("UNIQUE"));
}

#[test]
fn inv_issue_detail_renders_details() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    assert!(
        src.contains("issue.details"),
        "detail page must render issue.details"
    );
    assert!(
        src.contains("IssueComment"),
        "detail must load IssueComment from DB"
    );
    assert!(src.contains("/reply"), "detail must expose reply POST path");
    assert!(src.contains("/close"), "detail must expose close POST path");
    assert!(
        src.contains("/reopen"),
        "detail must expose reopen POST path"
    );
    assert!(
        src.contains("issue_is_closed"),
        "detail must use shared issue_is_closed helper"
    );
    assert!(
        src.contains("close_issue_status") && src.contains("reopen_issue_status"),
        "detail must call close/reopen status helpers"
    );
    assert!(
        !src.contains("<span class=\"vb-btn muted\">\"Close issue\"</span>")
            && !src.contains("<span class=\"vb-btn outline\">\"Reopen issue\"</span>"),
        "Close/Reopen must not remain stub spans"
    );
    assert!(
        src.contains("Vauban Support"),
        "support-side timeline must display Vauban Support"
    );
    assert!(
        !src.contains("max-width: 820px") && !src.contains("max-width: 720px"),
        "issue detail must use full content width"
    );
}

#[test]
fn inv_issue_status_helpers_exist() {
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let status = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_status.rs"));
    assert!(models.contains("ISSUE_STATUS_OPEN"));
    assert!(models.contains("ISSUE_STATUS_CLOSED"));
    assert!(models.contains("ISSUE_COMMENT_KIND_STATUS"));
    assert!(status.contains("fn issue_is_closed"));
    assert!(status.contains("ISSUE_TIMELINE_CLOSED"));
    assert!(status.contains("ISSUE_TIMELINE_REOPENED"));
}

#[test]
fn inv_admin_issues_aggregate_surface() {
    let list = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues.rs"
    ));
    let detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    assert!(list.contains("require_staff"));
    assert!(list.contains("issues_read"));
    assert!(
        list.contains("org"),
        "list must support optional org filter"
    );
    assert!(detail.contains("Vauban Support"));
    assert!(detail.contains("ISSUE_ROLE_SUPPORT"));
    assert!(detail.contains("/admin/issues/"));
    assert!(detail.contains("admin_issue_detail_href"));
    assert!(detail.contains("?org="));
    assert!(detail.contains("/close"));
    assert!(detail.contains("/reopen"));
    assert!(detail.contains("issue_is_closed"));
    let shard = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    assert!(
        shard.contains("admin_issue_detail_href"),
        "admin list shard must use org-disambiguated detail hrefs"
    );
    assert!(
        !detail.contains("<span class=\"vb-btn muted\">\"Close issue\"</span>")
            && !detail.contains("<span class=\"vb-btn outline\">\"Reopen issue\"</span>"),
        "admin Close/Reopen must not remain stub spans"
    );
    assert!(
        !detail.contains("max-width: 820px") && !detail.contains("max-width: 720px"),
        "admin issue detail must use full content width"
    );
}

#[test]
fn inv_issue_attachments_o_k_and_wired() {
    let helpers = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/issue_attachments.rs"
    ));
    let history = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/toasty/history.toml"));
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/toasty/migrations/0014_issue_attachments.sql"
    ));
    let models = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/models/mod.rs"));
    let report = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues.rs"
    ));
    let new_page = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/new.rs"
    ));
    let detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let app = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app.rs"));

    assert!(models.contains("struct IssueAttachment"));
    assert!(models.contains("DEFAULT_MAX_ATTACHMENTS_PER_COMMENT"));
    assert!(models.contains("MAX_ISSUE_ATTACHMENTS"));
    assert!(history.contains("0014_issue_attachments.sql"));
    assert!(migration.contains("CREATE TABLE \"issue_attachments\""));
    assert!(migration.contains("index_issue_attachments_by_issue_id_and_image_id"));
    assert!(helpers.contains("fn list_for_issue"));
    assert!(helpers.contains("fn attach_many"));
    assert!(helpers.contains("fn store_screenshot_uploads"));
    assert!(helpers.contains("issue_attachment_list_limit"));
    assert!(
        !helpers.contains("fn unlink_one"),
        "published attachments must not be unlinked from the portal"
    );
    assert!(
        !helpers.contains("StorageObject::all().exec"),
        "must not full-scan storage_objects"
    );
    assert!(report.contains("Multipart") && report.contains("store_screenshot_uploads"));
    assert!(
        new_page.contains("vb-drop")
            && new_page.contains("enctype=\"multipart/form-data\"")
            && new_page.contains("shot_file_input")
    );
    assert!(detail.contains("list_for_issue"));
    assert!(
        !detail.contains("attachments/remove") && !detail.contains("unlink_one"),
        "detail must not expose post-publish attachment remove"
    );
    assert!(detail.contains("issue_discussion") || detail.contains("opener_thumbs"));
    assert!(detail.contains("enctype=\"multipart/form-data\""));
    assert!(
        new_page.contains("shot_file_input"),
        "compose must wire Topcoat shot_file_input preview"
    );
    // screenshots field must appear before the reply form closes (not form= outside).
    let reply_idx = detail
        .find("id=(ISSUE_REPLY_ANCHOR)")
        .expect("reply form id");
    assert!(
        detail[reply_idx..].contains("shot_file_input")
            || detail[reply_idx..].contains("name=\"screenshots\""),
        "screenshots input must be inside #issue-reply"
    );
    assert!(
        !app.contains("vcp_issue_images.js") && !new_page.contains("VCP_ISSUE_IMAGES_JS"),
        "must not ship first-party issue image JS asset"
    );
    let thumbs = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/issue_thumbs.rs"
    ));
    assert!(
        thumbs.contains("data-src")
            && thumbs.contains("issue-lb")
            && thumbs.contains("@change")
            && thumbs.contains("data-shot-preview"),
        "lightbox/preview must use Topcoat @click/@change, not a .js asset"
    );
    assert!(
        thumbs.contains("<dialog") && thumbs.contains("method=\"dialog\""),
        "lightbox must be a native <dialog> closed by a method=\"dialog\" submit"
    );
    assert!(
        !thumbs.contains("preventDefault") && !thumbs.contains("stopPropagation"),
        "Topcoat handlers get the Event wrapper: camelCase DOM methods throw"
    );
    // Close button overlays the image corner, not the backdrop.
    let figure_at = thumbs
        .find("class=\"vb-issue-lightbox-figure\"")
        .expect("lightbox figure");
    let figure_end = thumbs[figure_at..]
        .find("</form>")
        .expect("figure form closes");
    assert!(
        thumbs[figure_at..figure_at + figure_end].contains("vb-issue-lightbox-close"),
        "close button must sit inside the figure so it tracks the image corner"
    );
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        css.contains(".vb-issue-lightbox-figure") && css.contains("width: fit-content"),
        "figure must shrink-wrap the rendered image"
    );
    let close_at = css
        .find(".vb-issue-lightbox-close {")
        .expect("lightbox close rule");
    let close_rule = &css[close_at..];
    let close_rule = &close_rule[..close_rule.find('}').unwrap_or(close_rule.len())];
    assert!(
        close_rule.contains("position: absolute; top: 12px; right: 12px;"),
        "close button must overlay the image top-right corner"
    );
    assert!(
        close_rule.contains("background: rgba(16, 19, 23, 0.55)"),
        "close overlay must stay translucent over the screenshot"
    );
    assert!(
        !css.contains("position: absolute; inset: 0; z-index: 40"),
        "lightbox must not go back to a pane-anchored absolute overlay"
    );
    let cfg = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"));
    assert!(
        cfg.contains("max_attachments_per_comment") && cfg.contains("IssuesConfig"),
        "config must expose issues.max_attachments_per_comment"
    );
    assert!(
        history.contains("0015_issue_attachment_comment_id.sql"),
        "history must record comment_id migration"
    );
}

/// A native `multiple` input replaces its `FileList` on every pick, so the
/// picker must keep its own accumulated list; and the lightbox figure must be
/// pinned to the measured image box, or the close button drifts into the
/// backdrop whenever a screenshot is height-constrained.
#[test]
fn inv_shot_picker_accumulates_and_lightbox_tracks_image() {
    let thumbs = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/issue_thumbs.rs"
    ));
    assert!(
        thumbs.contains("input.vcpShots") && thumbs.contains("new DataTransfer()"),
        "picker must accumulate picks across file dialogs (vcpShots + DataTransfer)"
    );
    assert!(
        !thumbs.contains("Array.from(input.files).slice(0, max)"),
        "picker must merge with kept files, not slice the fresh FileList"
    );
    assert!(
        thumbs.contains("data-shot-add") && thumbs.contains("data-shot-status"),
        "picker must expose the add trigger + live count hooks"
    );
    assert!(
        thumbs.contains("aria-live=\"polite\""),
        "attachment count must be announced politely"
    );
    assert!(
        thumbs.contains("attachment_cap_hint"),
        "cap wording must come from the shared helper (compose + reply)"
    );
    assert!(
        thumbs.contains("@load") && thumbs.contains("getBoundingClientRect"),
        "lightbox must size the figure from the rendered image on load"
    );
    assert!(
        thumbs.contains("window.addEventListener('resize'"),
        "lightbox figure must be refitted when the viewport changes"
    );

    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));
    assert!(
        !css.contains("max-width: min(100%, 1180px)"),
        "percentage caps resolve against the shrink-wrapping figure: use viewport units"
    );
    assert!(
        css.contains("--vb-lb-max-w:") && css.contains("--vb-lb-max-h:"),
        "lightbox caps must live in viewport-based custom properties"
    );
    assert!(
        css.contains(".vb-issue-lightbox-figure.is-fit .vb-issue-lightbox-close"),
        "close button must stay hidden until the figure is pinned to the image"
    );
    assert!(
        thumbs.contains("lightbox_step_index")
            && thumbs.contains("vcpGallery")
            && thumbs.contains("issue-lb-prev")
            && thumbs.contains("issue-lb-next")
            && thumbs.contains("ArrowLeft")
            && thumbs.contains("ArrowRight")
            && thumbs.contains("closest('.vb-issue-thumbs')"),
        "multi-image lightbox must wrap within one comment strip (prev/next + arrows)"
    );
    assert!(
        thumbs.contains("data-step=\"-1\"") && thumbs.contains("data-step=\"1\""),
        "nav buttons must expose data-step for wrap-around stepping"
    );
    assert!(
        css.contains(".vb-issue-lightbox-nav")
            && css.contains(".vb-issue-lightbox-prev")
            && css.contains(".vb-issue-lightbox-next")
            && css.contains(".vb-issue-lightbox-nav[hidden]"),
        "nav chevrons must be styled and hideable until a multi-image strip opens"
    );
    assert!(
        css.contains(".vb-shot-add:focus-within") && css.contains(".vb-shot-status"),
        "picker needs a visible keyboard focus ring and a status line"
    );
    assert!(
        css.contains(".vb-shot-add[aria-disabled=\"true\"]"),
        "picker trigger must render a disabled state at the cap"
    );
}

/// The portal body scrolls inside `.vb-scroll`, so a bare `303` back to the
/// detail URL re-renders at the page header. Every post-action redirect must
/// carry the reply-box fragment, and the anchor must exist in both the open
/// and the closed rendering of the pane.
#[test]
fn inv_issue_post_actions_anchor_on_the_reply_box() {
    let anchor = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/issue_anchor.rs"));
    let detail = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/org/issues/issue_key.rs"
    ));
    let admin = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/issue_key.rs"
    ));
    let shard = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/app/admin/issues/search_shard.rs"
    ));
    let css = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/styles.css"));

    assert!(
        anchor.contains("ISSUE_REPLY_ANCHOR: &str = \"issue-reply\"")
            && anchor.contains("fn with_reply_anchor"),
        "shared anchor helper must pin the id and expose with_reply_anchor"
    );
    assert!(
        css.contains(".vb-scroll { flex: 1; overflow-y: auto; }"),
        "anchor navigation is the only no-JS way to reach the bottom of .vb-scroll"
    );

    for (name, src) in [("org", detail), ("admin", admin)] {
        assert!(
            src.contains("with_reply_anchor"),
            "{name} detail must build post-action targets with with_reply_anchor"
        );
        assert_eq!(
            src.matches("id=(ISSUE_REPLY_ANCHOR)").count(),
            2,
            "{name} detail must anchor both the reply form and the closed panel"
        );
        assert!(
            !src.contains("id=\"issue-reply\""),
            "{name} detail must not hardcode the anchor id next to the constant"
        );
        assert!(
            !src.contains("see_other(&format!(\"/{org_slug}/issues/{key}"),
            "{name} detail must not redirect to an unanchored detail URL"
        );
    }
    assert!(
        detail.contains("fn org_reply_target") && detail.contains("fn reserved_admin_reply_target"),
        "org detail must route reply / close / reopen through anchored helpers"
    );
    assert!(
        admin.contains("fn admin_reply_target"),
        "admin detail must route reply / close / reopen through an anchored helper"
    );
    assert!(
        !shard.contains("with_reply_anchor"),
        "list hrefs must stay anchor-free"
    );
}

#[test]
fn inv_dashboard_activity_not_hardcoded_dates() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/app/org.rs"));
    assert!(
        !src.contains("\"Jun 23\""),
        "dashboard must not hardcode Jun 23"
    );
    assert!(
        !src.contains("\"3h ago\""),
        "dashboard must not hardcode relative fixtures"
    );
    assert!(
        src.contains("format_relative") || src.contains("released_on"),
        "dashboard activity must use DB timestamps"
    );
}
