//! Org-scoped routes under `/{org}/…`.

pub(crate) mod account;
pub(crate) mod builds;
mod dashboard_tiles;
pub(crate) mod docs;
pub(crate) mod images;
pub(crate) mod issues;

pub use builds::builds_list_href;
pub use builds::{DL_ERROR_PARAM, DownloadError, download_error_href};

use topcoat::{
    Result,
    context::Cx,
    router::{error::NotFoundError, href, layout, page, path_param},
    view::view,
};

use crate::{
    auth::require_org, models::RESERVED_ORG_SLUG, nav::nav_from_cx,
    release_pkg::org_builds_entitled, request_intern::intern,
};

use super::_components::{branded_404_body, vb_rail, vb_topbar};
use dashboard_tiles::{
    DashLoad, dash_activity, dash_card_builds, dash_card_docs, dash_card_issues, dash_notes,
    dash_stat_analysis, dash_stat_build, dash_stat_open,
};

path_param!(pub org);

#[layout]
async fn org_layout(cx: &Cx, slot: Result) -> Result {
    let slug = path_param::<Org>(cx);
    // Membership gate (memoized; rail/topbar re-use the same lookup).
    let _ctx = require_org(cx, slug).await?;
    let (section, crumb) = nav_from_cx(cx);
    let org_slug = slug.to_owned();
    let inner = match slot {
        Err(error) if error.downcast_ref::<NotFoundError>().is_some() => view! {
            (topcoat::router::StatusCode::NOT_FOUND)
            branded_404_body()
        },
        content => content,
    }?;

    view! {
        cx =>
        <div class="vb-shell">
            vb_rail(org_slug: &org_slug, section: section)
            <div class="vb-main">
                vb_topbar(org_slug: &org_slug, crumb: &crumb)
                <div class="vb-scroll"><div class="vb-screen">(inner)</div></div>
            </div>
        </div>
    }
}

#[page]
pub(crate) async fn dashboard(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let org_id = ctx.org.id;
    let lts = ctx.org.lts_subscriptions;
    let industrial = ctx.org.industrial_lts_subscriptions;
    let show_builds = org_builds_entitled(slug, lts, industrial);
    let slug_id = intern(cx, slug);
    let load = DashLoad {
        org_id,
        slug_id,
        lts,
        industrial,
        show_builds,
    };

    let issues_href = if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        href!(crate::app::admin::issues::admin_issues_page).resolve(cx)
    } else {
        href!(issues::issues_page, Org(slug)).resolve(cx)
    };
    let docs_href = href!(docs::docs_page, Org(slug)).resolve(cx);
    let builds_href = href!(builds::builds_page, Org(slug)).resolve(cx);

    view! {
        cx =>
        <h1 class="vb-title dash">"Dashboard"</h1>

        <div class="vb-stat-row">
            dash_stat_build(load: load)
            dash_stat_open(org_id: org_id)
            dash_stat_analysis(org_id: org_id)
        </div>

        <div class="vb-grid-3">
            dash_card_docs(docs_href: &docs_href)
            dash_card_builds(load: load, builds_href: &builds_href)
            dash_card_issues(org_id: org_id, issues_href: &issues_href)
        </div>

        <div class="vb-grid-2">
            dash_activity(load: load)
            dash_notes(load: load, builds_href: &builds_href)
        </div>
    }
}
