//! Global admin tools under `/admin/…` — gated by [`crate::auth::require_staff`].

pub(crate) mod companies;
pub(crate) mod docs;
pub(crate) mod issues;
pub(crate) mod key;
pub(crate) mod releases;

pub use releases::admin_releases_list_href;

use topcoat::{
    Result,
    context::Cx,
    router::{
        Slot, StatusCode, error::NotFoundError, error::redirect, href, layout, not_found, route,
    },
    view::{View, error_boundary, view},
};

not_found!("/admin");

use crate::{
    app::_components::{branded_404_body, vb_rail, vb_topbar},
    auth::require_staff,
    models::RESERVED_ORG_SLUG,
    nav::nav_from_cx,
};

#[layout]
async fn admin_layout(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    let _staff = require_staff(cx).await?;
    let (section, crumb) = nav_from_cx(cx);
    let org_slug = RESERVED_ORG_SLUG.to_owned();

    Ok(view! {
        cx =>
        <div class="vb-shell">
            vb_rail(org_slug: &org_slug, section: section)
            <div class="vb-main">
                vb_topbar(org_slug: &org_slug, crumb: &crumb)
                <div class="vb-scroll">
                    <div class="vb-screen">
                        error_boundary(
                            fallback: |error| {
                                if error.downcast_ref::<NotFoundError>().is_none() {
                                    return Err(error);
                                }
                                Ok(
                                    view! {
                                        (StatusCode::NOT_FOUND)
                                        branded_404_body()
                                    },
                                )
                            },
                            (slot)
                        )
                    </div>
                </div>
            </div>
        </div>
    })
}

/// Hub redirects to the first admin tool (Issues).
/// Navigational GET -> `redirect` (307), not `see_other` (303 PRG).
#[route(GET)]
pub(crate) async fn admin_index(cx: &Cx) -> Result<()> {
    let _staff = require_staff(cx).await?;
    Err(redirect(href!(issues::admin_issues_page).resolve(cx)).into())
}
