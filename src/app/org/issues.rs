use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::Issue,
    perms::perms_for_user,
};

#[page]
async fn issues_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(forbidden().into());
    }

    let mut database = crate::auth::db(cx);
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();

    let body = view! {
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap;">
            <div>
                <h1>"Issue tracker"</h1>
                <p class="muted">"SLA: initial analysis within 2–5 business days."</p>
            </div>
            if perms.issues_write {
                <span class="btn">"+ Report an issue"</span>
            }
        </div>
        <div class="card" style="margin-top: 18px;">
            if issues.is_empty() {
                <p class="muted">"No matching issues."</p>
            } else {
                <div style="display: flex; flex-direction: column; gap: 12px;">
                    for issue in issues {
                        <div style="display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; padding-bottom: 12px; border-bottom: 1px solid #e8ebe6;">
                            <div>
                                <div style="font-family: ui-monospace, monospace; color: var(--accent); font-size: 13px;">
                                    (issue.key.clone())
                                </div>
                                <div style="font-weight: 700; margin-top: 2px;">(issue.title.clone())</div>
                                <div class="muted" style="margin-top: 4px;">
                                    (issue.component.clone())
                                </div>
                            </div>
                            <div style="text-align: right;">
                                <div class="muted">(issue.severity.clone())</div>
                                <div style="margin-top: 6px; font-size: 13px;">(issue.status.clone())</div>
                            </div>
                        </div>
                    }
                </div>
            }
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Issues, "issues", body).await
}
