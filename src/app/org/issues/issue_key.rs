//! Issue detail at `/{org}/issues/{issue_key}`.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use super::{sev_class, status_class};
use crate::{
    app::org::Org,
    auth::require_org,
    layout::{self, NavSection},
    models::Issue,
    perms::perms_for_user,
};

#[path_param]
struct IssueKey(str);

#[page]
async fn issue_detail_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    let ctx = require_org(cx, org_slug).await?;
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
    let Some(issue) = issues.into_iter().find(|i| i.key == *key) else {
        return Err(topcoat::router::not_found().into());
    };

    let list_href = format!("/{org_slug}/issues");
    let sev = sev_class(&issue.severity);
    let st = status_class(&issue.status);
    let closed = issue.status.eq_ignore_ascii_case("Closed")
        || issue.status.eq_ignore_ascii_case("Resolved");

    let body = view! {
        <div style="max-width: 820px;">
            <a class="vb-link" href=(list_href) style="display: inline-block; margin-bottom: 16px;">
                "← Back to list"
            </a>
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap;">
                <span class="vb-mono" style="font-size: 13px; font-weight: 700; color: var(--accent);">
                    (issue.key.clone())
                </span>
                <span class=(sev)>(issue.severity.clone())</span>
                <span class=(st)>(issue.status.clone())</span>
            </div>
            <h1 class="vb-title" style="font-size: 21px; margin-bottom: 16px; line-height: 1.3;">
                (issue.title.clone())
            </h1>

            <div class="vb-meta-grid">
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">"COMPONENT"</div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        (issue.component.clone())
                    </div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">"OPENED BY"</div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">"Customer"</div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">"CREATED"</div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">"Jun 20"</div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">"UPDATED"</div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">"3h ago"</div>
                </div>
            </div>

            <div class="vb-callout">
                <span>"◷"</span>
                <span>
                    "SLA: initial analysis within 2–5 business days from the report timestamp."
                </span>
            </div>

            <div class="vb-section-label">"DISCUSSION"</div>
            <div style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 22px;">
                <div style="display: flex; flex-direction: column; align-items: flex-start;">
                    <div class="vb-bubble">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                            <span style="font-size: 12.5px; font-weight: 700;">"Customer"</span>
                            <span class="vb-mono" style="font-size: 9.5px; color: #fff; background: #5a5f66; padding: 1px 6px; border-radius: 3px;">
                                "reporter"
                            </span>
                            <span class="vb-mono" style="font-size: 10px; color: #9aa0a6;">"Jun 20"</span>
                        </div>
                        <div style="font-size: 13.5px; line-height: 1.55; color: #3a3f46;">
                            "Seeing intermittent latency spikes on the SSH proxy under load. Happy to share metrics."
                        </div>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 12px; padding: 2px 0;">
                    <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
                    <span class="vb-mono" style="font-size: 11px; color: #8a8f96; white-space: nowrap;">
                        "Moved to analysis · 3h ago"
                    </span>
                    <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
                </div>
                <div style="display: flex; flex-direction: column; align-items: flex-end;">
                    <div class="vb-bubble support">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                            <span style="font-size: 12.5px; font-weight: 700; color: var(--accent);">
                                "Vauban Support"
                            </span>
                            <span class="vb-mono" style="font-size: 9.5px; color: #fff; background: var(--accent); padding: 1px 6px; border-radius: 3px;">
                                "support"
                            </span>
                            <span class="vb-mono" style="font-size: 10px; color: #9aa0a6;">"2h ago"</span>
                        </div>
                        <div style="font-size: 13.5px; line-height: 1.55; color: #3a3f46;">
                            "Thanks — we are correlating proxy latency with concurrent session count. Initial analysis underway."
                        </div>
                    </div>
                </div>
            </div>

            if closed {
                <div class="vb-panel" style="background: #fafbf9; display: flex; align-items: center; justify-content: space-between; gap: 16px;">
                    <div style="display: flex; align-items: center; gap: 11px;">
                        <span style="width: 26px; height: 26px; flex: none; border-radius: 50%; background: #e9eaec; color: #5a5f66; display: flex; align-items: center; justify-content: center; font-size: 13px;">
                            "✓"
                        </span>
                        <div style="font-size: 13.5px; color: #5a5f66; line-height: 1.5;">
                            "This issue is closed. Reopen it to add a comment."
                        </div>
                    </div>
                    <span class="vb-btn outline">"Reopen issue"</span>
                </div>
            } else if perms.issues_write {
                <div class="vb-panel" style="padding: 14px;">
                    <textarea
                        placeholder="Add a reply…"
                        style="width: 100%; min-height: 76px; font-size: 14px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 12px;"
                    ></textarea>
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <span class="vb-btn muted">"📎 Attach screenshot"</span>
                        <div style="display: flex; gap: 10px;">
                            <span class="vb-btn muted">"Close issue"</span>
                            <span class="vb-btn">"Reply"</span>
                        </div>
                    </div>
                    <p class="vb-muted" style="margin: 12px 0 0; font-size: 12px;">
                        "Reply / close mutations ship in a later slice — layout matches Concept."
                    </p>
                </div>
            }
        </div>
    };

    layout::shell(cx, &ctx, &perms, NavSection::Issues, "issues", body).await
}
