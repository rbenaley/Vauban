//! Issue detail at `/{org}/issues/{issue_key}`.

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, not_found, redirect, see_other},
        page, path_param, route,
    },
    view::view,
};

use crate::{
    app::_components::{ico_check, ico_hourglass, ico_paperclip, severity_badge, status_badge},
    app::org::Org,
    auth::{capability_denied, db, require_org},
    db::now_unix,
    models::{
        ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER,
        ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, Issue, IssueComment, RESERVED_ORG_SLUG, User,
    },
    perms::perms_for_user,
    tz::{browser_tz, format_relative, format_unix_local, unix_rfc3339},
};

#[path_param]
struct IssueKey(str);

#[page]
async fn issue_detail_page(cx: &Cx) -> Result {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Err(redirect(&format!("/admin/issues/{key}")).into());
    }
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(issue) = issues.into_iter().find(|i| i.key == *key) else {
        return Err(not_found().into());
    };

    let mut comments = IssueComment::all()
        .filter(IssueComment::fields().issue_id().eq(issue.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    comments.sort_by_key(|c| c.created_at);

    let users = User::all().exec(&mut database).await.unwrap_or_default();
    let opener_name = user_display(&users, issue.opened_by_user_id);

    let tz = browser_tz(cx);
    let now = now_unix();
    let created_label = format_unix_local(issue.created_at, tz);
    let created_rfc = unix_rfc3339(issue.created_at);
    let updated_label = format_relative(issue.updated_at, now, tz);
    let updated_rfc = unix_rfc3339(issue.updated_at);
    let opener_created = format_relative(issue.created_at, now, tz);

    let list_href = format!("/{org_slug}/issues");
    let reply_action = format!("/{org_slug}/issues/{}/reply", issue.key);
    let closed = issue.status.eq_ignore_ascii_case("Closed")
        || issue.status.eq_ignore_ascii_case("Resolved");

    let timeline = build_timeline_rows(&issue, &comments, &users, now, tz);

    view! {
        <div style="max-width: 820px;">
            <a
                class="vb-back"
                href=(list_href)
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to list"
            </a>
            <div
                style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap;"
            >
                <span
                    class="vb-mono"
                    style="font-size: 13px; font-weight: 700; color: var(--accent);"
                >
                    (issue.key.clone())
                </span>
                severity_badge(severity: &issue.severity)
                status_badge(status: &issue.status)
            </div>
            <h1
                class="vb-title"
                style="font-size: 21px; margin-bottom: 16px; line-height: 1.3;"
            >
                (issue.title.clone())
            </h1>

            <div class="vb-meta-grid">
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">
                        "COMPONENT"
                    </div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        (issue.component.clone())
                    </div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">
                        "OPENED BY"
                    </div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        (opener_name.clone())
                    </div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">
                        "CREATED"
                    </div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        <time datetime=(created_rfc)>(created_label)</time>
                    </div>
                </div>
                <div>
                    <div class="vb-mono" style="font-size: 9.5px; color: #8a8f96;">
                        "UPDATED"
                    </div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        <time datetime=(updated_rfc)>(updated_label)</time>
                    </div>
                </div>
            </div>

            <div class="vb-callout">
                (ico_hourglass(cx, 16).await?)
                <span>
                    "SLA: initial analysis within 2–5 business days from the report timestamp."
                </span>
            </div>

            <div class="vb-section-label">"DISCUSSION"</div>
            <div
                style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 22px;"
            >
                <div
                    style="display: flex; flex-direction: column; align-items: flex-start;"
                >
                    <div class="vb-bubble">
                        <div
                            style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;"
                        >
                            <span style="font-size: 12.5px; font-weight: 700;">
                                (opener_name)
                            </span>
                            <span
                                class="vb-mono"
                                style="font-size: 9.5px; color: #fff; background: #5a5f66; padding: 1px 6px; border-radius: 3px;"
                            >
                                (ISSUE_ROLE_REPORTER)
                            </span>
                            <span
                                class="vb-mono"
                                style="font-size: 10px; color: #9aa0a6;"
                            >
                                (opener_created)
                            </span>
                        </div>
                        <div
                            style="font-size: 13.5px; line-height: 1.55; color: #3a3f46; white-space: pre-wrap;"
                        >
                            (issue.details.clone())
                        </div>
                    </div>
                </div>
                for row in timeline {
                    (render_timeline_row(cx, row).await?)
                }
            </div>

            if closed {
                <div
                    class="vb-panel"
                    style="background: #fafbf9; display: flex; align-items: center; justify-content: space-between; gap: 16px;"
                >
                    <div style="display: flex; align-items: center; gap: 11px;">
                        <span
                            style="width: 26px; height: 26px; flex: none; border-radius: 50%; background: #e9eaec; color: #5a5f66; display: flex; align-items: center; justify-content: center;"
                        >
                            (ico_check(cx, 13).await?)
                        </span>
                        <div
                            style="font-size: 13.5px; color: #5a5f66; line-height: 1.5;"
                        >
                            "This issue is closed. Reopen it to add a comment."
                        </div>
                    </div>
                    <span class="vb-btn outline">"Reopen issue"</span>
                </div>
            } else if perms.issues_write {
                <div class="vb-panel" style="padding: 14px;">
                    <form method="POST" action=(reply_action)>
                        <textarea
                            name="body"
                            required=""
                            placeholder="Add a reply…"
                            style="width: 100%; min-height: 76px; font-size: 14px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 12px;"
                        ></textarea>
                        <div
                            style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;"
                        >
                            <span class="vb-btn muted vb-btn-ico">
                                (ico_paperclip(cx, 13).await?)
                                <span>"Attach screenshot"</span>
                            </span>
                            <div style="display: flex; gap: 10px;">
                                <span class="vb-btn muted">"Close issue"</span>
                                <button class="vb-btn" type="submit">"Reply"</button>
                            </div>
                        </div>
                    </form>
                </div>
            }
        </div>
    }
}

#[derive(Deserialize)]
struct ReplyForm {
    body: String,
}

#[route(GET "/vauban/issues/{issue_key}")]
async fn redirect_reserved_issue_detail(cx: &Cx) -> Result {
    let key = path_param::<IssueKey>(cx);
    Err(redirect(&format!("/admin/issues/{key}")).into())
}

/// POST alias: keep `see_other` (303) so the follow-up is GET, not a re-POST.
#[route(POST "/vauban/issues/{issue_key}/reply")]
async fn redirect_reserved_issue_reply(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    Ok(see_other(&format!("/admin/issues/{key}")))
}

#[route(POST "/{org}/issues/{issue_key}/reply")]
async fn reply_issue(cx: &Cx, Form(form): Form<ReplyForm>) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(see_other(&format!("/admin/issues/{key}")));
    }
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(capability_denied().into());
    }

    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}")));
    }

    let mut database = db(cx);
    let issues = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(mut issue) = issues.into_iter().find(|i| i.key == *key) else {
        // Same 404 as missing write — do not confirm the key via redirect.
        return Err(capability_denied().into());
    };

    let closed = issue.status.eq_ignore_ascii_case("Closed")
        || issue.status.eq_ignore_ascii_case("Resolved");
    if closed {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}")));
    }

    let now = now_unix();
    let role = if perms.admin_view {
        ISSUE_ROLE_SUPPORT
    } else {
        ISSUE_ROLE_REPORTER
    };

    let _ = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: ctx.user.id,
        author_role: role.to_owned(),
        body,
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
    })
    .exec(&mut database)
    .await;

    let _ = issue.update().updated_at(now).exec(&mut database).await;

    Ok(see_other(&format!("/{org_slug}/issues/{key}")))
}

struct TimelineRow {
    kind: String,
    author_name: String,
    author_role: String,
    body: String,
    when: String,
    support_side: bool,
}

fn build_timeline_rows(
    _issue: &Issue,
    comments: &[IssueComment],
    users: &[User],
    now: i64,
    tz: chrono_tz::Tz,
) -> Vec<TimelineRow> {
    comments
        .iter()
        .map(|c| {
            let support_side = c.author_role == ISSUE_ROLE_SUPPORT;
            let author_name = if support_side {
                "Vauban Support".to_owned()
            } else if c.author_role == ISSUE_ROLE_SYSTEM {
                String::new()
            } else {
                user_display(users, c.author_user_id)
            };
            TimelineRow {
                kind: c.kind.clone(),
                author_name,
                author_role: c.author_role.clone(),
                body: c.body.clone(),
                when: format_relative(c.created_at, now, tz),
                support_side,
            }
        })
        .collect()
}

async fn render_timeline_row(cx: &Cx, row: TimelineRow) -> Result {
    if row.kind == ISSUE_COMMENT_KIND_STATUS {
        let label = format!("{} · {}", row.body, row.when);
        return view! {
            cx =>
            <div style="display: flex; align-items: center; gap: 12px; padding: 2px 0;">
                <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
                <span
                    class="vb-mono"
                    style="font-size: 11px; color: #8a8f96; white-space: nowrap;"
                >
                    (label)
                </span>
                <div style="flex: 1; height: 1px; background: #eef0ed;"></div>
            </div>
        };
    }

    let bubble_class = if row.support_side {
        "vb-bubble support"
    } else {
        "vb-bubble"
    };
    let align = if row.support_side {
        "display: flex; flex-direction: column; align-items: flex-end;"
    } else {
        "display: flex; flex-direction: column; align-items: flex-start;"
    };
    let name_style = if row.support_side {
        "font-size: 12.5px; font-weight: 700; color: var(--accent);"
    } else {
        "font-size: 12.5px; font-weight: 700;"
    };
    let badge_bg = if row.support_side {
        "font-size: 9.5px; color: #fff; background: var(--accent); padding: 1px 6px; border-radius: 3px;"
    } else {
        "font-size: 9.5px; color: #fff; background: #5a5f66; padding: 1px 6px; border-radius: 3px;"
    };

    view! {
        cx =>
        <div style=(align)>
            <div class=(bubble_class)>
                <div
                    style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;"
                >
                    <span style=(name_style)>(row.author_name)</span>
                    <span class="vb-mono" style=(badge_bg)>(row.author_role)</span>
                    <span class="vb-mono" style="font-size: 10px; color: #9aa0a6;">
                        (row.when)
                    </span>
                </div>
                <div
                    style="font-size: 13.5px; line-height: 1.55; color: #3a3f46; white-space: pre-wrap;"
                >
                    (row.body)
                </div>
            </div>
        </div>
    }
}

fn user_display(users: &[User], id: u64) -> String {
    users
        .iter()
        .find(|u| u.id == id)
        .map(|u| u.display_name.clone())
        .unwrap_or_else(|| "Unknown".to_owned())
}
