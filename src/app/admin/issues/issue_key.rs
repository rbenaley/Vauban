//! Issue detail at `/admin/issues/{issue_key}` (cross-org, staff-only).

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{Form, SeeOther, page, path_param, query_params, route, see_other},
    view::view,
};

use crate::{
    app::_components::{ico_check, ico_hourglass, ico_paperclip, severity_badge, status_badge},
    auth::{capability_denied, db, require_staff},
    db::now_unix,
    models::{
        ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER,
        ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, Issue, IssueComment, Organization, User,
    },
    perms::perms_for_user,
    tz::{browser_tz, format_relative, format_unix_local, unix_rfc3339},
};

#[path_param]
struct IssueKey(str);

#[query_params]
struct AdminIssueDetailQuery {
    org: Option<String>,
}

#[page]
async fn admin_issue_detail_page(cx: &Cx) -> Result {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();

    let mut database = db(cx);
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let issues = Issue::all().exec(&mut database).await.unwrap_or_default();
    let Some(issue) = pick_issue_by_key(&issues, &orgs, key, &org_hint) else {
        return Err(topcoat::router::not_found().into());
    };

    let mut comments = IssueComment::all()
        .filter(IssueComment::fields().issue_id().eq(issue.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    comments.sort_by_key(|c| c.created_at);

    let users = User::all().exec(&mut database).await.unwrap_or_default();
    let opener_name = user_display(&users, issue.opened_by_user_id);
    let org_label = orgs
        .iter()
        .find(|o| o.id == issue.organization_id)
        .map(|o| format!("{} ({})", o.name, o.slug))
        .unwrap_or_else(|| format!("org#{}", issue.organization_id));

    let tz = browser_tz(cx);
    let now = now_unix();
    let created_label = format_unix_local(issue.created_at, tz);
    let created_rfc = unix_rfc3339(issue.created_at);
    let updated_label = format_relative(issue.updated_at, now, tz);
    let updated_rfc = unix_rfc3339(issue.updated_at);
    let opener_created = format_relative(issue.created_at, now, tz);

    let list_href = "/admin/issues".to_owned();
    let reply_action = format!("/admin/issues/{}/reply", issue.key);
    let closed = issue.status.eq_ignore_ascii_case("Closed")
        || issue.status.eq_ignore_ascii_case("Resolved");

    let timeline = build_timeline_rows(&comments, &users, now, tz);

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
                        "ORGANIZATION"
                    </div>
                    <div style="font-size: 13px; font-weight: 600; margin-top: 4px;">
                        (org_label)
                    </div>
                </div>
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
                            placeholder="Add a support reply…"
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

#[route(POST "/admin/issues/{issue_key}/reply")]
async fn admin_reply_issue(cx: &Cx, Form(form): Form<ReplyForm>) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_write {
        return Ok(see_other(&format!("/admin/issues/{key}")));
    }

    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(&format!("/admin/issues/{key}")));
    }

    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();

    let mut database = db(cx);
    let orgs = Organization::all()
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let issues = Issue::all().exec(&mut database).await.unwrap_or_default();
    let Some(mut issue) = pick_issue_by_key(&issues, &orgs, key, &org_hint) else {
        return Ok(see_other("/admin/issues"));
    };

    let closed = issue.status.eq_ignore_ascii_case("Closed")
        || issue.status.eq_ignore_ascii_case("Resolved");
    if closed {
        return Ok(see_other(&format!("/admin/issues/{key}")));
    }

    let now = now_unix();
    let _ = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: staff.user.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body,
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
    })
    .exec(&mut database)
    .await;

    let _ = issue.update().updated_at(now).exec(&mut database).await;

    Ok(see_other(&format!("/admin/issues/{key}")))
}

fn pick_issue_by_key(
    issues: &[Issue],
    orgs: &[Organization],
    key: &str,
    org_hint: &str,
) -> Option<Issue> {
    let matches: Vec<Issue> = issues.iter().filter(|i| i.key == key).cloned().collect();
    if matches.is_empty() {
        return None;
    }
    if !org_hint.is_empty() {
        let org_id = if let Ok(id) = org_hint.parse::<u64>() {
            orgs.iter().find(|o| o.id == id).map(|o| o.id)
        } else {
            orgs.iter()
                .find(|o| o.slug.eq_ignore_ascii_case(org_hint))
                .map(|o| o.id)
        };
        if let Some(id) = org_id {
            if let Some(issue) = matches.into_iter().find(|i| i.organization_id == id) {
                return Some(issue);
            }
            return None;
        }
    }
    matches.into_iter().next()
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
