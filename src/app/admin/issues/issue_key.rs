//! Issue detail at `/admin/issues/{issue_key}` (cross-org, staff-only).

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::Form,
        error::{SeeOther, not_found, see_other},
        page, path_param, query_params, route,
    },
    view::view,
};

use crate::{
    app::_components::{ico_check, ico_hourglass, ico_paperclip, severity_badge, status_badge},
    auth::{capability_denied, db, require_staff},
    db::now_unix,
    id_lookups::{orgs_by_ids, users_by_ids},
    issue_status::{close_issue_status, issue_is_closed, reopen_issue_status},
    models::{
        ISSUE_COMMENT_KIND_COMMENT, ISSUE_COMMENT_KIND_STATUS, ISSUE_ROLE_REPORTER,
        ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, Issue, IssueComment, Organization, User,
    },
    perms::perms_for_user,
    sql_search::escape_ilike_literal,
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
    let Some(issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Err(not_found().into());
    };

    let orgs = orgs_by_ids(&mut database, &[issue.organization_id])
        .await
        .unwrap_or_default();
    let org = orgs.iter().find(|o| o.id == issue.organization_id);
    let org_label = org
        .map(|o| format!("{} ({})", o.name, o.slug))
        .unwrap_or_else(|| format!("org#{}", issue.organization_id));
    let org_slug_for_q = org.map(|o| o.slug.as_str()).unwrap_or("");

    let mut comments = IssueComment::all()
        .filter(IssueComment::fields().issue_id().eq(issue.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    comments.sort_by_key(|c| c.created_at);

    let mut user_ids: Vec<u64> = comments.iter().map(|c| c.author_user_id).collect();
    user_ids.push(issue.opened_by_user_id);
    let users = users_by_ids(&mut database, &user_ids)
        .await
        .unwrap_or_default();
    let opener_name = user_display(&users, issue.opened_by_user_id);

    let tz = browser_tz(cx);
    let now = now_unix();
    let created_label = format_unix_local(issue.created_at, tz);
    let created_rfc = unix_rfc3339(issue.created_at);
    let updated_label = format_relative(issue.updated_at, now, tz);
    let updated_rfc = unix_rfc3339(issue.updated_at);
    let opener_created = format_relative(issue.created_at, now, tz);

    let list_href = "/admin/issues".to_owned();
    let reply_action = admin_issue_action(&issue.key, "reply", org_slug_for_q);
    let close_action = admin_issue_action(&issue.key, "close", org_slug_for_q);
    let reopen_action = admin_issue_action(&issue.key, "reopen", org_slug_for_q);
    let closed = issue_is_closed(&issue.status);

    let timeline = build_timeline_rows(&comments, &users, now, tz);

    view! {
        <div>
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
                    if perms.issues_write {
                        <form method="POST" action=(reopen_action)>
                            <button class="vb-btn outline" type="submit">
                                "Reopen issue"
                            </button>
                        </form>
                    }
                </div>
            } else if perms.issues_write {
                <div class="vb-panel" style="padding: 14px;">
                    <form method="POST" action=(reply_action) id="issue-reply">
                        <textarea
                            name="body"
                            required=""
                            placeholder="Add a support reply…"
                            style="width: 100%; min-height: 76px; font-size: 14px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 12px;"
                        ></textarea>
                    </form>
                    <div
                        style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;"
                    >
                        <span class="vb-btn muted vb-btn-ico">
                            (ico_paperclip(cx, 13).await?)
                            <span>"Attach screenshot"</span>
                        </span>
                        <div style="display: flex; gap: 10px;">
                            <form method="POST" action=(close_action)>
                                <button class="vb-btn muted" type="submit">
                                    "Close issue"
                                </button>
                            </form>
                            <button class="vb-btn" type="submit" form="issue-reply">
                                "Reply"
                            </button>
                        </div>
                    </div>
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
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_issue_detail_href(key, &org_hint);
    if !perms.issues_write {
        return Ok(see_other(&detail));
    }

    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(&detail));
    }

    let mut database = db(cx);
    let Some(mut issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Ok(see_other("/admin/issues"));
    };

    if issue_is_closed(&issue.status) {
        return Ok(see_other(&detail));
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

    Ok(see_other(&detail))
}

#[route(POST "/admin/issues/{issue_key}/close")]
async fn admin_close_issue(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_issue_detail_href(key, &org_hint);
    if !perms.issues_write {
        return Ok(see_other(&detail));
    }

    let mut database = db(cx);
    let Some(mut issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Ok(see_other("/admin/issues"));
    };

    let _ = close_issue_status(&mut database, &mut issue).await;

    Ok(see_other(&detail))
}

#[route(POST "/admin/issues/{issue_key}/reopen")]
async fn admin_reopen_issue(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_issue_detail_href(key, &org_hint);
    if !perms.issues_write {
        return Ok(see_other(&detail));
    }

    let mut database = db(cx);
    let Some(mut issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Ok(see_other("/admin/issues"));
    };

    let _ = reopen_issue_status(&mut database, &mut issue).await;

    Ok(see_other(&detail))
}

fn admin_issue_action(key: &str, action: &str, org_slug: &str) -> String {
    if org_slug.is_empty() {
        format!("/admin/issues/{key}/{action}")
    } else {
        format!("/admin/issues/{key}/{action}?org={org_slug}")
    }
}

/// Detail URL for an admin issue. Always include `?org=` when known so
/// org-scoped keys like `VBN-200` cannot open the wrong tenant's ticket.
pub(super) fn admin_issue_detail_href(key: &str, org_hint: &str) -> String {
    if org_hint.is_empty() {
        format!("/admin/issues/{key}")
    } else {
        format!("/admin/issues/{key}?org={org_hint}")
    }
}

/// Resolve `?org=` hint to an organization id (numeric id or case-insensitive slug).
async fn resolve_org_hint(db: &mut toasty::Db, org_hint: &str) -> Option<u64> {
    let raw = org_hint.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(id) = raw.parse::<u64>() {
        return Organization::all()
            .filter(Organization::fields().id().eq(id))
            .limit(1)
            .exec(db)
            .await
            .ok()?
            .into_iter()
            .next()
            .map(|o| o.id);
    }
    let pat = escape_ilike_literal(raw);
    Organization::all()
        .filter(Organization::fields().slug().ilike_with_escape(pat, '\\'))
        .limit(1)
        .exec(db)
        .await
        .ok()?
        .into_iter()
        .next()
        .map(|o| o.id)
}

/// Load a single admin issue by key, optionally disambiguated by `?org=` hint.
///
/// With a resolvable hint: filter `organization_id` (missing -> None).
/// Without a resolvable hint: return the issue only when the key is unique
/// across orgs; multiple matches -> None (fail closed, no arbitrary first).
async fn load_admin_issue_by_key(db: &mut toasty::Db, key: &str, org_hint: &str) -> Option<Issue> {
    let key_owned = key.to_owned();
    let query = Issue::all().filter(Issue::fields().key().eq(key_owned));

    if !org_hint.is_empty()
        && let Some(org_id) = resolve_org_hint(db, org_hint).await
    {
        return query
            .filter(Issue::fields().organization_id().eq(org_id))
            .limit(1)
            .exec(db)
            .await
            .unwrap_or_default()
            .into_iter()
            .next();
    }

    let rows = query.limit(2).exec(db).await.unwrap_or_default();
    if rows.len() == 1 {
        rows.into_iter().next()
    } else {
        None
    }
}

/// In-memory selection oracle kept for unit tests of key / org-hint policy.
#[cfg(test)]
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
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_org(id: u64, slug: &str) -> Organization {
        Organization {
            id,
            slug: slug.to_owned(),
            name: slug.to_owned(),
            address: String::new(),
            vat: String::new(),
            plan_label: String::new(),
            supported_builds: String::new(),
            lts_subscriptions: 0,
            industrial_lts_subscriptions: 0,
            technical_contact_name: String::new(),
            technical_contact_email: String::new(),
            status: "active".to_owned(),
        }
    }

    fn sample_issue(id: u64, key: &str, organization_id: u64) -> Issue {
        Issue {
            id,
            key: key.to_owned(),
            title: "t".to_owned(),
            component: "c".to_owned(),
            severity: "Low".to_owned(),
            status: "Open".to_owned(),
            organization_id,
            details: String::new(),
            opened_by_user_id: 1,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn pick_issue_by_key_ambiguous_without_hint_is_none() {
        let orgs = [sample_org(1, "acme"), sample_org(2, "beta")];
        let issues = [sample_issue(10, "ISS-1", 1), sample_issue(11, "ISS-1", 2)];
        assert!(pick_issue_by_key(&issues, &orgs, "ISS-1", "").is_none());
    }

    #[test]
    fn pick_issue_by_key_unique_without_hint_ok() {
        let orgs = [sample_org(1, "acme")];
        let issues = [sample_issue(10, "ISS-1", 1)];
        let picked = pick_issue_by_key(&issues, &orgs, "ISS-1", "").unwrap();
        assert_eq!(picked.id, 10);
    }

    #[test]
    fn admin_issue_detail_href_includes_org_query() {
        assert_eq!(
            admin_issue_detail_href("VBN-200", "acme-infrastructure"),
            "/admin/issues/VBN-200?org=acme-infrastructure"
        );
        assert_eq!(
            admin_issue_detail_href("VBN-200", ""),
            "/admin/issues/VBN-200"
        );
    }

    #[test]
    fn pick_issue_by_key_disambiguates_by_slug_hint() {
        let orgs = [sample_org(1, "acme"), sample_org(2, "beta")];
        let issues = [sample_issue(10, "ISS-1", 1), sample_issue(11, "ISS-1", 2)];
        let picked = pick_issue_by_key(&issues, &orgs, "ISS-1", "BETA").unwrap();
        assert_eq!(picked.id, 11);
    }

    #[test]
    fn pick_issue_by_key_resolved_org_without_issue_is_none() {
        let orgs = [sample_org(1, "acme"), sample_org(2, "beta")];
        let issues = [sample_issue(10, "ISS-1", 1)];
        assert!(pick_issue_by_key(&issues, &orgs, "ISS-1", "beta").is_none());
    }

    #[test]
    fn pick_issue_by_key_unresolvable_hint_falls_through() {
        let orgs = [sample_org(1, "acme")];
        let issues = [sample_issue(10, "ISS-1", 1)];
        let picked = pick_issue_by_key(&issues, &orgs, "ISS-1", "missing").unwrap();
        assert_eq!(picked.id, 10);
    }
}
