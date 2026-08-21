//! Issue detail at `/admin/issues/{issue_key}` (cross-org, staff-only).

use serde::Deserialize;
use topcoat::{
    Result,
    context::Cx,
    router::{
        content::{Form, multipart::Multipart},
        error::{SeeOther, not_found, see_other},
        href, page, path_param, query_params, route,
    },
    view::view,
};

use crate::app::admin::issues::admin_issues_page;
use crate::{
    app::_components::{ico_check, ico_hourglass, ico_paperclip, severity_badge, status_badge},
    app::{DiscussionPane, DiscussionRow, issue_discussion, shot_file_input, thumbs_for_comment},
    auth::{capability_denied, config, db, require_staff, storage},
    db::now_unix,
    docs_body::DIALECT_HINT,
    id_lookups::{orgs_by_ids, users_by_ids},
    issue_anchor::{ISSUE_REPLY_ANCHOR, with_reply_anchor},
    issue_attachments::{
        ScreenshotUpload, attach_many, issue_attachment_list_limit, list_for_issue,
        screenshot_from_part, store_screenshot_uploads,
    },
    issue_comment_edit::{COMMENT_NOT_EDITED, can_edit_support_comment},
    issue_fsm::{IssueEvent, IssueState},
    issue_notify::{NotifyEvent, drain_pending, enqueue_issue_notify},
    issue_status::{ISSUE_ERR_CONFLICT, PersistError, advance_issue_with_retry, issue_is_closed},
    models::{
        ISSUE_ATTACHMENT_OPENER_COMMENT_ID, ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_REPORTER,
        ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, Issue, IssueAttachment, IssueComment, Organization,
        User,
    },
    perms::{PermissionContext, perms_for_user},
    sql_search::escape_ilike_literal,
    tz::{browser_tz, format_relative, format_unix_local, unix_rfc3339},
};

path_param!(pub(crate) issue_key);

#[query_params]
struct AdminIssueDetailQuery {
    org: Option<String>,
    err: Option<String>,
    edit: Option<String>,
}

#[derive(Deserialize)]
struct EditCommentForm {
    comment_id: String,
    body: String,
}

#[page]
pub(crate) async fn admin_issue_detail_page(cx: &Cx) -> Result {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let detail_q = query_params::<AdminIssueDetailQuery>(cx).ok();
    let org_hint = detail_q
        .as_ref()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let flash_conflict = detail_q
        .as_ref()
        .and_then(|q| q.err.as_deref())
        .is_some_and(|e| e == ISSUE_ERR_CONFLICT);

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

    let max_att = config(cx).issues.max_attachments_per_comment.max(1);
    let attachments = list_for_issue(
        &mut database,
        issue.organization_id,
        issue.id,
        issue_attachment_list_limit(max_att),
    )
    .await
    .unwrap_or_default();
    let org_slug = org
        .map(|o| o.slug.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(org_slug_for_q);
    let opener_thumbs =
        thumbs_for_comment(org_slug, &attachments, ISSUE_ATTACHMENT_OPENER_COMMENT_ID);

    let list_href = href!(admin_issues_page).resolve(cx);
    let reply_action = admin_issue_action(cx, &issue.key, "reply", org_slug_for_q);
    let close_action = admin_issue_action(cx, &issue.key, "close", org_slug_for_q);
    let reopen_action = admin_issue_action(cx, &issue.key, "reopen", org_slug_for_q);
    let start_action = admin_issue_action(cx, &issue.key, "start-analysis", org_slug_for_q);
    let resolve_action = admin_issue_action(cx, &issue.key, "resolve", org_slug_for_q);
    let state = IssueState::try_from(issue.status.as_str()).unwrap_or(IssueState::Open);
    let is_open = state == IssueState::Open;
    let is_in_analysis = state == IssueState::InAnalysis;
    let is_resolved = state == IssueState::Resolved;
    let is_closed = state == IssueState::Closed;
    let can_write = perms.issues_write;
    let editing_id = detail_q
        .as_ref()
        .and_then(|q| q.edit.as_deref())
        .and_then(|s| s.parse::<u64>().ok());

    let mut timeline = build_discussion_rows(&comments, &users, &attachments, org_slug, now, tz);
    decorate_support_edit(
        &mut timeline,
        &comments,
        SupportEditCtx {
            cx,
            perms: &perms,
            issue_key: key,
            org_hint: org_slug_for_q,
            editing_id,
            now,
            tz,
        },
    );

    view! {
        <div class="vb-issue-pane">
            <a
                class="vb-back"
                href=(list_href)
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to list"
            </a>
            if flash_conflict {
                <div
                    class="vb-callout"
                    style="margin-bottom: 12px; border-color: #c9a227; background: #fff8e6;"
                    role="status"
                >
                    "This issue was updated by someone else. Review the current status and try again."
                </div>
            }
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
            issue_discussion(
                pane: DiscussionPane {
                    opener_name,
                    opener_role: ISSUE_ROLE_REPORTER.to_owned(),
                    opener_when: opener_created,
                    opener_body: issue.details.clone(),
                    opener_thumbs,
                    timeline,
                    has_lightbox: !attachments.is_empty(),
                }
            )
            if is_resolved {
                <div
                    class="vb-panel"
                    id=(ISSUE_REPLY_ANCHOR)
                    style="background: #fafbf9; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;"
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
                            "This issue is resolved. Close it when finished, or reopen to continue analysis."
                        </div>
                    </div>
                    if can_write {
                        <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                            <form method="POST" action=(close_action)>
                                <button class="vb-btn muted" type="submit">
                                    "Close issue"
                                </button>
                            </form>
                            <form method="POST" action=(reopen_action)>
                                <button class="vb-btn outline" type="submit">
                                    "Reopen issue"
                                </button>
                            </form>
                        </div>
                    }
                </div>
            } else if is_closed {
                <div
                    class="vb-panel"
                    id=(ISSUE_REPLY_ANCHOR)
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
                    if can_write {
                        <form method="POST" action=(reopen_action)>
                            <button class="vb-btn outline" type="submit">
                                "Reopen issue"
                            </button>
                        </form>
                    }
                </div>
            } else if can_write {
                <div class="vb-panel" style="padding: 14px;">
                    if is_open {
                        <form
                            method="POST"
                            action=(start_action)
                            style="display: none;"
                            id="issue-start-analysis"
                        ></form>
                    }
                    if is_in_analysis {
                        <form
                            method="POST"
                            action=(resolve_action)
                            style="display: none;"
                            id="issue-resolve"
                        ></form>
                    }
                    <form
                        method="POST"
                        action=(reply_action)
                        id=(ISSUE_REPLY_ANCHOR)
                        enctype="multipart/form-data"
                    >
                        <textarea
                            name="body"
                            required=""
                            placeholder="Add a support reply…"
                            style="width: 100%; min-height: 76px; font-size: 14px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 12px;"
                        ></textarea>
                        <p class="vb-form-hint">(DIALECT_HINT)</p>
                        <div class="vb-drop vb-drop-inline">
                            shot_file_input(
                                label: view! {
                                    cx =>
                                    (ico_paperclip(cx, 13).await?)
                                    <span>"Attach screenshot"</span>
                                },
                                max: max_att
                            )
                        </div>
                        <div
                            style="display: flex; justify-content: flex-end; align-items: center; flex-wrap: wrap; gap: 10px; margin-top: 12px;"
                        >
                            if is_open {
                                <button
                                    class="vb-btn outline"
                                    type="submit"
                                    form="issue-start-analysis"
                                >
                                    "Start analysis"
                                </button>
                            }
                            if is_in_analysis {
                                <button
                                    class="vb-btn outline"
                                    type="submit"
                                    form="issue-resolve"
                                >
                                    "Mark resolved"
                                </button>
                            }
                            <button class="vb-btn" type="submit">"Reply"</button>
                        </div>
                    </form>
                </div>
            }
        </div>
    }
}

struct ReplyMultipart {
    body: String,
    screenshots: Vec<ScreenshotUpload>,
}

async fn parse_admin_reply_multipart(mut multipart: Multipart) -> Result<ReplyMultipart> {
    let mut body = String::new();
    let mut screenshots = Vec::new();
    while let Some(field) = multipart.next_field().await? {
        match field.name() {
            Some("body") => body = field.text().await?,
            Some("screenshots") | Some("screenshot") | Some("image") => {
                let fname = field.file_name().unwrap_or("").to_owned();
                let ctype = field.content_type().map(|s| s.to_owned());
                let data = field.bytes().await?.to_vec();
                if let Some(shot) = screenshot_from_part(&fname, ctype.as_deref(), data) {
                    screenshots.push(shot);
                }
            }
            _ => {
                let _ = field.bytes().await?;
            }
        }
    }
    Ok(ReplyMultipart { body, screenshots })
}

#[route(POST "/admin/issues/{issue_key}/reply")]
pub(crate) async fn admin_reply_issue(cx: &Cx, multipart: Multipart) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_reply_target(cx, key, &org_hint, None);
    if !perms.issues_write {
        return Ok(see_other(detail));
    }

    let form = parse_admin_reply_multipart(multipart).await?;
    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(detail));
    }
    let max_att = config(cx).issues.max_attachments_per_comment.max(1);
    if form.screenshots.len() > max_att {
        return Ok(see_other(admin_reply_target(
            cx,
            key,
            &org_hint,
            Some("attach"),
        )));
    }

    let mut database = db(cx);
    let Some(mut issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Ok(see_other(href!(admin_issues_page).resolve(cx)));
    };

    if issue_is_closed(&issue.status) {
        return Ok(see_other(detail));
    }

    let client = storage(cx);
    let tokens = if form.screenshots.is_empty() {
        Vec::new()
    } else {
        match store_screenshot_uploads(
            &mut database,
            &client,
            issue.organization_id,
            &form.screenshots,
            max_att,
        )
        .await
        {
            Ok(t) => t,
            Err(err) => {
                crate::storage::log::portal_attach_failed("admin_reply_screenshots", &err);
                return Ok(see_other(admin_reply_target(
                    cx,
                    key,
                    &org_hint,
                    Some("attach"),
                )));
            }
        }
    };

    let now = now_unix();
    let Ok(comment) = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: staff.user.id,
        author_role: ISSUE_ROLE_SUPPORT.to_owned(),
        body,
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
        edited_at: 0,
    })
    .exec(&mut database)
    .await
    else {
        return Ok(see_other(admin_reply_target(
            cx,
            key,
            &org_hint,
            Some("reply"),
        )));
    };
    if let Err(err) = enqueue_issue_notify(
        &mut database,
        &config(cx).issues.notify,
        &issue,
        NotifyEvent::SupportComment,
        comment.id,
        staff.user.id,
    )
    .await
    {
        tracing::warn!(key = %key, error = %err, "admin comment notify enqueue failed");
    }
    drain_pending(cx).await;

    if !tokens.is_empty()
        && let Err(err) = attach_many(
            &mut database,
            issue.organization_id,
            issue.id,
            comment.id,
            staff.user.id,
            &tokens,
            max_att,
        )
        .await
    {
        tracing::warn!(key = %key, error = %err, "admin reply attach_many failed");
        return Ok(see_other(admin_reply_target(
            cx,
            key,
            &org_hint,
            Some("attach"),
        )));
    }

    let _ = issue.update().updated_at(now).exec(&mut database).await;

    Ok(see_other(detail))
}

#[route(POST "/admin/issues/{issue_key}/edit-comment")]
pub(crate) async fn admin_edit_comment(
    cx: &Cx,
    Form(form): Form<EditCommentForm>,
) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_reply_target(cx, key, &org_hint, None);
    if !perms.issues_write || !perms.admin_view {
        return Err(capability_denied().into());
    }
    let Some(comment_id) = form.comment_id.trim().parse::<u64>().ok() else {
        return Err(capability_denied().into());
    };
    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(detail));
    }

    let mut database = db(cx);
    let Some(mut issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Err(capability_denied().into());
    };
    let rows = IssueComment::all()
        .filter(IssueComment::fields().id().eq(comment_id))
        .filter(IssueComment::fields().issue_id().eq(issue.id))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default();
    let Some(mut comment) = rows.into_iter().next() else {
        return Err(capability_denied().into());
    };
    if !can_edit_support_comment(&perms, &comment.kind, &comment.author_role) {
        return Err(capability_denied().into());
    }

    let now = now_unix();
    if comment
        .update()
        .body(body)
        .edited_at(now)
        .exec(&mut database)
        .await
        .is_err()
    {
        tracing::warn!(key = %key, comment_id, "admin comment edit failed");
        return Ok(see_other(detail));
    }
    let _ = issue.update().updated_at(now).exec(&mut database).await;
    Ok(see_other(detail))
}

#[route(POST "/admin/issues/{issue_key}/close")]
pub(crate) async fn admin_close_issue(cx: &Cx) -> Result<SeeOther> {
    admin_advance_issue(cx, IssueEvent::Close).await
}

#[route(POST "/admin/issues/{issue_key}/reopen")]
pub(crate) async fn admin_reopen_issue(cx: &Cx) -> Result<SeeOther> {
    admin_advance_issue(cx, IssueEvent::Reopen).await
}

#[route(POST "/admin/issues/{issue_key}/start-analysis")]
pub(crate) async fn admin_start_analysis_issue(cx: &Cx) -> Result<SeeOther> {
    admin_advance_issue(cx, IssueEvent::StartAnalysis).await
}

#[route(POST "/admin/issues/{issue_key}/resolve")]
pub(crate) async fn admin_resolve_issue(cx: &Cx) -> Result<SeeOther> {
    admin_advance_issue(cx, IssueEvent::Resolve).await
}

async fn admin_advance_issue(cx: &Cx, event: IssueEvent) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    let staff = require_staff(cx).await?;
    let perms = perms_for_user(cx, &staff.user).await;
    let org_hint = query_params::<AdminIssueDetailQuery>(cx)
        .ok()
        .and_then(|q| q.org.clone())
        .unwrap_or_default();
    let detail = admin_reply_target(cx, key, &org_hint, None);
    if !perms.issues_write {
        return Ok(see_other(detail));
    }

    let mut database = db(cx);
    let Some(issue) = load_admin_issue_by_key(&mut database, key, &org_hint).await else {
        return Ok(see_other(href!(admin_issues_page).resolve(cx)));
    };

    match advance_issue_with_retry(
        &mut database,
        issue.id,
        event,
        staff.user.id,
        &config(cx).issues.notify,
    )
    .await
    {
        Ok((..)) => {
            drain_pending(cx).await;
            Ok(see_other(detail))
        }
        Err(PersistError::Fsm(_)) | Err(PersistError::UnknownStatus(_)) => Ok(see_other(detail)),
        Err(PersistError::Conflict) => Ok(see_other(admin_reply_target(
            cx,
            key,
            &org_hint,
            Some(ISSUE_ERR_CONFLICT),
        ))),
        Err(PersistError::Db(err)) => {
            tracing::warn!(key = %key, error = %err, "admin issue advance failed");
            Ok(see_other(detail))
        }
    }
}

fn admin_issue_action(cx: &Cx, key: &str, action: &str, org_slug: &str) -> String {
    let q = crate::app::hrefs::AdminIssueOrgQ { org: org_slug };
    match action {
        "reply" => href!(admin_reply_issue, IssueKey(key)).query(q).resolve(cx),
        "close" => href!(admin_close_issue, IssueKey(key)).query(q).resolve(cx),
        "reopen" => href!(admin_reopen_issue, IssueKey(key))
            .query(q)
            .resolve(cx),
        "start-analysis" => href!(admin_start_analysis_issue, IssueKey(key))
            .query(q)
            .resolve(cx),
        "resolve" => href!(admin_resolve_issue, IssueKey(key))
            .query(q)
            .resolve(cx),
        other => panic!("unknown admin issue action {other}"),
    }
}

/// Detail target after a reply / close / reopen, anchored on the reply box so
/// the browser lands on the newest message instead of the page header.
///
/// Any `err` code is appended to the query string, before the fragment.
fn admin_reply_target(cx: &Cx, key: &str, org_hint: &str, err: Option<&str>) -> String {
    with_reply_anchor(&admin_issue_detail_href(cx, key, org_hint, err))
}

/// Detail URL for an admin issue. Always include `?org=` when known so
/// org-scoped keys like `VBN-200` cannot open the wrong tenant's ticket.
pub(super) fn admin_issue_detail_href(
    cx: &Cx,
    key: &str,
    org_hint: &str,
    err: Option<&str>,
) -> String {
    if org_hint.is_empty() {
        href!(admin_issue_detail_page, IssueKey(key))
            .query(crate::app::hrefs::ErrQ { err })
            .resolve(cx)
    } else {
        href!(admin_issue_detail_page, IssueKey(key))
            .query(crate::app::hrefs::AdminIssueOrgQ { org: org_hint })
            .query(crate::app::hrefs::ErrQ { err })
            .resolve(cx)
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

struct SupportEditCtx<'a> {
    cx: &'a Cx,
    perms: &'a PermissionContext,
    issue_key: &'a str,
    org_hint: &'a str,
    editing_id: Option<u64>,
    now: i64,
    tz: chrono_tz::Tz,
}

fn decorate_support_edit(
    rows: &mut [DiscussionRow],
    comments: &[IssueComment],
    ctx: SupportEditCtx<'_>,
) {
    for (row, comment) in rows.iter_mut().zip(comments.iter()) {
        if comment.edited_at != COMMENT_NOT_EDITED {
            row.edited_label = format_relative(comment.edited_at, ctx.now, ctx.tz);
        }
        if !can_edit_support_comment(ctx.perms, &comment.kind, &comment.author_role) {
            continue;
        }
        row.can_edit = true;
        let detail = admin_issue_detail_href(ctx.cx, ctx.issue_key, ctx.org_hint, None);
        let edit = href!(admin_issue_detail_page, IssueKey(ctx.issue_key))
            .query(crate::app::hrefs::AdminIssueOrgQ { org: ctx.org_hint })
            .query(crate::app::hrefs::EditCommentQ { edit: comment.id })
            .resolve(ctx.cx);
        row.edit_href = format!("{edit}#comment-{}", comment.id);
        row.edit_cancel = format!("{detail}#comment-{}", comment.id);
        row.edit_action = href!(admin_edit_comment, IssueKey(ctx.issue_key))
            .query(crate::app::hrefs::AdminIssueOrgQ { org: ctx.org_hint })
            .resolve(ctx.cx);
        row.editing = ctx.editing_id == Some(comment.id);
    }
}

fn build_discussion_rows(
    comments: &[IssueComment],
    users: &[User],
    attachments: &[IssueAttachment],
    org_slug: &str,
    now: i64,
    tz: chrono_tz::Tz,
) -> Vec<DiscussionRow> {
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
            DiscussionRow {
                kind: c.kind.clone(),
                author_name,
                author_role: c.author_role.clone(),
                body: c.body.clone(),
                when: format_relative(c.created_at, now, tz),
                support_side,
                thumbs: if c.kind == ISSUE_COMMENT_KIND_COMMENT {
                    thumbs_for_comment(org_slug, attachments, c.id)
                } else {
                    Vec::new()
                },
                comment_id: c.id,
                can_edit: false,
                editing: false,
                edit_href: String::new(),
                edit_action: String::new(),
                edit_cancel: String::new(),
                edited_label: String::new(),
            }
        })
        .collect()
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
            version: 1,
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
        let cx = Cx::default();
        assert_eq!(
            href!("/admin/issues/{issue_key}", IssueKey("VBN-200"))
                .query(crate::app::hrefs::AdminIssueOrgQ {
                    org: "acme-infrastructure"
                })
                .resolve(&cx),
            "/admin/issues/VBN-200?org=acme-infrastructure"
        );
        assert_eq!(
            href!("/admin/issues/{issue_key}", IssueKey("VBN-200")).resolve(&cx),
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
