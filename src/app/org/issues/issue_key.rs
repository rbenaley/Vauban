//! Issue detail at `/{org}/issues/{issue_key}`.

use topcoat::{
    Result,
    context::Cx,
    router::{
        content::multipart::Multipart,
        error::{SeeOther, not_found, redirect, see_other},
        page, path_param, route,
    },
    view::view,
};

use crate::{
    app::_components::{ico_check, ico_hourglass, ico_paperclip, severity_badge, status_badge},
    app::org::Org,
    app::{DiscussionPane, DiscussionRow, issue_discussion, shot_file_input, thumbs_for_comment},
    auth::{capability_denied, config, db, require_org, storage},
    db::now_unix,
    issue_attachments::{
        ScreenshotUpload, attach_many, issue_attachment_list_limit, list_for_issue,
        screenshot_from_part, store_screenshot_uploads,
    },
    issue_status::{close_issue_status, issue_is_closed, reopen_issue_status},
    models::{
        ISSUE_ATTACHMENT_OPENER_COMMENT_ID, ISSUE_COMMENT_KIND_COMMENT, ISSUE_ROLE_REPORTER,
        ISSUE_ROLE_SUPPORT, ISSUE_ROLE_SYSTEM, Issue, IssueAttachment, IssueComment,
        RESERVED_ORG_SLUG, User,
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
        return Err(redirect(&format!("/admin/issues/{key}?org={RESERVED_ORG_SLUG}")).into());
    }
    let ctx = require_org(cx, org_slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_read {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let key_owned = key.to_owned();
    let issue = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .filter(Issue::fields().key().eq(key_owned))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    let Some(issue) = issue else {
        return Err(not_found().into());
    };

    let mut comments = IssueComment::all()
        .filter(IssueComment::fields().issue_id().eq(issue.id))
        .exec(&mut database)
        .await
        .unwrap_or_default();
    comments.sort_by_key(|c| c.created_at);

    let mut user_ids: Vec<u64> = comments.iter().map(|c| c.author_user_id).collect();
    user_ids.push(issue.opened_by_user_id);
    let users = crate::id_lookups::users_by_ids(&mut database, &user_ids)
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
        ctx.org.id,
        issue.id,
        issue_attachment_list_limit(max_att),
    )
    .await
    .unwrap_or_default();
    let opener_thumbs =
        thumbs_for_comment(org_slug, &attachments, ISSUE_ATTACHMENT_OPENER_COMMENT_ID);

    let list_href = format!("/{org_slug}/issues");
    let reply_action = format!("/{org_slug}/issues/{}/reply", issue.key);
    let close_action = format!("/{org_slug}/issues/{}/close", issue.key);
    let reopen_action = format!("/{org_slug}/issues/{}/reopen", issue.key);
    let closed = issue_is_closed(&issue.status);

    let timeline = build_discussion_rows(&comments, &users, &attachments, org_slug, now, tz);
    view! {
        <div class="vb-issue-pane">
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
                    <form
                        method="POST"
                        action=(close_action)
                        id="issue-close"
                        style="display: none;"
                    ></form>
                    <form
                        method="POST"
                        action=(reply_action)
                        id="issue-reply"
                        enctype="multipart/form-data"
                    >
                        <textarea
                            name="body"
                            required=""
                            placeholder="Add a reply…"
                            style="width: 100%; min-height: 76px; font-size: 14px; padding: 10px 12px; border: 1px solid #e0e2de; border-radius: 4px; background: #fbfcfb; resize: vertical; font-family: 'Hanken Grotesk', sans-serif; line-height: 1.5; margin-bottom: 12px;"
                        ></textarea>
                        shot_file_input(
                            label: view! {
                                cx =>
                                (ico_paperclip(cx, 13).await?)
                                <span>"Attach screenshot"</span>
                            },
                            max: max_att
                        )
                        <div
                            style="display: flex; justify-content: flex-end; align-items: center; flex-wrap: wrap; gap: 10px; margin-top: 12px;"
                        >
                            <button
                                class="vb-btn muted"
                                type="submit"
                                form="issue-close"
                            >
                                "Close issue"
                            </button>
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

async fn parse_reply_multipart(mut multipart: Multipart) -> Result<ReplyMultipart> {
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

#[route(GET "/vauban/issues/{issue_key}")]
async fn redirect_reserved_issue_detail(cx: &Cx) -> Result {
    let key = path_param::<IssueKey>(cx);
    Err(redirect(&format!("/admin/issues/{key}?org={RESERVED_ORG_SLUG}")).into())
}

/// POST alias: keep `see_other` (303) so the follow-up is GET, not a re-POST.
#[route(POST "/vauban/issues/{issue_key}/reply")]
async fn redirect_reserved_issue_reply(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    Ok(see_other(&format!(
        "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
    )))
}

#[route(POST "/vauban/issues/{issue_key}/close")]
async fn redirect_reserved_issue_close(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    Ok(see_other(&format!(
        "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
    )))
}

#[route(POST "/vauban/issues/{issue_key}/reopen")]
async fn redirect_reserved_issue_reopen(cx: &Cx) -> Result<SeeOther> {
    let key = path_param::<IssueKey>(cx);
    Ok(see_other(&format!(
        "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
    )))
}

#[route(POST "/{org}/issues/{issue_key}/reply")]
async fn reply_issue(cx: &Cx, multipart: Multipart) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(see_other(&format!(
            "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
        )));
    }
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(capability_denied().into());
    }

    let form = parse_reply_multipart(multipart).await?;
    let body = form.body.trim().to_owned();
    if body.is_empty() {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}")));
    }
    let max_att = config(cx).issues.max_attachments_per_comment.max(1);
    if form.screenshots.len() > max_att {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}?err=attach")));
    }

    let mut database = db(cx);
    let key_owned = key.to_owned();
    let issue = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .filter(Issue::fields().key().eq(key_owned))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    let Some(mut issue) = issue else {
        // Same 404 as missing write — do not confirm the key via redirect.
        return Err(capability_denied().into());
    };

    if issue_is_closed(&issue.status) {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}")));
    }

    let client = storage(cx);
    let tokens = if form.screenshots.is_empty() {
        Vec::new()
    } else {
        match store_screenshot_uploads(
            &mut database,
            &client,
            ctx.org.id,
            &form.screenshots,
            max_att,
        )
        .await
        {
            Ok(t) => t,
            Err(_) => {
                return Ok(see_other(&format!("/{org_slug}/issues/{key}?err=attach")));
            }
        }
    };

    let now = now_unix();
    let role = if perms.admin_view {
        ISSUE_ROLE_SUPPORT
    } else {
        ISSUE_ROLE_REPORTER
    };

    let Ok(comment) = toasty::create!(IssueComment {
        issue_id: issue.id,
        author_user_id: ctx.user.id,
        author_role: role.to_owned(),
        body,
        kind: ISSUE_COMMENT_KIND_COMMENT.to_owned(),
        created_at: now,
    })
    .exec(&mut database)
    .await
    else {
        return Ok(see_other(&format!("/{org_slug}/issues/{key}?err=reply")));
    };

    if !tokens.is_empty()
        && let Err(err) = attach_many(
            &mut database,
            ctx.org.id,
            issue.id,
            comment.id,
            ctx.user.id,
            &tokens,
            max_att,
        )
        .await
    {
        tracing::warn!(
            org = %org_slug,
            key = %key,
            error = %err,
            "issue reply attach_many failed"
        );
        return Ok(see_other(&format!("/{org_slug}/issues/{key}?err=attach")));
    }

    let _ = issue.update().updated_at(now).exec(&mut database).await;

    Ok(see_other(&format!("/{org_slug}/issues/{key}")))
}

#[route(POST "/{org}/issues/{issue_key}/close")]
async fn close_issue(cx: &Cx) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(see_other(&format!(
            "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
        )));
    }
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let key_owned = key.to_owned();
    let issue = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .filter(Issue::fields().key().eq(key_owned))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    let Some(mut issue) = issue else {
        return Err(capability_denied().into());
    };

    let _ = close_issue_status(&mut database, &mut issue).await;

    Ok(see_other(&format!("/{org_slug}/issues/{key}")))
}

#[route(POST "/{org}/issues/{issue_key}/reopen")]
async fn reopen_issue(cx: &Cx) -> Result<SeeOther> {
    let org_slug = path_param::<Org>(cx);
    let key = path_param::<IssueKey>(cx);
    if org_slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Ok(see_other(&format!(
            "/admin/issues/{key}?org={RESERVED_ORG_SLUG}"
        )));
    }
    let ctx = require_org(cx, org_slug).await.map_err(|_| not_found())?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(capability_denied().into());
    }

    let mut database = db(cx);
    let key_owned = key.to_owned();
    let issue = Issue::all()
        .filter(Issue::fields().organization_id().eq(ctx.org.id))
        .filter(Issue::fields().key().eq(key_owned))
        .limit(1)
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .next();
    let Some(mut issue) = issue else {
        return Err(capability_denied().into());
    };

    let _ = reopen_issue_status(&mut database, &mut issue).await;

    Ok(see_other(&format!("/{org_slug}/issues/{key}")))
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
