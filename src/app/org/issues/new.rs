//! Full-screen report form at `/{org}/issues/new`.

use topcoat::{
    Result,
    context::Cx,
    router::{error::redirect, href, page, path_param, route},
    view::{View, view},
};

use crate::app::admin::issues::admin_issues_page;
use crate::{
    app::org::Org,
    app::shot_file_input,
    auth::{capability_denied, config, require_org},
    issue_component::{DEFAULT_ISSUE_COMPONENT, ISSUE_COMPONENTS},
    models::RESERVED_ORG_SLUG,
    perms::perms_for_user,
};

#[route(GET "/vauban/issues/new")]
pub(crate) async fn redirect_reserved_issues_new(cx: &Cx) -> Result<()> {
    Err(redirect(href!(admin_issues_page).resolve(cx)).into())
}

#[page]
pub(crate) async fn new_issue_page(cx: &Cx) -> Result<impl View> {
    let slug = path_param::<Org>(cx);
    if slug.eq_ignore_ascii_case(RESERVED_ORG_SLUG) {
        return Err(redirect(href!(admin_issues_page).resolve(cx)).into());
    }
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(capability_denied().into());
    }

    let list_href = href!(crate::app::org::issues::issues_page, Org(slug)).resolve(cx);
    let action = href!(crate::app::org::issues::report_issue, Org(slug)).resolve(cx);
    let max_att = config(cx).issues.max_attachments_per_comment.max(1);

    Ok(view! {
        <div>
            <a
                class="vb-back"
                href=(list_href.clone())
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to list"
            </a>
            <h1 class="vb-title">"Report an issue"</h1>
            <p class="vb-lead">
                "Describe the issue. Our team acknowledges receipt and begins analysis within 2–5 business days."
            </p>

            <div class="vb-panel" style="padding: 24px;">
                <form
                    class="vb-form"
                    method="POST"
                    action=(action)
                    enctype="multipart/form-data"
                >
                    <label
                        for="title"
                        class="vb-mono"
                        style="letter-spacing: 0.04em; font-size: 11px;"
                    >
                        "TITLE *"
                    </label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        maxlength="200"
                        placeholder="Short, precise summary of the issue"
                    >

                    <div
                        style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;"
                    >
                        <div>
                            <label
                                for="severity"
                                class="vb-mono"
                                style="letter-spacing: 0.04em; font-size: 11px;"
                            >
                                "SEVERITY"
                            </label>
                            <select id="severity" name="severity">
                                <option value="Minor">"Minor"</option>
                                <option value="Major" selected=(true)>"Major"</option>
                                <option value="Critical">"Critical"</option>
                            </select>
                        </div>
                        <div>
                            <label
                                for="component"
                                class="vb-mono"
                                style="letter-spacing: 0.04em; font-size: 11px;"
                            >
                                "COMPONENT"
                            </label>
                            <select id="component" name="component">
                                for label in ISSUE_COMPONENTS {
                                    let value = (*label).to_owned();
                                    let selected = *label == DEFAULT_ISSUE_COMPONENT;
                                    <option value=(value.clone()) selected=(selected)>
                                        (value)
                                    </option>
                                }
                            </select>
                        </div>
                    </div>

                    <label
                        for="details"
                        class="vb-mono"
                        style="letter-spacing: 0.04em; font-size: 11px;"
                    >
                        "DESCRIPTION *"
                    </label>
                    <textarea
                        id="details"
                        name="details"
                        required=""
                        placeholder="Steps to reproduce, expected vs. observed behavior, affected version, logs…"
                        style="min-height: 140px;"
                    ></textarea>

                    <label
                        class="vb-mono"
                        style="letter-spacing: 0.04em; font-size: 11px; margin-top: 18px;"
                    >
                        "SCREENSHOTS"
                    </label>
                    <div class="vb-drop" style="display: block;">
                        shot_file_input(
                            label: view! {
                                cx =>
                                <span style="font-size: 22px; color: var(--accent);">
                                    "⇪"
                                </span>
                                <span>"Click to choose images"</span>
                            },
                            max: max_att
                        )
                    </div>

                    <div
                        style="display: flex; align-items: center; gap: 12px; margin-top: 20px;"
                    >
                        <button class="vb-btn" type="submit">"Submit report"</button>
                        <a class="vb-link" href=(list_href) style="margin: 0;">
                            "Cancel"
                        </a>
                        <span
                            class="vb-mono"
                            style="font-size: 11px; color: #9aa0a6; margin-left: auto;"
                        >
                            "* required fields"
                        </span>
                    </div>
                </form>
            </div>
        </div>
    })
}
