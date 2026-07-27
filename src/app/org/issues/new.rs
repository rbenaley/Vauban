//! Full-screen report form at `/{org}/issues/new`.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{app::org::Org, auth::require_org, perms::perms_for_user};

#[page]
async fn new_issue_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.issues_write {
        return Err(forbidden().into());
    }

    let list_href = format!("/{slug}/issues");
    let action = format!("/{slug}/issues");

    view! {
        <div style="max-width: 720px;">
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
                <form class="vb-form" method="POST" action=(action)>
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
                                <option value="Major" selected="">"Major"</option>
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
                                <option value="SSH Proxy" selected="">"SSH Proxy"</option>
                                <option value="RDP Gateway">"RDP Gateway"</option>
                                <option value="Control plane">"Control plane"</option>
                                <option value="Portal">"Portal"</option>
                                <option value="Other">"Other"</option>
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
                    <div class="vb-drop">
                        <span style="font-size: 22px; color: var(--accent);">
                            "⇪"
                        </span>
                        <span>"Click to upload or drop images here"</span>
                        <span
                            class="vb-mono"
                            style="font-size: 10.5px; color: #9aa0a6;"
                        >
                            "PNG, JPG, GIF · up to 10 MB each · upload stub"
                        </span>
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
    }
}
