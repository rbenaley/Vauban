//! Admin compose stub at `/{org}/admin/docs/new`.

use topcoat::{
    Result,
    context::Cx,
    router::{forbidden, page, path_param},
    view::view,
};

use crate::{app::org::Org, auth::require_org, perms::perms_for_user};

#[page]
async fn admin_docs_new_page(cx: &Cx) -> Result {
    let slug = path_param::<Org>(cx);
    let ctx = require_org(cx, slug).await?;
    let perms = perms_for_user(cx, &ctx.user).await;
    if !perms.admin_view || !perms.docs_write {
        return Err(forbidden().into());
    }

    let back = format!("/{slug}/admin/docs");

    view! {
        <div style="max-width: 720px;">
            <a
                class="vb-link"
                href=(back.clone())
                style="display: inline-block; margin-bottom: 16px;"
            >
                "← Documentation editor"
            </a>
            <h1 class="vb-title">"Publish article"</h1>
            <p class="vb-lead">
                "Draft a knowledge-base article. Persist ships in a later slice."
            </p>
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="GET" action=(back.clone())>
                    <label for="title">"Title"</label>
                    <input
                        id="title"
                        name="title"
                        required=""
                        placeholder="Article title"
                    >
                    <label for="category">"Category"</label>
                    <select id="category" name="category">
                        <option>"Getting started"</option>
                        <option>"Deployment"</option>
                        <option>"Security"</option>
                        <option>"API"</option>
                        <option>"Operations"</option>
                    </select>
                    <label for="body">"Body"</label>
                    <textarea
                        id="body"
                        name="body"
                        placeholder="Markdown-style content…"
                        style="min-height: 180px;"
                    ></textarea>
                    <div style="display: flex; gap: 12px; margin-top: 18px;">
                        <button class="vb-btn" type="submit">"Publish (stub)"</button>
                        <a
                            class="vb-link"
                            href=(back)
                            style="margin: 0; align-self: center;"
                        >
                            "Cancel"
                        </a>
                    </div>
                </form>
            </div>
        </div>
    }
}
