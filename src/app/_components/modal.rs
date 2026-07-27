//! Concept article modal chrome with progressive close via Topcoat signals.

use topcoat::{
    Result,
    context::Cx,
    runtime::Event,
    view::{component, view},
};

use super::icons::ico_close;

#[component]
pub async fn article_modal_shell(
    cx: &Cx,
    title: &str,
    category: &str,
    version: &str,
    close_href: &str,
    body: Result,
) -> Result {
    let title = title.to_owned();
    let title_aria = title.clone();
    let category = category.to_owned();
    let version = version.to_owned();
    let close = close_href.to_owned();
    let close2 = close.clone();

    view! { cx =>
        signal open = true;

        <div
            class="vb-modal-root"
            role="dialog"
            aria-modal="true"
            aria-label=(title_aria)
            :style=$(if open.get() { "" } else { "display: none" })
        >
            <a
                class="vb-modal-backdrop"
                href=(close.clone())
                aria-label="Close article"
                @click=$(|e: Event| {
                    e.prevent_default();
                    open.set(false);
                })
            ></a>
            <div class="vb-modal">
                <div class="vb-modal-head">
                    <div>
                        <div class="vb-mono" style="font-size: 10px; color: var(--accent); letter-spacing: 0.06em; margin-bottom: 8px;">
                            (category)
                            " · Updated "
                            (version)
                        </div>
                        <h2 style="font-size: 23px; font-weight: 800; margin: 0; line-height: 1.25;">
                            (title)
                        </h2>
                    </div>
                    <a
                        class="vb-modal-close"
                        href=(close2)
                        aria-label="Close"
                        @click=$(|e: Event| {
                            e.prevent_default();
                            open.set(false);
                        })
                    >(ico_close(cx, 14).await?)</a>
                </div>
                <div class="vb-modal-body">
                    (body?)
                </div>
            </div>
        </div>
    }
}
