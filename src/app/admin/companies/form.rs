//! Shared company compose form (new + edit), email-only accounts.

use topcoat::{
    Result,
    context::Cx,
    router::{IntoResponse, Response},
    view::view,
};

use crate::companies_accounts::ensure_email_rows;

use super::super::render_admin_page;

pub struct CompanyFormView {
    pub action: String,
    pub title: String,
    pub submit_label: String,
    pub name: String,
    pub contact: String,
    pub vat: String,
    pub address: String,
    pub emails: Vec<String>,
    pub max_accounts: usize,
    pub error: Option<String>,
}

/// Form body only (for `#[page]` GET handlers that already wrap layouts).
pub async fn render_company_form(cx: &Cx, state: CompanyFormView) -> Result {
    let max = state.max_accounts;
    let max_label = max.to_string();
    let emails = ensure_email_rows(&state.emails, max);
    let can_add_row = emails.len() < max;
    let rows_label = emails.len().to_string();

    view! {
        cx =>
        <div>
            <a
                class="vb-back"
                href="/admin/companies"
                style="margin-bottom: 16px; margin-top: 0;"
            >
                "Back to companies"
            </a>
            <h1 class="vb-title">(state.title.clone())</h1>
            <p class="vb-lead">
                "Seat limit: "
                (max_label.clone())
                " user accounts per company."
            </p>
            if let Some(err) = state.error.clone() {
                <p style="color: #b5403a; margin-bottom: 14px;">(err)</p>
            }
            <div class="vb-panel" style="padding: 24px;">
                <form class="vb-form" method="POST" action=(state.action.clone())>
                    <input type="hidden" name="account_rows" value=(rows_label)>
                    <label for="name">"Company name *"</label>
                    <input id="name" name="name" required="" value=(state.name.clone())>
                    <label for="contact">"Contact point"</label>
                    <input id="contact" name="contact" value=(state.contact.clone())>
                    <label for="vat">"VAT number"</label>
                    <input id="vat" name="vat" value=(state.vat.clone())>
                    <label for="address">"Company address"</label>
                    <textarea id="address" name="address">
                        (state.address.clone())
                    </textarea>

                    <div
                        style="display: flex; justify-content: space-between; align-items: center; margin: 22px 0 12px; gap: 12px; flex-wrap: wrap;"
                    >
                        <div
                            class="vb-mono"
                            style="font-size: 11px; letter-spacing: 0.08em; color: #8a8f96;"
                        >
                            "USER ACCOUNTS · max "
                            (max_label)
                        </div>
                        if can_add_row {
                            <button
                                class="vb-btn outline compact"
                                type="submit"
                                name="compose_action"
                                value="add_row"
                            >
                                "+ Add account"
                            </button>
                        }
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        for (idx, email) in emails.iter().enumerate() {
                            let field = format!("email_{idx}");
                            let remove_val = format!("remove:{idx}");
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <input
                                    name=(field)
                                    type="email"
                                    placeholder="user@example.com"
                                    value=(email.clone())
                                    style="flex: 1; margin: 0;"
                                >
                                if emails.len() > 1 {
                                    <button
                                        class="vb-btn muted compact"
                                        type="submit"
                                        name="compose_action"
                                        value=(remove_val)
                                        aria-label="Remove account"
                                    >
                                        "Remove"
                                    </button>
                                }
                            </div>
                        }
                    </div>

                    <div style="display: flex; gap: 12px; margin-top: 22px;">
                        <button
                            class="vb-btn"
                            type="submit"
                            name="compose_action"
                            value="save"
                        >
                            (state.submit_label.clone())
                        </button>
                        <a
                            class="vb-link"
                            href="/admin/companies"
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

/// POST compose / validation re-render with root + admin shell (CSS + rail).
pub async fn company_form_response(cx: &Cx, state: CompanyFormView) -> Result<Response> {
    let body = render_company_form(cx, state).await?;
    render_admin_page(cx, Ok(body)).await?.into_response(cx)
}
