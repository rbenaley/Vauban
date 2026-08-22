//! Server-rendered transactional mail bodies (`view!`, auto-escaped).
//!
//! `email/*.html` stay visual fixtures for operators; MIME HTML comes from here.

use topcoat::{
    Result,
    context::Cx,
    view::{component, view},
};

use crate::mail_templates::IssueMailVars;

#[component]
async fn brand_header(cx: &Cx) -> Result {
    view! {
        cx =>
        <tr>
            <td style="padding:26px 40px 22px 40px; border-bottom:1px solid #e2e2de;">
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                    <tr>
                        <td width="54" style="width:54px; vertical-align:middle;">
                            <img
                                src="cid:vauban-logo"
                                width="48"
                                height="48"
                                alt="Vauban"
                                style="display:block; width:48px; height:48px; border:0; outline:none; text-decoration:none;"
                            >
                        </td>
                        <td style="vertical-align:middle; padding-left:14px;">
                            <div style="font-family:'Courier New',Courier,monospace; font-size:19px; font-weight:bold; letter-spacing:3px; color:#16202c; line-height:22px;">
                                "VAUBAN"
                            </div>
                            <div style="font-family:Arial,Helvetica,sans-serif; font-size:11px; letter-spacing:1px; color:#6b7684; line-height:16px; padding-top:3px;">
                                "Customer Portal"
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    }
}

#[component]
async fn brand_footer(cx: &Cx, from_address: &str) -> Result {
    let from = from_address.to_owned();
    view! {
        cx =>
        <tr>
            <td style="padding:22px 40px 34px 40px; font-family:Arial,Helvetica,sans-serif; font-size:12px; line-height:19px; color:#8a9099;">
                "Sent by Vauban Customer Portal · "
                (from)
                <br>
                "This is an automated message — replies are not monitored."
            </td>
        </tr>
    }
}

#[component]
async fn brand_tagline(cx: &Cx) -> Result {
    view! {
        cx =>
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px; max-width:600px;">
            <tr>
                <td align="center" style="padding:18px 20px 0 20px; font-family:Arial,Helvetica,sans-serif; font-size:11px; line-height:17px; color:#9aa1a8;">
                    "Vauban — open source security bastion for critical infrastructure"
                </td>
            </tr>
        </table>
    }
}

#[component]
async fn copy_url_box(cx: &Cx, url: &str) -> Result {
    let href = url.to_owned();
    let label = url.to_owned();
    view! {
        cx =>
        <tr>
            <td style="padding:26px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:12px; line-height:19px; color:#6b7684;">
                "If the button does not work, copy this address into your browser:"
            </td>
        </tr>
        <tr>
            <td style="padding:10px 40px 0 40px;">
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="width:100%;">
                    <tr>
                        <td bgcolor="#f7f6f2" style="background-color:#f7f6f2; border:1px solid #e6e4dd; border-radius:6px; padding:12px 14px; font-family:'Courier New',Courier,monospace; font-size:11px; line-height:17px; color:#4a4f55; word-break:break-all;">
                            <a href=(href) style="color:#b07f2e; text-decoration:none; word-break:break-all;">
                                (label)
                            </a>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    }
}

/// Sign-in magic link body.
#[component]
pub async fn login_mail_html(
    cx: &Cx,
    magic_url: &str,
    from_address: &str,
    ttl_minutes: u64,
) -> Result {
    let url = magic_url.to_owned();
    let ttl = format!("{ttl_minutes} minutes");
    view! {
        cx =>
        <html lang="en">
            <body style="margin:0; padding:0; background-color:#f2f1ee;">
                <span style="display:none; font-size:1px; color:#f2f1ee; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
                    "Your sign-in link for the Vauban Customer Portal. Expires in "
                    (ttl.clone())
                    ", single use."
                </span>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f2f1ee;">
                    <tr>
                        <td align="center" style="padding:32px 12px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px; max-width:600px; background-color:#ffffff; border:1px solid #e2e2de;">
                                brand_header()
                                <tr>
                                    <td style="padding:38px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:27px; line-height:34px; font-weight:bold; color:#16202c;">
                                        "Sign in to Vauban Customer Portal"
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:18px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        "Use the link below to sign in to the Vauban Customer Portal."
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:28px 40px 0 40px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td bgcolor="#16202c" style="background-color:#16202c; border-radius:6px;">
                                                    <a href=(url.clone()) style="display:block; padding:15px 30px; font-family:Arial,Helvetica,sans-serif; font-size:15px; font-weight:bold; line-height:18px; color:#ffffff; text-decoration:none;">
                                                        "Sign in to the portal"
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:26px 40px 0 40px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="width:100%;">
                                            <tr>
                                                <td bgcolor="#fdf9f0" style="background-color:#fdf9f0; border:1px solid #e0c68c; border-radius:6px; padding:14px 16px; font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:20px; color:#6f5417;">
                                                    "This link expires in "
                                                    <strong style="color:#5c460f;">(ttl)</strong>
                                                    " and can be used only once."
                                                    <br>
                                                    "If you did not request this, you can ignore this email."
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                copy_url_box(url: &url)
                                brand_footer(from_address: from_address)
                            </table>
                            brand_tagline()
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    }
}

/// Company invitation body.
#[component]
pub async fn join_mail_html(
    cx: &Cx,
    org_name: &str,
    magic_url: &str,
    from_address: &str,
    ttl_minutes: u64,
) -> Result {
    let org = org_name.to_owned();
    let url = magic_url.to_owned();
    let ttl = format!("{ttl_minutes} minutes");
    view! {
        cx =>
        <html lang="en">
            <body style="margin:0; padding:0; background-color:#f2f1ee;">
                <span style="display:none; font-size:1px; color:#f2f1ee; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
                    "You have been invited to the Vauban Customer Portal for "
                    (org.clone())
                    ". Sign-in link inside."
                </span>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f2f1ee;">
                    <tr>
                        <td align="center" style="padding:32px 12px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px; max-width:600px; background-color:#ffffff; border:1px solid #e2e2de;">
                                brand_header()
                                <tr>
                                    <td style="padding:38px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:27px; line-height:34px; font-weight:bold; color:#16202c;">
                                        "Invitation to "
                                        (org.clone())
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:18px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        "You have been invited to the Vauban Customer Portal for "
                                        (org)
                                        "."
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:28px 40px 0 40px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td bgcolor="#16202c" style="background-color:#16202c; border-radius:6px;">
                                                    <a href=(url.clone()) style="display:block; padding:15px 30px; font-family:Arial,Helvetica,sans-serif; font-size:15px; font-weight:bold; line-height:18px; color:#ffffff; text-decoration:none;">
                                                        "Sign in to the portal"
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:26px 40px 0 40px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="width:100%;">
                                            <tr>
                                                <td bgcolor="#fdf9f0" style="background-color:#fdf9f0; border:1px solid #e0c68c; border-radius:6px; padding:14px 16px; font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:20px; color:#6f5417;">
                                                    "This link expires in "
                                                    <strong style="color:#5c460f;">(ttl)</strong>
                                                    " and can be used only once."
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                copy_url_box(url: &url)
                                brand_footer(from_address: from_address)
                            </table>
                            brand_tagline()
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    }
}

/// Access-revoked body.
#[component]
pub async fn leave_mail_html(cx: &Cx, org_name: &str, from_address: &str) -> Result {
    let org = org_name.to_owned();
    view! {
        cx =>
        <html lang="en">
            <body style="margin:0; padding:0; background-color:#f2f1ee;">
                <span style="display:none; font-size:1px; color:#f2f1ee; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
                    "Your access to the Vauban Customer Portal for "
                    (org.clone())
                    " has been removed."
                </span>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f2f1ee;">
                    <tr>
                        <td align="center" style="padding:32px 12px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px; max-width:600px; background-color:#ffffff; border:1px solid #e2e2de;">
                                brand_header()
                                <tr>
                                    <td style="padding:38px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:27px; line-height:34px; font-weight:bold; color:#16202c;">
                                        "Access removed — "
                                        (org.clone())
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:18px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        "Your access to the Vauban Customer Portal for "
                                        (org)
                                        " has been removed."
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:18px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        "If you believe this is a mistake, contact your administrator."
                                    </td>
                                </tr>
                                brand_footer(from_address: from_address)
                            </table>
                            brand_tagline()
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    }
}

/// Issue create / comment / status body.
#[component]
pub async fn issue_mail_html(cx: &Cx, vars: IssueMailVars<'_>) -> Result {
    let org = vars.org_name.to_owned();
    let key = vars.issue_key.to_owned();
    let title = vars.issue_title.to_owned();
    let label = vars.event_label.to_owned();
    let excerpt = vars.excerpt.to_owned();
    let url = vars.issue_url.to_owned();
    view! {
        cx =>
        <html lang="en">
            <body style="margin:0; padding:0; background-color:#f2f1ee;">
                <span style="display:none; font-size:1px; color:#f2f1ee; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">
                    (label.clone())
                    " on "
                    (key.clone())
                    " ("
                    (org.clone())
                    ")."
                </span>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f2f1ee;">
                    <tr>
                        <td align="center" style="padding:32px 12px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px; max-width:600px; background-color:#ffffff; border:1px solid #e2e2de;">
                                brand_header()
                                <tr>
                                    <td style="padding:38px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:27px; line-height:34px; font-weight:bold; color:#16202c;">
                                        (label)
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:18px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        <strong>(key)</strong>
                                        " — "
                                        (title)
                                        <br>
                                        (org)
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:22px 40px 0 40px; font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:24px; color:#4a4f55;">
                                        (excerpt)
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:28px 40px 0 40px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td bgcolor="#16202c" style="background-color:#16202c; border-radius:6px;">
                                                    <a href=(url.clone()) style="display:block; padding:15px 30px; font-family:Arial,Helvetica,sans-serif; font-size:15px; font-weight:bold; line-height:18px; color:#ffffff; text-decoration:none;">
                                                        "Open the issue"
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                copy_url_box(url: &url)
                                brand_footer(from_address: vars.from_address)
                            </table>
                            brand_tagline()
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    }
}
