use std::sync::Arc;

use topcoat::{
    Result,
    context::{Cx, app_context},
    mail::Mailbox,
    router::{
        error::{SeeOther, redirect, see_other},
        layout, page, query_params, route,
    },
    runtime::{Event, procedure},
    session,
    view::{component, view},
};

use crate::{
    app::root_layout,
    auth::{
        PostAuthLanding, client_orgs_for_user, current_user, db, delete_session_hash,
        persist_session, post_auth_landing,
    },
    config::Config,
    login_limit::LoginRateLimiter,
    magic_link::{active_user_by_email, consume_token, ensure_vcp_admin_user, issue_token},
    mail_circuit::MailCircuitBreaker,
    mailer::send_login_magic_link,
    models::{PORTAL_ROLE_ADMIN, RESERVED_ORG_SLUG},
};

/// Split a TTL into `(minutes, seconds)` for MM:SS display seeds.
pub(crate) fn cooldown_mm_ss(total_secs: u64) -> (u64, u64) {
    (total_secs / 60, total_secs % 60)
}

/// Query flag for a failed magic-link consume (generic; no cause oracle).
pub(crate) const LOGIN_LINK_ERROR: &str = "link";

/// Shared copy for expired / used / unknown magic links.
pub(crate) const LOGIN_LINK_ERROR_MESSAGE: &str =
    "This sign-in link is invalid or has expired. Request a new one.";

/// Shared copy when the mail circuit is open (no account-existence oracle).
pub(crate) const LOGIN_UNAVAILABLE_MESSAGE: &str =
    "Sign-in is temporarily unavailable. Please try again later.";

fn see_other_login_link_error() -> SeeOther {
    see_other(&format!("/login?error={LOGIN_LINK_ERROR}"))
}

#[query_params]
struct LoginQuery {
    error: Option<String>,
}

/// Shared splash chrome for `/login/*` layout and absolute routes like `/choose-org`.
#[component]
async fn login_splash(cx: &Cx, body: Result) -> Result {
    view! {
        cx =>
        <div class="vb-login-body">
            <div class="vb-login-wrap">
                <div class="vb-login-brand">
                    <svg
                        width="120"
                        height="120"
                        viewBox="0 0 100 100"
                        fill="none"
                        aria-hidden="true"
                    >
                        <polygon
                            points="50,4 65,24.02 89.84,27 80,50 89.84,73 65,75.98 50,96 35,75.98 10.16,73 20,50 10.16,27 35,24.02"
                            stroke="#3ec2ad"
                            stroke-width="4"
                            stroke-linejoin="round"
                        ></polygon>
                        <circle cx="50" cy="50" r="9" stroke="#3ec2ad" stroke-width="4"></circle>
                    </svg>
                    <h1>"VAUBAN"</h1>
                    <p>"CUSTOMER PORTAL"</p>
                </div>
                <div class="vb-login-panel">(body?)</div>
            </div>
        </div>
    }
}

#[layout]
async fn login_layout(cx: &Cx, slot: Result) -> Result {
    view! { cx => login_splash(body: slot) }
}

/// Request (or re-request) a sign-in magic link.
///
/// Returns `true` when the client should show Check-your-email (anti-enumeration
/// for unknown / locked emails and for per-request SMTP failures). Returns
/// `false` only when the mail circuit is open — same unavailable UX for all
/// addresses so outages do not leak account existence.
#[procedure]
async fn request_login_link(cx: &Cx, email: String) -> Result<bool> {
    let cfg = app_context::<Arc<Config>>(cx);
    let limiter = app_context::<Arc<LoginRateLimiter>>(cx);
    let mail_circuit = app_context::<Arc<MailCircuitBreaker>>(cx);

    if !mail_circuit.allow_attempt() {
        return Ok(false);
    }

    let email = email.trim().to_ascii_lowercase();
    let email_ok = Mailbox::new(&email).is_ok();
    let allowed = limiter.allow(&email);

    if email_ok && allowed {
        let mut database = db(cx);
        let admin_email = cfg.magiclinks.vcp_admin_email();
        let user = if email == admin_email {
            ensure_vcp_admin_user(&mut database, &email).await.ok()
        } else {
            active_user_by_email(&mut database, &email)
                .await
                .ok()
                .flatten()
        };

        if let Some(user) = user {
            match issue_token(&mut database, user.id, cfg.magiclinks.token_ttl_secs).await {
                Ok(raw) => {
                    // SMTP err: mailer trips the circuit + logs; keep
                    // Check-your-email for this request (no oracle).
                    if send_login_magic_link(
                        cx,
                        &cfg.magiclinks,
                        cfg.primary_public_origin(),
                        &user.email,
                        &raw,
                    )
                    .await
                    .is_ok()
                    {
                        limiter.clear(&email);
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to issue magic link token");
                }
            }
        } else if allowed {
            // Unknown / deleted: count as a failed attempt without revealing which.
            limiter.record_failure(&email);
        }
    } else if email_ok && !allowed {
        // Locked out: still present the same check-email UX.
    } else if allowed {
        limiter.record_failure(&email);
    }

    Ok(true)
}

#[page]
async fn login_page(cx: &Cx) -> Result {
    // Valid session: skip the login form and land on the portal home / picker.
    if let Some(user) = current_user(cx).await {
        match post_auth_landing(cx, user).await? {
            PostAuthLanding::Org(slug) => {
                return Err(redirect(&format!("/{slug}")).into());
            }
            PostAuthLanding::ChooseOrg => {
                return Err(redirect("/choose-org").into());
            }
            PostAuthLanding::None => {}
        }
    }

    let cfg = app_context::<Arc<Config>>(cx);
    let ttl_secs = cfg.magiclinks.token_ttl_secs;
    let (ttl_m, ttl_s) = cooldown_mm_ss(ttl_secs);
    let ttl_remaining = ttl_secs as f64;
    let ttl_mins = ttl_m as f64;
    let ttl_secs_part = ttl_s as f64;
    let show_link_error = query_params::<LoginQuery>(cx)
        .ok()
        .as_ref()
        .and_then(|q| q.error.as_deref())
        .is_some_and(|e| e == LOGIN_LINK_ERROR);

    view! {
        cx =>
        signal sent = false;
        signal email = String::new();
        signal remaining = ttl_remaining;
        signal mins = ttl_mins;
        signal secs = ttl_secs_part;
        signal cooling = false;
        signal sending = false;
        signal unavailable = false;
        signal ttl_remaining_seed = ttl_remaining;
        signal ttl_mins_seed = ttl_mins;
        signal ttl_secs_seed = ttl_secs_part;

        <div :style=$(if sent.get() { "display:none" } else { "" })>
            <h2>"Sign in"</h2>
            <p class="vb-muted">"Access your customer organization."</p>
            if show_link_error {
                <p class="vb-login-error" role="alert">(LOGIN_LINK_ERROR_MESSAGE)</p>
            }
            <p
                class="vb-login-error"
                role="alert"
                :style=$(if unavailable.get() { "" } else { "display:none" })
            >
                (LOGIN_UNAVAILABLE_MESSAGE)
            </p>
            <form
                @submit=$(async |e: Event| {
                    e.prevent_default();
                    if sending.get() {
                        return;
                    }
                    sending.set(true);
                    unavailable.set(false);
                    let ok = request_login_link(email.get()).await;
                    sending.set(false);
                    if ok {
                        remaining.set(ttl_remaining_seed.get());
                        mins.set(ttl_mins_seed.get());
                        secs.set(ttl_secs_seed.get());
                        cooling.set(true);
                        sent.set(true);
                    } else {
                        unavailable.set(true);
                    }
                })
            >
                <label for="email">"Email"</label>
                <input
                    id="email"
                    name="email"
                    type="email"
                    required=""
                    autocomplete="username"
                    :value=$(email.get())
                    @input=$(|e: Event| email.set(e.target.value))
                >
                <button
                    type="submit"
                    :style=$(if sending.get() { "display:none" } else { "" })
                >
                    "Email me a sign-in link"
                </button>
                <button
                    type="button"
                    disabled=""
                    :style=$(if sending.get() { "" } else { "display:none" })
                >
                    "Sending..."
                </button>
            </form>
        </div>
        <div :style=$(if sent.get() { "" } else { "display:none" })>
            <h2>"Check your email"</h2>
            <p class="vb-muted">
                "If that address can access the portal, we sent a sign-in link to "
                $(email.get())
                "."
            </p>
            <p class="vb-muted" style="margin-top: 8px;">
                "Delivery can take a few minutes. If nothing arrives, try Resend or try again later."
            </p>
            <p
                class="vb-login-error"
                role="alert"
                :style=$(if unavailable.get() { "" } else { "display:none" })
            >
                (LOGIN_UNAVAILABLE_MESSAGE)
            </p>
            <span
                class="vb-eph-tick"
                aria-hidden="true"
                :style=$(if cooling.get() { "" } else { "display:none" })
                @animationiteration=$(|_e| {
                    let r = remaining.get();
                    if r > 0.0 {
                        let next = r - 1.0;
                        remaining.set(next);
                        let s = secs.get();
                        if s > 0.0 {
                            secs.set(s - 1.0);
                        } else {
                            secs.set(59.0);
                            let m = mins.get();
                            if m > 0.0 {
                                mins.set(m - 1.0);
                            }
                        }
                        if next <= 0.0 {
                            cooling.set(false);
                        }
                    }
                })
            ></span>
            <p style="margin-top: 16px;">
                <button
                    type="button"
                    disabled=""
                    :style=$(if cooling.get() { "" } else { "display:none" })
                >
                    "Resend in "
                    $(if mins.get() < 10.0 { "0" } else { "" })
                    $(mins.get())
                    ":"
                    $(if secs.get() < 10.0 { "0" } else { "" })
                    $(secs.get())
                </button>
                <button
                    type="button"
                    :style=$(if cooling.get() {
                        "display:none"
                    } else {
                        if sending.get() { "display:none" } else { "" }
                    })
                    @click=$(async |_e| {
                        if sending.get() {
                            return;
                        }
                        sending.set(true);
                        unavailable.set(false);
                        let ok = request_login_link(email.get()).await;
                        sending.set(false);
                        if ok {
                            remaining.set(ttl_remaining_seed.get());
                            mins.set(ttl_mins_seed.get());
                            secs.set(ttl_secs_seed.get());
                            cooling.set(true);
                        } else {
                            unavailable.set(true);
                        }
                    })
                >
                    "Resend"
                </button>
                <button
                    type="button"
                    disabled=""
                    :style=$(if cooling.get() {
                        "display:none"
                    } else {
                        if sending.get() { "" } else { "display:none" }
                    })
                >
                    "Sending..."
                </button>
            </p>
            <p style="margin-top: 12px;">
                <button
                    type="button"
                    @click=$(|_e| {
                        sent.set(false);
                        cooling.set(false);
                        unavailable.set(false);
                        sending.set(false);
                    })
                >
                    "Use a different email"
                </button>
            </p>
        </div>
    }
}

#[query_params]
struct MagicQuery {
    token: Option<String>,
}

#[route(GET "/login/magic")]
async fn login_magic(cx: &Cx) -> Result<SeeOther> {
    let raw = topcoat::router::query_params::<MagicQuery>(cx)
        .ok()
        .and_then(|q| q.token.clone())
        .unwrap_or_default();
    let mut database = db(cx);
    let Some(user) = consume_token(&mut database, raw.trim())
        .await
        .ok()
        .flatten()
    else {
        return Ok(see_other_login_link_error());
    };

    let session = session::start(cx).await?;
    persist_session(cx, session, user.id).await?;

    match post_auth_landing(cx, &user).await? {
        PostAuthLanding::Org(slug) => Ok(see_other(&format!("/{slug}"))),
        PostAuthLanding::ChooseOrg => Ok(see_other("/choose-org")),
        PostAuthLanding::None => {
            if let Some(hash) = session::stop(cx).await? {
                delete_session_hash(cx, &hash).await?;
            }
            Ok(see_other("/login"))
        }
    }
}

/// Multi-org picker after magic-link / session entry when N>1 client memberships.
#[route(GET "/choose-org")]
async fn choose_org_page(cx: &Cx) -> Result {
    let Some(user) = current_user(cx).await else {
        return Err(redirect("/login").into());
    };

    if user.portal_role == PORTAL_ROLE_ADMIN {
        return Err(redirect(&format!("/{RESERVED_ORG_SLUG}")).into());
    }

    let clients = client_orgs_for_user(cx, user.id).await?;
    match clients.len() {
        0 => {
            if let Some(hash) = session::stop(cx).await? {
                delete_session_hash(cx, &hash).await?;
            }
            return Err(redirect("/login").into());
        }
        1 => {
            return Err(redirect(&format!("/{}", clients[0].slug)).into());
        }
        _ => {}
    }

    // `#[route]` skips layouts (same as admin POST re-renders) — wrap root +
    // splash chrome so fonts / Tailwind / styles.css apply.
    let panel = view! {
        cx =>
        <h2>"Choose an organization"</h2>
        <p class="vb-muted">"Select which organization to open."</p>
        <ul class="vb-login-org-list">
            for org in &clients {
                <li>
                    <a class="vb-login-org-link" href=(format!("/{}", org.slug))>
                        <span class="vb-login-org-name">(org.name.clone())</span>
                        <span class="vb-login-org-slug vb-mono">
                            (org.slug.clone())
                        </span>
                    </a>
                </li>
            }
        </ul>
    }?;
    let splash = view! { cx => login_splash(body: Ok(panel)) }?;
    view! { cx => root_layout(slot: Ok(splash)) }
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await? {
        delete_session_hash(cx, &hash).await?;
    }
    Ok(see_other("/login"))
}

#[cfg(test)]
mod tests {
    use super::cooldown_mm_ss;
    use proptest::prelude::*;

    #[test]
    fn cooldown_mm_ss_known_cases() {
        assert_eq!(cooldown_mm_ss(300), (5, 0));
        assert_eq!(cooldown_mm_ss(61), (1, 1));
        assert_eq!(cooldown_mm_ss(9), (0, 9));
        assert_eq!(cooldown_mm_ss(0), (0, 0));
        assert_eq!(cooldown_mm_ss(3599), (59, 59));
    }

    proptest! {
        #![proptest_config(crate::proptest_util::default_config())]

        #[test]
        fn cooldown_mm_ss_props(total in 0u64..=10_000) {
            let (mins, secs) = cooldown_mm_ss(total);
            assert_eq!(mins, total / 60);
            assert_eq!(secs, total % 60);
            assert!(secs < 60);
            assert_eq!(mins * 60 + secs, total);
        }
    }
}
