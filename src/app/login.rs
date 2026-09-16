use std::sync::Arc;

use topcoat::{
    Result,
    context::{Cx, app_context},
    mail::Mailbox,
    router::{
        Slot,
        error::{SeeOther, redirect, see_other},
        href, layout, page, query_params, route,
    },
    runtime::{Event, procedure, signal},
    session,
    view::{Child, View, component, view},
};

use crate::{
    app::{
        hrefs::LoginErrorQ,
        org::{Org, dashboard},
    },
    auth::{
        PostAuthLanding, current_user, db, delete_session_hash, persist_session, post_auth_landing,
    },
    config::Config,
    login_limit::LoginRateLimiter,
    magic_link::{active_user_by_email, consume_token, ensure_vcp_admin_user, issue_token},
    mail_circuit::MailCircuitBreaker,
    mailer::send_login_magic_link,
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

fn see_other_login_link_error(cx: &Cx) -> SeeOther {
    see_other(
        href!(login_page)
            .query(LoginErrorQ {
                error: LOGIN_LINK_ERROR,
            })
            .resolve(cx),
    )
}

#[query_params]
struct LoginQuery {
    error: Option<String>,
}

/// Shared splash chrome for `/login/*` layout and absolute routes like `/choose-org`.
#[component]
pub(crate) async fn login_splash(cx: &Cx, #[default] child: Child<'_>) -> Result<impl View> {
    Ok(view! {
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
                <div class="vb-login-panel">(child)</div>
            </div>
        </div>
    })
}

#[layout]
async fn login_layout(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    Ok(view! { cx => login_splash((slot)) })
}

/// Wire values for [`request_login_link`] (Topcoat 0.7+ preserves `bool`
/// procedure results on the client, so no f64 shim is needed).
pub(crate) const LOGIN_LINK_ACCEPTED: bool = true;
pub(crate) const LOGIN_LINK_UNAVAILABLE: bool = false;

/// Request (or re-request) a sign-in magic link.
///
/// Returns [`LOGIN_LINK_ACCEPTED`] when the client should show Check-your-email
/// (anti-enumeration for unknown / locked emails and for SMTP failures while
/// the circuit is still closed). Returns [`LOGIN_LINK_UNAVAILABLE`] when the
/// mail circuit is open — including on the request that just opened it — so
/// every address shares the same unavailable UX.
#[procedure]
async fn request_login_link(cx: &Cx, email: String) -> Result<bool> {
    let cfg = app_context::<Arc<Config>>(cx);
    let limiter = app_context::<Arc<LoginRateLimiter>>(cx);
    let mail_circuit = app_context::<Arc<MailCircuitBreaker>>(cx);

    if !mail_circuit.allow_attempt() {
        return Ok(LOGIN_LINK_UNAVAILABLE);
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
                    // SMTP err: mailer trips the circuit + logs. If the circuit
                    // is now open, fall through to unavailable (no stuck UX).
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

    if mail_circuit.is_open() {
        return Ok(LOGIN_LINK_UNAVAILABLE);
    }
    Ok(LOGIN_LINK_ACCEPTED)
}

#[page]
pub(crate) async fn login_page(cx: &Cx) -> Result<impl View> {
    // Valid session: skip the login form and land on the portal home / picker.
    if let Some(user) = current_user(cx).await {
        match post_auth_landing(cx, user).await? {
            PostAuthLanding::Org(slug) => {
                return Err(redirect(href!(dashboard, Org(slug)).resolve(cx)).into());
            }
            PostAuthLanding::ChooseOrg => {
                return Err(
                    redirect(href!(crate::app::choose_org::choose_org_page).resolve(cx)).into(),
                );
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

    let sent = signal(cx, || false);
    let email = signal(cx, String::new);
    let remaining = signal(cx, || ttl_remaining);
    let mins = signal(cx, || ttl_mins);
    let secs = signal(cx, || ttl_secs_part);
    let cooling = signal(cx, || false);
    let sending = signal(cx, || false);
    let unavailable = signal(cx, || false);
    let ttl_remaining_seed = signal(cx, || ttl_remaining);
    let ttl_mins_seed = signal(cx, || ttl_mins);
    let ttl_secs_seed = signal(cx, || ttl_secs_part);

    Ok(view! {
        cx =>
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
                    let status = request_login_link(email.get()).await;
                    sending.set(false);
                    if status {
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
                        let status = request_login_link(email.get()).await;
                        sending.set(false);
                        if status {
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
    })
}

#[query_params]
struct MagicQuery {
    token: Option<String>,
}

#[route(GET "./magic")]
pub(crate) async fn login_magic(cx: &Cx) -> Result<SeeOther> {
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
        return Ok(see_other_login_link_error(cx));
    };

    let session = session::start(cx).await?;
    persist_session(cx, session, user.id).await?;

    match post_auth_landing(cx, &user).await? {
        PostAuthLanding::Org(slug) => Ok(see_other(href!(dashboard, Org(slug)).resolve(cx))),
        PostAuthLanding::ChooseOrg => Ok(see_other(
            href!(crate::app::choose_org::choose_org_page).resolve(cx),
        )),
        PostAuthLanding::None => {
            if let Some(hash) = session::stop(cx).await? {
                delete_session_hash(cx, &hash).await?;
            }
            Ok(see_other(href!(login_page).resolve(cx)))
        }
    }
}

#[route(POST "/logout")]
pub(crate) async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(hash) = session::stop(cx).await? {
        delete_session_hash(cx, &hash).await?;
    }
    Ok(see_other(href!(login_page).resolve(cx)))
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
