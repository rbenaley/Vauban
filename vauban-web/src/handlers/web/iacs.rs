//! IACS / EWS onboarding -- web handlers (user zone).
//!
//! User-zone surface (palier 6, Casbin gate `iacs_request`):
//!
//! * `GET  /iacs/onboard` -- new request form.
//! * `POST /iacs/onboard` -- submit a new request.
//! * `GET  /iacs/onboard/{uuid}/edit-form` -- edit-pending form.
//! * `POST /iacs/onboard/{uuid}/edit` -- save edits.
//! * `POST /iacs/onboard/{uuid}/cancel` -- cancel a pending request.
//! * `POST /iacs/{uuid}/offboard-self` -- self-offboard one of my
//!   approved EWS rows (irreversible).
//!
//! Admin-zone handlers (`iacs:manage`) live in palier 7. Every IPC
//! call routes through [`crate::services::iacs`], which itself
//! delegates to `vauban-access` for atomicity (transaction + audit
//! log). The web layer is intentionally thin: CSRF, RBAC,
//! anti-enumeration, flash messages, mailer queue.
//!
//! ## Anti-enumeration
//!
//! `EwsDenyReason::RequestNotFound`, `EwsNotFound` and `NotOwner`
//! collapse to `404 Not Found` so a non-owner cannot use a 403 vs 404
//! signal to confirm the existence of someone else's resource. The
//! actual SQL lookup happens in the IPC handler -- the web layer
//! never reads `ews_*` tables directly to fetch a row by UUID.

use super::*;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::services::iacs::{self as iacs_service, IacsError};
use crate::templates::iacs::{
    AdminDetailTemplate, AdminEwsRow, AdminListTemplate, AdminPendingRequest, EwsDetail, MyEwsItem,
    MyEwsState, OnboardFormPrefill, OnboardFormTemplate, RequestDetail,
};

/// Convert middleware-layer flash messages into the template-layer
/// shape expected by `BaseTemplate::with_messages`.
fn flash_messages_for_template(
    incoming: &IncomingFlash,
) -> Vec<crate::templates::base::FlashMessage> {
    incoming
        .messages()
        .iter()
        .map(|m| crate::templates::base::FlashMessage {
            level: m.level.clone(),
            message: m.message.clone(),
        })
        .collect()
}

// ===================================================================
// Form payloads
// ===================================================================

/// `POST /iacs/onboard` and `POST /iacs/onboard/{uuid}/edit`.
#[derive(Debug, Deserialize)]
pub struct OnboardForm {
    pub csrf_token: String,
    pub name: String,
    pub public_key: String,
    pub justification: String,
}

/// `POST /iacs/onboard/{uuid}/cancel` and `POST /iacs/{uuid}/offboard-self`.
#[derive(Debug, Deserialize)]
pub struct IacsCsrfOnlyForm {
    pub csrf_token: String,
}

// ===================================================================
// Validation
// ===================================================================

const MAX_EWS_NAME_LEN: usize = 128;
const MAX_JUSTIFICATION_LEN: usize = 250;

/// Trim, sanitize and length-check the three text fields shared by
/// submit / edit. Returns `Ok((name, justification))` (the public key
/// is parsed separately by `iacs_service::parse_and_validate_public_key`).
fn validate_text_fields(form: &OnboardForm) -> Result<(String, String), String> {
    let name = sanitize(form.name.trim());
    if name.is_empty() {
        return Err("EWS name is required".to_string());
    }
    if name.chars().count() > MAX_EWS_NAME_LEN {
        return Err(format!(
            "EWS name is too long (max {} characters)",
            MAX_EWS_NAME_LEN
        ));
    }

    let justification = sanitize(form.justification.trim());
    if justification.is_empty() {
        return Err("Justification is required".to_string());
    }
    if justification.chars().count() > MAX_JUSTIFICATION_LEN {
        return Err(format!(
            "Justification is too long (max {} characters)",
            MAX_JUSTIFICATION_LEN
        ));
    }

    Ok((name, justification))
}

// ===================================================================
// Shared helpers
// ===================================================================

fn validate_csrf(state: &AppState, jar: &CookieJar, token: &str) -> bool {
    let secret = state.config.secret_key.expose_secret().as_bytes();
    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    crate::middleware::csrf::validate_double_submit(secret, csrf_cookie.map(|c| c.value()), token)
}

fn resolve_actor_ip(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    client_addr: &crate::middleware::ClientAddr,
) -> Option<String> {
    let trusted = state.config.security.parsed_trusted_proxies();
    let resolved = crate::middleware::resolve_client_ip(headers, client_addr.addr().ip(), &trusted);
    Some(resolved.to_string())
}

/// Map an [`IacsError`] to either a flash redirect or a 404 (anti-
/// enumeration on `RequestNotFound` / `EwsNotFound` / `NotOwner`).
///
/// `redirect_target` is used for flash redirects; the 404 path returns
/// the constant `404 Not Found`.
fn iacs_error_to_response(
    error: IacsError,
    flash: crate::middleware::flash::Flash,
    redirect_target: &str,
) -> Response {
    use shared::messages::EwsDenyReason;
    match error {
        IacsError::InvalidInput(msg) => flash_redirect(flash.error(msg), redirect_target),
        IacsError::Deny(reason) => match reason {
            EwsDenyReason::RequestNotFound
            | EwsDenyReason::EwsNotFound
            | EwsDenyReason::NotOwner => {
                (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response()
            }
            other => flash_redirect(flash.error(other.as_message().to_string()), redirect_target),
        },
        IacsError::Internal(app_err) => {
            tracing::error!(error = %app_err, "IACS IPC failure");
            flash_redirect(
                flash.error("Operation failed; please retry later".to_string()),
                redirect_target,
            )
        }
    }
}

/// Apply the advisory uniqueness check and short-circuit with a flash
/// redirect when the fingerprint clashes. `exclude_request_uuid`
/// allows the edit flow to pass its own request UUID through (so the
/// row's CURRENT fingerprint does not flag itself).
async fn advisory_uniqueness_or_redirect(
    state: &AppState,
    parsed: &iacs_service::ParsedKey,
    exclude_request_uuid: Option<Uuid>,
    flash: crate::middleware::flash::Flash,
    redirect_target: &str,
) -> Result<crate::middleware::flash::Flash, Response> {
    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "IACS advisory uniqueness: DB conn unavailable");
            return Err(flash_redirect(
                flash.error("Database unavailable; please retry later".to_string()),
                redirect_target,
            ));
        }
    };
    use crate::services::iacs::AdvisoryUniqueness;
    match iacs_service::check_fingerprint_uniqueness_advisory(
        &mut conn,
        &parsed.fingerprint_sha256_hex,
        exclude_request_uuid,
    )
    .await
    {
        Ok(AdvisoryUniqueness::Available) => Ok(flash),
        Ok(AdvisoryUniqueness::LockedByActive) => Err(flash_redirect(
            flash.error(
                "This SSH public key is already registered against another active EWS".to_string(),
            ),
            redirect_target,
        )),
        Ok(AdvisoryUniqueness::LockedByPending) => Err(flash_redirect(
            flash.error(
                "This SSH public key is already attached to another pending request".to_string(),
            ),
            redirect_target,
        )),
        Err(e) => {
            tracing::error!(error = %e, "IACS advisory uniqueness: DB error");
            Err(flash_redirect(
                flash.error("Database error; please retry later".to_string()),
                redirect_target,
            ))
        }
    }
}

// ===================================================================
// GET /iacs/onboard -- new request form
// ===================================================================

pub async fn iacs_onboard_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    if !perms.iacs_request {
        return Err(AppError::NotFound("Not Found".to_string()));
    }

    let flash_messages = flash_messages_for_template(&incoming_flash);
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Onboard EWS".to_string(), user.clone())
        .with_current_path("/iacs/onboard")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = OnboardFormTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
        prefill: OnboardFormPrefill::default(),
        max_ews_per_user: state.config.industrial.max_ews_per_user,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ===================================================================
// POST /iacs/onboard
// ===================================================================

#[allow(clippy::too_many_arguments)]
pub async fn iacs_submit_onboarding(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    Form(form): Form<OnboardForm>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.iacs_request {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }

    let (name, justification) = match validate_text_fields(&form) {
        Ok(pair) => pair,
        Err(msg) => return flash_redirect(flash.error(msg), "/iacs/onboard"),
    };

    let parsed = match iacs_service::parse_and_validate_public_key(&form.public_key) {
        Ok(p) => p,
        Err(e) => return flash_redirect(flash.error(e.as_message()), "/iacs/onboard"),
    };

    let flash = match advisory_uniqueness_or_redirect(&state, &parsed, None, flash, "/iacs/onboard")
        .await
    {
        Ok(f) => f,
        Err(resp) => return resp,
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    let outcome = iacs_service::submit_onboarding(
        &state.access_client,
        &auth_user.uuid,
        name.clone(),
        &parsed,
        justification.clone(),
        state.config.industrial.max_ews_per_user,
        actor_ip,
    )
    .await;

    let (request_uuid, _audit_log_id) = match outcome {
        Ok(pair) => pair,
        Err(e) => return iacs_error_to_response(e, flash, "/iacs/onboard"),
    };

    tracing::info!(
        request_uuid = %request_uuid,
        user = %auth_user.username,
        ews_name = %name,
        "IACS EWS onboarding request submitted"
    );

    if let Err(e) = queue_iacs_onboard_submitted_emails(
        &state,
        &request_uuid,
        &auth_user.username,
        &name,
        &parsed.fingerprint_sha256_hex,
        &justification,
    )
    .await
    {
        tracing::warn!(
            request_uuid = %request_uuid,
            error = %e,
            "Failed to queue iacs.onboard_submitted emails (request itself was recorded)"
        );
    }

    broadcast_iacs_badge(&state).await;

    flash_redirect(
        flash.success(
            "EWS onboarding request submitted; an administrator will review it.".to_string(),
        ),
        "/sessions/my-requests",
    )
}

// ===================================================================
// GET /iacs/onboard/{uuid}/edit-form
// ===================================================================

pub async fn iacs_edit_form(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.iacs_request {
        return Err(AppError::NotFound("Not Found".to_string()));
    }
    let request_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return Err(AppError::NotFound("Not Found".to_string())),
    };

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let user_uuid = Uuid::parse_str(&auth_user.uuid)
        .map_err(|_| AppError::NotFound("Not Found".to_string()))?;
    let user_id: i32 = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(user_uuid))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .map_err(|_| AppError::NotFound("Not Found".to_string()))?;

    use crate::schema::ews_onboarding_requests as r;
    let row: Option<(String, String, String)> = r::table
        .filter(r::uuid.eq(request_uuid))
        .filter(r::user_id.eq(user_id))
        .filter(r::status.eq("pending"))
        .select((r::name, r::public_key, r::justification))
        .first::<(String, String, String)>(&mut conn)
        .await
        .ok();

    let (db_name, db_pubkey, db_just) = match row {
        Some(r) => r,
        // Anti-enumeration: same shape as "no such row".
        None => return Err(AppError::NotFound("Not Found".to_string())),
    };

    let flash_messages = flash_messages_for_template(&incoming_flash);
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Edit EWS request".to_string(), user.clone())
        .with_current_path("/iacs/onboard")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = OnboardFormTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
        prefill: OnboardFormPrefill {
            request_uuid: Some(request_uuid.to_string()),
            // The DB stores only the base64 payload + algo; rebuild
            // the canonical OpenSSH line so the user sees the same
            // shape they originally pasted.
            name: db_name,
            public_key: format!("ssh-ed25519 {}", db_pubkey),
            justification: db_just,
        },
        max_ews_per_user: state.config.industrial.max_ews_per_user,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ===================================================================
// POST /iacs/onboard/{uuid}/edit
// ===================================================================

#[allow(clippy::too_many_arguments)]
pub async fn iacs_edit_request(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<OnboardForm>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.iacs_request {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }

    let request_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let edit_form_url = format!("/iacs/onboard/{}/edit-form", request_uuid);

    let (name, justification) = match validate_text_fields(&form) {
        Ok(pair) => pair,
        Err(msg) => return flash_redirect(flash.error(msg), &edit_form_url),
    };

    let parsed = match iacs_service::parse_and_validate_public_key(&form.public_key) {
        Ok(p) => p,
        Err(e) => return flash_redirect(flash.error(e.as_message()), &edit_form_url),
    };

    let flash = match advisory_uniqueness_or_redirect(
        &state,
        &parsed,
        Some(request_uuid),
        flash,
        &edit_form_url,
    )
    .await
    {
        Ok(f) => f,
        Err(resp) => return resp,
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    let outcome = iacs_service::edit_request(
        &state.access_client,
        &auth_user.uuid,
        &request_uuid.to_string(),
        name.clone(),
        &parsed,
        justification,
        actor_ip,
    )
    .await;

    if let Err(e) = outcome {
        return iacs_error_to_response(e, flash, &edit_form_url);
    }

    tracing::info!(
        request_uuid = %request_uuid,
        user = %auth_user.username,
        ews_name = %name,
        "IACS EWS onboarding request edited"
    );

    flash_redirect(
        flash.success("Request updated.".to_string()),
        "/sessions/my-requests",
    )
}

// ===================================================================
// POST /iacs/onboard/{uuid}/cancel
// ===================================================================

#[allow(clippy::too_many_arguments)]
pub async fn iacs_cancel_request(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_request {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let request_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::cancel_request(
        &state.access_client,
        &auth_user.uuid,
        &request_uuid.to_string(),
        actor_ip,
    )
    .await
    {
        Ok(_audit_id) => {
            tracing::info!(
                request_uuid = %request_uuid,
                user = %auth_user.username,
                "IACS EWS onboarding request cancelled"
            );
            broadcast_iacs_badge(&state).await;
            flash_redirect(
                flash.success("Request cancelled.".to_string()),
                "/sessions/my-requests",
            )
        }
        Err(e) => iacs_error_to_response(e, flash, "/sessions/my-requests"),
    }
}

// ===================================================================
// POST /iacs/{uuid}/offboard-self
// ===================================================================

#[allow(clippy::too_many_arguments)]
pub async fn iacs_offboard_self(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_request {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let ews_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::offboard(
        &state.access_client,
        &auth_user.uuid,
        &ews_uuid.to_string(),
        true,
        None,
        actor_ip,
    )
    .await
    {
        Ok(_audit_id) => {
            tracing::info!(
                ews_uuid = %ews_uuid,
                user = %auth_user.username,
                "IACS EWS auto-offboarded by owner"
            );
            flash_redirect(
                flash.success("EWS offboarded.".to_string()),
                "/sessions/my-requests",
            )
        }
        Err(e) => iacs_error_to_response(e, flash, "/sessions/my-requests"),
    }
}

// ===================================================================
// Mailer hook: notify superusers on submit
// ===================================================================

/// Queue one `iacs.onboard_submitted` email per active superuser.
/// Best-effort, mirrors `queue_submitted_emails` for JIT.
async fn queue_iacs_onboard_submitted_emails(
    state: &AppState,
    request_uuid: &str,
    requester_username: &str,
    ews_name: &str,
    fingerprint: &str,
    justification: &str,
) -> Result<(), String> {
    use crate::schema::users;
    use crate::services::mailer::{
        EmailEvent, EmailRecipient, IacsOnboardSubmittedEvent, deterministic_event_id,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let approver_emails: Vec<(String, String)> = users::table
        .filter(users::is_active.eq(true))
        .filter(users::is_superuser.eq(true))
        .filter(users::email.ne(""))
        .select((users::email, users::username))
        .load(&mut conn)
        .await
        .map_err(|e| format!("approver lookup: {}", e))?;
    drop(conn);

    if approver_emails.is_empty() {
        return Ok(());
    }

    // The admin URL targets the admin detail page (palier 7); for now
    // the listing URL is used as fallback so the email always points
    // somewhere navigable.
    let admin_url = format!("{}/iacs/{}", state.config.mailer.base_url, request_uuid);
    let business_key = format!("submitted:{}", request_uuid);

    let mut errors: Vec<String> = Vec::new();
    for (email, username) in approver_emails {
        let event_id = deterministic_event_id("iacs.onboard_submitted", &business_key, &email);
        let event = EmailEvent::IacsOnboardSubmitted(IacsOnboardSubmittedEvent {
            event_id,
            recipient: EmailRecipient::new(email, username),
            requester_username: requester_username.to_string(),
            ews_name: ews_name.to_string(),
            fingerprint: fingerprint.to_string(),
            justification: Some(justification.to_string()),
            admin_url: admin_url.clone(),
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        });
        let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
        match state.mailer.queue(&mut conn, &event).await {
            Ok(()) | Err(crate::services::mailer::MailerError::Duplicate) => {}
            Err(e) => errors.push(e.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

// ===================================================================
// Helper: load EWS items for /sessions/my-requests integration
// ===================================================================

/// Project the (`ews_onboarding_requests` ⊕ `ews`) rows owned by
/// `user_id` into a single ordered `Vec<MyEwsItem>` ready for the
/// "My EWS" section. Newest first, capped at 50.
///
/// The two source tables are walked separately and merged in Rust;
/// Diesel does not have a UNION DSL and a raw `sql_query` would
/// duplicate the column list in three places (DB schema, Rust
/// QueryableByName, template). Capping at 50 keeps the page small
/// even for power-users with a large EWS history.
pub async fn load_my_ews_items(state: &AppState, user_id: i32) -> Result<Vec<MyEwsItem>, AppError> {
    use crate::schema::{ews, ews_onboarding_requests as r};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Pending / rejected / cancelled live in `ews_onboarding_requests`
    // (the matching `approved` row is duplicated under `ews` once the
    // admin decides; we filter `approved` out below to avoid showing
    // it twice).
    #[allow(clippy::type_complexity)]
    let req_rows: Vec<(
        Uuid,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )> = r::table
        .filter(r::user_id.eq(user_id))
        .filter(r::status.ne("approved"))
        .select((
            r::uuid,
            r::name,
            r::public_key_fingerprint,
            r::key_algo,
            r::status,
            r::justification,
            r::decision_reason,
            r::created_at,
            r::decided_at,
        ))
        .order(r::created_at.desc())
        .limit(50)
        .load::<(
            Uuid,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        )>(&mut conn)
        .await
        .map_err(AppError::Database)?;

    #[allow(clippy::type_complexity)]
    let ews_rows: Vec<(
        Uuid,
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = ews::table
        .filter(ews::user_id.eq(user_id))
        .select((
            ews::uuid,
            ews::name,
            ews::public_key_fingerprint,
            ews::key_algo,
            ews::disabled_at,
            ews::offboarded_at,
            ews::created_at,
        ))
        .order(ews::created_at.desc())
        .limit(50)
        .load::<(
            Uuid,
            String,
            String,
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )>(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let mut items: Vec<MyEwsItem> = Vec::with_capacity(req_rows.len() + ews_rows.len());
    let fmt = |dt: DateTime<Utc>| dt.format("%b %d, %Y %H:%M").to_string();
    let short_fp = |fp: &str| -> String { fp.chars().take(16).collect::<String>() };

    for (uuid, name, fp, algo, status, just, reason, created, decided) in req_rows {
        let state_v = match status.as_str() {
            "pending" => MyEwsState::Pending,
            "rejected" => MyEwsState::Rejected,
            "cancelled" => MyEwsState::Cancelled,
            // approved was filtered above; a stray status falls back
            // to Pending so the user still sees the row rather than
            // it disappearing silently.
            _ => MyEwsState::Pending,
        };
        items.push(MyEwsItem {
            uuid: uuid.to_string(),
            name,
            fingerprint_short: short_fp(&fp),
            key_algo: algo,
            state: state_v,
            created_at: fmt(created),
            decided_at: decided.map(fmt),
            rejection_reason: if matches!(status.as_str(), "rejected") {
                reason
            } else {
                None
            },
            justification: Some(just),
        });
    }

    for (uuid, name, fp, algo, disabled_at, offboarded_at, created) in ews_rows {
        let state_v = if offboarded_at.is_some() {
            MyEwsState::Offboarded
        } else if disabled_at.is_some() {
            MyEwsState::Disabled
        } else {
            MyEwsState::Active
        };
        items.push(MyEwsItem {
            uuid: uuid.to_string(),
            name,
            fingerprint_short: short_fp(&fp),
            key_algo: algo,
            state: state_v,
            created_at: fmt(created),
            decided_at: None,
            rejection_reason: None,
            justification: None,
        });
    }

    items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    items.truncate(50);

    Ok(items)
}

// ===================================================================
// Admin-zone handlers (palier 7) -- gated by `iacs_manage`
// ===================================================================
//
// All admin handlers live behind the `/iacs/admin` nest carrying a
// `route_layer(require_iacs_manage)` middleware. The middleware
// returns 403 BEFORE the handler runs (anti-enumeration: a non-admin
// cannot use `/iacs/admin/{random-uuid}` as an oracle for a row's
// existence). Each handler ALSO re-checks `perms.iacs_manage` at the
// top of its body so a routing misconfiguration that hoists a
// handler outside of the nest still fails closed -- mirroring the
// `/assets/manage` defence-in-depth pattern.

const ADMIN_PAGE_LIMIT: i64 = 50;

/// Render the admin landing page (`GET /iacs/admin`).
///
/// Aggregates pending onboarding requests (top section) and active /
/// disabled / offboarded EWS rows (bottom section) so an operator
/// can review the entire IACS surface at a glance.
pub async fn iacs_admin_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    if !perms.iacs_manage {
        return Err(AppError::NotFound("Not Found".to_string()));
    }

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::{ews, ews_onboarding_requests as r, users};

    #[allow(clippy::type_complexity)]
    let pending_rows: Vec<(Uuid, String, String, String, String, String, DateTime<Utc>)> = r::table
        .inner_join(users::table.on(users::id.eq(r::user_id)))
        .filter(r::status.eq("pending"))
        .order(r::created_at.desc())
        .limit(ADMIN_PAGE_LIMIT)
        .select((
            r::uuid,
            users::username,
            r::name,
            r::key_algo,
            r::public_key_fingerprint,
            r::justification,
            r::created_at,
        ))
        .load::<(Uuid, String, String, String, String, String, DateTime<Utc>)>(&mut conn)
        .await
        .map_err(AppError::Database)?;

    #[allow(clippy::type_complexity)]
    let ews_rows: Vec<(
        Uuid,
        String,
        String,
        String,
        String,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = ews::table
        .inner_join(users::table.on(users::id.eq(ews::user_id)))
        .order(ews::created_at.desc())
        .limit(ADMIN_PAGE_LIMIT)
        .select((
            ews::uuid,
            users::username,
            ews::name,
            ews::key_algo,
            ews::public_key_fingerprint,
            ews::disabled_at,
            ews::offboarded_at,
            ews::created_at,
        ))
        .load::<(
            Uuid,
            String,
            String,
            String,
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )>(&mut conn)
        .await
        .map_err(AppError::Database)?;
    drop(conn);

    let fmt = |dt: DateTime<Utc>| dt.format("%b %d, %Y %H:%M").to_string();
    let short_fp = |fp: &str| -> String { fp.chars().take(16).collect::<String>() };

    let pending_requests: Vec<AdminPendingRequest> = pending_rows
        .into_iter()
        .map(
            |(uuid, username, name, algo, fp, justification, created)| AdminPendingRequest {
                request_uuid: uuid.to_string(),
                requester_username: username,
                ews_name: name,
                key_algo: algo,
                fingerprint_short: short_fp(&fp),
                justification,
                created_at: fmt(created),
            },
        )
        .collect();

    let ews_rows: Vec<AdminEwsRow> = ews_rows
        .into_iter()
        .map(
            |(uuid, username, name, algo, fp, disabled_at, offboarded_at, created)| {
                let state = if offboarded_at.is_some() {
                    "offboarded"
                } else if disabled_at.is_some() {
                    "disabled"
                } else {
                    "active"
                };
                AdminEwsRow {
                    ews_uuid: uuid.to_string(),
                    owner_username: username,
                    name,
                    key_algo: algo,
                    fingerprint_short: short_fp(&fp),
                    state: state.to_string(),
                    created_at: fmt(created),
                    disabled_at: disabled_at.map(fmt),
                    offboarded_at: offboarded_at.map(fmt),
                }
            },
        )
        .collect();

    let flash_messages = flash_messages_for_template(&incoming_flash);
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("IACS".to_string(), user.clone())
        .with_current_path("/iacs/admin")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = AdminListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
        pending_requests,
        ews_rows,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Render the request detail page (`GET /iacs/admin/request/{uuid}`).
pub async fn iacs_admin_request_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.iacs_manage {
        return Err(AppError::NotFound("Not Found".to_string()));
    }
    let request_uuid =
        Uuid::parse_str(&uuid_str).map_err(|_| AppError::NotFound("Not Found".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::{ews_onboarding_requests as r, users};

    #[allow(clippy::type_complexity)]
    let row: Option<(
        Uuid,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<i32>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = r::table
        .inner_join(users::table.on(users::id.eq(r::user_id)))
        .filter(r::uuid.eq(request_uuid))
        .select((
            r::uuid,
            users::username,
            users::email,
            r::name,
            r::key_algo,
            r::public_key,
            r::public_key_fingerprint,
            r::justification,
            r::status,
            r::decision_reason,
            r::decided_by_id,
            r::decided_at,
            r::created_at,
        ))
        .first::<(
            Uuid,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<i32>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )>(&mut conn)
        .await
        .ok();

    let (
        uuid,
        username,
        email,
        name,
        algo,
        public_key,
        fp,
        justification,
        status,
        decision_reason,
        decided_by_id,
        decided_at,
        created,
    ) = match row {
        Some(t) => t,
        None => return Err(AppError::NotFound("Not Found".to_string())),
    };

    let decided_by_username = match decided_by_id {
        Some(id) => users::table
            .filter(users::id.eq(id))
            .select(users::username)
            .first::<String>(&mut conn)
            .await
            .ok(),
        None => None,
    };
    drop(conn);

    let fmt = |dt: DateTime<Utc>| dt.format("%b %d, %Y %H:%M").to_string();
    let short_fp = |s: &str| -> String { s.chars().take(16).collect::<String>() };

    let detail = RequestDetail {
        request_uuid: uuid.to_string(),
        requester_username: username,
        requester_email: if email.is_empty() { None } else { Some(email) },
        ews_name: name,
        key_algo: algo.clone(),
        fingerprint_short: short_fp(&fp),
        fingerprint_full: fp,
        full_public_key: format!("{} {}", algo, public_key),
        justification,
        status,
        created_at: fmt(created),
        decided_at: decided_at.map(fmt),
        decided_by_username,
        decision_reason,
    };

    let flash_messages = flash_messages_for_template(&incoming_flash);
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("IACS request".to_string(), user.clone())
        .with_current_path("/iacs/admin")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = AdminDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
        kind: "request".to_string(),
        request: Some(detail),
        ews: None,
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

/// Render the EWS detail page (`GET /iacs/admin/ews/{uuid}`).
pub async fn iacs_admin_ews_detail(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !perms.iacs_manage {
        return Err(AppError::NotFound("Not Found".to_string()));
    }
    let ews_uuid =
        Uuid::parse_str(&uuid_str).map_err(|_| AppError::NotFound("Not Found".to_string()))?;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    use crate::schema::{ews, users};

    #[allow(clippy::type_complexity)]
    let row: Option<(
        Uuid,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<i32>,
        Option<DateTime<Utc>>,
        Option<i32>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = ews::table
        .inner_join(users::table.on(users::id.eq(ews::user_id)))
        .filter(ews::uuid.eq(ews_uuid))
        .select((
            ews::uuid,
            users::username,
            users::email,
            ews::name,
            ews::key_algo,
            ews::public_key,
            ews::public_key_fingerprint,
            ews::disabled_by_id,
            ews::disabled_at,
            ews::offboarded_by_id,
            ews::offboarded_at,
            ews::created_at,
        ))
        .first::<(
            Uuid,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<i32>,
            Option<DateTime<Utc>>,
            Option<i32>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )>(&mut conn)
        .await
        .ok();

    let (
        uuid,
        username,
        email,
        name,
        algo,
        public_key,
        fp,
        disabled_by_id,
        disabled_at,
        offboarded_by_id,
        offboarded_at,
        created,
    ) = match row {
        Some(t) => t,
        None => return Err(AppError::NotFound("Not Found".to_string())),
    };

    let resolve_user =
        async |conn: &mut crate::db::DbConnection, id: Option<i32>| -> Option<String> {
            match id {
                Some(i) => users::table
                    .filter(users::id.eq(i))
                    .select(users::username)
                    .first::<String>(conn)
                    .await
                    .ok(),
                None => None,
            }
        };
    let disabled_by_username = resolve_user(&mut conn, disabled_by_id).await;
    let offboarded_by_username = resolve_user(&mut conn, offboarded_by_id).await;
    drop(conn);

    let fmt = |dt: DateTime<Utc>| dt.format("%b %d, %Y %H:%M").to_string();
    let short_fp = |s: &str| -> String { s.chars().take(16).collect::<String>() };

    let state_str = if offboarded_at.is_some() {
        "offboarded"
    } else if disabled_at.is_some() {
        "disabled"
    } else {
        "active"
    };

    let detail = EwsDetail {
        ews_uuid: uuid.to_string(),
        owner_username: username,
        owner_email: if email.is_empty() { None } else { Some(email) },
        name,
        key_algo: algo.clone(),
        fingerprint_short: short_fp(&fp),
        fingerprint_full: fp,
        full_public_key: format!("{} {}", algo, public_key),
        state: state_str.to_string(),
        created_at: fmt(created),
        disabled_at: disabled_at.map(fmt),
        disabled_by_username,
        offboarded_at: offboarded_at.map(fmt),
        offboarded_by_username,
    };

    let flash_messages = flash_messages_for_template(&incoming_flash);
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("IACS EWS".to_string(), user.clone())
        .with_current_path("/iacs/admin")
        .with_messages(flash_messages);
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();
    let csrf_token = jar
        .get(crate::middleware::csrf::CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let template = AdminDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        csrf_token,
        kind: "ews".to_string(),
        request: None,
        ews: Some(detail),
    };
    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ===================================================================
// Admin-zone POST handlers (decisions + lifecycle)
// ===================================================================

/// `POST /iacs/admin/request/{uuid}/approve`.
#[allow(clippy::too_many_arguments)]
pub async fn iacs_admin_approve(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_manage {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let request_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::record_decision(
        &state.access_client,
        &auth_user.uuid,
        &request_uuid.to_string(),
        shared::messages::EwsDecisionKind::Approve,
        None,
        actor_ip,
    )
    .await
    {
        Ok((_audit_id, ews_uuid)) => {
            tracing::info!(
                request_uuid = %request_uuid,
                actor = %auth_user.username,
                ?ews_uuid,
                "IACS EWS onboarding request approved"
            );
            if let Err(e) =
                queue_iacs_decision_email(&state, &request_uuid, &auth_user.username, true, None)
                    .await
            {
                tracing::warn!(
                    request_uuid = %request_uuid,
                    error = %e,
                    "Failed to queue iacs.onboard_approved email"
                );
            }
            broadcast_iacs_badge(&state).await;
            flash_redirect(
                flash.success("EWS onboarding request approved.".to_string()),
                "/iacs/admin",
            )
        }
        Err(e) => iacs_error_to_response(e, flash, "/iacs/admin"),
    }
}

/// `POST /iacs/admin/request/{uuid}/reject`.
#[derive(Debug, Deserialize)]
pub struct IacsRejectForm {
    pub csrf_token: String,
    pub reason: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn iacs_admin_reject(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsRejectForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_manage {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let request_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let reason = sanitize(form.reason.trim());
    if reason.chars().count() < 5 {
        return flash_redirect(
            flash.error("Rejection reason must be at least 5 characters".to_string()),
            &format!("/iacs/admin/request/{}", request_uuid),
        );
    }
    if reason.chars().count() > 1000 {
        return flash_redirect(
            flash.error("Rejection reason is too long (max 1000 characters)".to_string()),
            &format!("/iacs/admin/request/{}", request_uuid),
        );
    }

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::record_decision(
        &state.access_client,
        &auth_user.uuid,
        &request_uuid.to_string(),
        shared::messages::EwsDecisionKind::Reject,
        Some(reason.clone()),
        actor_ip,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                request_uuid = %request_uuid,
                actor = %auth_user.username,
                "IACS EWS onboarding request rejected"
            );
            if let Err(e) = queue_iacs_decision_email(
                &state,
                &request_uuid,
                &auth_user.username,
                false,
                Some(reason),
            )
            .await
            {
                tracing::warn!(
                    request_uuid = %request_uuid,
                    error = %e,
                    "Failed to queue iacs.onboard_rejected email"
                );
            }
            broadcast_iacs_badge(&state).await;
            flash_redirect(
                flash.success("EWS onboarding request rejected.".to_string()),
                "/iacs/admin",
            )
        }
        Err(e) => iacs_error_to_response(e, flash, "/iacs/admin"),
    }
}

/// `POST /iacs/admin/ews/{uuid}/disable`.
#[allow(clippy::too_many_arguments)]
pub async fn iacs_admin_disable(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_manage {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let ews_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::disable(
        &state.access_client,
        &auth_user.uuid,
        &ews_uuid.to_string(),
        actor_ip,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                ews_uuid = %ews_uuid,
                actor = %auth_user.username,
                "IACS EWS disabled"
            );
            flash_redirect(flash.success("EWS disabled.".to_string()), "/iacs/admin")
        }
        Err(e) => iacs_error_to_response(e, flash, "/iacs/admin"),
    }
}

/// `POST /iacs/admin/ews/{uuid}/enable`.
#[allow(clippy::too_many_arguments)]
pub async fn iacs_admin_enable(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_manage {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let ews_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::enable(
        &state.access_client,
        &auth_user.uuid,
        &ews_uuid.to_string(),
        actor_ip,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                ews_uuid = %ews_uuid,
                actor = %auth_user.username,
                "IACS EWS enabled"
            );
            flash_redirect(flash.success("EWS enabled.".to_string()), "/iacs/admin")
        }
        Err(e) => iacs_error_to_response(e, flash, "/iacs/admin"),
    }
}

/// `POST /iacs/admin/ews/{uuid}/offboard`.
#[allow(clippy::too_many_arguments)]
pub async fn iacs_admin_offboard(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    client_addr: crate::middleware::ClientAddr,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<IacsCsrfOnlyForm>,
) -> Response {
    let flash = incoming_flash.flash();
    if !perms.iacs_manage {
        return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !validate_csrf(&state, &jar, &form.csrf_token) {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response();
    }
    let ews_uuid = match Uuid::parse_str(&uuid_str) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    let actor_ip = resolve_actor_ip(&state, &headers, &client_addr);

    match iacs_service::offboard(
        &state.access_client,
        &auth_user.uuid,
        &ews_uuid.to_string(),
        false,
        None,
        actor_ip,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                ews_uuid = %ews_uuid,
                actor = %auth_user.username,
                "IACS EWS offboarded by admin"
            );
            if let Err(e) =
                queue_iacs_offboarded_email(&state, &ews_uuid, &auth_user.username).await
            {
                tracing::warn!(
                    ews_uuid = %ews_uuid,
                    error = %e,
                    "Failed to queue iacs.offboarded email"
                );
            }
            flash_redirect(flash.success("EWS offboarded.".to_string()), "/iacs/admin")
        }
        Err(e) => iacs_error_to_response(e, flash, "/iacs/admin"),
    }
}

// ===================================================================
// Sidebar badge broadcast (palier 8)
// ===================================================================

/// Broadcast an OOB update for the sidebar IACS badge. Mirrors
/// `broadcast_approval_badge` shape:
///
/// 1. Read the count of pending `ews_onboarding_requests` rows.
/// 2. Render an HTMX out-of-band swap targeting `#sidebar-iacs-badge`.
/// 3. Emit on the `notifications` channel (singleton, low-cardinality)
///    since every `iacs_manage`-capable admin already subscribes to
///    it for the JIT approval badge. Also emit on the dedicated
///    `iacs:requests` channel so future per-feature consumers can
///    listen without the global notifications firehose.
///
/// Non-admin pages ignore the swap because the target element is
/// only rendered in the sidebar when `sc.perms.iacs_manage` is true.
pub(crate) async fn broadcast_iacs_badge(state: &AppState) {
    use crate::schema::ews_onboarding_requests;
    let count: i64 = match state.db_pool.get().await {
        Ok(mut conn) => ews_onboarding_requests::table
            .filter(ews_onboarding_requests::status.eq("pending"))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap_or(0),
        Err(_) => return,
    };

    let badge_html = if count > 0 {
        format!(
            r#"<span id="sidebar-iacs-badge" hx-swap-oob="outerHTML" class="ml-auto inline-flex items-center rounded-full bg-vauban-600 px-2 py-0.5 text-xs font-medium text-white">{}</span>"#,
            count
        )
    } else {
        r#"<span id="sidebar-iacs-badge" hx-swap-oob="outerHTML"></span>"#.to_string()
    };

    let _ = state
        .broadcast
        .send_raw("notifications", badge_html.clone())
        .await;
    let _ = state.broadcast.send_raw("iacs:requests", badge_html).await;
}

// ===================================================================
// Admin-zone email helpers
// ===================================================================

/// Queue an `iacs.onboard_approved` or `iacs.onboard_rejected` email
/// to the requester. Best-effort; the decision itself was already
/// recorded when this function runs.
async fn queue_iacs_decision_email(
    state: &AppState,
    request_uuid: &Uuid,
    approver_username: &str,
    approved: bool,
    decision_reason: Option<String>,
) -> Result<(), String> {
    use crate::schema::{ews_onboarding_requests as r, users};
    use crate::services::mailer::{
        EmailEvent, EmailRecipient, IacsOnboardApprovedEvent, IacsOnboardRejectedEvent,
        deterministic_event_id,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let row: Option<(String, String, String, String)> = r::table
        .inner_join(users::table.on(users::id.eq(r::user_id)))
        .filter(r::uuid.eq(*request_uuid))
        .filter(users::email.ne(""))
        .select((
            users::email,
            users::username,
            r::name,
            r::public_key_fingerprint,
        ))
        .first::<(String, String, String, String)>(&mut conn)
        .await
        .ok();
    drop(conn);

    let (email, username, ews_name, fingerprint) = match row {
        Some(r) => r,
        None => return Ok(()),
    };

    let business_key = if approved {
        format!("approved:{}", request_uuid)
    } else {
        format!("rejected:{}", request_uuid)
    };
    let kind = if approved {
        "iacs.onboard_approved"
    } else {
        "iacs.onboard_rejected"
    };
    let event_id = deterministic_event_id(kind, &business_key, &email);
    let my_requests_url = format!("{}/sessions/my-requests", state.config.mailer.base_url);

    let event = if approved {
        EmailEvent::IacsOnboardApproved(IacsOnboardApprovedEvent {
            event_id,
            recipient: EmailRecipient::new(email, username),
            ews_name,
            fingerprint,
            approver_username: approver_username.to_string(),
            my_requests_url,
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        })
    } else {
        EmailEvent::IacsOnboardRejected(IacsOnboardRejectedEvent {
            event_id,
            recipient: EmailRecipient::new(email, username),
            ews_name,
            approver_username: approver_username.to_string(),
            reason: decision_reason.unwrap_or_default(),
            my_requests_url,
            base_url: state.config.mailer.base_url.clone(),
            from_brand: state.config.mailer.from_name.clone(),
        })
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    match state.mailer.queue(&mut conn, &event).await {
        Ok(()) | Err(crate::services::mailer::MailerError::Duplicate) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Queue an `iacs.offboarded` email to the EWS owner. Skipped on
/// auto-offboard (the owner already knows -- they triggered it).
async fn queue_iacs_offboarded_email(
    state: &AppState,
    ews_uuid: &Uuid,
    admin_username: &str,
) -> Result<(), String> {
    use crate::schema::{ews, users};
    use crate::services::mailer::{
        EmailEvent, EmailRecipient, IacsOffboardedEvent, deterministic_event_id,
    };

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    let row: Option<(String, String, String, String)> = ews::table
        .inner_join(users::table.on(users::id.eq(ews::user_id)))
        .filter(ews::uuid.eq(*ews_uuid))
        .filter(users::email.ne(""))
        .select((
            users::email,
            users::username,
            ews::name,
            ews::public_key_fingerprint,
        ))
        .first::<(String, String, String, String)>(&mut conn)
        .await
        .ok();
    drop(conn);

    let (email, username, ews_name, fingerprint) = match row {
        Some(r) => r,
        None => return Ok(()),
    };

    let business_key = format!("offboarded:{}", ews_uuid);
    let event_id = deterministic_event_id("iacs.offboarded", &business_key, &email);
    let event = EmailEvent::IacsOffboarded(IacsOffboardedEvent {
        event_id,
        recipient: EmailRecipient::new(email, username),
        ews_name,
        fingerprint,
        admin_username: admin_username.to_string(),
        base_url: state.config.mailer.base_url.clone(),
        from_brand: state.config.mailer.from_name.clone(),
    });

    let mut conn = state.db_pool.get().await.map_err(|e| e.to_string())?;
    match state.mailer.queue(&mut conn, &event).await {
        Ok(()) | Err(crate::services::mailer::MailerError::Duplicate) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
