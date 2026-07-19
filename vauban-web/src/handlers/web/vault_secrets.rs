/// Web CRUD handlers for organisational vault secrets (`/vault/secrets`).
///
/// Admin zone, self-contained (issue: Vault Secrets section). Defence in
/// depth: the whole nest carries
/// `route_layer(require_vault_secrets_manage)` AND every handler body
/// re-checks `perms.vault_secrets_manage`.
///
/// SECURITY invariants:
/// - The secret VALUE is write-only: encrypted with the dedicated
///   `"secrets"` vault domain at persistence, never re-displayed (no
///   template in `templates/secrets/` carries a value), empty value on
///   edit means "keep".
/// - A value change bumps `version` so API consumers can detect
///   rotation.
/// - Plaintext is capped at 16 KiB.
/// - Delete is a hard delete; the WORM audit trail is the trace.
use super::*;

use crate::templates::secrets::{
    SecretCreateForm, SecretCreateTemplate, SecretDetailData, SecretDetailTemplate, SecretEditData,
    SecretEditTemplate, SecretGroupRef, SecretItem, SecretListTemplate,
};

/// Maximum plaintext size for a secret value (16 KiB).
pub(crate) const MAX_SECRET_VALUE_BYTES: usize = 16 * 1024;

// ============================================================================
// Form structs
// ============================================================================

#[derive(Debug, serde::Deserialize)]
pub struct CreateVaultSecretWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
    pub value: String,
    pub is_active: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateVaultSecretWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
    /// Empty = keep the stored ciphertext; non-empty = re-encrypt + bump
    /// `version`.
    pub value: Option<String>,
    pub is_active: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteVaultSecretWebForm {
    pub csrf_token: String,
}

// ============================================================================
// Helpers
// ============================================================================

/// Encrypt a plaintext secret value through the dedicated `"secrets"`
/// vault domain. Same posture as `encrypt_connection_config`: without a
/// vault client (dev/tests) the value is stored as-is; the `vN:`
/// envelope is exclusively produced/consumed by the vault.
async fn seal_secret_value(state: &AppState, plaintext: &str) -> Result<String, AppError> {
    match &state.vault_client {
        Some(vault) => vault.encrypt("secrets", plaintext).await,
        None => Ok(plaintext.to_string()),
    }
}

// ============================================================================
// LIST
// ============================================================================

pub async fn vault_secrets_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::{secret_secret_groups, vault_secrets};
    use crate::services::list_filters::{opt_filter, paginate, parse_page};

    if !perms.vault_secrets_manage {
        return Err(AppError::forbidden("vault_secrets:manage"));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Vault Secrets".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/vault/secrets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    // Live filters (issue #28 pattern): search over name/description
    // (ILIKE, wildcards escaped by `like_contains`) + status select.
    let search_filter = opt_filter(&params, "search");
    let status_filter = opt_filter(&params, "status");
    let page = parse_page(&params);

    const SECRETS_PER_PAGE: usize = 30;

    let mut count_query = vault_secrets::table.into_boxed();
    let mut query = vault_secrets::table.into_boxed();
    if let Some(ref search) = search_filter {
        let pattern = crate::db::like_contains(search);
        count_query = count_query.filter(
            vault_secrets::name
                .ilike(pattern.clone())
                .or(vault_secrets::description.ilike(pattern.clone())),
        );
        query = query.filter(
            vault_secrets::name
                .ilike(pattern.clone())
                .or(vault_secrets::description.ilike(pattern)),
        );
    }
    if let Some(active) =
        crate::services::list_filters::parse_active_inactive(status_filter.as_deref())
    {
        count_query = count_query.filter(vault_secrets::is_active.eq(active));
        query = query.filter(vault_secrets::is_active.eq(active));
    }

    let total_items: i64 = count_query.count().get_result(&mut conn).await.unwrap_or(0);
    let window = paginate(
        usize::try_from(total_items).unwrap_or(0),
        page,
        SECRETS_PER_PAGE,
    );

    let rows: Vec<crate::models::vault_secret::VaultSecret> = query
        .order(vault_secrets::name.asc())
        .limit(window.limit_i64())
        .offset(window.offset_i64())
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let group_counts: std::collections::HashMap<i32, i64> = secret_secret_groups::table
        .group_by(secret_secret_groups::secret_id)
        .select((
            secret_secret_groups::secret_id,
            diesel::dsl::count(secret_secret_groups::secret_group_id),
        ))
        .load::<(i32, i64)>(&mut conn)
        .await
        .map_err(AppError::Database)?
        .into_iter()
        .collect();

    let secrets: Vec<SecretItem> = rows
        .into_iter()
        .map(|s| SecretItem {
            uuid: s.uuid.to_string(),
            name: s.name,
            description: s.description,
            version: s.version,
            is_active: s.is_active,
            group_count: group_counts.get(&s.id).copied().unwrap_or(0),
            updated_at: crate::utils::format_local(s.updated_at, browser_tz.0),
        })
        .collect();

    let pagination = (total_items > 0).then(|| window.to_pagination());

    let template = SecretListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        secrets,
        pagination,
        search: search_filter,
        status_filter,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ============================================================================
// CREATE FORM (GET) + CREATE (POST)
// ============================================================================

pub async fn vault_secret_create_form(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New Vault Secret".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/vault/secrets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form: SecretCreateForm {
            is_active: true,
            ..Default::default()
        },
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(flash.error("Failed to render form"), "/vault/secrets")
        }
    }
}

pub async fn create_vault_secret_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateVaultSecretWebForm>,
) -> Response {
    use crate::schema::vault_secrets;
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), "/vault/secrets/new");
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Secret name is required"), "/vault/secrets/new");
    }
    // The name is the machine-facing lookup key of the M2M API:
    // enforce the slug grammar BEFORE any DB write.
    if let Err(msg) = super::validate_slug_format("Secret name", form.name.trim()) {
        return flash_redirect(flash.error(msg), "/vault/secrets/new");
    }
    if form.value.is_empty() {
        return flash_redirect(
            flash.error("Secret value is required"),
            "/vault/secrets/new",
        );
    }
    if form.value.len() > MAX_SECRET_VALUE_BYTES {
        return flash_redirect(
            flash.error("Secret value exceeds the 16 KiB limit"),
            "/vault/secrets/new",
        );
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));

    let ciphertext = match seal_secret_value(&state, &form.value).await {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!("Failed to encrypt vault secret value: {}", e);
            return flash_redirect(
                flash.error("Failed to encrypt the secret value"),
                "/vault/secrets/new",
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/vault/secrets/new",
            );
        }
    };

    let actor_id: Option<i32> = {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()))
            .select(users::id)
            .first(&mut conn)
            .await
            .ok()
    };

    let new_secret = crate::models::vault_secret::NewVaultSecret {
        uuid: ::uuid::Uuid::new_v4(),
        name: sanitized_name.clone(),
        description: sanitized_desc,
        ciphertext,
        is_active: form.is_active.is_some(),
        created_by_id: actor_id,
        updated_by_id: actor_id,
    };

    let inserted_uuid: Result<::uuid::Uuid, _> = diesel::insert_into(vault_secrets::table)
        .values(&new_secret)
        .returning(vault_secrets::uuid)
        .get_result(&mut conn)
        .await;

    match inserted_uuid {
        Ok(secret_uuid) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::VaultSecretCreated,
                    format!(
                        r#"{{"secret":"{}","name":"{}"}}"#,
                        secret_uuid, sanitized_name
                    ),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret '{}' created", sanitized_name)),
                &format!("/vault/secrets/{}", secret_uuid),
            )
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => flash_redirect(
            flash.error("A secret with this name already exists"),
            "/vault/secrets/new",
        ),
        Err(e) => {
            tracing::error!("Failed to create vault secret: {}", e);
            flash_redirect(flash.error("Failed to create secret"), "/vault/secrets/new")
        }
    }
}

// ============================================================================
// DETAIL
// ============================================================================

pub async fn vault_secret_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    use crate::schema::{secret_groups, secret_secret_groups, vault_secrets};
    let flash = incoming_flash.flash();

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let Ok(parsed_uuid) = ::uuid::Uuid::parse_str(&uuid_str) else {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets");
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/vault/secrets",
            );
        }
    };

    let secret: crate::models::vault_secret::VaultSecret = match vault_secrets::table
        .filter(vault_secrets::uuid.eq(parsed_uuid))
        .first(&mut conn)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return flash_redirect(flash.error("Secret not found"), "/vault/secrets");
        }
    };

    let groups: Vec<SecretGroupRef> = secret_groups::table
        .inner_join(
            secret_secret_groups::table
                .on(secret_groups::id.eq(secret_secret_groups::secret_group_id)),
        )
        .filter(secret_secret_groups::secret_id.eq(secret.id))
        .select((secret_groups::uuid, secret_groups::name))
        .order(secret_groups::name.asc())
        .load::<(::uuid::Uuid, String)>(&mut conn)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(u, n)| SecretGroupRef {
            uuid: u.to_string(),
            name: n,
        })
        .collect();

    let (created_by, updated_by) = crate::services::audit_authors::resolve_audit_pair(
        &mut conn,
        secret.created_by_id,
        secret.updated_by_id,
    )
    .await;

    let detail = SecretDetailData {
        uuid: secret.uuid.to_string(),
        name: secret.name.clone(),
        description: secret.description.clone(),
        version: secret.version,
        is_active: secret.is_active,
        created_at: crate::utils::format_local(secret.created_at, browser_tz.0),
        updated_at: crate::utils::format_local(secret.updated_at, browser_tz.0),
        created_by: created_by.map(|a| a.label()),
        updated_by: updated_by.map(|a| a.label()),
        groups,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("{} - Vault Secret", secret.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        secret: detail,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(flash.error("Failed to render page"), "/vault/secrets")
        }
    }
}

// ============================================================================
// EDIT FORM (GET) + UPDATE (POST)
// ============================================================================

pub async fn vault_secret_edit(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    use crate::schema::vault_secrets;
    let flash = incoming_flash.flash();

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let Ok(parsed_uuid) = ::uuid::Uuid::parse_str(&uuid_str) else {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets");
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/vault/secrets",
            );
        }
    };

    let secret: crate::models::vault_secret::VaultSecret = match vault_secrets::table
        .filter(vault_secrets::uuid.eq(parsed_uuid))
        .first(&mut conn)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return flash_redirect(flash.error("Secret not found"), "/vault/secrets");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("Edit {} - Vault Secret", secret.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        secret: SecretEditData {
            uuid: secret.uuid.to_string(),
            name: secret.name.clone(),
            description: secret.description.clone().unwrap_or_default(),
            is_active: secret.is_active,
            version: secret.version,
        },
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(flash.error("Failed to render form"), "/vault/secrets")
        }
    }
}

pub async fn update_vault_secret_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<UpdateVaultSecretWebForm>,
) -> Response {
    use crate::schema::vault_secrets;
    let flash = incoming_flash.flash();
    let edit_url = format!("/vault/secrets/{}/edit", uuid_str);

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), &edit_url);
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let Ok(parsed_uuid) = ::uuid::Uuid::parse_str(&uuid_str) else {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets");
    };

    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Secret name is required"), &edit_url);
    }
    // The name is the machine-facing lookup key of the M2M API:
    // enforce the slug grammar BEFORE any DB write.
    if let Err(msg) = super::validate_slug_format("Secret name", form.name.trim()) {
        return flash_redirect(flash.error(msg), &edit_url);
    }

    let new_value = form.value.as_deref().filter(|v| !v.is_empty());
    if let Some(v) = new_value
        && v.len() > MAX_SECRET_VALUE_BYTES
    {
        return flash_redirect(
            flash.error("Secret value exceeds the 16 KiB limit"),
            &edit_url,
        );
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));
    let is_active = form.is_active.is_some();

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &edit_url,
            );
        }
    };

    let actor_id: Option<i32> = {
        use crate::schema::users;
        users::table
            .filter(users::uuid.eq(::uuid::Uuid::parse_str(&auth_user.uuid).unwrap_or_default()))
            .select(users::id)
            .first(&mut conn)
            .await
            .ok()
    };

    // Two shapes: metadata-only update (value untouched, version kept) vs
    // value rotation (re-encrypt + version bump). Split so a
    // description-only edit does not re-encrypt (and does not rotate).
    let result = if let Some(plaintext) = new_value {
        let ciphertext = match seal_secret_value(&state, plaintext).await {
            Ok(ct) => ct,
            Err(e) => {
                tracing::error!("Failed to encrypt vault secret value: {}", e);
                return flash_redirect(
                    flash.error("Failed to encrypt the secret value"),
                    &edit_url,
                );
            }
        };
        diesel::update(vault_secrets::table.filter(vault_secrets::uuid.eq(parsed_uuid)))
            .set((
                vault_secrets::name.eq(&sanitized_name),
                vault_secrets::description.eq(&sanitized_desc),
                vault_secrets::ciphertext.eq(&ciphertext),
                vault_secrets::version.eq(vault_secrets::version + 1),
                vault_secrets::is_active.eq(is_active),
                vault_secrets::updated_by_id.eq(actor_id),
                vault_secrets::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
            .await
    } else {
        diesel::update(vault_secrets::table.filter(vault_secrets::uuid.eq(parsed_uuid)))
            .set((
                vault_secrets::name.eq(&sanitized_name),
                vault_secrets::description.eq(&sanitized_desc),
                vault_secrets::is_active.eq(is_active),
                vault_secrets::updated_by_id.eq(actor_id),
                vault_secrets::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut conn)
            .await
    };

    match result {
        Ok(0) => flash_redirect(flash.error("Secret not found"), "/vault/secrets"),
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::VaultSecretUpdated,
                    format!(
                        r#"{{"secret":"{}","name":"{}","value_rotated":{}}}"#,
                        uuid_str,
                        sanitized_name,
                        new_value.is_some()
                    ),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret '{}' updated", sanitized_name)),
                &format!("/vault/secrets/{}", uuid_str),
            )
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => flash_redirect(
            flash.error("A secret with this name already exists"),
            &edit_url,
        ),
        Err(e) => {
            tracing::error!("Failed to update vault secret: {}", e);
            flash_redirect(flash.error("Failed to update secret"), &edit_url)
        }
    }
}

// ============================================================================
// DELETE (POST) — hard delete, the WORM audit trail is the trace
// ============================================================================

// Speaks both dialects (BUG-12): plain forms get 303 + Location, HTMX
// requests get 200 + HX-Redirect. The delete form on the detail page is
// HTMX-driven (styled deleteConfirm modal) since the CSP hardening.
#[allow(clippy::too_many_arguments)]
pub async fn delete_vault_secret_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteVaultSecretWebForm>,
) -> Response {
    use crate::schema::vault_secrets;
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid CSRF token"),
            &format!("/vault/secrets/{}", uuid_str),
        );
    }

    if !perms.vault_secrets_manage {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let Ok(parsed_uuid) = ::uuid::Uuid::parse_str(&uuid_str) else {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid identifier"),
            "/vault/secrets",
        );
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return htmx_or_flash_redirect(
                &headers,
                flash.error("Database connection error. Please try again."),
                "/vault/secrets",
            );
        }
    };

    match diesel::delete(vault_secrets::table.filter(vault_secrets::uuid.eq(parsed_uuid)))
        .execute(&mut conn)
        .await
    {
        Ok(0) => {
            htmx_or_flash_redirect(&headers, flash.error("Secret not found"), "/vault/secrets")
        }
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::VaultSecretDeleted,
                    format!(r#"{{"secret":"{}"}}"#, uuid_str),
                )
                .user(auth_user.uuid.clone()),
            );
            htmx_or_flash_redirect(&headers, flash.success("Secret deleted"), "/vault/secrets")
        }
        Err(e) => {
            tracing::error!("Failed to delete vault secret: {}", e);
            htmx_or_flash_redirect(
                &headers,
                flash.error("Failed to delete secret"),
                &format!("/vault/secrets/{}", uuid_str),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_secret_value_is_16_kib() {
        assert_eq!(MAX_SECRET_VALUE_BYTES, 16384);
    }
}
