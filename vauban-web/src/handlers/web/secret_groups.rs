/// Web CRUD handlers for secret groups (`/vault/secrets/groups`).
///
/// Entity CRUD is 100% IPC (vauban-access is the oracle); only the
/// `secret_secret_groups` junction is driven in direct Diesel, exactly
/// like `asset_asset_groups` on the asset side.
///
/// The virtual "All secrets" group is guarded at three layers: the UUID
/// short-circuit below, the IPC handlers in vauban-access, and the
/// Postgres triggers.
use super::*;

use crate::templates::secrets::{
    GroupSecretItem, SecretGroupCreateTemplate, SecretGroupDetailData, SecretGroupDetailTemplate,
    SecretGroupEditData, SecretGroupEditTemplate, SecretGroupForm, SecretGroupItem,
    SecretGroupListTemplate, SecretOption,
};

/// Returns `true` if the given UUID string matches the singleton virtual
/// "All secrets" group. Canonicalised through `Uuid::parse_str` so case /
/// whitespace cannot bypass it.
fn is_virtual_secret_group_uuid(uuid_str: &str) -> bool {
    use shared::messages::ALL_SECRETS_GROUP_UUID;
    match (
        ::uuid::Uuid::parse_str(uuid_str),
        ::uuid::Uuid::parse_str(ALL_SECRETS_GROUP_UUID),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn format_rfc3339_local(s: &str, tz: chrono_tz::Tz) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| crate::utils::format_local(d.with_timezone(&chrono::Utc), tz))
        .unwrap_or_else(|_| s.to_string())
}

// ============================================================================
// Form structs
// ============================================================================

#[derive(Debug, serde::Deserialize)]
pub struct SecretGroupWebForm {
    pub csrf_token: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteSecretGroupWebForm {
    pub csrf_token: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct AddSecretToGroupWebForm {
    pub csrf_token: String,
    pub secret_uuid: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct RemoveSecretFromGroupWebForm {
    pub csrf_token: String,
}

// ============================================================================
// LIST
// ============================================================================

pub async fn secret_group_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::services::list_filters::{
        matches_search, opt_filter, paginate, parse_page, slice_page,
    };

    if !perms.vault_secrets_manage {
        return Err(AppError::forbidden("vault_secrets:manage"));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Secret Groups".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/vault/secrets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Live filter (issue #28 pattern): in-memory search on the
    // IPC-returned catalogue, like /accounts/groups.
    let search_filter = opt_filter(&params, "search");

    // Virtual group intentionally excluded: it is not a browsable entity.
    let mut infos = state.access_client.list_secret_groups().await?;
    infos.sort_by_key(|g| g.name.to_lowercase());
    let groups: Vec<SecretGroupItem> = infos
        .into_iter()
        .filter(|g| {
            matches_search(
                &[g.name.as_str(), g.slug.as_str()],
                search_filter.as_deref(),
            )
        })
        .map(|g| SecretGroupItem {
            uuid: g.uuid,
            name: g.name,
            slug: g.slug,
            description: g.description,
            member_count: g.member_count,
            created_at: format_rfc3339_local(&g.created_at, browser_tz.0),
        })
        .collect();

    const GROUPS_PER_PAGE: usize = 30;
    let page = parse_page(&params);
    let total_items = groups.len();
    let window = paginate(total_items, page, GROUPS_PER_PAGE);
    let groups = slice_page(groups, &window);
    let pagination = (total_items > 0).then(|| window.to_pagination());

    let template = SecretGroupListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        groups,
        search: search_filter,
        pagination,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ============================================================================
// CREATE FORM (GET) + CREATE (POST)
// ============================================================================

pub async fn secret_group_create_form(
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
    let base = BaseTemplate::new("New Secret Group".to_string(), user.clone(), browser_tz.0)
        .with_current_path("/vault/secrets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretGroupCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form: SecretGroupForm::default(),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render form"),
                "/vault/secrets/groups",
            )
        }
    }
}

pub async fn create_secret_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<SecretGroupWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token"),
            "/vault/secrets/groups/new",
        );
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if form.name.trim().is_empty() || form.slug.trim().is_empty() {
        return flash_redirect(
            flash.error("Name and slug are required"),
            "/vault/secrets/groups/new",
        );
    }

    // Closed-format field: validate BEFORE any IPC/DB write.
    if let Err(msg) = super::validate_slug_format("Group slug", form.slug.trim()) {
        return flash_redirect(flash.error(msg), "/vault/secrets/groups/new");
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_slug = sanitize(form.slug.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));

    match state
        .access_client
        .create_secret_group(
            &sanitized_name,
            &sanitized_slug,
            sanitized_desc,
            Some(auth_user.uuid.clone()),
        )
        .await
    {
        Ok(info) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretGroupCreated,
                    format!(r#"{{"group":"{}","name":"{}"}}"#, info.uuid, sanitized_name),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret group '{}' created", sanitized_name)),
                &format!("/vault/secrets/groups/{}", info.uuid),
            )
        }
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error("A secret group with this name or slug already exists"),
                "/vault/secrets/groups/new",
            )
        }
        Err(e) => {
            tracing::error!("Failed to create secret group: {}", e);
            flash_redirect(
                flash.error("Failed to create secret group"),
                "/vault/secrets/groups/new",
            )
        }
    }
}

// ============================================================================
// DETAIL
// ============================================================================

pub async fn secret_group_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    use crate::schema::{secret_secret_groups, vault_secrets};
    let flash = incoming_flash.flash();

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    }

    // The virtual "All secrets" group is system-managed and never
    // directly browsable (anti-tamper: it has no membership to edit).
    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("Secret group not found"),
            "/vault/secrets/groups",
        );
    }

    let info = match state.access_client.get_secret_group(&uuid_str).await {
        Ok(i) => i,
        Err(_) => {
            return flash_redirect(
                flash.error("Secret group not found"),
                "/vault/secrets/groups",
            );
        }
    };

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                "/vault/secrets/groups",
            );
        }
    };

    let member_rows: Vec<crate::models::vault_secret::VaultSecret> = vault_secrets::table
        .inner_join(
            secret_secret_groups::table.on(vault_secrets::id.eq(secret_secret_groups::secret_id)),
        )
        .filter(secret_secret_groups::secret_group_id.eq(info.id))
        .select(crate::models::vault_secret::VaultSecret::as_select())
        .order(vault_secrets::name.asc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let member_ids: Vec<i32> = member_rows.iter().map(|s| s.id).collect();
    let available: Vec<(::uuid::Uuid, String)> = vault_secrets::table
        .filter(vault_secrets::id.ne_all(&member_ids))
        .select((vault_secrets::uuid, vault_secrets::name))
        .order(vault_secrets::name.asc())
        .load(&mut conn)
        .await
        .unwrap_or_default();

    let group = SecretGroupDetailData {
        uuid: info.uuid,
        name: info.name.clone(),
        slug: info.slug,
        description: info.description,
        created_at: format_rfc3339_local(&info.created_at, browser_tz.0),
        updated_at: format_rfc3339_local(&info.updated_at, browser_tz.0),
        secrets: member_rows
            .into_iter()
            .map(|s| GroupSecretItem {
                uuid: s.uuid.to_string(),
                name: s.name,
                version: s.version,
                is_active: s.is_active,
            })
            .collect(),
        available_secrets: available
            .into_iter()
            .map(|(u, n)| SecretOption {
                uuid: u.to_string(),
                name: n,
            })
            .collect(),
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("{} - Secret Group", info.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretGroupDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render page"),
                "/vault/secrets/groups",
            )
        }
    }
}

// ============================================================================
// EDIT FORM (GET) + UPDATE (POST)
// ============================================================================

pub async fn secret_group_edit(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    }
    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("Secret group not found"),
            "/vault/secrets/groups",
        );
    }

    let info = match state.access_client.get_secret_group(&uuid_str).await {
        Ok(i) => i,
        Err(_) => {
            return flash_redirect(
                flash.error("Secret group not found"),
                "/vault/secrets/groups",
            );
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("Edit {} - Secret Group", info.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/groups");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretGroupEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        group: SecretGroupEditData {
            uuid: info.uuid,
            name: info.name,
            slug: info.slug,
            description: info.description.unwrap_or_default(),
        },
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render form"),
                "/vault/secrets/groups",
            )
        }
    }
}

pub async fn update_secret_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<SecretGroupWebForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let edit_url = format!("/vault/secrets/groups/{}/edit", uuid_str);

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

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    }
    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("The virtual secret group cannot be modified"),
            "/vault/secrets/groups",
        );
    }

    if form.name.trim().is_empty() || form.slug.trim().is_empty() {
        return flash_redirect(flash.error("Name and slug are required"), &edit_url);
    }

    // Closed-format field: validate BEFORE any IPC/DB write.
    if let Err(msg) = super::validate_slug_format("Group slug", form.slug.trim()) {
        return flash_redirect(flash.error(msg), &edit_url);
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_slug = sanitize(form.slug.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));

    match state
        .access_client
        .update_secret_group(
            &uuid_str,
            &sanitized_name,
            &sanitized_slug,
            sanitized_desc,
            Some(auth_user.uuid.clone()),
        )
        .await
    {
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretGroupUpdated,
                    format!(r#"{{"group":"{}","name":"{}"}}"#, uuid_str, sanitized_name),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret group '{}' updated", sanitized_name)),
                &format!("/vault/secrets/groups/{}", uuid_str),
            )
        }
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => flash_redirect(
            flash.error("Secret group not found"),
            "/vault/secrets/groups",
        ),
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error("A secret group with this name or slug already exists"),
                &edit_url,
            )
        }
        Err(e) => {
            tracing::error!("Failed to update secret group: {}", e);
            flash_redirect(flash.error("Failed to update secret group"), &edit_url)
        }
    }
}

// ============================================================================
// DELETE (POST)
// ============================================================================

pub async fn delete_secret_group_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteSecretGroupWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(
            flash.error("Invalid CSRF token"),
            &format!("/vault/secrets/groups/{}", uuid_str),
        );
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    }
    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("The virtual secret group cannot be deleted"),
            "/vault/secrets/groups",
        );
    }

    match state.access_client.delete_secret_group(&uuid_str).await {
        Ok(()) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretGroupDeleted,
                    format!(r#"{{"group":"{}"}}"#, uuid_str),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success("Secret group deleted"),
                "/vault/secrets/groups",
            )
        }
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => flash_redirect(
            flash.error("Secret group not found"),
            "/vault/secrets/groups",
        ),
        Err(e) => {
            tracing::error!("Failed to delete secret group: {}", e);
            flash_redirect(
                flash.error("Failed to delete secret group"),
                &format!("/vault/secrets/groups/{}", uuid_str),
            )
        }
    }
}

// ============================================================================
// MEMBERSHIP (junction in direct Diesel, like asset_asset_groups)
// ============================================================================

pub async fn secret_group_add_secret(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<AddSecretToGroupWebForm>,
) -> Response {
    use crate::schema::{secret_groups, secret_secret_groups, vault_secrets};
    let flash = incoming_flash.flash();
    let detail_url = format!("/vault/secrets/groups/{}", uuid_str);

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), &detail_url);
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let (Ok(group_uuid), Ok(secret_uuid)) = (
        ::uuid::Uuid::parse_str(&uuid_str),
        ::uuid::Uuid::parse_str(&form.secret_uuid),
    ) else {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    };

    // Layer 1 of 3 (handler guard; IPC + DB trigger back it up).
    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("The virtual secret group has no editable membership"),
            "/vault/secrets/groups",
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &detail_url,
            );
        }
    };

    let group_id: i32 = match secret_groups::table
        .filter(secret_groups::uuid.eq(group_uuid))
        .select(secret_groups::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return flash_redirect(
                flash.error("Secret group not found"),
                "/vault/secrets/groups",
            );
        }
    };
    let secret_id: i32 = match vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .select(vault_secrets::id)
        .first(&mut conn)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return flash_redirect(flash.error("Secret not found"), &detail_url);
        }
    };

    match diesel::insert_into(secret_secret_groups::table)
        .values((
            secret_secret_groups::secret_id.eq(secret_id),
            secret_secret_groups::secret_group_id.eq(group_id),
        ))
        .on_conflict_do_nothing()
        .execute(&mut conn)
        .await
    {
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretGroupMemberAdded,
                    format!(r#"{{"group":"{}","secret":"{}"}}"#, group_uuid, secret_uuid),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(flash.success("Secret added to group"), &detail_url)
        }
        Err(e) => {
            tracing::error!("Failed to add secret to group: {}", e);
            flash_redirect(flash.error("Failed to add secret to group"), &detail_url)
        }
    }
}

pub async fn secret_group_remove_secret(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path((uuid_str, secret_uuid_str)): axum::extract::Path<(String, String)>,
    Form(form): Form<RemoveSecretFromGroupWebForm>,
) -> Response {
    use crate::schema::{secret_groups, secret_secret_groups, vault_secrets};
    let flash = incoming_flash.flash();
    let detail_url = format!("/vault/secrets/groups/{}", uuid_str);

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), &detail_url);
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    let (Ok(group_uuid), Ok(secret_uuid)) = (
        ::uuid::Uuid::parse_str(&uuid_str),
        ::uuid::Uuid::parse_str(&secret_uuid_str),
    ) else {
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/groups");
    };

    if is_virtual_secret_group_uuid(&uuid_str) {
        return flash_redirect(
            flash.error("The virtual secret group has no editable membership"),
            "/vault/secrets/groups",
        );
    }

    let mut conn = match state.db_pool.get().await {
        Ok(c) => c,
        Err(_) => {
            return flash_redirect(
                flash.error("Database connection error. Please try again."),
                &detail_url,
            );
        }
    };

    let group_id_sub = secret_groups::table
        .filter(secret_groups::uuid.eq(group_uuid))
        .select(secret_groups::id)
        .single_value();
    let secret_id_sub = vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid))
        .select(vault_secrets::id)
        .single_value();

    match diesel::delete(
        secret_secret_groups::table
            .filter(
                secret_secret_groups::secret_group_id
                    .nullable()
                    .eq(group_id_sub),
            )
            .filter(secret_secret_groups::secret_id.nullable().eq(secret_id_sub)),
    )
    .execute(&mut conn)
    .await
    {
        Ok(0) => flash_redirect(flash.error("Membership not found"), &detail_url),
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretGroupMemberRemoved,
                    format!(r#"{{"group":"{}","secret":"{}"}}"#, group_uuid, secret_uuid),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(flash.success("Secret removed from group"), &detail_url)
        }
        Err(e) => {
            tracing::error!("Failed to remove secret from group: {}", e);
            flash_redirect(
                flash.error("Failed to remove secret from group"),
                &detail_url,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_secret_group_uuid_is_detected_case_insensitively() {
        assert!(is_virtual_secret_group_uuid(
            shared::messages::ALL_SECRETS_GROUP_UUID
        ));
        assert!(is_virtual_secret_group_uuid(
            &shared::messages::ALL_SECRETS_GROUP_UUID.to_uppercase()
        ));
        assert!(!is_virtual_secret_group_uuid(
            "11111111-1111-1111-1111-111111111111"
        ));
        assert!(!is_virtual_secret_group_uuid("not-a-uuid"));
    }
}
