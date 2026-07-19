/// Web CRUD handlers for secret access rules (`/vault/secrets/access`).
///
/// 100% IPC: vauban-access is the single oracle for `secret_access_rules`
/// (no `secret_access_rules::table` Diesel access in vauban-web, pinned
/// by `tests/web/vault_secrets_pins_test`). Mirror of the asset access
/// rules pages, but deliberately leaner: no protocols, no MFA, no JIT.
use super::*;

use crate::handlers::web::access_rules::{
    format_rfc3339_str_to_display, format_rfc3339_to_display, format_rfc3339_to_local,
    parse_datetime, to_rfc3339_opt,
};
use crate::templates::secrets::{
    SecretGroupOption, SecretRuleCreateTemplate, SecretRuleDetailData, SecretRuleDetailTemplate,
    SecretRuleEditData, SecretRuleEditTemplate, SecretRuleForm, SecretRuleItem,
    SecretRuleListTemplate,
};
use shared::messages::{
    ASSET_GROUP_KIND_ALL, SECRET_GROUP_KIND_ALL, SecretAccessRuleData, SecretAccessRuleInfo,
};

/// Map IPC `GroupOption`s to the rule-editor dropdown options, virtual
/// entries first (mirrors the asset rule editor ordering). The `kind`
/// vocabulary is shared between secret groups and asset groups
/// (`static` / `all`), so one mapper serves all three dropdowns.
fn map_secret_group_options(opts: Vec<shared::messages::GroupOption>) -> Vec<SecretGroupOption> {
    let mut mapped: Vec<SecretGroupOption> = opts
        .into_iter()
        .map(|g| SecretGroupOption {
            id: g.id,
            name: g.name,
            is_virtual: g.kind == SECRET_GROUP_KIND_ALL,
        })
        .collect();
    mapped.sort_by(|a, b| match (a.is_virtual, b.is_virtual) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    mapped
}

/// Load the three dropdowns for the rule editor: user groups (never
/// virtual), secret groups INCLUDING the virtual "All secrets" entry,
/// and asset groups INCLUDING the virtual "All assets" entry
/// (provenance dimension).
async fn load_rule_editor_options(
    state: &AppState,
) -> Result<
    (
        Vec<SecretGroupOption>,
        Vec<SecretGroupOption>,
        Vec<SecretGroupOption>,
    ),
    AppError,
> {
    let (groups_res, secret_groups_res) = tokio::join!(
        state.access_client.get_group_options_with_virtual(),
        state.access_client.list_secret_group_options(true),
    );
    let (user_groups, asset_groups) = groups_res?;
    let secret_groups = secret_groups_res?;
    Ok((
        map_secret_group_options(user_groups),
        map_secret_group_options(secret_groups),
        map_secret_group_options(asset_groups),
    ))
}

/// Eclipse lint (pure function, table-driven-tested): the set of rule
/// UUIDs whose asset-group restriction is moot because another ACTIVE
/// rule grants the same user group a covering secret group (same group
/// or the virtual "All secrets") from the virtual "All assets"
/// provenance.
///
/// A rule whose own asset group IS the virtual "All assets" is never
/// flagged (there is nothing narrower to eclipse).
pub(crate) fn eclipsed_rule_uuids(
    rules: &[SecretAccessRuleInfo],
) -> std::collections::HashSet<String> {
    use shared::messages::ALL_SECRETS_GROUP_UUID;

    let mut eclipsed = std::collections::HashSet::new();
    for r in rules {
        if r.asset_group_kind == ASSET_GROUP_KIND_ALL {
            continue;
        }
        let covered = rules.iter().any(|s| {
            s.uuid != r.uuid
                && s.is_active
                && s.user_group_id == r.user_group_id
                && s.asset_group_kind == ASSET_GROUP_KIND_ALL
                && (s.secret_group_id == r.secret_group_id
                    || s.secret_group_uuid == ALL_SECRETS_GROUP_UUID)
        });
        if covered {
            eclipsed.insert(r.uuid.clone());
        }
    }
    eclipsed
}

// ============================================================================
// Form structs
// ============================================================================

#[derive(Debug, serde::Deserialize)]
pub struct SecretAccessRuleWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub secret_group_id: i32,
    pub asset_group_id: i32,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub is_active: Option<String>,
    pub priority: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteSecretAccessRuleWebForm {
    pub csrf_token: String,
}

// ============================================================================
// LIST
// ============================================================================

pub async fn secret_access_rules_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    use crate::services::list_filters::{
        distinct_sorted, matches_bool, matches_search, matches_select, opt_filter, paginate,
        parse_active_inactive, parse_page, slice_page,
    };

    if !perms.vault_secrets_manage {
        return Err(AppError::forbidden("vault_secrets:manage"));
    }

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        "Secret Access Rules".to_string(),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    // Live filters (issue #28 pattern): in-memory predicates on the
    // IPC-returned rule set. The select options are derived from the
    // FULL (unfiltered) set so they never shrink while filtering.
    let search_filter = opt_filter(&params, "search");
    let user_group_filter = opt_filter(&params, "user_group");
    let secret_group_filter = opt_filter(&params, "secret_group");
    let asset_group_filter = opt_filter(&params, "asset_group");
    let status_filter = opt_filter(&params, "status");
    let eclipsed_filter = opt_filter(&params, "eclipsed");
    let active_wanted = parse_active_inactive(status_filter.as_deref());
    let eclipsed_wanted = crate::services::list_filters::parse_yes_no(eclipsed_filter.as_deref());

    let mut infos = state.access_client.list_secret_access_rules().await?;
    infos.sort_by_key(|r| r.name.to_lowercase());
    let eclipsed = eclipsed_rule_uuids(&infos);

    let user_groups = distinct_sorted(infos.iter().map(|r| r.user_group_name.as_str()));
    let secret_groups = distinct_sorted(infos.iter().map(|r| r.secret_group_name.as_str()));
    let asset_groups = distinct_sorted(infos.iter().map(|r| r.asset_group_name.as_str()));

    let rules: Vec<SecretRuleItem> = infos
        .into_iter()
        .map(|r| SecretRuleItem {
            is_eclipsed: eclipsed.contains(&r.uuid),
            uuid: r.uuid,
            name: r.name,
            user_group_name: r.user_group_name,
            secret_group_name: r.secret_group_name,
            asset_group_name: r.asset_group_name,
            is_active: r.is_active,
        })
        .filter(|r| {
            matches_search(&[r.name.as_str()], search_filter.as_deref())
                && matches_select(&r.user_group_name, user_group_filter.as_deref())
                && matches_select(&r.secret_group_name, secret_group_filter.as_deref())
                && matches_select(&r.asset_group_name, asset_group_filter.as_deref())
                && matches_bool(r.is_active, active_wanted)
                && matches_bool(r.is_eclipsed, eclipsed_wanted)
        })
        .collect();

    const RULES_PER_PAGE: usize = 30;
    let page = parse_page(&params);
    let total_items = rules.len();
    let window = paginate(total_items, page, RULES_PER_PAGE);
    let rules = slice_page(rules, &window);
    let pagination = (total_items > 0).then(|| window.to_pagination());

    let template = SecretRuleListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rules,
        pagination,
        search: search_filter,
        user_group_filter,
        secret_group_filter,
        asset_group_filter,
        status_filter,
        eclipsed_filter,
        user_groups,
        secret_groups,
        asset_groups,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ============================================================================
// CREATE FORM (GET) + CREATE (POST)
// ============================================================================

pub async fn secret_access_rule_create_form(
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

    let (user_groups, secret_groups, asset_groups) = match load_rule_editor_options(&state).await {
        Ok(triple) => triple,
        Err(e) => {
            tracing::error!("IPC error loading rule editor options: {}", e);
            return flash_redirect(
                flash.error("Failed to load groups"),
                "/vault/secrets/access",
            );
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        "New Secret Access Rule".to_string(),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretRuleCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form: SecretRuleForm {
            is_active: true,
            ..Default::default()
        },
        user_groups,
        secret_groups,
        asset_groups,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render form"),
                "/vault/secrets/access",
            )
        }
    }
}

pub async fn create_secret_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    browser_tz: BrowserTz,
    Form(form): Form<SecretAccessRuleWebForm>,
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
            "/vault/secrets/access/new",
        );
    }

    if !perms.vault_secrets_manage {
        return flash_redirect(
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Rule name is required"),
            "/vault/secrets/access/new",
        );
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));
    let valid_from = parse_datetime(&form.valid_from, browser_tz.0);
    let valid_until = parse_datetime(&form.valid_until, browser_tz.0);
    let priority: i32 = form
        .priority
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let data = SecretAccessRuleData {
        name: sanitized_name.clone(),
        description: sanitized_desc,
        user_group_id: form.user_group_id,
        secret_group_id: form.secret_group_id,
        asset_group_id: form.asset_group_id,
        valid_from: to_rfc3339_opt(&valid_from),
        valid_until: to_rfc3339_opt(&valid_until),
        is_active: form.is_active.is_some(),
        priority,
    };

    match state
        .access_client
        .create_secret_access_rule(data, Some(auth_user.uuid.clone()))
        .await
    {
        Ok(info) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretAccessRuleCreated,
                    format!(r#"{{"rule":"{}","name":"{}"}}"#, info.uuid, sanitized_name),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret access rule '{}' created", sanitized_name)),
                &format!("/vault/secrets/access/{}", info.uuid),
            )
        }
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error(
                    "A rule for this user group / secret group / asset group combination already exists",
                ),
                "/vault/secrets/access/new",
            )
        }
        Err(e) => {
            tracing::error!("Failed to create secret access rule: {}", e);
            flash_redirect(
                flash.error("Failed to create secret access rule"),
                "/vault/secrets/access/new",
            )
        }
    }
}

// ============================================================================
// DETAIL
// ============================================================================

pub async fn secret_access_rule_detail(
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
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/access");
    }

    // The eclipse lint needs the full rule set; fetch it alongside the
    // rule itself. A failure of the list call degrades to "no eclipse
    // information" rather than blocking the detail page.
    let (info_res, all_rules_res) = tokio::join!(
        state.access_client.get_secret_access_rule(&uuid_str),
        state.access_client.list_secret_access_rules(),
    );

    let info = match info_res {
        Ok(i) => i,
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            return flash_redirect(
                flash.error("Secret access rule not found"),
                "/vault/secrets/access",
            );
        }
        Err(e) => {
            tracing::error!("IPC error fetching secret access rule: {}", e);
            return flash_redirect(
                flash.error("Failed to load secret access rule"),
                "/vault/secrets/access",
            );
        }
    };

    let is_eclipsed = match all_rules_res {
        Ok(all) => eclipsed_rule_uuids(&all).contains(&info.uuid),
        Err(e) => {
            tracing::warn!("IPC error loading rules for eclipse lint: {}", e);
            false
        }
    };

    let detail = SecretRuleDetailData {
        uuid: info.uuid,
        name: info.name.clone(),
        description: info.description,
        user_group_name: info.user_group_name,
        secret_group_name: info.secret_group_name,
        asset_group_name: info.asset_group_name,
        asset_group_is_virtual: info.asset_group_kind == ASSET_GROUP_KIND_ALL,
        valid_from: format_rfc3339_to_display(&info.valid_from, browser_tz.0),
        valid_until: format_rfc3339_to_display(&info.valid_until, browser_tz.0),
        is_active: info.is_active,
        priority: info.priority,
        is_eclipsed,
        created_at: format_rfc3339_str_to_display(&info.created_at, browser_tz.0),
        updated_at: format_rfc3339_str_to_display(&info.updated_at, browser_tz.0),
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("{} - Secret Access Rule", detail.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretRuleDetailTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rule: detail,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render page"),
                "/vault/secrets/access",
            )
        }
    }
}

// ============================================================================
// EDIT FORM (GET) + UPDATE (POST)
// ============================================================================

pub async fn secret_access_rule_edit(
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
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/access");
    }

    let (rule_res, options_res) = tokio::join!(
        state.access_client.get_secret_access_rule(&uuid_str),
        load_rule_editor_options(&state),
    );

    let info = match rule_res {
        Ok(i) => i,
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            return flash_redirect(
                flash.error("Secret access rule not found"),
                "/vault/secrets/access",
            );
        }
        Err(e) => {
            tracing::error!("IPC error fetching secret access rule: {}", e);
            return flash_redirect(
                flash.error("Failed to load secret access rule"),
                "/vault/secrets/access",
            );
        }
    };

    let (user_groups, secret_groups, asset_groups) = match options_res {
        Ok(triple) => triple,
        Err(e) => {
            tracing::error!("IPC error loading rule editor options: {}", e);
            return flash_redirect(
                flash.error("Failed to load groups"),
                "/vault/secrets/access",
            );
        }
    };

    let rule_edit = SecretRuleEditData {
        uuid: info.uuid.clone(),
        name: info.name.clone(),
        description: info.description.clone().unwrap_or_default(),
        user_group_id: info.user_group_id,
        secret_group_id: info.secret_group_id,
        asset_group_id: info.asset_group_id,
        valid_from: format_rfc3339_to_local(&info.valid_from, browser_tz.0),
        valid_until: format_rfc3339_to_local(&info.valid_until, browser_tz.0),
        is_active: info.is_active,
        priority: info.priority.to_string(),
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("Edit {} - Secret Access Rule", info.name),
        user.clone(),
        browser_tz.0,
    )
    .with_current_path("/vault/secrets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = SecretRuleEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rule: rule_edit,
        user_groups,
        secret_groups,
        asset_groups,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(
                flash.error("Failed to render form"),
                "/vault/secrets/access",
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn update_secret_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    browser_tz: BrowserTz,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<SecretAccessRuleWebForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let edit_url = format!("/vault/secrets/access/{}/edit", uuid_str);

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
        return flash_redirect(flash.error("Invalid identifier"), "/vault/secrets/access");
    }

    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Rule name is required"), &edit_url);
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));
    let valid_from = parse_datetime(&form.valid_from, browser_tz.0);
    let valid_until = parse_datetime(&form.valid_until, browser_tz.0);
    let priority: i32 = form
        .priority
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let data = SecretAccessRuleData {
        name: sanitized_name.clone(),
        description: sanitized_desc,
        user_group_id: form.user_group_id,
        secret_group_id: form.secret_group_id,
        asset_group_id: form.asset_group_id,
        valid_from: to_rfc3339_opt(&valid_from),
        valid_until: to_rfc3339_opt(&valid_until),
        is_active: form.is_active.is_some(),
        priority,
    };

    match state
        .access_client
        .update_secret_access_rule(&uuid_str, data, Some(auth_user.uuid.clone()))
        .await
    {
        Ok(_) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretAccessRuleUpdated,
                    format!(r#"{{"rule":"{}","name":"{}"}}"#, uuid_str, sanitized_name),
                )
                .user(auth_user.uuid.clone()),
            );
            flash_redirect(
                flash.success(format!("Secret access rule '{}' updated", sanitized_name)),
                &format!("/vault/secrets/access/{}", uuid_str),
            )
        }
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => flash_redirect(
            flash.error("Secret access rule not found"),
            "/vault/secrets/access",
        ),
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error(
                    "A rule for this user group / secret group / asset group combination already exists",
                ),
                &edit_url,
            )
        }
        Err(e) => {
            tracing::error!("Failed to update secret access rule: {}", e);
            flash_redirect(
                flash.error("Failed to update secret access rule"),
                &edit_url,
            )
        }
    }
}

// ============================================================================
// DELETE (POST)
// ============================================================================

// Speaks both dialects (BUG-12): plain forms get 303 + Location, HTMX
// requests get 200 + HX-Redirect. The delete form on the detail page is
// HTMX-driven (styled deleteConfirm modal) since the CSP hardening.
#[allow(clippy::too_many_arguments)]
pub async fn delete_secret_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteSecretAccessRuleWebForm>,
) -> Response {
    let flash = incoming_flash.flash();
    let detail_url = format!("/vault/secrets/access/{}", uuid_str);

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return htmx_or_flash_redirect(&headers, flash.error("Invalid CSRF token"), &detail_url);
    }

    if !perms.vault_secrets_manage {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("You do not have permission to manage vault secrets"),
            "/vault/secrets",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return htmx_or_flash_redirect(
            &headers,
            flash.error("Invalid identifier"),
            "/vault/secrets/access",
        );
    }

    match state
        .access_client
        .delete_secret_access_rule(&uuid_str)
        .await
    {
        Ok(()) => {
            crate::services::emit_audit(
                &state,
                crate::ipc::AuditEvent::new(
                    shared::messages::AuditEventType::SecretAccessRuleDeleted,
                    format!(r#"{{"rule":"{}"}}"#, uuid_str),
                )
                .user(auth_user.uuid.clone()),
            );
            htmx_or_flash_redirect(
                &headers,
                flash.success("Secret access rule deleted"),
                "/vault/secrets/access",
            )
        }
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            htmx_or_flash_redirect(
                &headers,
                flash.error("Secret access rule not found"),
                "/vault/secrets/access",
            )
        }
        Err(e) => {
            tracing::error!("Failed to delete secret access rule: {}", e);
            htmx_or_flash_redirect(
                &headers,
                flash.error("Failed to delete secret access rule"),
                &detail_url,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_secret_groups_sort_first_in_dropdown() {
        let opts = vec![
            shared::messages::GroupOption {
                id: 1,
                uuid: "u1".into(),
                name: "Zeta".into(),
                kind: "static".into(),
            },
            shared::messages::GroupOption {
                id: 2,
                uuid: "u2".into(),
                name: "All secrets".into(),
                kind: "all".into(),
            },
            shared::messages::GroupOption {
                id: 3,
                uuid: "u3".into(),
                name: "Alpha".into(),
                kind: "static".into(),
            },
        ];
        let mapped = map_secret_group_options(opts);
        assert!(mapped[0].is_virtual);
        assert_eq!(mapped[0].name, "All secrets");
        assert_eq!(mapped[1].name, "Alpha");
        assert_eq!(mapped[2].name, "Zeta");
    }

    /// Builder for eclipse-lint table tests.
    #[allow(clippy::too_many_arguments)]
    fn rule(
        uuid: &str,
        user_group_id: i32,
        secret_group_id: i32,
        secret_group_uuid: &str,
        asset_group_kind: &str,
        is_active: bool,
    ) -> SecretAccessRuleInfo {
        SecretAccessRuleInfo {
            uuid: uuid.to_string(),
            name: uuid.to_string(),
            description: None,
            user_group_id,
            user_group_uuid: format!("ug-{user_group_id}"),
            user_group_name: format!("ug-{user_group_id}"),
            secret_group_id,
            secret_group_uuid: secret_group_uuid.to_string(),
            secret_group_name: format!("sg-{secret_group_id}"),
            asset_group_id: 1,
            asset_group_uuid: "ag-uuid".to_string(),
            asset_group_name: "ag".to_string(),
            asset_group_kind: asset_group_kind.to_string(),
            valid_from: None,
            valid_until: None,
            is_active,
            priority: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn eclipse_lint_table_driven() {
        use shared::messages::ALL_SECRETS_GROUP_UUID;

        // (description, rules, expected eclipsed uuids)
        let cases: Vec<(&str, Vec<SecretAccessRuleInfo>, Vec<&str>)> = vec![
            ("empty set has no eclipse", vec![], vec![]),
            (
                "narrow rule eclipsed by active All-assets rule on same secret group",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", true),
                    rule("broad", 1, 10, "sg-10", "all", true),
                ],
                vec!["narrow"],
            ),
            (
                "narrow rule eclipsed by active All-assets + All-secrets rule",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", true),
                    rule("broad", 1, 99, ALL_SECRETS_GROUP_UUID, "all", true),
                ],
                vec!["narrow"],
            ),
            (
                "inactive broad rule does NOT eclipse",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", true),
                    rule("broad", 1, 10, "sg-10", "all", false),
                ],
                vec![],
            ),
            (
                "different user group does NOT eclipse",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", true),
                    rule("broad", 2, 10, "sg-10", "all", true),
                ],
                vec![],
            ),
            (
                "different secret group (non-virtual) does NOT eclipse",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", true),
                    rule("broad", 1, 11, "sg-11", "all", true),
                ],
                vec![],
            ),
            (
                "All-assets rule itself is never flagged",
                vec![
                    rule("broad-1", 1, 10, "sg-10", "all", true),
                    rule("broad-2", 1, 10, "sg-10", "all", true),
                ],
                vec![],
            ),
            (
                "broad static rule does NOT eclipse another static rule",
                vec![
                    rule("static-1", 1, 10, "sg-10", "static", true),
                    rule("static-2", 1, 10, "sg-10", "static", true),
                ],
                vec![],
            ),
            (
                "inactive narrow rule is still flagged (redundant even if re-activated)",
                vec![
                    rule("narrow", 1, 10, "sg-10", "static", false),
                    rule("broad", 1, 10, "sg-10", "all", true),
                ],
                vec!["narrow"],
            ),
        ];

        for (desc, rules, expected) in cases {
            let got = eclipsed_rule_uuids(&rules);
            let want: std::collections::HashSet<String> =
                expected.into_iter().map(String::from).collect();
            assert_eq!(got, want, "case failed: {desc}");
        }
    }
}
