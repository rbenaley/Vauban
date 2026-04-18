/// Web CRUD handlers for access rules.
use super::*;

use crate::templates::assets::access_list::AccessRuleListItem;
use crate::templates::assets::{
    AccessRuleCreateForm, AccessRuleCreateTemplate, AccessRuleDetailData, AccessRuleDetailTemplate,
    AccessRuleEdit, AccessRuleEditTemplate, GroupOption,
};
use shared::messages::{AccessRuleData, GroupOption as IpcGroupOption};

// ============================================================================
// Form structs
// ============================================================================

#[derive(Debug, serde::Deserialize)]
pub struct CreateAccessRuleWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_ssh: Option<String>,
    pub allowed_rdp: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: Option<String>,
    pub require_approval: Option<String>,
    pub duration_value: Option<i32>,
    pub duration_unit: Option<String>,
    pub is_active: Option<String>,
    pub priority: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateAccessRuleWebForm {
    pub csrf_token: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub allowed_ssh: Option<String>,
    pub allowed_rdp: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: Option<String>,
    pub require_approval: Option<String>,
    pub duration_value: Option<i32>,
    pub duration_unit: Option<String>,
    pub is_active: Option<String>,
    pub priority: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeleteAccessRuleWebForm {
    pub csrf_token: String,
}

// ============================================================================
// Helpers
// ============================================================================

fn build_protocols(ssh: &Option<String>, rdp: &Option<String>) -> Vec<String> {
    let mut protocols = Vec::new();
    if ssh.is_some() {
        protocols.push("ssh".to_string());
    }
    if rdp.is_some() {
        protocols.push("rdp".to_string());
    }
    protocols
}

fn parse_datetime(s: &Option<String>) -> Option<chrono::DateTime<chrono::Utc>> {
    s.as_deref().filter(|v| !v.is_empty()).and_then(|v| {
        chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M")
            .ok()
            .map(|dt| dt.and_utc())
    })
}

/// Convert RFC3339 string from IPC to display format "YYYY-MM-DD HH:MM UTC".
fn format_rfc3339_to_display(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .filter(|v| !v.is_empty())
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
}

/// Convert required RFC3339 string to display format.
fn format_rfc3339_str_to_display(s: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|_| s.to_string())
}

/// Convert RFC3339 string from IPC to local form format "%Y-%m-%dT%H:%M".
fn format_rfc3339_to_local(s: &Option<String>) -> String {
    s.as_deref()
        .filter(|v| !v.is_empty())
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.format("%Y-%m-%dT%H:%M").to_string())
        .unwrap_or_default()
}

/// Convert DateTime<Utc> to RFC3339 string for IPC.
fn to_rfc3339_opt(dt: &Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    dt.map(|d| d.to_rfc3339())
}

// ============================================================================
// LIST
// ============================================================================

pub async fn access_rules_list(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Access Rules".to_string(), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let client = &state.access_client;
    let rules: Vec<AccessRuleListItem> = {
        let list = client.list_access_rules().await?;
        list.into_iter()
            .map(|info| AccessRuleListItem {
                uuid: info.uuid,
                name: info.name,
                user_group_name: info.user_group_name,
                asset_group_name: info.asset_group_name,
                allowed_protocols: info.allowed_protocols,
                is_active: info.is_active,
                require_mfa: info.require_mfa,
                require_approval: info.require_approval,
            })
            .collect()
    };

    const RULES_PER_PAGE: usize = 30;

    let page: usize = params
        .get("page")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let total_items = rules.len();
    let total_pages = ((total_items as f64) / (RULES_PER_PAGE as f64))
        .ceil()
        .max(1.0) as usize;
    let page = page.min(total_pages);
    let offset = (page - 1) * RULES_PER_PAGE;
    let paged_rules: Vec<_> = rules
        .into_iter()
        .skip(offset)
        .take(RULES_PER_PAGE)
        .collect();

    use crate::templates::accounts::user_list::Pagination;

    let start_index = if total_items > 0 { offset + 1 } else { 0 };
    let end_index = (offset + RULES_PER_PAGE).min(total_items);

    let pagination = if total_items > 0 {
        Some(Pagination {
            current_page: page as i32,
            total_pages: total_pages as i32,
            total_items: total_items as i32,
            items_per_page: RULES_PER_PAGE as i32,
            has_previous: page > 1,
            has_next: page < total_pages,
            start_index: start_index as i32,
            end_index: end_index as i32,
        })
    } else {
        None
    };

    let template = AccessListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rules: paged_rules,
        pagination,
    };

    let html = template
        .render()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render error: {}", e)))?;
    Ok(Html(html))
}

// ============================================================================
// DETAIL
// ============================================================================

pub async fn access_rule_detail(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.access_rules_read {
        return flash_redirect(
            flash.error("You do not have permission to view access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let client = &state.access_client;
    let detail = match client.get_access_rule(&uuid_str).await {
        Ok(info) => AccessRuleDetailData {
            uuid: info.uuid,
            name: info.name,
            description: info.description,
            user_group_name: info.user_group_name,
            asset_group_name: info.asset_group_name,
            allowed_protocols: info.allowed_protocols,
            valid_from: format_rfc3339_to_display(&info.valid_from),
            valid_until: format_rfc3339_to_display(&info.valid_until),
            require_mfa: info.require_mfa,
            require_approval: info.require_approval,
            max_session_duration: info.max_session_duration,
            is_active: info.is_active,
            priority: info.priority,
            created_at: format_rfc3339_str_to_display(&info.created_at),
            updated_at: format_rfc3339_str_to_display(&info.updated_at),
        },
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            return flash_redirect(flash.error("Access rule not found"), "/assets/access");
        }
        Err(e) => {
            tracing::error!("IPC error fetching access rule: {}", e);
            return flash_redirect(flash.error("Failed to load access rule"), "/assets/access");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("{} - Access Rule", detail.name), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AccessRuleDetailTemplate {
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
            flash_redirect(flash.error("Failed to render page"), "/assets/access")
        }
    }
}

// ============================================================================
// CREATE FORM (GET)
// ============================================================================

pub async fn access_rule_create_form(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to create access rules"),
            "/assets/access",
        );
    }

    let client = &state.access_client;
    let (user_groups, asset_groups) = match client.get_group_options().await {
        Ok((ug, ag)) => (
            ug.into_iter()
                .map(|g: IpcGroupOption| GroupOption {
                    id: g.id,
                    name: g.name,
                })
                .collect(),
            ag.into_iter()
                .map(|g: IpcGroupOption| GroupOption {
                    id: g.id,
                    name: g.name,
                })
                .collect(),
        ),
        Err(e) => {
            tracing::error!("IPC error loading group options: {}", e);
            return flash_redirect(flash.error("Failed to load groups"), "/assets/access");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New Access Rule".to_string(), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AccessRuleCreateTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        form: AccessRuleCreateForm {
            is_active: true,
            allowed_ssh: true,
            allowed_rdp: true,
            ..Default::default()
        },
        user_groups,
        asset_groups,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(flash.error("Failed to render form"), "/assets/access")
        }
    }
}

// ============================================================================
// CREATE (POST)
// ============================================================================

pub async fn create_access_rule_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    Form(form): Form<CreateAccessRuleWebForm>,
) -> Response {
    let flash = incoming_flash.flash();

    let csrf_cookie = jar.get(crate::middleware::csrf::CSRF_COOKIE_NAME);
    if !crate::middleware::csrf::validate_double_submit(
        state.config.secret_key.expose_secret().as_bytes(),
        csrf_cookie.map(|c| c.value()),
        &form.csrf_token,
    ) {
        return flash_redirect(flash.error("Invalid CSRF token"), "/assets/access/new");
    }

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to create access rules"),
            "/assets/access",
        );
    }

    if form.name.trim().is_empty() {
        return flash_redirect(flash.error("Rule name is required"), "/assets/access/new");
    }

    let protocols = build_protocols(&form.allowed_ssh, &form.allowed_rdp);
    if protocols.is_empty() {
        return flash_redirect(
            flash.error("At least one protocol must be selected"),
            "/assets/access/new",
        );
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));
    let valid_from = parse_datetime(&form.valid_from);
    let valid_until = parse_datetime(&form.valid_until);
    let max_dur: Option<i32> = match crate::utils::resolve_duration_seconds(
        form.duration_value,
        form.duration_unit.as_deref(),
    ) {
        Ok(d) => d,
        Err(msg) => {
            return flash_redirect(flash.error(msg), "/assets/access/new");
        }
    };
    let priority: i32 = form
        .priority
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let client = &state.access_client;
    let data = AccessRuleData {
        name: sanitized_name.clone(),
        description: sanitized_desc.clone(),
        user_group_id: form.user_group_id,
        asset_group_id: form.asset_group_id,
        allowed_protocols: protocols.clone(),
        valid_from: to_rfc3339_opt(&valid_from),
        valid_until: to_rfc3339_opt(&valid_until),
        require_mfa: form.require_mfa.is_some(),
        require_approval: form.require_approval.is_some(),
        max_session_duration: max_dur,
        is_active: form.is_active.is_some(),
        priority,
    };
    match client.create_access_rule(data).await {
        Ok(info) => flash_redirect(
            flash.success(format!("Access rule '{}' created", sanitized_name)),
            &format!("/assets/access/{}", info.uuid),
        ),
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error("A rule for this user group / asset group combination already exists"),
                "/assets/access/new",
            )
        }
        Err(e) => {
            tracing::error!("Failed to create access rule: {}", e);
            flash_redirect(
                flash.error("Failed to create access rule"),
                "/assets/access/new",
            )
        }
    }
}

// ============================================================================
// EDIT FORM (GET)
// ============================================================================

pub async fn access_rule_edit(
    State(state): State<AppState>,
    incoming_flash: IncomingFlash,
    auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to edit access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let client = &state.access_client;
    let (rule_edit, rule_name, user_groups, asset_groups) = {
        let (rule_fut, groups_fut) = (
            client.get_access_rule(&uuid_str),
            client.get_group_options(),
        );
        let (rule_res, groups_res) = tokio::join!(rule_fut, groups_fut);

        let info = match rule_res {
            Ok(r) => r,
            Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
                return flash_redirect(flash.error("Access rule not found"), "/assets/access");
            }
            Err(e) => {
                tracing::error!("IPC error fetching access rule: {}", e);
                return flash_redirect(flash.error("Failed to load access rule"), "/assets/access");
            }
        };

        let (ug, ag) = match groups_res {
            Ok((a, b)) => (
                a.into_iter()
                    .map(|g: IpcGroupOption| GroupOption {
                        id: g.id,
                        name: g.name,
                    })
                    .collect(),
                b.into_iter()
                    .map(|g: IpcGroupOption| GroupOption {
                        id: g.id,
                        name: g.name,
                    })
                    .collect(),
            ),
            Err(e) => {
                tracing::error!("IPC error loading group options: {}", e);
                return flash_redirect(flash.error("Failed to load groups"), "/assets/access");
            }
        };

        let (dur_val, dur_unit) = crate::utils::duration_to_value_unit(info.max_session_duration);
        let rule_edit = AccessRuleEdit {
            uuid: info.uuid.clone(),
            name: info.name.clone(),
            description: info.description.clone().unwrap_or_default(),
            user_group_id: info.user_group_id,
            asset_group_id: info.asset_group_id,
            allowed_ssh: info.allowed_protocols.iter().any(|p| p == "ssh"),
            allowed_rdp: info.allowed_protocols.iter().any(|p| p == "rdp"),
            valid_from: format_rfc3339_to_local(&info.valid_from),
            valid_until: format_rfc3339_to_local(&info.valid_until),
            require_mfa: info.require_mfa,
            require_approval: info.require_approval,
            duration_value: dur_val,
            duration_unit: dur_unit.to_string(),
            is_active: info.is_active,
            priority: info.priority.to_string(),
        };
        (rule_edit, info.name, ug, ag)
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(format!("Edit {} - Access Rule", rule_name), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let template = AccessRuleEditTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rule: rule_edit,
        user_groups,
        asset_groups,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template render error: {}", e);
            flash_redirect(flash.error("Failed to render form"), "/assets/access")
        }
    }
}

// ============================================================================
// UPDATE (POST)
// ============================================================================

pub async fn update_access_rule_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<UpdateAccessRuleWebForm>,
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
            &format!("/assets/access/{}/edit", uuid_str),
        );
    }

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to edit access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    if form.name.trim().is_empty() {
        return flash_redirect(
            flash.error("Rule name is required"),
            &format!("/assets/access/{}/edit", uuid_str),
        );
    }

    let protocols = build_protocols(&form.allowed_ssh, &form.allowed_rdp);
    if protocols.is_empty() {
        return flash_redirect(
            flash.error("At least one protocol must be selected"),
            &format!("/assets/access/{}/edit", uuid_str),
        );
    }

    let sanitized_name = sanitize(form.name.trim());
    let sanitized_desc = sanitize_opt(form.description.filter(|s| !s.trim().is_empty()));
    let valid_from = parse_datetime(&form.valid_from);
    let valid_until = parse_datetime(&form.valid_until);
    let edit_url = format!("/assets/access/{}/edit", uuid_str);
    let max_dur: Option<i32> = match crate::utils::resolve_duration_seconds(
        form.duration_value,
        form.duration_unit.as_deref(),
    ) {
        Ok(d) => d,
        Err(msg) => {
            return flash_redirect(flash.error(msg), &edit_url);
        }
    };
    let priority: i32 = form
        .priority
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let client = &state.access_client;
    let data = AccessRuleData {
        name: sanitized_name.clone(),
        description: sanitized_desc.clone(),
        user_group_id: form.user_group_id,
        asset_group_id: form.asset_group_id,
        allowed_protocols: protocols.clone(),
        valid_from: to_rfc3339_opt(&valid_from),
        valid_until: to_rfc3339_opt(&valid_until),
        require_mfa: form.require_mfa.is_some(),
        require_approval: form.require_approval.is_some(),
        max_session_duration: max_dur,
        is_active: form.is_active.is_some(),
        priority,
    };
    match client.update_access_rule(&uuid_str, data).await {
        Ok(_) => flash_redirect(
            flash.success(format!("Access rule '{}' updated", sanitized_name)),
            &format!("/assets/access/{}", uuid_str),
        ),
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            flash_redirect(flash.error("Access rule not found"), "/assets/access")
        }
        Err(AppError::Ipc(ref msg))
            if msg.to_lowercase().contains("unique")
                || msg.to_lowercase().contains("duplicate")
                || msg.to_lowercase().contains("already exists") =>
        {
            flash_redirect(
                flash.error("A rule for this user group / asset group combination already exists"),
                &edit_url,
            )
        }
        Err(e) => {
            tracing::error!("Failed to update access rule: {}", e);
            flash_redirect(flash.error("Failed to update access rule"), &edit_url)
        }
    }
}

// ============================================================================
// DELETE (POST)
// ============================================================================

pub async fn delete_access_rule_web(
    State(state): State<AppState>,
    _auth_user: WebAuthUser,
    perms: crate::auth::PermissionContext,
    incoming_flash: IncomingFlash,
    jar: CookieJar,
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
    Form(form): Form<DeleteAccessRuleWebForm>,
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
            &format!("/assets/access/{}", uuid_str),
        );
    }

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to delete access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let detail_url = format!("/assets/access/{}", uuid_str);

    let client = &state.access_client;
    match client.delete_access_rule(&uuid_str).await {
        Ok(()) => flash_redirect(flash.success("Access rule deleted"), "/assets/access"),
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            flash_redirect(flash.error("Access rule not found"), "/assets/access")
        }
        Err(e) => {
            tracing::error!("Failed to delete access rule: {}", e);
            flash_redirect(flash.error("Failed to delete access rule"), &detail_url)
        }
    }
}
