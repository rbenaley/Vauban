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

async fn load_group_options(
    conn: &mut diesel_async::AsyncPgConnection,
) -> Result<(Vec<GroupOption>, Vec<GroupOption>), AppError> {
    use crate::schema::{asset_groups, vauban_groups};

    let user_groups: Vec<(i32, String)> = vauban_groups::table
        .select((vauban_groups::id, vauban_groups::name))
        .order(vauban_groups::name.asc())
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    let asset_groups_list: Vec<(i32, String)> = asset_groups::table
        .filter(asset_groups::is_deleted.eq(false))
        .select((asset_groups::id, asset_groups::name))
        .order(asset_groups::name.asc())
        .load(conn)
        .await
        .map_err(AppError::Database)?;

    Ok((
        user_groups
            .into_iter()
            .map(|(id, name)| GroupOption { id, name })
            .collect(),
        asset_groups_list
            .into_iter()
            .map(|(id, name)| GroupOption { id, name })
            .collect(),
    ))
}

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

fn format_datetime_local(dt: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    dt.map(|d| d.format("%Y-%m-%dT%H:%M").to_string())
        .unwrap_or_default()
}

fn format_datetime_display(dt: &Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    dt.map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
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
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Access Rules".to_string(), user.clone())
        .with_current_path("/assets/access");
    let (title, user_ctx, vauban, messages, language_code, sidebar_content, header_user) =
        apply_sidebar_rbac(&state, &auth_user, base)
            .await
            .into_fields();

    let rules: Vec<AccessRuleListItem> = if let Some(ref client) = state.access_client {
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
    } else {
        let mut conn = state
            .db_pool
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Database error: {}", e)))?;

        use crate::schema::{access_rules, asset_groups, vauban_groups};

        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            ::uuid::Uuid,
            String,
            i32,
            i32,
            Vec<Option<String>>,
            bool,
            bool,
            bool,
        )> = access_rules::table
            .select((
                access_rules::uuid,
                access_rules::name,
                access_rules::user_group_id,
                access_rules::asset_group_id,
                access_rules::allowed_protocols,
                access_rules::is_active,
                access_rules::require_mfa,
                access_rules::require_approval,
            ))
            .order(access_rules::priority.desc())
            .load(&mut conn)
            .await
            .map_err(AppError::Database)?;

        let ug_map: std::collections::HashMap<i32, String> = vauban_groups::table
            .select((vauban_groups::id, vauban_groups::name))
            .load::<(i32, String)>(&mut conn)
            .await
            .map_err(AppError::Database)?
            .into_iter()
            .collect();

        let ag_map: std::collections::HashMap<i32, String> = asset_groups::table
            .select((asset_groups::id, asset_groups::name))
            .load::<(i32, String)>(&mut conn)
            .await
            .map_err(AppError::Database)?
            .into_iter()
            .collect();

        rows.into_iter()
            .map(
                |(
                    uuid,
                    name,
                    ug_id,
                    ag_id,
                    protocols,
                    is_active,
                    require_mfa,
                    require_approval,
                )| {
                    let allowed_protocols = protocols.into_iter().flatten().collect();
                    AccessRuleListItem {
                        uuid: uuid.to_string(),
                        name,
                        user_group_name: ug_map
                            .get(&ug_id)
                            .cloned()
                            .unwrap_or_else(|| format!("Group #{}", ug_id)),
                        asset_group_name: ag_map
                            .get(&ag_id)
                            .cloned()
                            .unwrap_or_else(|| format!("Group #{}", ag_id)),
                        allowed_protocols,
                        is_active,
                        require_mfa,
                        require_approval,
                    }
                },
            )
            .collect()
    };

    let template = AccessListTemplate {
        title,
        user: user_ctx,
        vauban,
        messages,
        language_code,
        sidebar_content,
        header_user,
        rules,
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
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !check_rbac(&state, &auth_user, "access_rules", "read").await {
        return flash_redirect(
            flash.error("You do not have permission to view access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let detail = if let Some(ref client) = state.access_client {
        match client.get_access_rule(&uuid_str).await {
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
        }
    } else {
        let rule_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
            Ok(u) => u,
            Err(_) => return flash_redirect(flash.error("Invalid UUID"), "/assets/access"),
        };
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(_) => return flash_redirect(flash.error("Database error"), "/assets/access"),
        };

        use crate::models::access_rule::AccessRule;
        use crate::schema::{access_rules, asset_groups, vauban_groups};

        let rule: AccessRule = match access_rules::table
            .filter(access_rules::uuid.eq(rule_uuid))
            .first(&mut conn)
            .await
        {
            Ok(r) => r,
            Err(diesel::result::Error::NotFound) => {
                return flash_redirect(flash.error("Access rule not found"), "/assets/access");
            }
            Err(_) => return flash_redirect(flash.error("Database error"), "/assets/access"),
        };

        let ug_name: String = vauban_groups::table
            .filter(vauban_groups::id.eq(rule.user_group_id))
            .select(vauban_groups::name)
            .first(&mut conn)
            .await
            .unwrap_or_else(|_| format!("Group #{}", rule.user_group_id));

        let ag_name: String = asset_groups::table
            .filter(asset_groups::id.eq(rule.asset_group_id))
            .select(asset_groups::name)
            .first(&mut conn)
            .await
            .unwrap_or_else(|_| format!("Group #{}", rule.asset_group_id));

        AccessRuleDetailData {
            uuid: rule.uuid.to_string(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            user_group_name: ug_name,
            asset_group_name: ag_name,
            allowed_protocols: rule.protocols().into_iter().map(String::from).collect(),
            valid_from: format_datetime_display(&rule.valid_from),
            valid_until: format_datetime_display(&rule.valid_until),
            require_mfa: rule.require_mfa,
            require_approval: rule.require_approval,
            max_session_duration: rule.max_session_duration,
            is_active: rule.is_active,
            priority: rule.priority,
            created_at: rule.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            updated_at: rule.updated_at.format("%Y-%m-%d %H:%M UTC").to_string(),
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
) -> Response {
    let flash = incoming_flash.flash();

    if !check_rbac(&state, &auth_user, "access_rules", "write").await {
        return flash_redirect(
            flash.error("You do not have permission to create access rules"),
            "/assets/access",
        );
    }

    let (user_groups, asset_groups) = if let Some(ref client) = state.access_client {
        match client.get_group_options().await {
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
        }
    } else {
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(_) => return flash_redirect(flash.error("Database error"), "/assets/access"),
        };
        match load_group_options(&mut conn).await {
            Ok(opts) => opts,
            Err(_) => {
                return flash_redirect(flash.error("Failed to load groups"), "/assets/access");
            }
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
    auth_user: WebAuthUser,
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

    if !check_rbac(&state, &auth_user, "access_rules", "write").await {
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

    if let Some(ref client) = state.access_client {
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
                    flash.error(
                        "A rule for this user group / asset group combination already exists",
                    ),
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
    } else {
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Database connection error: {}", e);
                return flash_redirect(flash.error("Database error"), "/assets/access/new");
            }
        };

        let new_uuid = ::uuid::Uuid::new_v4();
        let now = chrono::Utc::now();

        use crate::schema::access_rules::dsl as ar;
        let result = diesel::insert_into(ar::access_rules)
            .values((
                ar::uuid.eq(new_uuid),
                ar::name.eq(&sanitized_name),
                ar::description.eq(&sanitized_desc),
                ar::user_group_id.eq(form.user_group_id),
                ar::asset_group_id.eq(form.asset_group_id),
                ar::allowed_protocols.eq(&protocols),
                ar::valid_from.eq(valid_from),
                ar::valid_until.eq(valid_until),
                ar::require_mfa.eq(form.require_mfa.is_some()),
                ar::require_approval.eq(form.require_approval.is_some()),
                ar::max_session_duration.eq(max_dur),
                ar::is_active.eq(form.is_active.is_some()),
                ar::priority.eq(priority),
                ar::created_at.eq(now),
                ar::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await;

        match result {
            Ok(_) => flash_redirect(
                flash.success(format!("Access rule '{}' created", sanitized_name)),
                &format!("/assets/access/{}", new_uuid),
            ),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => flash_redirect(
                flash.error("A rule for this user group / asset group combination already exists"),
                "/assets/access/new",
            ),
            Err(e) => {
                tracing::error!("Failed to create access rule: {}", e);
                flash_redirect(
                    flash.error("Failed to create access rule"),
                    "/assets/access/new",
                )
            }
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
    axum::extract::Path(uuid_str): axum::extract::Path<String>,
) -> Response {
    let flash = incoming_flash.flash();

    if !check_rbac(&state, &auth_user, "access_rules", "write").await {
        return flash_redirect(
            flash.error("You do not have permission to edit access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let (rule_edit, rule_name, user_groups, asset_groups) = if let Some(ref client) =
        state.access_client
    {
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
    } else {
        let rule_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
            Ok(u) => u,
            Err(_) => return flash_redirect(flash.error("Invalid UUID"), "/assets/access"),
        };
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(_) => return flash_redirect(flash.error("Database error"), "/assets/access"),
        };

        use crate::models::access_rule::AccessRule;
        use crate::schema::access_rules;

        let rule: AccessRule = match access_rules::table
            .filter(access_rules::uuid.eq(rule_uuid))
            .first(&mut conn)
            .await
        {
            Ok(r) => r,
            Err(diesel::result::Error::NotFound) => {
                return flash_redirect(flash.error("Access rule not found"), "/assets/access");
            }
            Err(_) => return flash_redirect(flash.error("Database error"), "/assets/access"),
        };

        let (user_groups, asset_groups) = match load_group_options(&mut conn).await {
            Ok(opts) => opts,
            Err(_) => {
                return flash_redirect(flash.error("Failed to load groups"), "/assets/access");
            }
        };

        let protocols = rule.protocols();
        let (dur_val, dur_unit) = crate::utils::duration_to_value_unit(rule.max_session_duration);
        let rule_edit = AccessRuleEdit {
            uuid: rule.uuid.to_string(),
            name: rule.name.clone(),
            description: rule.description.clone().unwrap_or_default(),
            user_group_id: rule.user_group_id,
            asset_group_id: rule.asset_group_id,
            allowed_ssh: protocols.contains(&"ssh"),
            allowed_rdp: protocols.contains(&"rdp"),
            valid_from: format_datetime_local(&rule.valid_from),
            valid_until: format_datetime_local(&rule.valid_until),
            require_mfa: rule.require_mfa,
            require_approval: rule.require_approval,
            duration_value: dur_val,
            duration_unit: dur_unit.to_string(),
            is_active: rule.is_active,
            priority: rule.priority.to_string(),
        };
        (rule_edit, rule.name.clone(), user_groups, asset_groups)
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
    auth_user: WebAuthUser,
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

    if !check_rbac(&state, &auth_user, "access_rules", "write").await {
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

    if let Some(ref client) = state.access_client {
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
                    flash.error(
                        "A rule for this user group / asset group combination already exists",
                    ),
                    &edit_url,
                )
            }
            Err(e) => {
                tracing::error!("Failed to update access rule: {}", e);
                flash_redirect(flash.error("Failed to update access rule"), &edit_url)
            }
        }
    } else {
        let rule_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
            Ok(u) => u,
            Err(_) => return flash_redirect(flash.error("Invalid UUID"), &edit_url),
        };
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Database connection error: {}", e);
                return flash_redirect(flash.error("Database error"), &edit_url);
            }
        };

        use crate::schema::access_rules::dsl as ar;

        let result = diesel::update(ar::access_rules.filter(ar::uuid.eq(rule_uuid)))
            .set((
                ar::name.eq(&sanitized_name),
                ar::description.eq(&sanitized_desc),
                ar::user_group_id.eq(form.user_group_id),
                ar::asset_group_id.eq(form.asset_group_id),
                ar::allowed_protocols.eq(&protocols),
                ar::valid_from.eq(valid_from),
                ar::valid_until.eq(valid_until),
                ar::require_mfa.eq(form.require_mfa.is_some()),
                ar::require_approval.eq(form.require_approval.is_some()),
                ar::max_session_duration.eq(max_dur),
                ar::is_active.eq(form.is_active.is_some()),
                ar::priority.eq(priority),
                ar::updated_at.eq(chrono::Utc::now()),
            ))
            .execute(&mut conn)
            .await;

        match result {
            Ok(0) => flash_redirect(flash.error("Access rule not found"), "/assets/access"),
            Ok(_) => flash_redirect(
                flash.success(format!("Access rule '{}' updated", sanitized_name)),
                &format!("/assets/access/{}", uuid_str),
            ),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => flash_redirect(
                flash.error("A rule for this user group / asset group combination already exists"),
                &edit_url,
            ),
            Err(e) => {
                tracing::error!("Failed to update access rule: {}", e);
                flash_redirect(flash.error("Failed to update access rule"), &edit_url)
            }
        }
    }
}

// ============================================================================
// DELETE (POST)
// ============================================================================

pub async fn delete_access_rule_web(
    State(state): State<AppState>,
    auth_user: WebAuthUser,
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

    if !check_rbac(&state, &auth_user, "access_rules", "write").await {
        return flash_redirect(
            flash.error("You do not have permission to delete access rules"),
            "/assets/access",
        );
    }

    if ::uuid::Uuid::parse_str(&uuid_str).is_err() {
        return flash_redirect(flash.error("Invalid identifier"), "/assets/access");
    }

    let detail_url = format!("/assets/access/{}", uuid_str);

    if let Some(ref client) = state.access_client {
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
    } else {
        let rule_uuid = match ::uuid::Uuid::parse_str(&uuid_str) {
            Ok(u) => u,
            Err(_) => return flash_redirect(flash.error("Invalid UUID"), &detail_url),
        };
        let mut conn = match state.db_pool.get().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Database connection error: {}", e);
                return flash_redirect(flash.error("Database error"), &detail_url);
            }
        };

        use crate::schema::access_rules::dsl as ar;

        let result = diesel::delete(ar::access_rules.filter(ar::uuid.eq(rule_uuid)))
            .execute(&mut conn)
            .await;

        match result {
            Ok(0) => flash_redirect(flash.error("Access rule not found"), "/assets/access"),
            Ok(_) => flash_redirect(flash.success("Access rule deleted"), "/assets/access"),
            Err(e) => {
                tracing::error!("Failed to delete access rule: {}", e);
                flash_redirect(flash.error("Failed to delete access rule"), &detail_url)
            }
        }
    }
}
