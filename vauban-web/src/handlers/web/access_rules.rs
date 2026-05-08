/// Web CRUD handlers for access rules.
use super::*;

use crate::templates::assets::access_list::AccessRuleListItem;
use crate::templates::assets::{
    AccessRuleCreateForm, AccessRuleCreateTemplate, AccessRuleDetailData, AccessRuleDetailTemplate,
    AccessRuleEdit, AccessRuleEditTemplate, GroupOption,
};
use shared::messages::{ASSET_GROUP_KIND_ALL, AccessRuleData, GroupOption as IpcGroupOption};

/// Map IPC `GroupOption`s into template `GroupOption`s for the access-rule
/// editor. Virtual asset groups (`kind == "all"`) are flagged with
/// `is_virtual = true`, so the template can render the "Virtual" badge and
/// the dynamic asset count, and ordered FIRST in the dropdown so they
/// stand out from regular static groups.
///
/// `dynamic_asset_count` is the live count of non-deleted assets, only
/// attached to entries flagged `is_virtual`. Pass `None` for user-group
/// dropdowns (which never contain virtual entries today).
fn map_group_options(
    opts: Vec<IpcGroupOption>,
    dynamic_asset_count: Option<i64>,
) -> Vec<GroupOption> {
    let mut mapped: Vec<GroupOption> = opts
        .into_iter()
        .map(|g| {
            let is_virtual = g.kind == ASSET_GROUP_KIND_ALL;
            GroupOption {
                id: g.id,
                name: g.name,
                is_virtual,
                virtual_asset_count: if is_virtual {
                    dynamic_asset_count
                } else {
                    None
                },
            }
        })
        .collect();
    mapped.sort_by(|a, b| match (a.is_virtual, b.is_virtual) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    mapped
}

/// Best-effort fetch of the dynamic asset count for the virtual "All
/// assets" group: `SELECT count(*) FROM assets WHERE is_deleted = false`.
///
/// Returns `None` on DB error: the badge is informational only, the
/// access rule still applies correctly thanks to the boot-time-resolved
/// virtual id, so a transient failure must not crash the editor.
async fn live_virtual_asset_count(state: &AppState) -> Option<i64> {
    use crate::schema::assets::dsl as a;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    let mut conn = state.db_pool.get().await.ok()?;
    a::assets
        .filter(a::is_deleted.eq(false))
        .count()
        .get_result::<i64>(&mut conn)
        .await
        .ok()
}

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
    /// Master "IACS (all industrial protocols)" checkbox -- expanded
    /// at save time to every `iacs_*` asset_type so the admin does
    /// not have to tick five protocols separately. See
    /// [`build_protocols`].
    pub allowed_iacs: Option<String>,
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
    /// Master IACS checkbox; see [`CreateAccessRuleWebForm::allowed_iacs`].
    pub allowed_iacs: Option<String>,
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

/// All 5 IACS asset_type values listed at once. Source of truth lives
/// on `AssetType::ALL` filtered through `is_iacs()` so a future variant
/// added in `models/asset.rs` automatically lands in any rule the
/// admin marked with the "IACS (all industrial protocols)" master
/// checkbox -- no second place to remember to update.
fn iacs_protocols() -> Vec<String> {
    crate::models::asset::AssetType::ALL
        .iter()
        .filter(|t| t.is_iacs())
        .map(|t| t.as_str().to_string())
        .collect()
}

/// Build the `allowed_protocols` Vec from the access-rule form
/// checkboxes. The `iacs` master checkbox is a UX shortcut that
/// expands to every `iacs_*` value at save time -- it never lands
/// on the persisted row as a single token. Admins who want a
/// partial subset (e.g. Modbus only) must still go through the
/// IPC layer; the web form is intentionally all-or-nothing on
/// IACS to keep the operator surface focused.
fn build_protocols(
    ssh: &Option<String>,
    rdp: &Option<String>,
    iacs: &Option<String>,
) -> Vec<String> {
    let mut protocols = Vec::new();
    if ssh.is_some() {
        protocols.push("ssh".to_string());
    }
    if rdp.is_some() {
        protocols.push("rdp".to_string());
    }
    if iacs.is_some() {
        protocols.extend(iacs_protocols());
    }
    protocols
}

/// Whether any `iacs_*` protocol appears in the rule's persisted
/// `allowed_protocols` Vec. Used to pre-fill the IACS master
/// checkbox on edit. Note the asymmetry: a rule with even ONE
/// `iacs_*` protocol pre-checks the master; a subsequent save then
/// expands it to every `iacs_*`. That one-way upgrade is the
/// trade-off for the simplified UX -- partial IACS rules created
/// via IPC stay accessible read-only and a banner could later
/// surface this if it becomes a pain point.
fn any_iacs_protocol(allowed_protocols: &[String]) -> bool {
    allowed_protocols.iter().any(|p| p.starts_with("iacs_"))
}

fn parse_datetime(s: &Option<String>) -> Option<chrono::DateTime<chrono::Utc>> {
    s.as_deref().filter(|v| !v.is_empty()).and_then(|v| {
        chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M")
            .ok()
            .map(|dt| dt.and_utc())
    })
}

/// Convert RFC3339 string from IPC to display format "YYYY-MM-DD HH:MM <Z>"
/// in the operator's browser timezone.
fn format_rfc3339_to_display(s: &Option<String>, tz: chrono_tz::Tz) -> Option<String> {
    s.as_deref()
        .filter(|v| !v.is_empty())
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| crate::utils::format_local(dt.with_timezone(&chrono::Utc), tz))
}

/// Convert required RFC3339 string to display format in `tz`.
fn format_rfc3339_str_to_display(s: &str, tz: chrono_tz::Tz) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| crate::utils::format_local(dt.with_timezone(&chrono::Utc), tz))
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
    browser_tz: BrowserTz,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("Access Rules".to_string(), user.clone(), browser_tz.0)
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
    browser_tz: BrowserTz,
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
    let info = match client.get_access_rule(&uuid_str).await {
        Ok(info) => info,
        Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
            return flash_redirect(flash.error("Access rule not found"), "/assets/access");
        }
        Err(e) => {
            tracing::error!("IPC error fetching access rule: {}", e);
            return flash_redirect(flash.error("Failed to load access rule"), "/assets/access");
        }
    };

    // Audit pair (issue #22). The IPC `AccessRuleData` does not
    // carry `created_by_id` / `updated_by_id` (those are pure
    // presentation, not a policy decision), so fetch them via a
    // small UUID-keyed lookup. Best-effort: a transient DB error
    // here only loses the audit attribution, the rest of the
    // page still renders.
    let (created_by, updated_by) = {
        use crate::schema::access_rules::dsl as ar_dsl;
        use diesel::prelude::*;
        use diesel_async::RunQueryDsl;
        let parsed_uuid = ::uuid::Uuid::parse_str(&info.uuid).ok();
        let pair: Option<(Option<i32>, Option<i32>)> =
            match (parsed_uuid, state.db_pool.get().await) {
                (Some(u), Ok(mut conn)) => ar_dsl::access_rules
                    .filter(ar_dsl::uuid.eq(u))
                    .select((ar_dsl::created_by_id, ar_dsl::updated_by_id))
                    .first(&mut conn)
                    .await
                    .ok(),
                _ => None,
            };
        match (pair, state.db_pool.get().await) {
            (Some((c, u)), Ok(mut conn)) => {
                crate::services::audit_authors::resolve_audit_pair(&mut conn, c, u).await
            }
            _ => (None, None),
        }
    };

    let detail = AccessRuleDetailData {
        uuid: info.uuid,
        name: info.name,
        description: info.description,
        user_group_name: info.user_group_name,
        asset_group_name: info.asset_group_name,
        allowed_protocols: info.allowed_protocols,
        valid_from: format_rfc3339_to_display(&info.valid_from, browser_tz.0),
        valid_until: format_rfc3339_to_display(&info.valid_until, browser_tz.0),
        require_mfa: info.require_mfa,
        require_approval: info.require_approval,
        max_session_duration: info.max_session_duration,
        is_active: info.is_active,
        priority: info.priority,
        created_at: format_rfc3339_str_to_display(&info.created_at, browser_tz.0),
        updated_at: format_rfc3339_str_to_display(&info.updated_at, browser_tz.0),
        created_by,
        updated_by,
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new(
        format!("{} - Access Rule", detail.name),
        user.clone(),
        browser_tz.0,
    )
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
    browser_tz: BrowserTz,
) -> Response {
    let flash = incoming_flash.flash();

    if !perms.access_rules_write {
        return flash_redirect(
            flash.error("You do not have permission to create access rules"),
            "/assets/access",
        );
    }

    let client = &state.access_client;
    let virtual_count = live_virtual_asset_count(&state).await;
    let (user_groups, asset_groups) = match client.get_group_options_with_virtual().await {
        Ok((ug, ag)) => (
            map_group_options(ug, None),
            map_group_options(ag, virtual_count),
        ),
        Err(e) => {
            tracing::error!("IPC error loading group options: {}", e);
            return flash_redirect(flash.error("Failed to load groups"), "/assets/access");
        }
    };

    let user = Some(user_context_from_auth(&auth_user));
    let base = BaseTemplate::new("New Access Rule".to_string(), user.clone(), browser_tz.0)
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
            allowed_iacs: false,
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

    let protocols = build_protocols(&form.allowed_ssh, &form.allowed_rdp, &form.allowed_iacs);
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
    // Issue #22 — forward the operator UUID so vauban-access
    // stamps `created_by_id` / `updated_by_id` on the new row.
    match client
        .create_access_rule(data, Some(auth_user.uuid.clone()))
        .await
    {
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
    browser_tz: BrowserTz,
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
    let virtual_count = live_virtual_asset_count(&state).await;
    let (rule_edit, rule_name, user_groups, asset_groups) = {
        let (rule_fut, groups_fut) = (
            client.get_access_rule(&uuid_str),
            client.get_group_options_with_virtual(),
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
                map_group_options(a, None),
                map_group_options(b, virtual_count),
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
            allowed_iacs: any_iacs_protocol(&info.allowed_protocols),
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
    let base = BaseTemplate::new(
        format!("Edit {} - Access Rule", rule_name),
        user.clone(),
        browser_tz.0,
    )
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

    let protocols = build_protocols(&form.allowed_ssh, &form.allowed_rdp, &form.allowed_iacs);
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
    // Issue #22 — forward the operator UUID so vauban-access
    // re-stamps `updated_by_id` on the row.
    match client
        .update_access_rule(&uuid_str, data, Some(auth_user.uuid.clone()))
        .await
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `iacs_protocols()` is the source of truth for the master IACS
    /// checkbox expansion. It MUST cover every `iacs_*` variant
    /// declared on `AssetType` -- otherwise a virtual "All assets"
    /// rule would still silently exclude the missing protocol.
    #[test]
    fn iacs_protocols_covers_every_iacs_variant() {
        let from_helper: std::collections::BTreeSet<String> =
            iacs_protocols().into_iter().collect();
        let from_enum: std::collections::BTreeSet<String> =
            crate::models::asset::AssetType::ALL
                .iter()
                .filter(|t| t.is_iacs())
                .map(|t| t.as_str().to_string())
                .collect();
        assert_eq!(
            from_helper, from_enum,
            "iacs_protocols() must enumerate every AssetType::is_iacs variant"
        );
        assert_eq!(
            from_helper.len(),
            5,
            "today the closed vocabulary has exactly five IACS protocols (Modbus, OPC UA, PROFINET, IEC-104, generic TCP)"
        );
    }

    #[test]
    fn build_protocols_with_iacs_master_expands_to_every_iacs_variant() {
        let protos = build_protocols(
            &Some("true".to_string()),
            &None,
            &Some("true".to_string()),
        );
        assert!(protos.contains(&"ssh".to_string()));
        assert!(!protos.contains(&"rdp".to_string()));
        assert!(protos.contains(&"iacs_modbus".to_string()));
        assert!(protos.contains(&"iacs_opcua".to_string()));
        assert!(protos.contains(&"iacs_profinet".to_string()));
        assert!(protos.contains(&"iacs_iec104".to_string()));
        assert!(protos.contains(&"iacs_tcp".to_string()));
    }

    #[test]
    fn build_protocols_without_iacs_master_yields_no_iacs_protocols() {
        let protos = build_protocols(
            &Some("true".to_string()),
            &Some("true".to_string()),
            &None,
        );
        assert_eq!(protos, vec!["ssh".to_string(), "rdp".to_string()]);
        assert!(!protos.iter().any(|p| p.starts_with("iacs_")));
    }

    /// Pre-fill semantics on edit: the master IACS checkbox must
    /// surface AS SOON AS at least one `iacs_*` protocol is on the
    /// rule. The intentional asymmetry (any -> checked, save ->
    /// expand to all) is documented on
    /// [`AccessRuleCreateForm::allowed_iacs`].
    #[test]
    fn any_iacs_protocol_detects_partial_iacs_rule() {
        assert!(any_iacs_protocol(&["iacs_modbus".to_string()]));
        assert!(any_iacs_protocol(&[
            "ssh".to_string(),
            "iacs_opcua".to_string()
        ]));
        assert!(!any_iacs_protocol(&["ssh".to_string(), "rdp".to_string()]));
        assert!(!any_iacs_protocol(&[]));
    }
}
