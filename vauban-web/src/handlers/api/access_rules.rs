/// VAUBAN Web - Access rules API handlers.
///
/// CRUD endpoints for managing access rules that link user groups
/// to asset groups with protocol and time constraints.
///
/// When `state.access_client` is Some, all DB operations are delegated to vauban-access via IPC.
/// When None (dev/test), operations fall back to direct SQL.
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use shared::messages::{AccessRuleData, AccessRuleInfo};

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::access_rule::{
    AccessRule, AccessRuleResponse, CreateAccessRuleRequest, NewAccessRule, UpdateAccessRuleRequest,
};

fn sanitize(s: &str) -> String {
    ammonia::Builder::new()
        .tags(std::collections::HashSet::new())
        .clean(s)
        .to_string()
}

fn info_to_response(info: AccessRuleInfo) -> AccessRuleResponse {
    AccessRuleResponse {
        uuid: info.uuid,
        name: info.name,
        description: info.description,
        user_group_uuid: info.user_group_uuid,
        user_group_name: info.user_group_name,
        asset_group_uuid: info.asset_group_uuid,
        asset_group_name: info.asset_group_name,
        allowed_protocols: info.allowed_protocols,
        valid_from: info.valid_from.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
        }),
        valid_until: info.valid_until.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
        }),
        require_mfa: info.require_mfa,
        require_approval: info.require_approval,
        max_session_duration: info.max_session_duration,
        is_active: info.is_active,
        priority: info.priority,
        created_at: chrono::DateTime::parse_from_rfc3339(&info.created_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_default(),
        updated_at: chrono::DateTime::parse_from_rfc3339(&info.updated_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_default(),
    }
}

/// List all access rules with enriched group names.
pub async fn list_access_rules(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<AccessRuleResponse>>> {
    super::require_staff(&state, &user).await?;

    if let Some(ref client) = state.access_client {
        let list = client.list_access_rules().await?;
        let results = list.into_iter().map(info_to_response).collect();
        return Ok(Json(results));
    }

    use crate::schema::{access_rules, asset_groups, vauban_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(AccessRule, (Uuid, String), (Uuid, String))> = access_rules::table
        .inner_join(vauban_groups::table.on(vauban_groups::id.eq(access_rules::user_group_id)))
        .inner_join(asset_groups::table.on(asset_groups::id.eq(access_rules::asset_group_id)))
        .select((
            AccessRule::as_select(),
            (vauban_groups::uuid, vauban_groups::name),
            (asset_groups::uuid, asset_groups::name),
        ))
        .order(access_rules::name.asc())
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let results = rows
        .into_iter()
        .map(
            |(rule, (ug_uuid, ug_name), (ag_uuid, ag_name))| AccessRuleResponse {
                uuid: rule.uuid.to_string(),
                name: rule.name,
                description: rule.description,
                user_group_uuid: ug_uuid.to_string(),
                user_group_name: ug_name,
                asset_group_uuid: ag_uuid.to_string(),
                asset_group_name: ag_name,
                allowed_protocols: rule.allowed_protocols.into_iter().flatten().collect(),
                valid_from: rule.valid_from,
                valid_until: rule.valid_until,
                require_mfa: rule.require_mfa,
                require_approval: rule.require_approval,
                max_session_duration: rule.max_session_duration,
                is_active: rule.is_active,
                priority: rule.priority,
                created_at: rule.created_at,
                updated_at: rule.updated_at,
            },
        )
        .collect();

    Ok(Json(results))
}

/// Get a single access rule by UUID.
pub async fn get_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_uuid_str): Path<String>,
) -> AppResult<Json<AccessRuleResponse>> {
    super::require_staff(&state, &user).await?;

    let rule_uuid = Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    if let Some(ref client) = state.access_client {
        match client.get_access_rule(&rule_uuid_str).await {
            Ok(info) => return Ok(Json(info_to_response(info))),
            Err(AppError::Ipc(ref msg)) if msg.to_lowercase().contains("not found") => {
                return Err(AppError::NotFound("Access rule not found".to_string()));
            }
            Err(e) => return Err(e),
        }
    }

    use crate::schema::{access_rules, asset_groups, vauban_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let (rule, (ug_uuid, ug_name), (ag_uuid, ag_name)): (
        AccessRule,
        (Uuid, String),
        (Uuid, String),
    ) = access_rules::table
        .inner_join(vauban_groups::table.on(vauban_groups::id.eq(access_rules::user_group_id)))
        .inner_join(asset_groups::table.on(asset_groups::id.eq(access_rules::asset_group_id)))
        .filter(access_rules::uuid.eq(rule_uuid))
        .select((
            AccessRule::as_select(),
            (vauban_groups::uuid, vauban_groups::name),
            (asset_groups::uuid, asset_groups::name),
        ))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Access rule not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    Ok(Json(AccessRuleResponse {
        uuid: rule.uuid.to_string(),
        name: rule.name,
        description: rule.description,
        user_group_uuid: ug_uuid.to_string(),
        user_group_name: ug_name,
        asset_group_uuid: ag_uuid.to_string(),
        asset_group_name: ag_name,
        allowed_protocols: rule.allowed_protocols.into_iter().flatten().collect(),
        valid_from: rule.valid_from,
        valid_until: rule.valid_until,
        require_mfa: rule.require_mfa,
        require_approval: rule.require_approval,
        max_session_duration: rule.max_session_duration,
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }))
}

/// Create a new access rule.
pub async fn create_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<CreateAccessRuleRequest>,
) -> AppResult<Json<AccessRuleResponse>> {
    super::require_staff(&state, &user).await?;

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let ug_uuid = Uuid::parse_str(&request.user_group_uuid)
        .map_err(|_| AppError::Validation("Invalid user_group_uuid format".to_string()))?;
    let ag_uuid = Uuid::parse_str(&request.asset_group_uuid)
        .map_err(|_| AppError::Validation("Invalid asset_group_uuid format".to_string()))?;

    if let Some(ref client) = state.access_client {
        let ug = client
            .get_vauban_group(&request.user_group_uuid)
            .await
            .map_err(|e| {
                if let AppError::Ipc(ref msg) = e
                    && msg.to_lowercase().contains("not found")
                {
                    return AppError::NotFound("User group not found".to_string());
                }
                e
            })?;
        let ag = client
            .get_asset_group(&request.asset_group_uuid)
            .await
            .map_err(|e| {
                if let AppError::Ipc(ref msg) = e
                    && msg.to_lowercase().contains("not found")
                {
                    return AppError::NotFound("Asset group not found".to_string());
                }
                e
            })?;

        let protocols = request
            .allowed_protocols
            .unwrap_or_else(|| vec!["ssh".to_string(), "rdp".to_string()]);

        let data = AccessRuleData {
            name: sanitize(&request.name),
            description: request.description.map(|d| sanitize(&d)),
            user_group_id: ug.id,
            asset_group_id: ag.id,
            allowed_protocols: protocols,
            valid_from: request.valid_from.map(|d| d.to_rfc3339()),
            valid_until: request.valid_until.map(|d| d.to_rfc3339()),
            require_mfa: request.require_mfa,
            require_approval: request.require_approval,
            max_session_duration: request.max_session_duration,
            is_active: true,
            priority: request.priority,
        };

        let info = client.create_access_rule(data).await.map_err(|e| {
            if let AppError::Ipc(ref msg) = e
                && (msg.to_lowercase().contains("already exists")
                    || msg.to_lowercase().contains("unique"))
            {
                return AppError::Validation(
                    "An access rule for this user group and asset group already exists".to_string(),
                );
            }
            e
        })?;
        return Ok(Json(info_to_response(info)));
    }

    use crate::schema::{access_rules, asset_groups, vauban_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let (ug_id, ug_name): (i32, String) = vauban_groups::table
        .filter(vauban_groups::uuid.eq(ug_uuid))
        .select((vauban_groups::id, vauban_groups::name))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("User group not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    let (ag_id, ag_name): (i32, String) = asset_groups::table
        .filter(asset_groups::uuid.eq(ag_uuid))
        .select((asset_groups::id, asset_groups::name))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Asset group not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    let protocols: Vec<Option<String>> = request
        .allowed_protocols
        .unwrap_or_else(|| vec!["ssh".to_string(), "rdp".to_string()])
        .into_iter()
        .map(Some)
        .collect();

    // Resolve the user's internal ID for created_by_id
    let creator_id: Option<i32> = crate::schema::users::table
        .filter(crate::schema::users::uuid.eq(Uuid::parse_str(&user.uuid).unwrap_or_default()))
        .select(crate::schema::users::id)
        .first(&mut conn)
        .await
        .ok();

    let new_rule = NewAccessRule {
        uuid: Uuid::new_v4(),
        name: sanitize(&request.name),
        description: request.description.map(|d| sanitize(&d)),
        user_group_id: ug_id,
        asset_group_id: ag_id,
        allowed_protocols: protocols,
        valid_from: request.valid_from,
        valid_until: request.valid_until,
        require_mfa: request.require_mfa,
        require_approval: request.require_approval,
        max_session_duration: request.max_session_duration,
        is_active: true,
        priority: request.priority,
        created_by_id: creator_id,
    };

    let rule: AccessRule = diesel::insert_into(access_rules::table)
        .values(&new_rule)
        .get_result(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => AppError::Validation(
                "An access rule for this user group and asset group already exists".to_string(),
            ),
            _ => AppError::Database(e),
        })?;

    Ok(Json(AccessRuleResponse {
        uuid: rule.uuid.to_string(),
        name: rule.name,
        description: rule.description,
        user_group_uuid: ug_uuid.to_string(),
        user_group_name: ug_name,
        asset_group_uuid: ag_uuid.to_string(),
        asset_group_name: ag_name,
        allowed_protocols: rule.allowed_protocols.into_iter().flatten().collect(),
        valid_from: rule.valid_from,
        valid_until: rule.valid_until,
        require_mfa: rule.require_mfa,
        require_approval: rule.require_approval,
        max_session_duration: rule.max_session_duration,
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }))
}

/// Update an existing access rule.
pub async fn update_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_uuid_str): Path<String>,
    Json(request): Json<UpdateAccessRuleRequest>,
) -> AppResult<Json<AccessRuleResponse>> {
    super::require_staff(&state, &user).await?;

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    let rule_uuid = Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    if let Some(ref client) = state.access_client {
        let info = client.get_access_rule(&rule_uuid_str).await.map_err(|e| {
            if let AppError::Ipc(ref msg) = e
                && msg.to_lowercase().contains("not found")
            {
                return AppError::NotFound("Access rule not found".to_string());
            }
            e
        })?;

        let data = AccessRuleData {
            name: request
                .name
                .as_deref()
                .map(sanitize)
                .unwrap_or_else(|| info.name.clone()),
            description: request
                .description
                .map(|d| sanitize(&d))
                .or(info.description),
            user_group_id: info.user_group_id,
            asset_group_id: info.asset_group_id,
            allowed_protocols: request.allowed_protocols.unwrap_or(info.allowed_protocols),
            valid_from: request
                .valid_from
                .map(|d| d.to_rfc3339())
                .or(info.valid_from),
            valid_until: request
                .valid_until
                .map(|d| d.to_rfc3339())
                .or(info.valid_until),
            require_mfa: request.require_mfa.unwrap_or(info.require_mfa),
            require_approval: request
                .require_approval
                .unwrap_or(info.require_approval),
            max_session_duration: request.max_session_duration.or(info.max_session_duration),
            is_active: request.is_active.unwrap_or(info.is_active),
            priority: request.priority.unwrap_or(info.priority),
        };

        let updated = client
            .update_access_rule(&rule_uuid_str, data)
            .await
            .map_err(|e| {
                if let AppError::Ipc(ref msg) = e
                    && msg.to_lowercase().contains("not found")
                {
                    return AppError::NotFound("Access rule not found".to_string());
                }
                e
            })?;
        return Ok(Json(info_to_response(updated)));
    }

    use crate::schema::{access_rules, asset_groups, vauban_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let existing: AccessRule = access_rules::table
        .filter(access_rules::uuid.eq(rule_uuid))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                AppError::NotFound("Access rule not found".to_string())
            }
            _ => AppError::Database(e),
        })?;

    if let Some(ref name) = request.name {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::name.eq(sanitize(name)))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(ref desc) = request.description {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::description.eq(Some(sanitize(desc))))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(ref protos) = request.allowed_protocols {
        let vals: Vec<Option<String>> = protos.iter().cloned().map(Some).collect();
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::allowed_protocols.eq(vals))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(mfa) = request.require_mfa {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::require_mfa.eq(mfa))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(just) = request.require_approval {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::require_approval.eq(just))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(dur) = request.max_session_duration {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::max_session_duration.eq(Some(dur)))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(active) = request.is_active {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::is_active.eq(active))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if let Some(prio) = request.priority {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::priority.eq(prio))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if request.valid_from.is_some() {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::valid_from.eq(request.valid_from))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }
    if request.valid_until.is_some() {
        diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
            .set(access_rules::valid_until.eq(request.valid_until))
            .execute(&mut conn)
            .await
            .map_err(AppError::Database)?;
    }

    diesel::update(access_rules::table.filter(access_rules::id.eq(existing.id)))
        .set(access_rules::updated_at.eq(Utc::now()))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?;

    // Re-fetch with group names
    let (rule, (ug_uuid, ug_name), (ag_uuid, ag_name)): (
        AccessRule,
        (Uuid, String),
        (Uuid, String),
    ) = access_rules::table
        .inner_join(vauban_groups::table.on(vauban_groups::id.eq(access_rules::user_group_id)))
        .inner_join(asset_groups::table.on(asset_groups::id.eq(access_rules::asset_group_id)))
        .filter(access_rules::id.eq(existing.id))
        .select((
            AccessRule::as_select(),
            (vauban_groups::uuid, vauban_groups::name),
            (asset_groups::uuid, asset_groups::name),
        ))
        .first(&mut conn)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(AccessRuleResponse {
        uuid: rule.uuid.to_string(),
        name: rule.name,
        description: rule.description,
        user_group_uuid: ug_uuid.to_string(),
        user_group_name: ug_name,
        asset_group_uuid: ag_uuid.to_string(),
        asset_group_name: ag_name,
        allowed_protocols: rule.allowed_protocols.into_iter().flatten().collect(),
        valid_from: rule.valid_from,
        valid_until: rule.valid_until,
        require_mfa: rule.require_mfa,
        require_approval: rule.require_approval,
        max_session_duration: rule.max_session_duration,
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }))
}

/// Delete an access rule.
pub async fn delete_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_uuid_str): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    super::require_staff(&state, &user).await?;

    let rule_uuid = Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    if let Some(ref client) = state.access_client {
        client
            .delete_access_rule(&rule_uuid_str)
            .await
            .map_err(|e| {
                if let AppError::Ipc(ref msg) = e
                    && msg.to_lowercase().contains("not found")
                {
                    return AppError::NotFound("Access rule not found".to_string());
                }
                e
            })?;
        return Ok(Json(serde_json::json!({
            "status": "deleted",
            "uuid": rule_uuid_str
        })));
    }

    use crate::schema::access_rules;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let deleted = diesel::delete(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .execute(&mut conn)
        .await
        .map_err(AppError::Database)?;

    if deleted == 0 {
        return Err(AppError::NotFound("Access rule not found".to_string()));
    }

    Ok(Json(serde_json::json!({
        "status": "deleted",
        "uuid": rule_uuid_str
    })))
}
