/// VAUBAN Web - Access rules API handlers.
///
/// CRUD endpoints for managing access rules that link user groups
/// to asset groups with protocol and time constraints.
///
/// All DB operations are delegated to vauban-access via IPC. vauban-web has
/// no standalone mode, so there is no SQL fallback.
use ::uuid::Uuid;
use axum::{
    Json,
    extract::{Path, State},
};
use shared::messages::{AccessRuleData, AccessRuleInfo};

use crate::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::AuthUser;
use crate::models::access_rule::{
    AccessRuleResponse, CreateAccessRuleRequest, UpdateAccessRuleRequest,
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

fn map_not_found(e: AppError, what: &'static str) -> AppError {
    if let AppError::Ipc(ref msg) = e
        && msg.to_lowercase().contains("not found")
    {
        return AppError::NotFound(format!("{what} not found"));
    }
    e
}

/// List all access rules with enriched group names.
pub async fn list_access_rules(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<AccessRuleResponse>>> {
    super::require_staff(&state, &user).await?;

    let list = state.access_client.list_access_rules().await?;
    Ok(Json(list.into_iter().map(info_to_response).collect()))
}

/// Get a single access rule by UUID.
pub async fn get_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_uuid_str): Path<String>,
) -> AppResult<Json<AccessRuleResponse>> {
    super::require_staff(&state, &user).await?;

    Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let info = state
        .access_client
        .get_access_rule(&rule_uuid_str)
        .await
        .map_err(|e| map_not_found(e, "Access rule"))?;
    Ok(Json(info_to_response(info)))
}

/// Create a new access rule.
pub async fn create_access_rule(
    State(state): State<AppState>,
    _user: AuthUser,
    Json(request): Json<CreateAccessRuleRequest>,
) -> AppResult<Json<AccessRuleResponse>> {
    super::require_staff(&state, &_user).await?;

    validator::Validate::validate(&request)
        .map_err(|e| AppError::Validation(format!("Validation failed: {:?}", e)))?;

    Uuid::parse_str(&request.user_group_uuid)
        .map_err(|_| AppError::Validation("Invalid user_group_uuid format".to_string()))?;
    Uuid::parse_str(&request.asset_group_uuid)
        .map_err(|_| AppError::Validation("Invalid asset_group_uuid format".to_string()))?;

    let ug = state
        .access_client
        .get_vauban_group(&request.user_group_uuid)
        .await
        .map_err(|e| map_not_found(e, "User group"))?;
    let ag = state
        .access_client
        .get_asset_group(&request.asset_group_uuid)
        .await
        .map_err(|e| map_not_found(e, "Asset group"))?;

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

    let info = state
        .access_client
        .create_access_rule(data)
        .await
        .map_err(|e| {
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
    Ok(Json(info_to_response(info)))
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

    Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    let info = state
        .access_client
        .get_access_rule(&rule_uuid_str)
        .await
        .map_err(|e| map_not_found(e, "Access rule"))?;

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
        require_approval: request.require_approval.unwrap_or(info.require_approval),
        max_session_duration: request.max_session_duration.or(info.max_session_duration),
        is_active: request.is_active.unwrap_or(info.is_active),
        priority: request.priority.unwrap_or(info.priority),
    };

    let updated = state
        .access_client
        .update_access_rule(&rule_uuid_str, data)
        .await
        .map_err(|e| map_not_found(e, "Access rule"))?;
    Ok(Json(info_to_response(updated)))
}

/// Delete an access rule.
pub async fn delete_access_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_uuid_str): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    super::require_staff(&state, &user).await?;

    Uuid::parse_str(&rule_uuid_str)
        .map_err(|_| AppError::Validation("Invalid UUID format".to_string()))?;

    state
        .access_client
        .delete_access_rule(&rule_uuid_str)
        .await
        .map_err(|e| map_not_found(e, "Access rule"))?;
    Ok(Json(serde_json::json!({
        "status": "deleted",
        "uuid": rule_uuid_str,
    })))
}
