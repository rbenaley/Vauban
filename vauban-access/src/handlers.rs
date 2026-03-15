use chrono::Utc;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel::sql_types::Bool as SqlBool;
use diesel_async::RunQueryDsl;
use shared::messages::{
    AccessCheckResult, AccessRequest, AccessResponse, AccessRuleData, AccessRuleInfo,
    AccessibleGroupEntry, AssetGroupInfo, GroupOption, VaubanGroupInfo,
};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::{DbConnection, DbPool};
use crate::schema::{access_rules, asset_groups, user_groups, vauban_groups};

type AccessRuleRow = (
    Uuid,
    String,
    Option<String>,
    i32,
    Uuid,
    String,
    i32,
    Uuid,
    String,
    Vec<Option<String>>,
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
    bool,
    bool,
    Option<i32>,
    bool,
    i32,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

macro_rules! access_rule_columns {
    () => {
        (
            access_rules::uuid,
            access_rules::name,
            access_rules::description,
            access_rules::user_group_id,
            vauban_groups::uuid,
            vauban_groups::name,
            access_rules::asset_group_id,
            asset_groups::uuid,
            asset_groups::name,
            access_rules::allowed_protocols,
            access_rules::valid_from,
            access_rules::valid_until,
            access_rules::require_mfa,
            access_rules::require_justification,
            access_rules::max_session_duration,
            access_rules::is_active,
            access_rules::priority,
            access_rules::created_at,
            access_rules::updated_at,
        )
    };
}

// ==================== Main dispatch ====================

pub async fn handle_access_request(pool: &DbPool, request: AccessRequest) -> AccessResponse {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => return AccessResponse::Error(format!("DB connection error: {}", e)),
    };

    match request {
        AccessRequest::CheckAccess {
            user_id,
            asset_group_id,
            protocol,
        } => handle_check_access(&mut conn, user_id, asset_group_id, &protocol).await,

        AccessRequest::ListAccessibleGroups { user_id } => {
            handle_list_accessible_groups(&mut conn, user_id).await
        }

        AccessRequest::CreateAccessRule { data } => {
            handle_create_access_rule(&mut conn, data).await
        }
        AccessRequest::GetAccessRule { uuid } => handle_get_access_rule(&mut conn, &uuid).await,
        AccessRequest::ListAccessRules => handle_list_access_rules(&mut conn).await,
        AccessRequest::UpdateAccessRule { uuid, data } => {
            handle_update_access_rule(&mut conn, &uuid, data).await
        }
        AccessRequest::DeleteAccessRule { uuid } => {
            handle_delete_access_rule(&mut conn, &uuid).await
        }

        AccessRequest::CreateVaubanGroup { name, description } => {
            handle_create_vauban_group(&mut conn, &name, description.as_deref()).await
        }
        AccessRequest::GetVaubanGroup { uuid } => handle_get_vauban_group(&mut conn, &uuid).await,
        AccessRequest::GetVaubanGroupById { id } => {
            handle_get_vauban_group_by_id(&mut conn, id).await
        }
        AccessRequest::ListVaubanGroups => handle_list_vauban_groups(&mut conn).await,
        AccessRequest::UpdateVaubanGroup {
            uuid,
            name,
            description,
        } => handle_update_vauban_group(&mut conn, &uuid, &name, description.as_deref()).await,
        AccessRequest::DeleteVaubanGroup { uuid } => {
            handle_delete_vauban_group(&mut conn, &uuid).await
        }

        AccessRequest::AddGroupMember { group_id, user_id } => {
            handle_add_group_member(&mut conn, group_id, user_id).await
        }
        AccessRequest::RemoveGroupMember { group_id, user_id } => {
            handle_remove_group_member(&mut conn, group_id, user_id).await
        }
        AccessRequest::ListGroupMembers { group_id } => {
            handle_list_group_members(&mut conn, group_id).await
        }
        AccessRequest::ListUserGroups { user_id } => {
            handle_list_user_groups(&mut conn, user_id).await
        }

        AccessRequest::CreateAssetGroup {
            name,
            slug,
            description,
            color,
            icon,
        } => {
            handle_create_asset_group(
                &mut conn,
                &name,
                &slug,
                description.as_deref(),
                &color,
                &icon,
            )
            .await
        }
        AccessRequest::GetAssetGroup { uuid } => handle_get_asset_group(&mut conn, &uuid).await,
        AccessRequest::ListAssetGroups => handle_list_asset_groups(&mut conn).await,
        AccessRequest::UpdateAssetGroup {
            uuid,
            name,
            slug,
            description,
            color,
            icon,
        } => {
            handle_update_asset_group(
                &mut conn,
                &uuid,
                &name,
                &slug,
                description.as_deref(),
                &color,
                &icon,
            )
            .await
        }
        AccessRequest::DeleteAssetGroup { uuid } => {
            handle_delete_asset_group(&mut conn, &uuid).await
        }

        AccessRequest::GetGroupOptions => handle_get_group_options(&mut conn).await,
    }
}

// ==================== Helpers ====================

fn parse_optional_datetime(
    value: &Option<String>,
) -> Result<Option<chrono::DateTime<Utc>>, String> {
    match value {
        Some(s) if !s.is_empty() => {
            let dt = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid datetime '{}': {}", s, e))?;
            Ok(Some(dt.with_timezone(&Utc)))
        }
        _ => Ok(None),
    }
}

fn to_access_rule_info(row: AccessRuleRow) -> AccessRuleInfo {
    AccessRuleInfo {
        uuid: row.0.to_string(),
        name: row.1,
        description: row.2,
        user_group_id: row.3,
        user_group_uuid: row.4.to_string(),
        user_group_name: row.5,
        asset_group_id: row.6,
        asset_group_uuid: row.7.to_string(),
        asset_group_name: row.8,
        allowed_protocols: row.9.into_iter().flatten().collect(),
        valid_from: row.10.map(|dt| dt.to_rfc3339()),
        valid_until: row.11.map(|dt| dt.to_rfc3339()),
        require_mfa: row.12,
        require_justification: row.13,
        max_session_duration: row.14,
        is_active: row.15,
        priority: row.16,
        created_at: row.17.to_rfc3339(),
        updated_at: row.18.to_rfc3339(),
    }
}

async fn load_access_rule_by_uuid(
    conn: &mut DbConnection,
    rule_uuid: Uuid,
) -> Result<AccessRuleInfo, String> {
    let row: AccessRuleRow = access_rules::table
        .inner_join(vauban_groups::table)
        .inner_join(asset_groups::table)
        .filter(access_rules::uuid.eq(rule_uuid))
        .select(access_rule_columns!())
        .first(conn)
        .await
        .map_err(|e| format!("Access rule not found: {}", e))?;

    Ok(to_access_rule_info(row))
}

#[allow(clippy::too_many_arguments)]
async fn build_vauban_group_info(
    conn: &mut DbConnection,
    id: i32,
    uuid: Uuid,
    name: &str,
    description: Option<&str>,
    source: &str,
    external_id: Option<&str>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    last_synced: Option<chrono::DateTime<Utc>>,
) -> Result<VaubanGroupInfo, diesel::result::Error> {
    let member_count: i64 = user_groups::table
        .filter(user_groups::group_id.eq(id))
        .count()
        .get_result(conn)
        .await?;

    Ok(VaubanGroupInfo {
        id,
        uuid: uuid.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        source: source.to_string(),
        external_id: external_id.map(String::from),
        created_at: created_at.to_rfc3339(),
        updated_at: updated_at.to_rfc3339(),
        last_synced: last_synced.map(|dt| dt.to_rfc3339()),
        member_count,
    })
}

fn parse_uuid(uuid_str: &str) -> Result<Uuid, String> {
    Uuid::parse_str(uuid_str).map_err(|e| format!("Invalid UUID '{}': {}", uuid_str, e))
}

// ==================== Access checking ====================

async fn handle_check_access(
    conn: &mut DbConnection,
    user_id: i32,
    asset_group_id: i32,
    protocol: &str,
) -> AccessResponse {
    let matching_rules = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::asset_group_id.eq(asset_group_id))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .filter(access_rules::allowed_protocols.contains(vec![Some(protocol.to_string())]))
        .select((
            access_rules::require_mfa,
            access_rules::require_justification,
            access_rules::max_session_duration,
        ))
        .load::<(bool, bool, Option<i32>)>(conn)
        .await;

    match matching_rules {
        Ok(rules) if rules.is_empty() => {
            info!(
                user_id,
                asset_group_id, protocol, "Access denied: no matching rules"
            );
            AccessResponse::AccessChecked(AccessCheckResult {
                allowed: false,
                require_mfa: false,
                require_justification: false,
                max_session_duration: None,
            })
        }
        Ok(rules) => {
            let require_mfa = rules.iter().any(|(mfa, _, _)| *mfa);
            let require_justification = rules.iter().any(|(_, just, _)| *just);
            let max_session_duration = rules.iter().filter_map(|(_, _, dur)| *dur).min();

            info!(
                user_id,
                asset_group_id,
                protocol,
                rule_count = rules.len(),
                require_mfa,
                require_justification,
                "Access granted"
            );

            AccessResponse::AccessChecked(AccessCheckResult {
                allowed: true,
                require_mfa,
                require_justification,
                max_session_duration,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to check access: {}", e)),
    }
}

async fn handle_list_accessible_groups(conn: &mut DbConnection, user_id: i32) -> AccessResponse {
    let rows = access_rules::table
        .inner_join(user_groups::table.on(user_groups::group_id.eq(access_rules::user_group_id)))
        .filter(user_groups::user_id.eq(user_id))
        .filter(access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(valid_from IS NULL OR valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(valid_until IS NULL OR valid_until >= NOW())",
        ))
        .select((
            access_rules::asset_group_id,
            access_rules::allowed_protocols,
        ))
        .load::<(i32, Vec<Option<String>>)>(conn)
        .await;

    match rows {
        Ok(results) => {
            let mut group_map: HashMap<i32, Vec<String>> = HashMap::new();
            for (group_id, protocols) in results {
                let entry = group_map.entry(group_id).or_default();
                for proto in protocols.into_iter().flatten() {
                    if !entry.contains(&proto) {
                        entry.push(proto);
                    }
                }
            }

            let entries: Vec<AccessibleGroupEntry> = group_map
                .into_iter()
                .map(|(asset_group_id, protocols)| AccessibleGroupEntry {
                    asset_group_id,
                    protocols,
                })
                .collect();

            AccessResponse::AccessibleGroups(entries)
        }
        Err(e) => AccessResponse::Error(format!("Failed to list accessible groups: {}", e)),
    }
}

// ==================== Access rule CRUD ====================

async fn handle_create_access_rule(
    conn: &mut DbConnection,
    data: AccessRuleData,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let protocols: Vec<Option<String>> = data.allowed_protocols.into_iter().map(Some).collect();

    let result = diesel::insert_into(access_rules::table)
        .values((
            access_rules::uuid.eq(new_uuid),
            access_rules::name.eq(&data.name),
            access_rules::description.eq(&data.description),
            access_rules::user_group_id.eq(data.user_group_id),
            access_rules::asset_group_id.eq(data.asset_group_id),
            access_rules::allowed_protocols.eq(&protocols),
            access_rules::valid_from.eq(valid_from),
            access_rules::valid_until.eq(valid_until),
            access_rules::require_mfa.eq(data.require_mfa),
            access_rules::require_justification.eq(data.require_justification),
            access_rules::max_session_duration.eq(data.max_session_duration),
            access_rules::is_active.eq(data.is_active),
            access_rules::priority.eq(data.priority),
            access_rules::created_at.eq(now),
            access_rules::updated_at.eq(now),
        ))
        .execute(conn)
        .await;

    match result {
        Ok(_) => {
            info!(uuid = %new_uuid, name = %data.name, "Access rule created");
            match load_access_rule_by_uuid(conn, new_uuid).await {
                Ok(info) => AccessResponse::AccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::AccessRule(Err(format!("Failed to create access rule: {}", e))),
    }
}

async fn handle_get_access_rule(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    match load_access_rule_by_uuid(conn, rule_uuid).await {
        Ok(info) => AccessResponse::AccessRule(Ok(info)),
        Err(e) => AccessResponse::AccessRule(Err(e)),
    }
}

async fn handle_list_access_rules(conn: &mut DbConnection) -> AccessResponse {
    let result = access_rules::table
        .inner_join(vauban_groups::table)
        .inner_join(asset_groups::table)
        .order(access_rules::priority.desc())
        .select(access_rule_columns!())
        .load::<AccessRuleRow>(conn)
        .await;

    match result {
        Ok(rows) => {
            let infos: Vec<AccessRuleInfo> = rows.into_iter().map(to_access_rule_info).collect();
            AccessResponse::AccessRuleList(infos)
        }
        Err(e) => AccessResponse::Error(format!("Failed to list access rules: {}", e)),
    }
}

async fn handle_update_access_rule(
    conn: &mut DbConnection,
    uuid_str: &str,
    data: AccessRuleData,
) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::AccessRule(Err(e)),
    };

    let protocols: Vec<Option<String>> = data.allowed_protocols.into_iter().map(Some).collect();
    let now = Utc::now();

    let affected = diesel::update(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .set((
            access_rules::name.eq(&data.name),
            access_rules::description.eq(&data.description),
            access_rules::user_group_id.eq(data.user_group_id),
            access_rules::asset_group_id.eq(data.asset_group_id),
            access_rules::allowed_protocols.eq(&protocols),
            access_rules::valid_from.eq(valid_from),
            access_rules::valid_until.eq(valid_until),
            access_rules::require_mfa.eq(data.require_mfa),
            access_rules::require_justification.eq(data.require_justification),
            access_rules::max_session_duration.eq(data.max_session_duration),
            access_rules::is_active.eq(data.is_active),
            access_rules::priority.eq(data.priority),
            access_rules::updated_at.eq(now),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::AccessRule(Err(format!("Access rule {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Access rule updated");
            match load_access_rule_by_uuid(conn, rule_uuid).await {
                Ok(info) => AccessResponse::AccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::AccessRule(Err(format!("Failed to update access rule: {}", e))),
    }
}

async fn handle_delete_access_rule(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(access_rules::table.filter(access_rules::uuid.eq(rule_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Access rule {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Access rule deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete access rule: {}", e))),
    }
}

// ==================== Vauban group CRUD ====================

async fn handle_create_vauban_group(
    conn: &mut DbConnection,
    name: &str,
    description: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let result = diesel::insert_into(vauban_groups::table)
        .values((
            vauban_groups::uuid.eq(new_uuid),
            vauban_groups::name.eq(name),
            vauban_groups::description.eq(description),
            vauban_groups::source.eq("local"),
            vauban_groups::created_at.eq(now),
            vauban_groups::updated_at.eq(now),
        ))
        .returning(vauban_groups::id)
        .get_result::<i32>(conn)
        .await;

    match result {
        Ok(id) => {
            info!(uuid = %new_uuid, name, "Vauban group created");
            AccessResponse::VaubanGroup(Ok(VaubanGroupInfo {
                id,
                uuid: new_uuid.to_string(),
                name: name.to_string(),
                description: description.map(String::from),
                source: "local".to_string(),
                external_id: None,
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                last_synced: None,
                member_count: 0,
            }))
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to create group: {}", e))),
    }
}

type VaubanGroupRow = (
    i32,
    Uuid,
    String,
    Option<String>,
    String,
    Option<String>,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
    Option<chrono::DateTime<Utc>>,
);

async fn handle_get_vauban_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::VaubanGroup(Err(e)),
    };

    let row = vauban_groups::table
        .filter(vauban_groups::uuid.eq(group_uuid))
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .first::<VaubanGroupRow>(conn)
        .await;

    match row {
        Ok((
            id,
            uuid,
            name,
            description,
            source,
            external_id,
            created_at,
            updated_at,
            last_synced,
        )) => {
            match build_vauban_group_info(
                conn,
                id,
                uuid,
                &name,
                description.as_deref(),
                &source,
                external_id.as_deref(),
                created_at,
                updated_at,
                last_synced,
            )
            .await
            {
                Ok(info) => AccessResponse::VaubanGroup(Ok(info)),
                Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to load group: {}", e))),
            }
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Group not found: {}", e))),
    }
}

async fn handle_get_vauban_group_by_id(conn: &mut DbConnection, id: i32) -> AccessResponse {
    let row = vauban_groups::table
        .filter(vauban_groups::id.eq(id))
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .first::<VaubanGroupRow>(conn)
        .await;

    match row {
        Ok((
            id,
            uuid,
            name,
            description,
            source,
            external_id,
            created_at,
            updated_at,
            last_synced,
        )) => {
            match build_vauban_group_info(
                conn,
                id,
                uuid,
                &name,
                description.as_deref(),
                &source,
                external_id.as_deref(),
                created_at,
                updated_at,
                last_synced,
            )
            .await
            {
                Ok(info) => AccessResponse::VaubanGroup(Ok(info)),
                Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to load group: {}", e))),
            }
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Group not found: {}", e))),
    }
}

async fn handle_list_vauban_groups(conn: &mut DbConnection) -> AccessResponse {
    let rows = vauban_groups::table
        .order(vauban_groups::name.asc())
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .load::<VaubanGroupRow>(conn)
        .await;

    match rows {
        Ok(groups) => {
            let mut infos = Vec::with_capacity(groups.len());
            for (
                id,
                uuid,
                name,
                description,
                source,
                external_id,
                created_at,
                updated_at,
                last_synced,
            ) in groups
            {
                match build_vauban_group_info(
                    conn,
                    id,
                    uuid,
                    &name,
                    description.as_deref(),
                    &source,
                    external_id.as_deref(),
                    created_at,
                    updated_at,
                    last_synced,
                )
                .await
                {
                    Ok(info) => infos.push(info),
                    Err(e) => {
                        warn!(group_id = id, error = %e, "Failed to load group member count");
                        infos.push(VaubanGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            description,
                            source,
                            external_id,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                            last_synced: last_synced.map(|dt| dt.to_rfc3339()),
                            member_count: 0,
                        });
                    }
                }
            }
            AccessResponse::VaubanGroupList(infos)
        }
        Err(e) => AccessResponse::Error(format!("Failed to list groups: {}", e)),
    }
}

async fn handle_update_vauban_group(
    conn: &mut DbConnection,
    uuid_str: &str,
    name: &str,
    description: Option<&str>,
) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::VaubanGroup(Err(e)),
    };

    let affected = diesel::update(vauban_groups::table.filter(vauban_groups::uuid.eq(group_uuid)))
        .set((
            vauban_groups::name.eq(name),
            vauban_groups::description.eq(description),
            vauban_groups::updated_at.eq(Utc::now()),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::VaubanGroup(Err(format!("Group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, name, "Vauban group updated");
            handle_get_vauban_group(conn, uuid_str).await
        }
        Err(e) => AccessResponse::VaubanGroup(Err(format!("Failed to update group: {}", e))),
    }
}

async fn handle_delete_vauban_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(vauban_groups::table.filter(vauban_groups::uuid.eq(group_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Vauban group deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete group: {}", e))),
    }
}

// ==================== Group member management ====================

async fn handle_add_group_member(
    conn: &mut DbConnection,
    group_id: i32,
    user_id: i32,
) -> AccessResponse {
    let result = diesel::insert_into(user_groups::table)
        .values((
            user_groups::user_id.eq(user_id),
            user_groups::group_id.eq(group_id),
        ))
        .on_conflict_do_nothing()
        .execute(conn)
        .await;

    match result {
        Ok(_) => {
            info!(group_id, user_id, "Group member added");
            AccessResponse::Ok
        }
        Err(e) => AccessResponse::Error(format!("Failed to add group member: {}", e)),
    }
}

async fn handle_remove_group_member(
    conn: &mut DbConnection,
    group_id: i32,
    user_id: i32,
) -> AccessResponse {
    let result = diesel::delete(
        user_groups::table
            .filter(user_groups::group_id.eq(group_id))
            .filter(user_groups::user_id.eq(user_id)),
    )
    .execute(conn)
    .await;

    match result {
        Ok(_) => {
            info!(group_id, user_id, "Group member removed");
            AccessResponse::Ok
        }
        Err(e) => AccessResponse::Error(format!("Failed to remove group member: {}", e)),
    }
}

async fn handle_list_group_members(conn: &mut DbConnection, group_id: i32) -> AccessResponse {
    let result = user_groups::table
        .filter(user_groups::group_id.eq(group_id))
        .select(user_groups::user_id)
        .load::<i32>(conn)
        .await;

    match result {
        Ok(members) => AccessResponse::MemberList(members),
        Err(e) => AccessResponse::Error(format!("Failed to list group members: {}", e)),
    }
}

async fn handle_list_user_groups(conn: &mut DbConnection, user_id: i32) -> AccessResponse {
    let rows = user_groups::table
        .inner_join(vauban_groups::table)
        .filter(user_groups::user_id.eq(user_id))
        .select((
            vauban_groups::id,
            vauban_groups::uuid,
            vauban_groups::name,
            vauban_groups::description,
            vauban_groups::source,
            vauban_groups::external_id,
            vauban_groups::created_at,
            vauban_groups::updated_at,
            vauban_groups::last_synced,
        ))
        .load::<VaubanGroupRow>(conn)
        .await;

    match rows {
        Ok(groups) => {
            let mut infos = Vec::with_capacity(groups.len());
            for (
                id,
                uuid,
                name,
                description,
                source,
                external_id,
                created_at,
                updated_at,
                last_synced,
            ) in groups
            {
                match build_vauban_group_info(
                    conn,
                    id,
                    uuid,
                    &name,
                    description.as_deref(),
                    &source,
                    external_id.as_deref(),
                    created_at,
                    updated_at,
                    last_synced,
                )
                .await
                {
                    Ok(info) => infos.push(info),
                    Err(e) => {
                        warn!(group_id = id, error = %e, "Failed to count group members");
                        infos.push(VaubanGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            description,
                            source,
                            external_id,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                            last_synced: last_synced.map(|dt| dt.to_rfc3339()),
                            member_count: 0,
                        });
                    }
                }
            }
            AccessResponse::UserGroupList(infos)
        }
        Err(e) => AccessResponse::Error(format!("Failed to list user groups: {}", e)),
    }
}

// ==================== Asset group CRUD ====================

async fn handle_create_asset_group(
    conn: &mut DbConnection,
    name: &str,
    slug: &str,
    description: Option<&str>,
    color: &str,
    icon: &str,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let result = diesel::insert_into(asset_groups::table)
        .values((
            asset_groups::uuid.eq(new_uuid),
            asset_groups::name.eq(name),
            asset_groups::slug.eq(slug),
            asset_groups::description.eq(description),
            asset_groups::color.eq(color),
            asset_groups::icon.eq(icon),
            asset_groups::created_at.eq(now),
            asset_groups::updated_at.eq(now),
        ))
        .returning((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
        ))
        .get_result::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        )>(conn)
        .await;

    match result {
        Ok((id, uuid, name, slug, description, color, icon, created_at, updated_at)) => {
            info!(uuid = %uuid, name = %name, "Asset group created");
            AccessResponse::AssetGroup(Ok(AssetGroupInfo {
                id,
                uuid: uuid.to_string(),
                name,
                slug,
                description,
                color,
                icon,
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
            }))
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Failed to create asset group: {}", e))),
    }
}

async fn handle_get_asset_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AssetGroup(Err(e)),
    };

    let result = asset_groups::table
        .filter(asset_groups::uuid.eq(group_uuid))
        .select((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
        ))
        .first::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        )>(conn)
        .await;

    match result {
        Ok((id, uuid, name, slug, description, color, icon, created_at, updated_at)) => {
            AccessResponse::AssetGroup(Ok(AssetGroupInfo {
                id,
                uuid: uuid.to_string(),
                name,
                slug,
                description,
                color,
                icon,
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
            }))
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Asset group not found: {}", e))),
    }
}

async fn handle_list_asset_groups(conn: &mut DbConnection) -> AccessResponse {
    let result = asset_groups::table
        .order(asset_groups::name.asc())
        .select((
            asset_groups::id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::slug,
            asset_groups::description,
            asset_groups::color,
            asset_groups::icon,
            asset_groups::created_at,
            asset_groups::updated_at,
        ))
        .load::<(
            i32,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        )>(conn)
        .await;

    match result {
        Ok(rows) => {
            let infos: Vec<AssetGroupInfo> = rows
                .into_iter()
                .map(
                    |(id, uuid, name, slug, description, color, icon, created_at, updated_at)| {
                        AssetGroupInfo {
                            id,
                            uuid: uuid.to_string(),
                            name,
                            slug,
                            description,
                            color,
                            icon,
                            created_at: created_at.to_rfc3339(),
                            updated_at: updated_at.to_rfc3339(),
                        }
                    },
                )
                .collect();
            AccessResponse::AssetGroupList(infos)
        }
        Err(e) => AccessResponse::Error(format!("Failed to list asset groups: {}", e)),
    }
}

async fn handle_update_asset_group(
    conn: &mut DbConnection,
    uuid_str: &str,
    name: &str,
    slug: &str,
    description: Option<&str>,
    color: &str,
    icon: &str,
) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::AssetGroup(Err(e)),
    };

    let affected = diesel::update(asset_groups::table.filter(asset_groups::uuid.eq(group_uuid)))
        .set((
            asset_groups::name.eq(name),
            asset_groups::slug.eq(slug),
            asset_groups::description.eq(description),
            asset_groups::color.eq(color),
            asset_groups::icon.eq(icon),
            asset_groups::updated_at.eq(Utc::now()),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::AssetGroup(Err(format!("Asset group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, name, "Asset group updated");
            handle_get_asset_group(conn, uuid_str).await
        }
        Err(e) => AccessResponse::AssetGroup(Err(format!("Failed to update asset group: {}", e))),
    }
}

async fn handle_delete_asset_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(asset_groups::table.filter(asset_groups::uuid.eq(group_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Asset group {} not found", uuid_str))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Asset group deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete asset group: {}", e))),
    }
}

// ==================== Group options ====================

async fn handle_get_group_options(conn: &mut DbConnection) -> AccessResponse {
    let user_group_rows = vauban_groups::table
        .order(vauban_groups::name.asc())
        .select((vauban_groups::id, vauban_groups::uuid, vauban_groups::name))
        .load::<(i32, Uuid, String)>(conn)
        .await;

    let asset_group_rows = asset_groups::table
        .order(asset_groups::name.asc())
        .select((asset_groups::id, asset_groups::uuid, asset_groups::name))
        .load::<(i32, Uuid, String)>(conn)
        .await;

    match (user_group_rows, asset_group_rows) {
        (Ok(ug_rows), Ok(ag_rows)) => {
            let user_groups = ug_rows
                .into_iter()
                .map(|(id, uuid, name)| GroupOption {
                    id,
                    uuid: uuid.to_string(),
                    name,
                })
                .collect();
            let asset_groups = ag_rows
                .into_iter()
                .map(|(id, uuid, name)| GroupOption {
                    id,
                    uuid: uuid.to_string(),
                    name,
                })
                .collect();
            AccessResponse::GroupOptions {
                user_groups,
                asset_groups,
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            AccessResponse::Error(format!("Failed to load group options: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::handle_access_request;
    use crate::db::DbPool;
    use diesel::sql_types::Integer;
    use diesel_async::pooled_connection::AsyncDieselConnectionManager;
    use diesel_async::pooled_connection::deadpool::Pool;
    use diesel_async::{AsyncPgConnection, RunQueryDsl};
    use shared::messages::{
        AccessRequest, AccessResponse, AccessRuleData, AccessRuleInfo, AssetGroupInfo,
        VaubanGroupInfo,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_name(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("{}_{ts}_{id}", prefix)
    }

    async fn test_pool() -> DbPool {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://vauban_test:vauban_test@localhost/vauban_test".to_string()
        });
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
        Pool::builder(manager).max_size(2).build().unwrap()
    }

    #[derive(diesel::QueryableByName)]
    struct UserId {
        #[diesel(sql_type = Integer)]
        id: i32,
    }

    async fn ensure_test_user(pool: &DbPool) -> i32 {
        let mut conn = pool.get().await.unwrap();
        let rows: Vec<UserId> = diesel::sql_query(
            "INSERT INTO users (username, email, password_hash, is_superuser, is_staff, is_active) \
             VALUES ('access_test_user', 'access_test@test.local', 'nologin', false, false, true) \
             ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username \
             RETURNING id",
        )
        .load::<UserId>(&mut conn)
        .await
        .unwrap();
        rows[0].id
    }

    async fn create_test_vauban_group(pool: &DbPool, name: &str) -> VaubanGroupInfo {
        match handle_access_request(
            pool,
            AccessRequest::CreateVaubanGroup {
                name: name.to_string(),
                description: Some("test group".to_string()),
            },
        )
        .await
        {
            AccessResponse::VaubanGroup(Ok(info)) => info,
            other => panic!("Expected VaubanGroup(Ok), got {:?}", other),
        }
    }

    async fn create_test_asset_group(pool: &DbPool, name: &str) -> AssetGroupInfo {
        let slug = name.to_lowercase().replace(' ', "-");
        match handle_access_request(
            pool,
            AccessRequest::CreateAssetGroup {
                name: name.to_string(),
                slug: slug.clone(),
                description: Some("test asset group".to_string()),
                color: "#6B7280".to_string(),
                icon: "folder".to_string(),
            },
        )
        .await
        {
            AccessResponse::AssetGroup(Ok(info)) => info,
            other => panic!("Expected AssetGroup(Ok), got {:?}", other),
        }
    }

    async fn create_test_rule(
        pool: &DbPool,
        name: &str,
        ug_id: i32,
        ag_id: i32,
        protocols: Vec<&str>,
    ) -> AccessRuleInfo {
        let data = AccessRuleData {
            name: name.to_string(),
            description: None,
            user_group_id: ug_id,
            asset_group_id: ag_id,
            allowed_protocols: protocols.into_iter().map(|s| s.to_string()).collect(),
            valid_from: None,
            valid_until: None,
            require_mfa: false,
            require_justification: false,
            max_session_duration: None,
            is_active: true,
            priority: 0,
        };
        match handle_access_request(pool, AccessRequest::CreateAccessRule { data }).await {
            AccessResponse::AccessRule(Ok(info)) => info,
            other => panic!("Expected AccessRule(Ok), got {:?}", other),
        }
    }

    async fn cleanup_rule(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteAccessRule {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    async fn cleanup_vauban_group(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteVaubanGroup {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    async fn cleanup_asset_group(pool: &DbPool, uuid: &str) {
        handle_access_request(
            pool,
            AccessRequest::DeleteAssetGroup {
                uuid: uuid.to_string(),
            },
        )
        .await;
    }

    // ==================== Vauban Groups CRUD ====================

    #[tokio::test]
    async fn test_create_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg");
        let group = create_test_vauban_group(&pool, &name).await;
        assert_eq!(group.name, name);
        assert!(group.id > 0);
        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_get_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg_get");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::GetVaubanGroup {
                uuid: group.uuid.clone(),
            },
        )
        .await;
        match resp {
            AccessResponse::VaubanGroup(Ok(info)) => {
                assert_eq!(info.name, name);
                assert_eq!(info.uuid, group.uuid);
            }
            other => panic!("Expected VaubanGroup(Ok), got {:?}", other),
        }
        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_get_vauban_group_not_found() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::GetVaubanGroup {
                uuid: "nonexistent-uuid".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::VaubanGroup(Err(_)) => {}
            other => panic!("Expected VaubanGroup(Err), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_vauban_groups() {
        let pool = test_pool().await;
        let resp = handle_access_request(&pool, AccessRequest::ListVaubanGroups).await;
        match resp {
            AccessResponse::VaubanGroupList(list) => {
                let _ = list;
            }
            other => panic!("Expected VaubanGroupList, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_delete_vauban_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("vg_del");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::DeleteVaubanGroup {
                uuid: group.uuid.clone(),
            },
        )
        .await;
        match resp {
            AccessResponse::Deleted(Ok(())) => {}
            other => panic!("Expected Deleted(Ok), got {:?}", other),
        }
    }

    // ==================== Asset Groups CRUD ====================

    #[tokio::test]
    async fn test_create_asset_group_ok() {
        let pool = test_pool().await;
        let name = unique_name("ag");
        let group = create_test_asset_group(&pool, &name).await;
        assert_eq!(group.name, name);
        cleanup_asset_group(&pool, &group.uuid).await;
    }

    #[tokio::test]
    async fn test_list_asset_groups() {
        let pool = test_pool().await;
        let resp = handle_access_request(&pool, AccessRequest::ListAssetGroups).await;
        match resp {
            AccessResponse::AssetGroupList(_) => {}
            other => panic!("Expected AssetGroupList, got {:?}", other),
        }
    }

    // ==================== Access Rules CRUD ====================

    #[tokio::test]
    async fn test_create_access_rule_ok() {
        let pool = test_pool().await;
        let ug_name = unique_name("ug_rule");
        let ag_name = unique_name("ag_rule");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        let rule = create_test_rule(&pool, &unique_name("rule"), ug.id, ag.id, vec!["ssh"]).await;
        assert!(!rule.uuid.is_empty());
        assert!(rule.is_active);

        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_access_rules() {
        let pool = test_pool().await;
        let resp = handle_access_request(&pool, AccessRequest::ListAccessRules).await;
        match resp {
            AccessResponse::AccessRuleList(_) => {}
            other => panic!("Expected AccessRuleList, got {:?}", other),
        }
    }

    // ==================== Membership ====================

    #[tokio::test]
    async fn test_add_and_list_group_member() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let name = unique_name("vg_member");
        let group = create_test_vauban_group(&pool, &name).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: group.id,
                user_id,
            },
        )
        .await;
        match resp {
            AccessResponse::Ok => {}
            other => panic!("Expected Ok, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::ListGroupMembers { group_id: group.id },
        )
        .await;
        match resp {
            AccessResponse::MemberList(members) => {
                assert!(members.contains(&user_id));
            }
            other => panic!("Expected MemberList, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: group.id,
                user_id,
            },
        )
        .await;
        match resp {
            AccessResponse::Ok => {}
            other => panic!("Expected Ok, got {:?}", other),
        }

        cleanup_vauban_group(&pool, &group.uuid).await;
    }

    // ==================== Evaluation ====================

    #[tokio::test]
    async fn test_check_access_denied_no_rule() {
        let pool = test_pool().await;
        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id: 99999,
                asset_group_id: 99999,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(!result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_access_allowed() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("ug_eval");
        let ag_name = unique_name("ag_eval");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;

        let rule =
            create_test_rule(&pool, &unique_name("eval_rule"), ug.id, ag.id, vec!["ssh"]).await;

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id,
                asset_group_id: ag.id,
                protocol: "ssh".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        let resp = handle_access_request(
            &pool,
            AccessRequest::CheckAccess {
                user_id,
                asset_group_id: ag.id,
                protocol: "rdp".to_string(),
            },
        )
        .await;
        match resp {
            AccessResponse::AccessChecked(result) => {
                assert!(!result.allowed);
            }
            other => panic!("Expected AccessChecked, got {:?}", other),
        }

        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    #[tokio::test]
    async fn test_list_accessible_groups() {
        let pool = test_pool().await;
        let user_id = ensure_test_user(&pool).await;
        let ug_name = unique_name("ug_lag");
        let ag_name = unique_name("ag_lag");
        let ug = create_test_vauban_group(&pool, &ug_name).await;
        let ag = create_test_asset_group(&pool, &ag_name).await;

        handle_access_request(
            &pool,
            AccessRequest::AddGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        let rule = create_test_rule(
            &pool,
            &unique_name("lag_rule"),
            ug.id,
            ag.id,
            vec!["ssh", "rdp"],
        )
        .await;

        let resp =
            handle_access_request(&pool, AccessRequest::ListAccessibleGroups { user_id }).await;
        match resp {
            AccessResponse::AccessibleGroups(entries) => {
                let entry = entries.iter().find(|e| e.asset_group_id == ag.id);
                assert!(entry.is_some(), "Should find the asset group");
                let entry = entry.unwrap();
                assert!(entry.protocols.contains(&"ssh".to_string()));
                assert!(entry.protocols.contains(&"rdp".to_string()));
            }
            other => panic!("Expected AccessibleGroups, got {:?}", other),
        }

        handle_access_request(
            &pool,
            AccessRequest::RemoveGroupMember {
                group_id: ug.id,
                user_id,
            },
        )
        .await;
        cleanup_rule(&pool, &rule.uuid).await;
        cleanup_asset_group(&pool, &ag.uuid).await;
        cleanup_vauban_group(&pool, &ug.uuid).await;
    }

    // ==================== Group Options ====================

    #[tokio::test]
    async fn test_get_group_options() {
        let pool = test_pool().await;
        let resp = handle_access_request(&pool, AccessRequest::GetGroupOptions).await;
        match resp {
            AccessResponse::GroupOptions {
                user_groups,
                asset_groups,
            } => {
                let _ = (user_groups, asset_groups);
            }
            other => panic!("Expected GroupOptions, got {:?}", other),
        }
    }
}
