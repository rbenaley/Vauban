//! Organisational vault secrets -- access-control handlers.
//!
//! Group-to-group evaluation 100% parallel to the asset machinery:
//! `vauban_groups` (subject, read-only FK) x `secret_groups` (object),
//! joined through `secret_access_rules`. vauban-access is the SINGLE
//! evaluation oracle -- vauban-web never evaluates `secret_access_rules`
//! in SQL (pinned by `check`-style tests on the web side).
//!
//! Deliberate differences with the asset rules:
//! - no `allowed_protocols` (a secret has no protocol),
//! - no `require_mfa` / `require_approval` (the consumer is an M2M API
//!   key; there is no interactive step-up and no JIT),
//! - no `max_session_duration` (there is no session),
//! - and NO Casbin/read_all bypass anywhere: even a superuser must be
//!   covered by a rule to read a secret value.
//!
//! Fail-closed: every error path in the evaluation verbs collapses to
//! "not allowed" / an empty page rather than an error the caller could
//! interpret loosely.

use chrono::Utc;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel::sql_types::Bool as SqlBool;
use diesel_async::RunQueryDsl;
use shared::messages::{
    AccessibleSecretGroupEntry, GroupOption, IpcPage, IpcPageParams, SECRET_GROUP_KIND_STATIC,
    SecretAccessRuleData, SecretAccessRuleInfo, SecretGroupInfo,
};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::DbConnection;
use crate::handlers::{normalize_ipc_page, parse_optional_datetime, parse_uuid, resolve_actor_id};
use crate::schema::{
    asset_asset_groups, asset_groups, assets, secret_access_rules, secret_groups,
    secret_secret_groups, user_groups, users, vault_secrets,
};
use shared::messages::AccessResponse;

// ==================== Secret group CRUD ====================

type SecretGroupRow = (
    i32,
    Uuid,
    String,
    String,
    Option<String>,
    String,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

fn to_secret_group_info(row: SecretGroupRow, member_count: i64) -> SecretGroupInfo {
    SecretGroupInfo {
        id: row.0,
        uuid: row.1.to_string(),
        name: row.2,
        slug: row.3,
        description: row.4,
        kind: row.5,
        created_at: row.6.to_rfc3339(),
        updated_at: row.7.to_rfc3339(),
        member_count,
    }
}

/// One grouped COUNT query for a page of group ids (avoids N+1).
async fn member_counts_for(conn: &mut DbConnection, group_ids: &[i32]) -> HashMap<i32, i64> {
    if group_ids.is_empty() {
        return HashMap::new();
    }
    let rows: Vec<(i32, i64)> = match secret_secret_groups::table
        .filter(secret_secret_groups::secret_group_id.eq_any(group_ids))
        .group_by(secret_secret_groups::secret_group_id)
        .select((
            secret_secret_groups::secret_group_id,
            diesel::dsl::count_star(),
        ))
        .load(conn)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(error = %e, "secret_groups: member count query failed; rendering 0");
            Vec::new()
        }
    };
    rows.into_iter().collect()
}

pub async fn handle_create_secret_group(
    conn: &mut DbConnection,
    name: &str,
    slug: &str,
    description: Option<&str>,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    // CreateSecretGroup is the user-facing path; only static groups can
    // be minted this way. The virtual "All secrets" row is system-seeded
    // by migration and protected by DB triggers -- it can never be
    // created (nor re-created) via this handler.
    let result = diesel::insert_into(secret_groups::table)
        .values((
            secret_groups::uuid.eq(new_uuid),
            secret_groups::name.eq(name),
            secret_groups::slug.eq(slug),
            secret_groups::description.eq(description),
            secret_groups::kind.eq(SECRET_GROUP_KIND_STATIC),
            secret_groups::created_by_id.eq(actor_id),
            secret_groups::updated_by_id.eq(actor_id),
            secret_groups::created_at.eq(now),
            secret_groups::updated_at.eq(now),
        ))
        .returning(secret_groups::id)
        .get_result::<i32>(conn)
        .await;

    match result {
        Ok(id) => {
            info!(uuid = %new_uuid, name, "Secret group created");
            AccessResponse::SecretGroup(Ok(SecretGroupInfo {
                id,
                uuid: new_uuid.to_string(),
                name: name.to_string(),
                slug: slug.to_string(),
                description: description.map(String::from),
                kind: SECRET_GROUP_KIND_STATIC.to_string(),
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
                member_count: 0,
            }))
        }
        Err(e) => AccessResponse::SecretGroup(Err(format!("Failed to create secret group: {e}"))),
    }
}

pub async fn handle_get_secret_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::SecretGroup(Err(e)),
    };

    let row = secret_groups::table
        .filter(secret_groups::uuid.eq(group_uuid))
        .select((
            secret_groups::id,
            secret_groups::uuid,
            secret_groups::name,
            secret_groups::slug,
            secret_groups::description,
            secret_groups::kind,
            secret_groups::created_at,
            secret_groups::updated_at,
        ))
        .first::<SecretGroupRow>(conn)
        .await;

    match row {
        Ok(row) => {
            let counts = member_counts_for(conn, &[row.0]).await;
            let member_count = counts.get(&row.0).copied().unwrap_or(0);
            AccessResponse::SecretGroup(Ok(to_secret_group_info(row, member_count)))
        }
        Err(e) => AccessResponse::SecretGroup(Err(format!("Secret group not found: {e}"))),
    }
}

pub async fn handle_list_secret_groups(
    conn: &mut DbConnection,
    page: IpcPageParams,
    include_virtual: bool,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    // Fail-closed default: the virtual "All secrets" group stays hidden
    // unless the caller explicitly opts in (secret-access-rule editor).
    let mut query = secret_groups::table.into_boxed();
    if !include_virtual {
        query = query.filter(secret_groups::kind.eq(SECRET_GROUP_KIND_STATIC));
    }

    let result = query
        .order(secret_groups::name.asc())
        .then_order_by(secret_groups::id.asc())
        .select((
            secret_groups::id,
            secret_groups::uuid,
            secret_groups::name,
            secret_groups::slug,
            secret_groups::description,
            secret_groups::kind,
            secret_groups::created_at,
            secret_groups::updated_at,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<SecretGroupRow>(conn)
        .await;

    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > base_limit as usize;
            if has_more {
                rows.truncate(base_limit as usize);
            }
            let ids: Vec<i32> = rows.iter().map(|r| r.0).collect();
            let counts = member_counts_for(conn, &ids).await;
            let infos: Vec<SecretGroupInfo> = rows
                .into_iter()
                .map(|row| {
                    let count = counts.get(&row.0).copied().unwrap_or(0);
                    to_secret_group_info(row, count)
                })
                .collect();
            AccessResponse::SecretGroupPage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list secret groups: {e}")),
    }
}

pub async fn handle_update_secret_group(
    conn: &mut DbConnection,
    uuid_str: &str,
    name: &str,
    slug: &str,
    description: Option<&str>,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::SecretGroup(Err(e)),
    };
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    // The DB trigger `block_mutation_on_virtual_secret_groups` refuses any
    // UPDATE on the virtual row -- the error surfaces as a plain failure.
    let affected = diesel::update(secret_groups::table.filter(secret_groups::uuid.eq(group_uuid)))
        .set((
            secret_groups::name.eq(name),
            secret_groups::slug.eq(slug),
            secret_groups::description.eq(description),
            secret_groups::updated_at.eq(Utc::now()),
            secret_groups::updated_by_id.eq(actor_id),
        ))
        .execute(conn)
        .await;

    match affected {
        Ok(0) => AccessResponse::SecretGroup(Err(format!("Secret group {uuid_str} not found"))),
        Ok(_) => {
            info!(uuid = %uuid_str, name, "Secret group updated");
            handle_get_secret_group(conn, uuid_str).await
        }
        Err(e) => AccessResponse::SecretGroup(Err(format!("Failed to update secret group: {e}"))),
    }
}

pub async fn handle_delete_secret_group(conn: &mut DbConnection, uuid_str: &str) -> AccessResponse {
    let group_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    // The DB trigger refuses any DELETE on the virtual row (fail-closed).
    match diesel::delete(secret_groups::table.filter(secret_groups::uuid.eq(group_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Secret group {uuid_str} not found"))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Secret group deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete secret group: {e}"))),
    }
}

pub async fn handle_list_secret_group_options(
    conn: &mut DbConnection,
    page: IpcPageParams,
    include_virtual: bool,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    let mut query = secret_groups::table.into_boxed();
    if !include_virtual {
        query = query.filter(secret_groups::kind.eq(SECRET_GROUP_KIND_STATIC));
    }

    let rows = query
        .order(secret_groups::name.asc())
        .then_order_by(secret_groups::id.asc())
        .select((
            secret_groups::id,
            secret_groups::uuid,
            secret_groups::name,
            secret_groups::kind,
        ))
        .limit(fetch)
        .offset(offset)
        .load::<(i32, Uuid, String, String)>(conn)
        .await;

    match rows {
        Ok(mut rows) => {
            let has_more = rows.len() > base_limit as usize;
            if has_more {
                rows.truncate(base_limit as usize);
            }
            let items = rows
                .into_iter()
                .map(|(id, uuid, name, kind)| GroupOption {
                    id,
                    uuid: uuid.to_string(),
                    name,
                    kind,
                })
                .collect();
            AccessResponse::SecretGroupOptionsPage(IpcPage { items, has_more })
        }
        Err(e) => AccessResponse::Error(format!("Failed to load secret group options: {e}")),
    }
}

// ==================== Secret access rule CRUD ====================

type SecretAccessRuleRow = (
    Uuid,
    String,
    Option<String>,
    i32,
    Uuid,
    String,
    i32,
    Uuid,
    String,
    i32,
    Uuid,
    String,
    String,
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
    bool,
    i32,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

macro_rules! secret_access_rule_columns {
    () => {
        (
            secret_access_rules::uuid,
            secret_access_rules::name,
            secret_access_rules::description,
            secret_access_rules::user_group_id,
            crate::schema::vauban_groups::uuid,
            crate::schema::vauban_groups::name,
            secret_access_rules::secret_group_id,
            secret_groups::uuid,
            secret_groups::name,
            secret_access_rules::asset_group_id,
            asset_groups::uuid,
            asset_groups::name,
            asset_groups::kind,
            secret_access_rules::valid_from,
            secret_access_rules::valid_until,
            secret_access_rules::is_active,
            secret_access_rules::priority,
            secret_access_rules::created_at,
            secret_access_rules::updated_at,
        )
    };
}

fn to_secret_access_rule_info(row: SecretAccessRuleRow) -> SecretAccessRuleInfo {
    SecretAccessRuleInfo {
        uuid: row.0.to_string(),
        name: row.1,
        description: row.2,
        user_group_id: row.3,
        user_group_uuid: row.4.to_string(),
        user_group_name: row.5,
        secret_group_id: row.6,
        secret_group_uuid: row.7.to_string(),
        secret_group_name: row.8,
        asset_group_id: row.9,
        asset_group_uuid: row.10.to_string(),
        asset_group_name: row.11,
        asset_group_kind: row.12,
        valid_from: row.13.map(|dt| dt.to_rfc3339()),
        valid_until: row.14.map(|dt| dt.to_rfc3339()),
        is_active: row.15,
        priority: row.16,
        created_at: row.17.to_rfc3339(),
        updated_at: row.18.to_rfc3339(),
    }
}

async fn load_secret_access_rule_by_uuid(
    conn: &mut DbConnection,
    rule_uuid: Uuid,
) -> Result<SecretAccessRuleInfo, String> {
    secret_access_rules::table
        .inner_join(crate::schema::vauban_groups::table)
        .inner_join(secret_groups::table)
        .inner_join(asset_groups::table)
        .filter(secret_access_rules::uuid.eq(rule_uuid))
        .select(secret_access_rule_columns!())
        .first::<SecretAccessRuleRow>(conn)
        .await
        .map(to_secret_access_rule_info)
        .map_err(|e| format!("Secret access rule not found: {e}"))
}

pub async fn handle_create_secret_access_rule(
    conn: &mut DbConnection,
    data: SecretAccessRuleData,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let new_uuid = Uuid::new_v4();
    let now = Utc::now();

    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let result = diesel::insert_into(secret_access_rules::table)
        .values((
            secret_access_rules::uuid.eq(new_uuid),
            secret_access_rules::name.eq(&data.name),
            secret_access_rules::description.eq(&data.description),
            secret_access_rules::user_group_id.eq(data.user_group_id),
            secret_access_rules::secret_group_id.eq(data.secret_group_id),
            secret_access_rules::asset_group_id.eq(data.asset_group_id),
            secret_access_rules::valid_from.eq(valid_from),
            secret_access_rules::valid_until.eq(valid_until),
            secret_access_rules::is_active.eq(data.is_active),
            secret_access_rules::priority.eq(data.priority),
            secret_access_rules::created_by_id.eq(actor_id),
            secret_access_rules::updated_by_id.eq(actor_id),
            secret_access_rules::created_at.eq(now),
            secret_access_rules::updated_at.eq(now),
        ))
        .execute(conn)
        .await;

    match result {
        Ok(_) => {
            info!(uuid = %new_uuid, name = %data.name, "Secret access rule created");
            match load_secret_access_rule_by_uuid(conn, new_uuid).await {
                Ok(info) => AccessResponse::SecretAccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::SecretAccessRule(Err(format!(
            "Failed to create secret access rule: {e}"
        ))),
    }
}

pub async fn handle_get_secret_access_rule(
    conn: &mut DbConnection,
    uuid_str: &str,
) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    match load_secret_access_rule_by_uuid(conn, rule_uuid).await {
        Ok(info) => AccessResponse::SecretAccessRule(Ok(info)),
        Err(e) => AccessResponse::SecretAccessRule(Err(e)),
    }
}

pub async fn handle_list_secret_access_rules(
    conn: &mut DbConnection,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);
    let result = secret_access_rules::table
        .inner_join(crate::schema::vauban_groups::table)
        .inner_join(secret_groups::table)
        .inner_join(asset_groups::table)
        .order(secret_access_rules::priority.desc())
        .then_order_by(secret_access_rules::id.desc())
        .select(secret_access_rule_columns!())
        .limit(fetch)
        .offset(offset)
        .load::<SecretAccessRuleRow>(conn)
        .await;

    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > base_limit as usize;
            if has_more {
                rows.truncate(base_limit as usize);
            }
            let infos: Vec<SecretAccessRuleInfo> =
                rows.into_iter().map(to_secret_access_rule_info).collect();
            AccessResponse::SecretAccessRulePage(IpcPage {
                items: infos,
                has_more,
            })
        }
        Err(e) => AccessResponse::Error(format!("Failed to list secret access rules: {e}")),
    }
}

pub async fn handle_update_secret_access_rule(
    conn: &mut DbConnection,
    uuid_str: &str,
    data: SecretAccessRuleData,
    actor_uuid: Option<&str>,
) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    let valid_from = match parse_optional_datetime(&data.valid_from) {
        Ok(v) => v,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    let valid_until = match parse_optional_datetime(&data.valid_until) {
        Ok(v) => v,
        Err(e) => return AccessResponse::SecretAccessRule(Err(e)),
    };
    let now = Utc::now();
    let actor_id = resolve_actor_id(conn, actor_uuid).await;

    let affected =
        diesel::update(secret_access_rules::table.filter(secret_access_rules::uuid.eq(rule_uuid)))
            .set((
                secret_access_rules::name.eq(&data.name),
                secret_access_rules::description.eq(&data.description),
                secret_access_rules::user_group_id.eq(data.user_group_id),
                secret_access_rules::secret_group_id.eq(data.secret_group_id),
                secret_access_rules::asset_group_id.eq(data.asset_group_id),
                secret_access_rules::valid_from.eq(valid_from),
                secret_access_rules::valid_until.eq(valid_until),
                secret_access_rules::is_active.eq(data.is_active),
                secret_access_rules::priority.eq(data.priority),
                secret_access_rules::updated_at.eq(now),
                secret_access_rules::updated_by_id.eq(actor_id),
            ))
            .execute(conn)
            .await;

    match affected {
        Ok(0) => AccessResponse::SecretAccessRule(Err(format!(
            "Secret access rule {uuid_str} not found"
        ))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Secret access rule updated");
            match load_secret_access_rule_by_uuid(conn, rule_uuid).await {
                Ok(info) => AccessResponse::SecretAccessRule(Ok(info)),
                Err(e) => AccessResponse::Error(e),
            }
        }
        Err(e) => AccessResponse::SecretAccessRule(Err(format!(
            "Failed to update secret access rule: {e}"
        ))),
    }
}

pub async fn handle_delete_secret_access_rule(
    conn: &mut DbConnection,
    uuid_str: &str,
) -> AccessResponse {
    let rule_uuid = match parse_uuid(uuid_str) {
        Ok(u) => u,
        Err(e) => return AccessResponse::Deleted(Err(e)),
    };

    match diesel::delete(secret_access_rules::table.filter(secret_access_rules::uuid.eq(rule_uuid)))
        .execute(conn)
        .await
    {
        Ok(0) => AccessResponse::Deleted(Err(format!("Secret access rule {uuid_str} not found"))),
        Ok(_) => {
            info!(uuid = %uuid_str, "Secret access rule deleted");
            AccessResponse::Deleted(Ok(()))
        }
        Err(e) => AccessResponse::Deleted(Err(format!("Failed to delete secret access rule: {e}"))),
    }
}

// ==================== Evaluation ====================

/// Resolve the provenance search ids for a verified source asset: the
/// asset group memberships of `source_asset_id`, plus the virtual "All
/// assets" singleton (a rule on the virtual group covers ANY known
/// asset). Mirrors the asset-side pattern in `handlers.rs`.
///
/// Fail-closed contract: `Err(())` when the asset is unknown/deleted or
/// any DB lookup fails -- callers must translate that into a denial.
async fn provenance_asset_group_ids(
    conn: &mut DbConnection,
    source_asset_id: i32,
) -> Result<Vec<i32>, ()> {
    // Defense-in-depth: re-assert the source asset is a live row even
    // though vauban-web only forwards ids it just matched. A deleted
    // asset must never anchor provenance.
    let live: i64 = match assets::table
        .filter(assets::id.eq(source_asset_id))
        .filter(assets::is_deleted.eq(false))
        .count()
        .get_result::<i64>(conn)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            warn!(source_asset_id, error = %e, "provenance: db error resolving source asset");
            return Err(());
        }
    };
    if live == 0 {
        warn!(
            source_asset_id,
            "provenance: unknown or deleted source asset"
        );
        return Err(());
    }

    let mut group_ids: Vec<i32> = match asset_asset_groups::table
        .filter(asset_asset_groups::asset_id.eq(source_asset_id))
        .select(asset_asset_groups::asset_group_id)
        .load::<i32>(conn)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            warn!(source_asset_id, error = %e, "provenance: db error loading asset groups");
            return Err(());
        }
    };

    // The sentinel UNINITIALIZED_VIRTUAL_ID cannot match any real row,
    // so pre-boot lookups degrade to "no virtual rule applies".
    let virtual_id = crate::virtual_group::virtual_asset_group_id();
    if !group_ids.contains(&virtual_id) {
        group_ids.push(virtual_id);
    }
    Ok(group_ids)
}

/// Bulk list-filter primitive: which secret groups can `user_id` access
/// right now, calling from the identity-verified `source_asset_id`?
/// Returns the distinct accessible `secret_groups.id` values; an entry
/// whose id is the virtual "All secrets" singleton is flagged
/// `is_virtual_all` so vauban-web resolves it to every active secret.
///
/// Only rules whose `asset_group_id` contains the source asset (or the
/// virtual "All assets" group) participate.
pub async fn handle_list_accessible_secret_groups(
    conn: &mut DbConnection,
    user_id: i32,
    source_asset_id: i32,
    page: IpcPageParams,
) -> AccessResponse {
    let (base_limit, offset) = normalize_ipc_page(page);
    let fetch = base_limit.saturating_add(1);

    let provenance_ids = match provenance_asset_group_ids(conn, source_asset_id).await {
        Ok(ids) => ids,
        Err(()) => {
            // Fail-closed: an invalid provenance yields an empty page,
            // indistinguishable from "no rule grants anything".
            return AccessResponse::AccessibleSecretGroupsPage(IpcPage {
                items: Vec::new(),
                has_more: false,
            });
        }
    };

    let mut distinct_ids = match secret_access_rules::table
        .inner_join(
            user_groups::table.on(user_groups::group_id.eq(secret_access_rules::user_group_id)),
        )
        .filter(user_groups::user_id.eq(user_id))
        .filter(secret_access_rules::asset_group_id.eq_any(&provenance_ids))
        .filter(secret_access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(secret_access_rules.valid_from IS NULL OR secret_access_rules.valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(secret_access_rules.valid_until IS NULL OR secret_access_rules.valid_until >= NOW())",
        ))
        .select(secret_access_rules::secret_group_id)
        .distinct()
        .order_by(secret_access_rules::secret_group_id.asc())
        .limit(fetch)
        .offset(offset)
        .load::<i32>(conn)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            return AccessResponse::Error(format!("Failed to list accessible secret groups: {e}"));
        }
    };

    let has_more = distinct_ids.len() > base_limit as usize;
    if has_more {
        distinct_ids.truncate(base_limit as usize);
    }

    let virtual_id = crate::virtual_secret_group::virtual_secret_group_id();
    let entries: Vec<AccessibleSecretGroupEntry> = distinct_ids
        .into_iter()
        .map(|id| AccessibleSecretGroupEntry {
            secret_group_id: id,
            is_virtual_all: id == virtual_id,
        })
        .collect();

    AccessResponse::AccessibleSecretGroupsPage(IpcPage {
        items: entries,
        has_more,
    })
}

/// Unit check before revealing one secret's value.
///
/// Fail-closed semantics: any failure path (UUID parse error, unknown or
/// inactive user, unknown or inactive secret, unknown/deleted source
/// asset, DB error) returns `SecretAccessChecked { allowed: false }`
/// rather than `Error(...)`, so the caller treats the response as a
/// clean denial without having to distinguish "policy says no" from
/// "infrastructure error". There is deliberately NO Casbin/read_all
/// bypass: even a superuser must be covered by an active rule.
///
/// The provenance dimension: only rules whose `asset_group_id` contains
/// `source_asset_id` (directly or via the virtual "All assets" group)
/// can grant.
pub async fn handle_check_secret_access_by_uuid(
    conn: &mut DbConnection,
    user_uuid: &str,
    secret_uuid: &str,
    source_asset_id: i32,
) -> AccessResponse {
    let denied = || AccessResponse::SecretAccessChecked { allowed: false };

    let user_uuid_parsed = match Uuid::parse_str(user_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(user_uuid, error = %e, "CheckSecretAccessByUuid: invalid user uuid");
            return denied();
        }
    };
    let secret_uuid_parsed = match Uuid::parse_str(secret_uuid) {
        Ok(u) => u,
        Err(e) => {
            warn!(secret_uuid, error = %e, "CheckSecretAccessByUuid: invalid secret uuid");
            return denied();
        }
    };

    let user_id: i32 = match users::table
        .filter(users::uuid.eq(user_uuid_parsed))
        .filter(users::is_active.eq(true))
        .select(users::id)
        .first::<i32>(conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            warn!(
                user_uuid,
                "CheckSecretAccessByUuid: unknown or inactive user"
            );
            return denied();
        }
        Err(e) => {
            warn!(user_uuid, error = %e, "CheckSecretAccessByUuid: db error resolving user");
            return denied();
        }
    };

    let secret_id: i32 = match vault_secrets::table
        .filter(vault_secrets::uuid.eq(secret_uuid_parsed))
        .filter(vault_secrets::is_active.eq(true))
        .select(vault_secrets::id)
        .first::<i32>(conn)
        .await
    {
        Ok(id) => id,
        Err(diesel::result::Error::NotFound) => {
            info!(
                secret_uuid,
                "CheckSecretAccessByUuid: unknown or inactive secret"
            );
            return denied();
        }
        Err(e) => {
            warn!(secret_uuid, error = %e, "CheckSecretAccessByUuid: db error resolving secret");
            return denied();
        }
    };

    let mut secret_group_ids: Vec<i32> = match secret_secret_groups::table
        .filter(secret_secret_groups::secret_id.eq(secret_id))
        .select(secret_secret_groups::secret_group_id)
        .load::<i32>(conn)
        .await
    {
        Ok(ids) => ids,
        Err(e) => {
            warn!(
                secret_uuid, secret_id, error = %e,
                "CheckSecretAccessByUuid: db error loading secret groups"
            );
            return denied();
        }
    };

    // Defense-in-depth: ALWAYS append the virtual "All secrets" id so an
    // orphan secret (member of no static group) is still reachable when
    // the user has a virtual rule. The sentinel UNINITIALIZED_VIRTUAL_ID
    // cannot match any real row, so pre-boot lookups degrade to "no
    // virtual rule applies" (fail-closed).
    let virtual_id = crate::virtual_secret_group::virtual_secret_group_id();
    if !secret_group_ids.contains(&virtual_id) {
        secret_group_ids.push(virtual_id);
    }

    let provenance_ids = match provenance_asset_group_ids(conn, source_asset_id).await {
        Ok(ids) => ids,
        Err(()) => return denied(),
    };

    let matching: Result<i64, _> = secret_access_rules::table
        .inner_join(
            user_groups::table.on(user_groups::group_id.eq(secret_access_rules::user_group_id)),
        )
        .filter(user_groups::user_id.eq(user_id))
        .filter(secret_access_rules::secret_group_id.eq_any(&secret_group_ids))
        .filter(secret_access_rules::asset_group_id.eq_any(&provenance_ids))
        .filter(secret_access_rules::is_active.eq(true))
        .filter(sql::<SqlBool>(
            "(secret_access_rules.valid_from IS NULL OR secret_access_rules.valid_from <= NOW())",
        ))
        .filter(sql::<SqlBool>(
            "(secret_access_rules.valid_until IS NULL OR secret_access_rules.valid_until >= NOW())",
        ))
        .count()
        .get_result::<i64>(conn)
        .await;

    match matching {
        Ok(n) if n > 0 => {
            info!(user_uuid, secret_uuid, "CheckSecretAccessByUuid granted");
            AccessResponse::SecretAccessChecked { allowed: true }
        }
        Ok(_) => {
            info!(
                user_uuid,
                secret_uuid, "CheckSecretAccessByUuid denied: no granting secret_access_rule"
            );
            denied()
        }
        Err(e) => {
            warn!(user_uuid, secret_uuid, error = %e, "CheckSecretAccessByUuid: db error");
            denied()
        }
    }
}
