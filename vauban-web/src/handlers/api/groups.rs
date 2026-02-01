/// VAUBAN Web - Groups API handlers.
///
/// This module provides read-only API access to Vauban groups.
/// Group modification (add/remove members, edit) is only available via the web interface.
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::Serialize;

use crate::AppState;
use crate::error::AppError;
use crate::middleware::auth::AuthUser;

/// Group member response.
#[derive(Debug, Serialize)]
pub struct GroupMemberResponse {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: bool,
}

/// List members response.
#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub group_uuid: String,
    pub group_name: String,
    pub members: Vec<GroupMemberResponse>,
    pub total: usize,
}

/// List members of a group (GET /api/v1/groups/{uuid}/members).
///
/// Returns the list of users that are members of the specified group.
/// This is a read-only endpoint.
pub async fn list_group_members(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    Path(uuid_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    use crate::schema::user_groups::dsl as ug;
    use crate::schema::users::dsl as u;
    use crate::schema::vauban_groups::dsl as vg;

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("DB error: {}", e)))?;

    let group_uuid = uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Validation(format!("Invalid UUID: {}", e)))?;

    // Get group info
    let group_row: (uuid::Uuid, String) = vg::vauban_groups
        .filter(vg::uuid.eq(group_uuid))
        .select((vg::uuid, vg::name))
        .first(&mut conn)
        .await
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AppError::NotFound("Group not found".to_string()),
            _ => AppError::Database(e),
        })?;

    let (g_uuid, g_name) = group_row;

    // Get group members
    #[allow(clippy::type_complexity)]
    let members_data: Vec<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
    )> = u::users
        .inner_join(ug::user_groups.on(ug::user_id.eq(u::id)))
        .inner_join(vg::vauban_groups.on(vg::id.eq(ug::group_id)))
        .filter(vg::uuid.eq(group_uuid))
        .filter(u::is_deleted.eq(false))
        .order(u::username.asc())
        .select((
            u::uuid,
            u::username,
            u::email,
            u::first_name,
            u::last_name,
            u::is_active,
        ))
        .load(&mut conn)
        .await
        .map_err(AppError::Database)?;

    let members: Vec<GroupMemberResponse> = members_data
        .into_iter()
        .map(
            |(uuid, username, email, first_name, last_name, is_active)| GroupMemberResponse {
                uuid: uuid.to_string(),
                username,
                email,
                first_name,
                last_name,
                is_active,
            },
        )
        .collect();

    let total = members.len();

    let response = ListMembersResponse {
        group_uuid: g_uuid.to_string(),
        group_name: g_name,
        members,
        total,
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_member_response_serialization() {
        let member = GroupMemberResponse {
            uuid: "test-uuid".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            is_active: true,
        };

        let json = unwrap_ok!(serde_json::to_string(&member));
        assert!(json.contains("testuser"));
        assert!(json.contains("test@example.com"));
    }

    #[test]
    fn test_list_members_response_serialization() {
        let response = ListMembersResponse {
            group_uuid: "group-uuid".to_string(),
            group_name: "Test Group".to_string(),
            members: vec![],
            total: 0,
        };

        let json = unwrap_ok!(serde_json::to_string(&response));
        assert!(json.contains("Test Group"));
        assert!(json.contains("\"total\":0"));
    }
}
