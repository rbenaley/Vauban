//! Revoke every open MCP visit covered by an access rule that was just
//! created, edited or deleted.
//!
//! Covered means: the session is MCP, the user is in the rule's user group,
//! and the asset is in the rule's asset group (every asset of those users
//! when the rule targets All assets). Active and suspended MCP visits are
//! ended through [`terminate_live_session`]. SSH, RDP and industrial
//! tunnels in the same groups stay open, and so does an MCP visit outside
//! the cohort. The agent receives [`shared::access_rule_revoke::sentence`].

use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::AppState;
use crate::error::AppResult;
use crate::models::session::{ProxySession, SessionStatus};
use crate::services::session_termination::{
    broadcast_session_list_updates, terminate_live_session,
};

/// One user-group / asset-group pair the changed rule covers.
/// On an edit that moves the rule, pass the pair from before and the pair
/// from after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCohort {
    pub user_group_id: i32,
    pub asset_group_id: i32,
}

/// A live ticket reduced to the fields the match needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTicket {
    pub id: i32,
    pub user_id: i32,
    pub asset_id: i32,
    pub mcp: bool,
}

/// Scope passed to the pure match. `all_assets` is the virtual group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleScope {
    pub user_group_id: i32,
    pub asset_group_id: i32,
    pub all_assets: bool,
}

/// Ids of MCP tickets whose user is in the scope's user group and whose
/// asset is in the scope's asset group. Several scopes are a union. Each
/// id is returned once, in ascending order. A non-MCP ticket is never
/// returned.
#[must_use]
pub fn covered_ticket_ids(
    tickets: &[OpenTicket],
    user_memberships: &[(i32, i32)],
    asset_memberships: &[(i32, i32)],
    scopes: &[RuleScope],
) -> Vec<i32> {
    let mut ids: Vec<i32> = tickets
        .iter()
        .filter(|ticket| {
            ticket.mcp
                && scopes.iter().any(|scope| {
                    user_memberships.iter().any(|(user_id, group_id)| {
                        *user_id == ticket.user_id && *group_id == scope.user_group_id
                    }) && (scope.all_assets
                        || asset_memberships.iter().any(|(asset_id, group_id)| {
                            *asset_id == ticket.asset_id && *group_id == scope.asset_group_id
                        }))
                })
        })
        .map(|ticket| ticket.id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// End every open MCP visit covered by `cohorts` and tell proxy-mcp why.
/// Returns how many visits were ended.
pub async fn revoke_sessions_for_rule_change(
    state: &AppState,
    rule_name: &str,
    cohorts: &[RuleCohort],
) -> AppResult<usize> {
    if cohorts.is_empty() {
        return Ok(0);
    }
    let scopes = scopes_of(cohorts);
    let user_group_ids: Vec<i32> = scopes.iter().map(|s| s.user_group_id).collect();
    let asset_group_ids: Vec<i32> = scopes
        .iter()
        .filter(|s| !s.all_assets)
        .map(|s| s.asset_group_id)
        .collect();

    use crate::schema::{asset_asset_groups, proxy_sessions, user_groups};

    let mut conn = state
        .db_pool
        .get()
        .await
        .map_err(|e| crate::error::AppError::Internal(anyhow::anyhow!("DB error: {e}")))?;

    let user_memberships: Vec<(i32, i32)> = user_groups::table
        .filter(user_groups::group_id.eq_any(&user_group_ids))
        .select((user_groups::user_id, user_groups::group_id))
        .load(&mut conn)
        .await
        .map_err(crate::error::AppError::Database)?;
    if user_memberships.is_empty() {
        return Ok(0);
    }
    let user_ids: Vec<i32> = user_memberships.iter().map(|(id, _)| *id).collect();

    let asset_memberships: Vec<(i32, i32)> = if asset_group_ids.is_empty() {
        Vec::new()
    } else {
        asset_asset_groups::table
            .filter(asset_asset_groups::asset_group_id.eq_any(&asset_group_ids))
            .select((
                asset_asset_groups::asset_id,
                asset_asset_groups::asset_group_id,
            ))
            .load(&mut conn)
            .await
            .map_err(crate::error::AppError::Database)?
    };

    let open: Vec<ProxySession> = proxy_sessions::table
        .filter(proxy_sessions::user_id.eq_any(&user_ids))
        .filter(proxy_sessions::status.eq_any(SessionStatus::OPEN_AS_STR))
        .load(&mut conn)
        .await
        .map_err(crate::error::AppError::Database)?;
    drop(conn);

    let tickets: Vec<OpenTicket> = open
        .iter()
        .map(|session| OpenTicket {
            id: session.id,
            user_id: session.user_id,
            asset_id: session.asset_id,
            mcp: session.session_type == crate::models::session::SessionType::Mcp,
        })
        .collect();
    let wanted = covered_ticket_ids(&tickets, &user_memberships, &asset_memberships, &scopes);
    let reason = shared::access_rule_revoke::wire_reason(rule_name);

    let mut ended = 0usize;
    for session in open.iter().filter(|session| wanted.contains(&session.id)) {
        match terminate_live_session(state, session, &reason).await {
            Ok(_) => ended += 1,
            Err(e) => tracing::warn!(
                session_uuid = %session.uuid,
                rule = %rule_name,
                error = %e,
                "access rule change: failed to revoke an open ticket"
            ),
        }
    }
    if ended > 0 {
        broadcast_session_list_updates(state).await;
    }
    Ok(ended)
}

fn scopes_of(cohorts: &[RuleCohort]) -> Vec<RuleScope> {
    let virtual_id = crate::services::virtual_group::virtual_asset_group_id();
    let virtual_ready = virtual_id != crate::services::virtual_group::UNINITIALIZED_VIRTUAL_ID;
    let mut scopes: Vec<RuleScope> = cohorts
        .iter()
        .map(|cohort| RuleScope {
            user_group_id: cohort.user_group_id,
            asset_group_id: cohort.asset_group_id,
            all_assets: virtual_ready && cohort.asset_group_id == virtual_id,
        })
        .collect();
    scopes.sort_by_key(|s| (s.user_group_id, s.asset_group_id, s.all_assets));
    scopes.dedup();
    scopes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(id: i32, user_id: i32, asset_id: i32, mcp: bool) -> OpenTicket {
        OpenTicket {
            id,
            user_id,
            asset_id,
            mcp,
        }
    }

    fn scope(user_group_id: i32, asset_group_id: i32) -> RuleScope {
        RuleScope {
            user_group_id,
            asset_group_id,
            all_assets: false,
        }
    }

    #[test]
    fn a_ticket_in_the_groups_is_revoked_and_the_others_stay() {
        let tickets = vec![
            ticket(1, 10, 100, true),
            ticket(2, 10, 200, true),
            ticket(3, 11, 100, true),
            ticket(4, 10, 100, true),
        ];
        let users = [(10, 7)];
        let assets = [(100, 8)];
        let ids = covered_ticket_ids(&tickets, &users, &assets, &[scope(7, 8)]);
        assert_eq!(ids, vec![1, 4]);
    }

    #[test]
    fn all_assets_covers_every_asset_of_the_user_group() {
        let tickets = vec![
            ticket(1, 10, 100, true),
            ticket(2, 10, 200, true),
            ticket(3, 11, 100, true),
        ];
        let users = [(10, 7)];
        let scope = RuleScope {
            user_group_id: 7,
            asset_group_id: 1,
            all_assets: true,
        };
        assert_eq!(
            covered_ticket_ids(&tickets, &users, &[], &[scope]),
            vec![1, 2]
        );
    }

    #[test]
    fn moving_a_rule_covers_the_old_group_and_the_new_one() {
        let tickets = vec![ticket(1, 10, 100, true), ticket(2, 12, 300, true)];
        let users = [(10, 7), (12, 9)];
        let assets = [(100, 8), (300, 4)];
        let ids = covered_ticket_ids(&tickets, &users, &assets, &[scope(7, 8), scope(9, 4)]);
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn an_ssh_ticket_in_the_same_groups_is_not_revoked() {
        let tickets = vec![ticket(1, 10, 100, true), ticket(2, 10, 100, false)];
        let users = [(10, 7)];
        let assets = [(100, 8)];
        assert_eq!(
            covered_ticket_ids(&tickets, &users, &assets, &[scope(7, 8)]),
            vec![1]
        );
    }

    #[test]
    fn the_sentence_contains_the_rule_name() {
        let text = shared::access_rule_revoke::sentence("Night shift");
        assert!(text.contains("Night shift"));
        assert!(text.contains("Open a new session"));
        assert_eq!(
            shared::access_rule_revoke::client_message(&shared::access_rule_revoke::wire_reason(
                "Night shift"
            )),
            Some(text.as_str())
        );
    }
}
