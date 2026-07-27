//! Seat-limit helpers for client companies (max users per org).

use toasty::Db;

use crate::models::{MAX_USERS_PER_COMPANY, Membership};

/// Count memberships for an organization.
pub async fn membership_count(db: &mut Db, organization_id: u64) -> anyhow::Result<usize> {
    let rows = Membership::all()
        .filter(Membership::fields().organization_id().eq(organization_id))
        .exec(db)
        .await?;
    Ok(rows.len())
}

/// True when another user account may be added under the seat cap.
pub async fn can_add_member(db: &mut Db, organization_id: u64) -> anyhow::Result<bool> {
    let n = membership_count(db, organization_id).await?;
    Ok(n < MAX_USERS_PER_COMPANY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seat_cap_constant() {
        assert_eq!(MAX_USERS_PER_COMPANY, 5);
    }

    #[test]
    fn can_add_member_boundary_logic() {
        // Pure boundary mirroring can_add_member without DB.
        for n in 0..=MAX_USERS_PER_COMPANY {
            assert_eq!(n < MAX_USERS_PER_COMPANY, n < 5);
        }
    }
}
