//! Seat-limit helpers for client companies (max users per org).

use toasty::Db;

use crate::models::Membership;

/// Count memberships for an organization.
pub async fn membership_count(db: &mut Db, organization_id: u64) -> anyhow::Result<usize> {
    let rows = Membership::all()
        .filter(Membership::fields().organization_id().eq(organization_id))
        .exec(db)
        .await?;
    Ok(rows.len())
}

/// True when another user account may be added under `max` seats.
pub async fn can_add_member(db: &mut Db, organization_id: u64, max: usize) -> anyhow::Result<bool> {
    let n = membership_count(db, organization_id).await?;
    Ok(n < max)
}

/// Boundary helper (no DB): whether `current_count` is still under `max`.
pub fn under_seat_cap(current_count: usize, max: usize) -> bool {
    current_count < max
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MAX_USERS_PER_COMPANY;

    #[test]
    fn default_seat_cap_constant() {
        assert_eq!(MAX_USERS_PER_COMPANY, 5);
    }

    #[test]
    fn under_seat_cap_respects_injected_max() {
        assert!(under_seat_cap(0, 5));
        assert!(under_seat_cap(4, 5));
        assert!(!under_seat_cap(5, 5));
        assert!(under_seat_cap(2, 3));
        assert!(!under_seat_cap(3, 3));
    }
}
