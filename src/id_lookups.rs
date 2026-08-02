//! Targeted Toasty lookups by primary key (avoid `Model::all()` for labels).

use toasty::Db;

use crate::models::{Organization, User};

fn dedupe_ids(ids: &[u64]) -> Vec<u64> {
    let mut unique = ids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    unique
}

/// Load users whose ids appear in `ids` (deduped). Empty `ids` → empty vec.
pub async fn users_by_ids(db: &mut Db, ids: &[u64]) -> anyhow::Result<Vec<User>> {
    let unique = dedupe_ids(ids);
    if unique.is_empty() {
        return Ok(Vec::new());
    }
    Ok(User::all()
        .filter(User::fields().id().in_list(unique))
        .exec(db)
        .await?)
}

/// Load organizations whose ids appear in `ids` (deduped). Empty `ids` → empty vec.
pub async fn orgs_by_ids(db: &mut Db, ids: &[u64]) -> anyhow::Result<Vec<Organization>> {
    let unique = dedupe_ids(ids);
    if unique.is_empty() {
        return Ok(Vec::new());
    }
    Ok(Organization::all()
        .filter(Organization::fields().id().in_list(unique))
        .exec(db)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_ids_sorts_and_dedups() {
        assert_eq!(dedupe_ids(&[]), Vec::<u64>::new());
        assert_eq!(dedupe_ids(&[3, 1, 3, 2]), vec![1, 2, 3]);
    }
}
