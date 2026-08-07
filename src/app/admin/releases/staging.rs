//! Staged-release lifecycle for the C1 upload ceremony.
//!
//! The helper keys a release blob on the release id, so the row must exist
//! before the bytes are streamed. It is created as
//! [`RELEASE_STATUS_STAGING`] and is therefore invisible everywhere: either
//! the ceremony commits (row becomes `PUBLISHED`) or the whole operation is
//! rolled back — aborted upload, no storage row, no release row.
//!
//! A staged row is only legitimate while `StorageClient` holds a live
//! reservation for it. Expired reservations (admin closed the tab) and rows
//! with no reservation at all (portal restarted mid-ceremony) are orphans.

use topcoat::context::Cx;

use crate::{
    auth::{db, storage},
    models::{RELEASE_STATUS_STAGING, Release},
    storage::{delete_release_object, find_release_object},
};

/// Ceremony budget: how long a staged row may survive without committing.
pub(super) const STAGING_TTL_SECS: u64 = 300;

/// Staged rows no longer covered by a reservation, in `staged` order.
pub(super) fn orphan_staged_ids(staged: &[u64], live: &[u64]) -> Vec<u64> {
    staged
        .iter()
        .copied()
        .filter(|id| !live.contains(id))
        .collect()
}

/// Undo a staged publish: abort the upload, drop any blob that already
/// landed, and delete the release row. Never touches a row that left
/// `STAGING` (a committed release is the admin's to delete explicitly).
pub(super) async fn rollback_staged_release(
    cx: &Cx,
    release_id: u64,
    upload_id: Option<&str>,
    blob_committed: bool,
) {
    let store = storage(cx);
    if let Some(upload_id) = upload_id {
        let _ = store.put_abort(upload_id);
    }
    store.unmark_staged_release(release_id);

    let mut database = db(cx);
    if blob_committed
        || find_release_object(&mut database, release_id)
            .await
            .is_some()
    {
        let _ = store.delete_release(release_id);
        let _ = delete_release_object(&mut database, release_id).await;
    }

    let rows = Release::all()
        .filter(Release::fields().id().eq(release_id))
        .filter(
            Release::fields()
                .status()
                .eq(RELEASE_STATUS_STAGING.to_owned()),
        )
        .exec(&mut database)
        .await
        .unwrap_or_default();
    for rel in rows {
        let _ = rel.delete().exec(&mut database).await;
    }
}

/// Roll back every abandoned ceremony. Cheap enough to run on the admin
/// release list and before a new publish, which is where an admin who
/// walked away from the signature prompt shows up next.
pub(super) async fn sweep_staged_releases(cx: &Cx) {
    let store = storage(cx);
    let now = crate::storage::StorageClient::now_unix();
    for expired in store.take_expired_pending_releases(now) {
        let _ = store.put_abort(&expired.upload_id);
    }
    let live_before = store.live_staged_release_ids(now);

    let mut database = db(cx);
    let staged: Vec<u64> = Release::all()
        .filter(
            Release::fields()
                .status()
                .eq(RELEASE_STATUS_STAGING.to_owned()),
        )
        .exec(&mut database)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|rel| rel.id)
        .collect();

    // A row inserted while this sweep was reading is not an orphan: bracket
    // the read with both reservation snapshots, and stand down entirely while
    // another request sits between its insert and its reservation.
    let mut live = store.live_staged_release_ids(crate::storage::StorageClient::now_unix());
    live.extend(live_before);
    if store.staging_creates_in_flight() {
        return;
    }

    for id in orphan_staged_ids(&staged, &live) {
        rollback_staged_release(cx, id, None, false).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphans_exclude_live_reservations() {
        assert_eq!(orphan_staged_ids(&[1, 2, 3], &[2]), vec![1, 3]);
    }

    #[test]
    fn orphans_empty_when_every_row_is_reserved() {
        assert!(orphan_staged_ids(&[7, 8], &[8, 7]).is_empty());
    }

    #[test]
    fn orphans_include_everything_after_a_restart() {
        assert_eq!(orphan_staged_ids(&[4, 5], &[]), vec![4, 5]);
    }

    #[test]
    fn orphans_ignore_reservations_without_a_row() {
        assert!(orphan_staged_ids(&[], &[11]).is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::proptest_util::cases(64))]

        #[test]
        fn prop_orphans_are_staged_minus_live(
            staged in proptest::collection::vec(1u64..40, 0..12),
            live in proptest::collection::vec(1u64..40, 0..12),
        ) {
            let orphans = orphan_staged_ids(&staged, &live);
            for id in &orphans {
                prop_assert!(staged.contains(id), "orphan must come from a staged row");
                prop_assert!(!live.contains(id), "reserved ceremony must survive");
            }
            for id in &staged {
                if !live.contains(id) {
                    prop_assert!(orphans.contains(id), "abandoned row must be swept");
                }
            }
        }
    }
}
