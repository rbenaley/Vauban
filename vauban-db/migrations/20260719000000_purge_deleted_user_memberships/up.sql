-- Purge user_groups memberships of soft-deleted users (July 2026
-- ghost-members incident).
--
-- The user deletion flow soft-deletes (users.is_deleted = true), so the
-- ON DELETE CASCADE on user_groups.user_id never fires and the
-- membership rows survive. The group list counted those raw rows while
-- the detail page filtered them out: groups displayed "2 members" with
-- an empty member list and became undeletable (the delete guard also
-- counted raw rows).
--
-- Going forward delete_user_web purges the memberships inside its
-- SERIALIZABLE transaction and every read path filters NOT is_deleted;
-- this migration cleans up the rows already orphaned in existing
-- databases.
DELETE FROM user_groups ug
USING users u
WHERE u.id = ug.user_id
  AND u.is_deleted;
