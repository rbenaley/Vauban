-- Overturn restores every group the MCP drift RemoveGroupMember cut.
ALTER TABLE proxy_sessions
  ADD COLUMN decision_source_group_ids JSONB NULL;

COMMENT ON COLUMN proxy_sessions.decision_source_group_ids IS
  'IAM groups removed on MCP suspend_group drift (array of int ids). decision_source_group_id is the first / UI principal.';
