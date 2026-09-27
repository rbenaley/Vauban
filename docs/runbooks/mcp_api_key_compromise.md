# Runbook — MCP API key compromise (`vbn_`)

> TRUSTED R2.2. Lab / operator playbook.

## Goal

When a `vbn_…` key may have leaked: **invalidate the secret**, **cut live MCP
sessions** opened with that key, and leave a **sealed audit** trail.

## Actions (UI)

1. Sign in as the key owner (or an admin with access to that user’s keys).
2. Open **Accounts → API keys**.
3. Choose either:
   - **Revoke** — key stays listed but inactive forever for that secret.
   - **Regenerate** — same key row / scopes; **new** `vbn_…` shown once; old secret dead.
4. Confirm: live MCP sessions that carried `metadata.api_key_id` for that key
   are terminated immediately (Access decision reason: API key revoked/rotated).
5. Issue the new secret only through a secure channel if you regenerated.

## What the product does (code)

On successful revoke or regenerate:

1. Persist the key change (`is_active = false` or new hash).
2. Terminate matching live MCP sessions (`api_key_inactive`).
3. Emit critical WORM `ApiKeyRevoked` or `ApiKeyRotated` with
   `api_key_id`, `action`, `mcp_sessions_terminated`.

Do **not** wait for the ~30 s MCP recheck for this path.

## Verify

```sql
-- key inactive or new prefix after rotate
SELECT uuid, key_prefix, is_active FROM api_keys WHERE uuid = '<key-uuid>';

-- sessions cut with decision
SELECT uuid, status, termination_reason, decision_id
FROM proxy_sessions
WHERE session_type = 'mcp'
  AND termination_reason = 'api_key_inactive'
ORDER BY decision_at DESC NULLS LAST
LIMIT 5;
```

Pin: `gwt_r2_api_key_compromise_kills_sessions_and_audits`.

## Related

- User guide: cutting access — [`Vauban_MCP_User_Guide_EN.md`](../user/Vauban_MCP_User_Guide_EN.md)  
