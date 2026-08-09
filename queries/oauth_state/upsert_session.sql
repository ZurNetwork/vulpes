INSERT INTO atproto_oauth.client_session (account_did, session_id, data, updated_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (account_did, session_id) DO UPDATE
SET data = excluded.data, updated_at = now()
