SELECT data FROM atproto_oauth.client_session
WHERE account_did = $1 AND session_id = $2
