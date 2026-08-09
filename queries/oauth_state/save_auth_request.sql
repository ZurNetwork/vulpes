INSERT INTO atproto_oauth.auth_request (state, data, created_at)
VALUES ($1, $2, now())
ON CONFLICT (state) DO UPDATE SET data = excluded.data
