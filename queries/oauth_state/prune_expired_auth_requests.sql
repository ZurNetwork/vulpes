-- Drop every in-flight authorization request older than $1 seconds.
--
-- The reader already refuses expired rows, so this is not a correctness
-- backstop — it is hygiene: an abandoned sign-in leaves a sealed PKCE verifier
-- and DPoP key behind, and rows nobody will ever read should not accumulate in
-- a table that is otherwise tiny and hot.
DELETE FROM atproto_oauth.auth_request
WHERE created_at <= now() - ($1::double precision * interval '1 second')
