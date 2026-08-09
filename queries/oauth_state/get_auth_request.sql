-- Read an in-flight authorization request AND consume it, in one statement.
--
-- A DELETE … RETURNING rather than a SELECT: the caller (jacquard's callback)
-- does a get followed by a separate delete, which is a window in which two
-- concurrent callbacks carrying the same `state` both read the same PKCE
-- verifier and DPoP key. One statement closes it — PostgreSQL serializes the
-- row lock, so exactly one caller gets the row and every other sees nothing.
DELETE FROM atproto_oauth.auth_request
WHERE state = $1
RETURNING data
