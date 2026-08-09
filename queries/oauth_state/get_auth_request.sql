-- Read an in-flight authorization request AND consume it, in one statement.
--
-- A DELETE … RETURNING rather than a SELECT: the caller (jacquard's callback)
-- does a get followed by a separate delete, which is a window in which two
-- concurrent callbacks carrying the same `state` both read the same PKCE
-- verifier and DPoP key. One statement closes it — PostgreSQL serializes the
-- row lock, so exactly one caller gets the row and every other sees nothing.
--
-- $2 is the time-to-live in seconds. A row older than that is treated as
-- ABSENT: an authorization that was started and never finished is a live PKCE
-- verifier and DPoP key sitting in a table, and "the callback never came" is
-- indistinguishable from "the callback came a week later". Expiry is enforced
-- in the read rather than trusted to a sweeper, so a lapsed sweeper cannot
-- quietly extend the window.
DELETE FROM atproto_oauth.auth_request
WHERE state = $1
  AND created_at > now() - ($2::double precision * interval '1 second')
RETURNING data
