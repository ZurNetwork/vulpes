-- vulpes: durable storage for the atproto OAuth handshake's two tiers of state.
--
-- These rows hold live upstream credentials on a user's behalf: an established
-- session carries the DPoP private signing key plus the long-lived refresh token
-- and access token; an in-flight request carries the PKCE verifier and DPoP key.
-- A read of them in the clear (a leaked backup, a read replica, an injection
-- read gadget) is a RENEWABLE PDS-session takeover, so every `data` blob is
-- sealed with an AEAD under the same root key that seals key custody (see
-- vulpes::SecretVault). The database holds ciphertext, never plaintext.
--
-- The blobs are opaque to SQL by design: vulpes's OAuth layer serializes and
-- seals them, so this schema stores bytes and never sees a token.
CREATE SCHEMA atproto_oauth;

-- Established OAuth sessions: the token set and DPoP key, keyed by account DID +
-- session id. Persisting these lets the upstream grant and the refresh machinery
-- survive a restart or a move between replicas.
CREATE TABLE atproto_oauth.client_session (
    account_did text        NOT NULL,
    session_id  text        NOT NULL,
    data        bytea       NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_did, session_id)
);

-- In-flight authorization requests: PKCE verifier + DPoP key, keyed by the OAuth
-- `state`. Short-lived — written when the flow starts, read then deleted at the
-- callback. Persisting them is what lets the redirect land on a different
-- process than the one that started the flow.
--
-- created_at is load-bearing, not bookkeeping: the read refuses any row older
-- than the store's TTL (so a sign-in that was started and abandoned cannot be
-- completed days later), and `PgOAuthStateStore::prune_expired` sweeps them.
CREATE TABLE atproto_oauth.auth_request (
    state      text        PRIMARY KEY NOT NULL,
    data       bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The prune filters on created_at and nothing else, so without this index it is
-- a sequential scan of the whole table — which is exactly the shape that makes
-- an operator quietly stop running the sweep.
CREATE INDEX atproto_oauth_auth_request_created_at
    ON atproto_oauth.auth_request (created_at);
