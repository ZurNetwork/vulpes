//! [`PgOAuthStateStore`] — PostgreSQL storage for the OAuth handshake's two
//! tiers of state.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;

use crate::postgres::storage;
use crate::{OAuthStateStore, StorageResult};

/// How long an in-flight authorization request stays readable, by default.
///
/// An auth-request row holds a live PKCE verifier and DPoP key for one sign-in
/// that is still mid-flight. It should live exactly as long as a human takes to
/// approve a consent screen, and not one redirect longer — "the visitor never
/// came back" and "the callback arrived a week later" are otherwise the same
/// row. Ten minutes is the top of the range RFC 9126 §2.2 gives for a pushed
/// authorization request's lifetime ("typically … between 5 and 600 seconds");
/// the atproto OAuth profile does not narrow it further.
pub const DEFAULT_AUTH_REQUEST_TTL: Duration = Duration::from_secs(600);

/// PostgreSQL [`OAuthStateStore`] over the `atproto_oauth` schema.
///
/// It stores **opaque bytes**: the blobs handed to it are already serialized and
/// sealed by [`crate::oauth`], so this type never sees a token, a DPoP key or a
/// PKCE verifier. That split is deliberate — the encryption lives in one place,
/// and a storage backend can be written without knowing anything about OAuth.
#[derive(Clone, Debug)]
pub struct PgOAuthStateStore {
    pool: PgPool,
    auth_request_ttl: Duration,
}

impl PgOAuthStateStore {
    /// Build the store over a connection `pool`, expiring in-flight
    /// authorization requests after [`DEFAULT_AUTH_REQUEST_TTL`].
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            auth_request_ttl: DEFAULT_AUTH_REQUEST_TTL,
        }
    }

    /// Expire in-flight authorization requests after `ttl` instead of the
    /// default.
    ///
    /// Shorten it freely; lengthen it only knowing what the row holds. The
    /// budget has to cover a visitor reading a consent screen on a phone, so
    /// something under a minute will fail real sign-ins.
    #[must_use]
    pub fn with_auth_request_ttl(mut self, ttl: Duration) -> Self {
        self.auth_request_ttl = ttl;
        self
    }

    /// How long this store keeps an in-flight authorization request readable.
    pub fn auth_request_ttl(&self) -> Duration {
        self.auth_request_ttl
    }

    /// Delete every in-flight authorization request past its TTL, returning how
    /// many rows went.
    ///
    /// Hygiene, not correctness: [`get_auth_request`](OAuthStateStore::get_auth_request)
    /// already refuses an expired row, so a deployment that never calls this is
    /// still safe — it just accumulates sealed rows nobody will ever read. Call
    /// it from whatever periodic job you already have; it is a single indexed
    /// `DELETE` and safe to run concurrently with anything.
    pub async fn prune_expired(&self) -> StorageResult<u64> {
        let pruned = sqlx::query(include_str!(
            "../../queries/oauth_state/prune_expired_auth_requests.sql"
        ))
        .bind(self.auth_request_ttl.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(pruned.rows_affected())
    }
}

#[async_trait]
impl OAuthStateStore for PgOAuthStateStore {
    async fn get_session(
        &self,
        account_did: &str,
        session_id: &str,
    ) -> StorageResult<Option<Vec<u8>>> {
        sqlx::query_scalar(include_str!("../../queries/oauth_state/get_session.sql"))
            .bind(account_did)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)
    }

    /// Insert or replace, so every refresh overwrites the prior token set in
    /// place and a later request on any replica reads the freshest grant.
    async fn upsert_session(
        &self,
        account_did: &str,
        session_id: &str,
        data: &[u8],
    ) -> StorageResult<()> {
        sqlx::query(include_str!("../../queries/oauth_state/upsert_session.sql"))
            .bind(account_did)
            .bind(session_id)
            .bind(data)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    async fn delete_session(&self, account_did: &str, session_id: &str) -> StorageResult<()> {
        sqlx::query(include_str!("../../queries/oauth_state/delete_session.sql"))
            .bind(account_did)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Read the in-flight request **and delete it**, in one `DELETE … RETURNING`
    /// — and only if it is younger than
    /// [`auth_request_ttl`](PgOAuthStateStore::auth_request_ttl).
    ///
    /// Single-use atomically, per the [trait's
    /// contract](OAuthStateStore::get_auth_request): jacquard's callback does a
    /// get and then a separate delete, so a plain `SELECT` would let two
    /// concurrent callbacks bearing the same `state` both walk away with the
    /// PKCE verifier and DPoP key. PostgreSQL serializes the row lock, so
    /// exactly one caller sees the row.
    ///
    /// An expired row reads as `Ok(None)` — absent, not an error, because from
    /// the callback's point of view a stale `state` is indistinguishable from an
    /// unknown one, and jacquard turns both into the same "start again".
    ///
    /// **This "read" is a write.** Despite the name it issues a `DELETE`, so the
    /// pool behind it must reach the **primary** — a deployment that routes this
    /// store's reads to a replica will fail here, unlike every other `get_*` on
    /// this type.
    async fn get_auth_request(&self, state: &str) -> StorageResult<Option<Vec<u8>>> {
        sqlx::query_scalar(include_str!(
            "../../queries/oauth_state/get_auth_request.sql"
        ))
        .bind(state)
        .bind(self.auth_request_ttl.as_secs_f64())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)
    }

    async fn save_auth_request(&self, state: &str, data: &[u8]) -> StorageResult<()> {
        sqlx::query(include_str!(
            "../../queries/oauth_state/save_auth_request.sql"
        ))
        .bind(state)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn delete_auth_request(&self, state: &str) -> StorageResult<()> {
        sqlx::query(include_str!(
            "../../queries/oauth_state/delete_auth_request.sql"
        ))
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }
}
