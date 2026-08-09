//! [`PgOAuthStateStore`] — PostgreSQL storage for the OAuth handshake's two
//! tiers of state.

use async_trait::async_trait;
use sqlx::PgPool;

use crate::postgres::storage;
use crate::{OAuthStateStore, StorageResult};

/// PostgreSQL [`OAuthStateStore`] over the `atproto_oauth` schema.
///
/// It stores **opaque bytes**: the blobs handed to it are already serialized and
/// sealed by [`crate::oauth`], so this type never sees a token, a DPoP key or a
/// PKCE verifier. That split is deliberate — the encryption lives in one place,
/// and a storage backend can be written without knowing anything about OAuth.
#[derive(Clone, Debug)]
pub struct PgOAuthStateStore {
    pool: PgPool,
}

impl PgOAuthStateStore {
    /// Build the store over a connection `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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

    /// Read the in-flight request **and delete it**, in one `DELETE … RETURNING`.
    ///
    /// Single-use atomically, per the [trait's
    /// contract](OAuthStateStore::get_auth_request): jacquard's callback does a
    /// get and then a separate delete, so a plain `SELECT` would let two
    /// concurrent callbacks bearing the same `state` both walk away with the
    /// PKCE verifier and DPoP key. PostgreSQL serializes the row lock, so
    /// exactly one caller sees the row.
    async fn get_auth_request(&self, state: &str) -> StorageResult<Option<Vec<u8>>> {
        sqlx::query_scalar(include_str!(
            "../../queries/oauth_state/get_auth_request.sql"
        ))
        .bind(state)
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
