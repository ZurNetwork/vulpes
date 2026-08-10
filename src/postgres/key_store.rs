//! [`PgKeyStore`] — PostgreSQL custody for minted `did:plc` keys, stored sealed.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row as _};

use crate::postgres::storage;
use crate::{Did, KeyStore, SealedKeys, StorageResult};

/// PostgreSQL [`KeyStore`]: persists the sealed custody blob and its envelope
/// version in `account_keys`.
///
/// It holds **no vault** and never opens a blob — sealing and opening live with
/// the [`Minter`](crate::Minter), which owns the [`SecretVault`](crate::SecretVault).
/// This store round-trips opaque bytes, so a plaintext custody store is not a
/// thing it can be (the custody-side mirror of [`PgOAuthStateStore`](crate::postgres::PgOAuthStateStore)).
///
/// The write is a single-row insert performed *during minting*, before any row
/// of yours can exist — the identity's DID is derived from the very operation
/// these keys sign — so it deliberately does not join an application
/// transaction. That is same-store temporal ordering, not a cross-store concern.
pub struct PgKeyStore {
    pool: PgPool,
}

impl PgKeyStore {
    /// Build the store over a connection `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyStore for PgKeyStore {
    /// Insert the sealed `keys` — ciphertext plus envelope version — for `did`.
    ///
    /// One DID mints once, so a duplicate insert is a primary-key violation,
    /// surfaced to the caller rather than overwriting custody.
    async fn put(&self, did: &Did, keys: &SealedKeys) -> StorageResult<()> {
        sqlx::query(include_str!("../../queries/key_store/put.sql"))
            .bind(did.as_str())
            .bind(keys.blob())
            .bind(keys.version())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Return the sealed blob and its stored version as [`SealedKeys`], or
    /// `None` if the DID is unknown.
    ///
    /// A byte round-trip: the version is stored and returned verbatim, and it is
    /// the opener (the [`Minter`](crate::Minter)) — not this store — that
    /// resolves it to an envelope scheme and rejects an unknown one. A database
    /// fault is `Err`; "no such row" is `Ok(None)`.
    async fn get(&self, did: &Did) -> StorageResult<Option<SealedKeys>> {
        let row = sqlx::query(include_str!("../../queries/key_store/get.sql"))
            .bind(did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let blob: Vec<u8> = row.try_get("wrapped_keys").map_err(storage)?;
        let version: i32 = row.try_get("key_version").map_err(storage)?;
        Ok(Some(SealedKeys::from_parts(version, blob)))
    }
}
