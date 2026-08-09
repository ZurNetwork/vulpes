//! [`PgKeyStore`] — PostgreSQL custody for minted `did:plc` keys, encrypted at
//! rest.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row as _};

use crate::postgres::storage;
use crate::{
    CustodyEnvelope, CustodyKeys, Did, KeyStore, SecretVault, StorageError, StorageResult,
};

/// PostgreSQL [`KeyStore`]: seals custody keys under a [`SecretVault`] and
/// persists the ciphertext in `account_keys`.
///
/// The write is a single-row insert performed *during minting*, before any row
/// of yours can exist — the identity's DID is derived from the very operation
/// these keys sign — so it deliberately does not join an application
/// transaction. That is same-store temporal ordering, not a cross-store concern.
pub struct PgKeyStore {
    pool: PgPool,
    vault: SecretVault,
}

impl PgKeyStore {
    /// Build the store over a connection `pool` and the `vault` that seals every
    /// custody record.
    pub fn new(pool: PgPool, vault: SecretVault) -> Self {
        Self { pool, vault }
    }
}

#[async_trait]
impl KeyStore for PgKeyStore {
    /// Seal `keys` under the vault (binding them to `did`) and insert them.
    ///
    /// One DID mints once, so a duplicate insert is a primary-key violation,
    /// surfaced to the caller rather than overwriting custody.
    async fn put(&self, did: &Did, keys: &CustodyKeys) -> StorageResult<()> {
        let sealed = keys.seal(&self.vault, did).map_err(StorageError::new)?;
        sqlx::query(include_str!("../../queries/key_store/put.sql"))
            .bind(did.as_str())
            .bind(&sealed)
            .bind(i32::from(CustodyEnvelope::CURRENT))
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Load the sealed blob for `did` and open it **under the envelope scheme
    /// the row records**, or `None` if the DID is unknown.
    ///
    /// The `key_version` column is read, not assumed: a value naming no scheme
    /// this build knows — a row written by a newer zurid, met during a rolling
    /// deploy or after a rollback — is an explicit error. Opening it under a
    /// guessed scheme would at best fail the AEAD tag and at worst hand back
    /// bytes that were never these keys.
    ///
    /// A decryption failure — the wrong root key, a blob lifted from another
    /// row, tampering — is likewise an error, never a `None`.
    async fn get(&self, did: &Did) -> StorageResult<Option<CustodyKeys>> {
        let row = sqlx::query(include_str!("../../queries/key_store/get.sql"))
            .bind(did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let sealed: Vec<u8> = row.try_get("wrapped_keys").map_err(storage)?;
        let version: i32 = row.try_get("key_version").map_err(storage)?;
        let envelope = CustodyEnvelope::try_from(version).map_err(StorageError::new)?;

        let keys =
            CustodyKeys::open(&self.vault, did, &sealed, envelope).map_err(StorageError::new)?;
        Ok(Some(keys))
    }
}
