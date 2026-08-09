//! [`PgKeyStore`] — PostgreSQL custody for minted `did:plc` keys, encrypted at
//! rest.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;

use crate::postgres::storage;
use crate::{CustodyKeys, Did, KeyStore, SecretVault, StorageError, StorageResult};

/// The envelope scheme this store writes. Recorded per row so custody can be
/// re-wrapped under a new root key (or a KMS) later without guessing what the
/// existing bytes are.
const KEY_VERSION: i32 = 1;

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
            .bind(KEY_VERSION)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Load the sealed blob for `did` and open it, or `None` if unknown.
    ///
    /// A decryption failure — the wrong root key, a blob lifted from another
    /// row, tampering — is an error, never a `None`.
    async fn get(&self, did: &Did) -> StorageResult<Option<CustodyKeys>> {
        let sealed: Option<Vec<u8>> =
            sqlx::query_scalar(include_str!("../../queries/key_store/get.sql"))
                .bind(did.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage)?;

        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let keys = CustodyKeys::open(&self.vault, did, &sealed).map_err(StorageError::new)?;
        Ok(Some(keys))
    }
}
