//! [`PgPlcOperationLog`] — the PostgreSQL append-only log of submitted `did:plc`
//! operations.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row as _};

use crate::postgres::storage;
use crate::{Did, PlcOperationLog, PlcOperationRecord, StorageError, StorageResult};

/// PostgreSQL [`PlcOperationLog`] over the `plc_operations` table.
///
/// The two integrity properties the [trait's contract](PlcOperationLog) demands
/// are enforced by the schema, not by this code: `UNIQUE(cid)` makes a
/// content-addressed operation loggable once, and the partial
/// `UNIQUE(did, prev) WHERE prev IS NOT NULL` index makes a forked chain
/// unrepresentable. Both surface here as ordinary insert errors, which is
/// exactly what the caller's replay and retry logic expects.
pub struct PgPlcOperationLog {
    pool: PgPool,
}

impl PgPlcOperationLog {
    /// Build the log over a connection `pool`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PlcOperationLog for PgPlcOperationLog {
    /// Insert one operation row. `operation_json` (public material only) lands
    /// as native `jsonb`.
    async fn append(&self, record: &PlcOperationRecord) -> StorageResult<()> {
        // The record carries the operation as JSON text by contract; parse it
        // here so it is stored as `jsonb` rather than an opaque string.
        let operation: serde_json::Value =
            serde_json::from_str(&record.operation_json).map_err(StorageError::new)?;
        sqlx::query(include_str!("../../queries/plc_log/append.sql"))
            .bind(record.did.as_str())
            .bind(&record.cid)
            .bind(&record.op_type)
            .bind(record.prev.as_deref())
            .bind(&operation)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// The `cid` of the DID's highest-`seq` (most recent) operation, or `None`.
    async fn latest_cid(&self, did: &Did) -> StorageResult<Option<String>> {
        sqlx::query_scalar(include_str!("../../queries/plc_log/latest_cid.sql"))
            .bind(did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)
    }

    /// The DID's most recent operation as a full record, or `None`.
    ///
    /// `operation` is stored as `jsonb`; it is re-serialized into the JSON text
    /// the record carries. An update reads this to carry the prior operation's
    /// public fields forward without decrypting any key but the signer.
    async fn latest_op(&self, did: &Did) -> StorageResult<Option<PlcOperationRecord>> {
        let row = sqlx::query(include_str!("../../queries/plc_log/latest_op.sql"))
            .bind(did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let operation: serde_json::Value = row.try_get("operation").map_err(storage)?;
        Ok(Some(PlcOperationRecord {
            did: did.clone(),
            cid: row.try_get("cid").map_err(storage)?,
            op_type: row.try_get("op_type").map_err(storage)?,
            prev: row.try_get("prev").map_err(storage)?,
            operation_json: operation.to_string(),
        }))
    }
}
