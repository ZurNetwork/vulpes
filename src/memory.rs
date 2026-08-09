//! In-memory storage fakes used by this crate's own unit tests.
//!
//! They mirror the two integrity constraints the
//! [`PlcOperationLog`](crate::PlcOperationLog) contract requires of a real
//! backend — `UNIQUE(cid)` and the no-chain-fork `UNIQUE(did, prev)` — so a
//! minter test that passes here would also pass against PostgreSQL.
//!
//! Test-only on purpose: shipping fakes in the public API is a separate
//! decision, and a real backend is the thing worth testing against.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::{
    CustodyKeys, Did, KeyStore, PlcOperationLog, PlcOperationRecord, StorageError, StorageResult,
};

/// An in-memory [`KeyStore`]. Rejects a second `put` for the same DID, as a
/// primary key would.
#[derive(Default)]
pub struct MemoryKeyStore {
    entries: Mutex<Vec<(Did, CustodyKeys)>>,
}

impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn put(&self, did: &Did, keys: &CustodyKeys) -> StorageResult<()> {
        let mut entries = self.entries.lock().expect("key store lock");
        if entries.iter().any(|(stored, _)| stored == did) {
            return Err(StorageError::new(format!("custody already held for {did}")));
        }
        entries.push((did.clone(), keys.clone()));
        Ok(())
    }

    async fn get(&self, did: &Did) -> StorageResult<Option<CustodyKeys>> {
        let entries = self.entries.lock().expect("key store lock");
        Ok(entries
            .iter()
            .find(|(stored, _)| stored == did)
            .map(|(_, keys)| keys.clone()))
    }
}

/// An in-memory [`PlcOperationLog`] holding full records in append order, with
/// both integrity constraints the trait's contract demands.
#[derive(Default)]
pub struct MemoryPlcOperationLog {
    records: Mutex<Vec<PlcOperationRecord>>,
}

impl MemoryPlcOperationLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every appended record, in append order.
    pub fn records(&self) -> Vec<PlcOperationRecord> {
        self.records.lock().expect("op log lock").clone()
    }
}

#[async_trait]
impl PlcOperationLog for MemoryPlcOperationLog {
    async fn append(&self, record: &PlcOperationRecord) -> StorageResult<()> {
        let mut records = self.records.lock().expect("op log lock");
        // UNIQUE(cid): a content-addressed operation is logged at most once.
        if records.iter().any(|stored| stored.cid == record.cid) {
            return Err(StorageError::new(format!(
                "plc operation {} already logged",
                record.cid
            )));
        }
        // UNIQUE(did, prev) WHERE prev IS NOT NULL: the chain cannot fork.
        if let Some(prev) = &record.prev
            && records
                .iter()
                .any(|stored| stored.did == record.did && stored.prev.as_ref() == Some(prev))
        {
            return Err(StorageError::new(format!(
                "plc operation already chains onto {prev} (the chain would fork)"
            )));
        }
        records.push(record.clone());
        Ok(())
    }

    async fn latest_cid(&self, did: &Did) -> StorageResult<Option<String>> {
        Ok(self.latest(did).map(|record| record.cid))
    }

    async fn latest_op(&self, did: &Did) -> StorageResult<Option<PlcOperationRecord>> {
        Ok(self.latest(did))
    }
}

impl MemoryPlcOperationLog {
    /// The DID's most recently appended record.
    fn latest(&self, did: &Did) -> Option<PlcOperationRecord> {
        self.records
            .lock()
            .expect("op log lock")
            .iter()
            .rev()
            .find(|record| &record.did == did)
            .cloned()
    }
}
