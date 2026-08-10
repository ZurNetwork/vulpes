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
    Did, KeyStore, PlcOperationLog, PlcOperationRecord, SealedKeys, StorageError, StorageResult,
};

/// An in-memory [`KeyStore`]. Holds sealed blobs (never plaintext) and rejects a
/// second `put` for the same DID, as a primary key would.
#[derive(Default)]
pub struct MemoryKeyStore {
    entries: Mutex<Vec<(Did, SealedKeys)>>,
}

impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn put(&self, did: &Did, keys: &SealedKeys) -> StorageResult<()> {
        let mut entries = self.entries.lock().expect("key store lock");
        if entries.iter().any(|(stored, _)| stored == did) {
            return Err(StorageError::new(format!("custody already held for {did}")));
        }
        entries.push((did.clone(), keys.clone()));
        Ok(())
    }

    async fn get(&self, did: &Did) -> StorageResult<Option<SealedKeys>> {
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

/// An in-memory [`OAuthStateStore`](crate::OAuthStateStore), holding the sealed
/// blobs the OAuth bridge hands it. Only compiled with the `oauth` feature,
/// which is the only thing that drives it.
#[cfg(feature = "oauth")]
#[derive(Default)]
pub struct MemoryOAuthStateStore {
    sessions: Mutex<Vec<(SessionKey, Vec<u8>)>>,
    requests: Mutex<Vec<(String, Vec<u8>)>>,
}

/// The `(account_did, session_id)` pair an established session is keyed by.
#[cfg(feature = "oauth")]
type SessionKey = (String, String);

#[cfg(feature = "oauth")]
#[async_trait]
impl crate::OAuthStateStore for MemoryOAuthStateStore {
    async fn get_session(
        &self,
        account_did: &str,
        session_id: &str,
    ) -> StorageResult<Option<Vec<u8>>> {
        let key = (account_did.to_string(), session_id.to_string());
        let sessions = self.sessions.lock().expect("session lock");
        Ok(sessions
            .iter()
            .find(|(stored, _)| stored == &key)
            .map(|(_, data)| data.clone()))
    }

    async fn upsert_session(
        &self,
        account_did: &str,
        session_id: &str,
        data: &[u8],
    ) -> StorageResult<()> {
        let key = (account_did.to_string(), session_id.to_string());
        let mut sessions = self.sessions.lock().expect("session lock");
        sessions.retain(|(stored, _)| stored != &key);
        sessions.push((key, data.to_vec()));
        Ok(())
    }

    async fn delete_session(&self, account_did: &str, session_id: &str) -> StorageResult<()> {
        let key = (account_did.to_string(), session_id.to_string());
        self.sessions
            .lock()
            .expect("session lock")
            .retain(|(stored, _)| stored != &key);
        Ok(())
    }

    /// Single-use, as the trait's contract requires: the read **removes** the
    /// entry under the same lock, so two concurrent callbacks bearing one
    /// `state` cannot both come away with the PKCE verifier.
    async fn get_auth_request(&self, state: &str) -> StorageResult<Option<Vec<u8>>> {
        let mut requests = self.requests.lock().expect("request lock");
        let found = requests.iter().position(|(stored, _)| stored == state);
        Ok(found.map(|index| requests.swap_remove(index).1))
    }

    async fn save_auth_request(&self, state: &str, data: &[u8]) -> StorageResult<()> {
        let mut requests = self.requests.lock().expect("request lock");
        requests.retain(|(stored, _)| stored != state);
        requests.push((state.to_string(), data.to_vec()));
        Ok(())
    }

    async fn delete_auth_request(&self, state: &str) -> StorageResult<()> {
        self.requests
            .lock()
            .expect("request lock")
            .retain(|(stored, _)| stored != state);
        Ok(())
    }
}
