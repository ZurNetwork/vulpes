//! In-memory fakes for the ACP ports — test-only (FORKS F19).
//!
//! Same discipline as `crate::memory`: each fake honours the port's
//! contract exactly (absent is `Ok(None)` / empty; only a "dark" switch
//! produces `Err`), so a verifier test that passes here would pass against
//! a real PDS, directory and mirror. The extra methods beyond the traits —
//! `replace`, `rotate`, `clear`, `go_dark` — are how a test plays the
//! adversary or the outage.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde::Serialize;

use crate::Did;

use super::ports::{
    DidResolver, FetchedRecord, KeyMaterial, RepoError, RepoReader, ResolveError, StatusFetchError,
    StatusSource,
};
use super::record::{AtUri, RecordCid, canonical_bytes};

/// Every subject's repo at once, keyed by at-uri.
#[derive(Default)]
pub struct MemoryRepo {
    records: Mutex<BTreeMap<String, (Did, Vec<u8>)>>,
    dark: AtomicBool,
}

impl MemoryRepo {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write `record` into `repo`; returns its address and CID.
    pub fn put<T: Serialize>(
        &self,
        repo: &Did,
        collection: &str,
        rkey: &str,
        record: &T,
    ) -> (AtUri, RecordCid) {
        let bytes = canonical_bytes(record).expect("fixture serializes");
        let cid = RecordCid::of(&bytes);
        (self.put_bytes(repo, collection, rkey, bytes), cid)
    }

    /// Write raw canonical bytes — how a transplant or a malformed record
    /// gets planted.
    pub fn put_bytes(&self, repo: &Did, collection: &str, rkey: &str, bytes: Vec<u8>) -> AtUri {
        let uri = AtUri::record(repo, collection, rkey);
        self.records
            .lock()
            .expect("repo lock")
            .insert(uri.as_str().to_string(), (repo.clone(), bytes));
        uri
    }

    /// Overwrite a record in place (a rewrite: same address, new CID).
    pub fn replace<T: Serialize>(&self, uri: &AtUri, record: &T) {
        let bytes = canonical_bytes(record).expect("fixture serializes");
        self.replace_bytes(uri, bytes);
    }

    /// Overwrite a record's bytes in place.
    pub fn replace_bytes(&self, uri: &AtUri, bytes: Vec<u8>) {
        let mut records = self.records.lock().expect("repo lock");
        let (repo, _) = records
            .get(uri.as_str())
            .cloned()
            .expect("replace targets an existing record");
        records.insert(uri.as_str().to_string(), (repo, bytes));
    }

    /// Delete a record (retraction / severance).
    pub fn delete(&self, uri: &AtUri) {
        self.records.lock().expect("repo lock").remove(uri.as_str());
    }

    /// Synchronous read for test assertions.
    pub fn get(&self, uri: &AtUri) -> Option<FetchedRecord> {
        self.records
            .lock()
            .expect("repo lock")
            .get(uri.as_str())
            .map(|(repo, bytes)| FetchedRecord {
                cid: RecordCid::of(bytes),
                bytes: bytes.clone(),
                uri: uri.clone(),
                repository: repo.clone(),
            })
    }

    /// Everything in `repo` — a CAR export, in spirit.
    pub fn export(&self, repo: &Did) -> Vec<(AtUri, FetchedRecord)> {
        self.records
            .lock()
            .expect("repo lock")
            .iter()
            .filter(|(_, (r, _))| r == repo)
            .map(|(uri, (r, bytes))| {
                let uri = AtUri::parse(uri).expect("stored uris are valid");
                (
                    uri.clone(),
                    FetchedRecord {
                        cid: RecordCid::of(bytes),
                        bytes: bytes.clone(),
                        uri,
                        repository: r.clone(),
                    },
                )
            })
            .collect()
    }

    /// Every call from now on fails: the host is down.
    pub fn go_dark(&self) {
        self.dark.store(true, Ordering::SeqCst);
    }

    fn check(&self) -> Result<(), RepoError> {
        if self.dark.load(Ordering::SeqCst) {
            Err(RepoError::new("pds unreachable"))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl RepoReader for MemoryRepo {
    async fn get_record(&self, uri: &AtUri) -> Result<Option<FetchedRecord>, RepoError> {
        self.check()?;
        Ok(self.get(uri))
    }

    async fn list_records(
        &self,
        repo: &Did,
        collection: &str,
    ) -> Result<Vec<FetchedRecord>, RepoError> {
        self.check()?;
        Ok(self
            .export(repo)
            .into_iter()
            .filter(|(uri, _)| uri.collection() == Some(collection))
            .map(|(_, f)| f)
            .collect())
    }
}

/// A DID directory: DID → current key material.
#[derive(Default)]
pub struct MemoryResolver {
    docs: Mutex<BTreeMap<Did, KeyMaterial>>,
    dark: AtomicBool,
}

impl MemoryResolver {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish (or republish) a DID's keys.
    pub fn publish(&self, did: &Did, keys: KeyMaterial) {
        self.docs
            .lock()
            .expect("resolver lock")
            .insert(did.clone(), keys);
    }

    /// Replace a DID's keys — the old ones no longer verify anything.
    pub fn rotate(&self, did: &Did, keys: KeyMaterial) {
        self.publish(did, keys);
    }

    /// The DID stops resolving (tombstoned, or a `did:web` host gone).
    pub fn remove(&self, did: &Did) {
        self.docs.lock().expect("resolver lock").remove(did);
    }

    /// Every call from now on fails: the directory is down.
    pub fn go_dark(&self) {
        self.dark.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl DidResolver for MemoryResolver {
    async fn keys(&self, did: &Did) -> Result<Option<KeyMaterial>, ResolveError> {
        if self.dark.load(Ordering::SeqCst) {
            return Err(ResolveError::new("directory unreachable"));
        }
        Ok(self.docs.lock().expect("resolver lock").get(did).cloned())
    }
}

/// Status-list mirrors: URL → every copy anyone has published there.
#[derive(Default)]
pub struct MemoryStatus {
    lists: Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
    dark: AtomicBool,
}

impl MemoryStatus {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a copy at `url` (another mirror picked it up; older copies stay).
    pub fn publish(&self, url: &str, bytes: Vec<u8>) {
        self.lists
            .lock()
            .expect("status lock")
            .entry(url.to_string())
            .or_default()
            .push(bytes);
    }

    /// No copy of `url` anywhere.
    pub fn clear(&self, url: &str) {
        self.lists.lock().expect("status lock").remove(url);
    }

    /// Every call from now on fails.
    pub fn go_dark(&self) {
        self.dark.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl StatusSource for MemoryStatus {
    async fn fetch(&self, list: &str) -> Result<Vec<Vec<u8>>, StatusFetchError> {
        if self.dark.load(Ordering::SeqCst) {
            return Err(StatusFetchError::new("mirrors unreachable"));
        }
        Ok(self
            .lists
            .lock()
            .expect("status lock")
            .get(list)
            .cloned()
            .unwrap_or_default())
    }
}
