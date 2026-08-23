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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde::Serialize;

use crate::Did;

use super::ports::{
    DidResolver, FetchedRecord, KeyMaterial, RepoError, RepoReader, ResolveError, StatusFetchError,
    StatusSource,
};
use super::record::{AtUri, RecordCid, StatusUri, canonical_bytes};

/// Every subject's repo at once, keyed by at-uri.
#[derive(Default)]
pub struct MemoryRepo {
    records: Mutex<BTreeMap<String, (Did, Vec<u8>)>>,
    dark: AtomicBool,
    reads: AtomicUsize,
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
            .map(|(repo, bytes)| FetchedRecord::new(bytes.clone(), uri.clone(), repo.clone()))
    }

    /// Everything in `repo` — a CAR export, in spirit. A test knob (the
    /// custodian-death test restores a repo elsewhere from it), not a port.
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
                    FetchedRecord::new(bytes.clone(), uri, r.clone()),
                )
            })
            .collect()
    }

    /// Re-file a record under another repository DID without moving it —
    /// what a `RepoReader` that resolved the address through a re-assigned
    /// handle (or simply mis-set `repository`) would hand back.
    pub fn misfile(&self, uri: &AtUri, repo: &Did) {
        let mut records = self.records.lock().expect("repo lock");
        if let Some((r, _)) = records.get_mut(uri.as_str()) {
            *r = repo.clone();
        }
    }

    /// Every call from now on fails: the host is down.
    pub fn go_dark(&self) {
        self.dark.store(true, Ordering::SeqCst);
    }

    /// How many port calls the verifier made — dark calls included.
    pub fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), RepoError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
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
/// Counts fetches, so a test can prove the verifier made none.
#[derive(Default)]
pub struct MemoryStatus {
    lists: Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
    dark: AtomicBool,
    fetches: AtomicUsize,
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

    /// How many times the verifier asked — dark calls included.
    pub fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl StatusSource for MemoryStatus {
    async fn fetch(&self, list: &StatusUri) -> Result<Vec<Vec<u8>>, StatusFetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self.dark.load(Ordering::SeqCst) {
            return Err(StatusFetchError::new("mirrors unreachable"));
        }
        Ok(self
            .lists
            .lock()
            .expect("status lock")
            .get(list.as_str())
            .cloned()
            .unwrap_or_default())
    }
}
