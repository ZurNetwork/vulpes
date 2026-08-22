//! The I/O seams a verifier needs — and nothing else.
//!
//! Three traits, each `#[async_trait]` and object-safe (held as
//! `Arc<dyn …>` / `&dyn …`), each with an **opaque** error because the
//! implementation is the caller's (a PDS client, a DID resolver, an HTTP
//! mirror fetch — see FORKS F1 for the rule). The behavioural contract
//! every implementation must honour, copied from the storage seam:
//! **absent is `Ok(None)` / empty; broken is `Err`.** A verifier that saw
//! "broken" as "absent" would fail open.
//!
//! Note what is *not* here: an attestor. The attestor is never a port —
//! verification reads public, mirrorable infrastructure only, which is how
//! the kill test passes by construction.

use std::error::Error as StdError;
use std::fmt;

use async_trait::async_trait;
use serde::de::DeserializeOwned;

use crate::Did;

use super::error::CodecError;
use super::record::{AtUri, RecordCid, StatusUri, from_canonical_bytes};
use super::sign::VerifyingKey;

type BoxError = Box<dyn StdError + Send + Sync + 'static>;

macro_rules! opaque_error {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name(BoxError);

        impl $name {
            /// Wrap any thread-safe error.
            pub fn new(source: impl Into<BoxError>) -> Self {
                Self(source.into())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, ": {}"), self.0)
            }
        }

        impl StdError for $name {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(self.0.as_ref())
            }
        }
    };
}

opaque_error!(
    /// A [`RepoReader`] failed — transport, auth, a malformed response. Not
    /// "record absent": that is `Ok(None)`.
    RepoError,
    "repository read error"
);
opaque_error!(
    /// A [`DidResolver`] failed — directory unreachable, bad document. Not
    /// "DID unknown": that is `Ok(None)`.
    ResolveError,
    "DID resolution error"
);
opaque_error!(
    /// A [`StatusSource`] failed outright. "No mirror had it" is `Ok(vec![])`.
    StatusFetchError,
    "status artifact fetch error"
);

/// A record as retrieved from a repository: its canonical bytes, its CID,
/// its address, and — the field that matters most — **which repository it
/// came from**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedRecord {
    /// Canonical DAG-CBOR of the record as the repository holds it.
    pub bytes: Vec<u8>,
    /// The CID of `bytes` (as the repository reports it; implementations
    /// should compute it from `bytes` rather than trust a side channel).
    pub cid: RecordCid,
    /// The address it was fetched at.
    pub uri: AtUri,
    /// The DID of the repository it was retrieved from — the fetch context.
    /// This feeds [`Repository`](super::sign::Repository); it is never read
    /// out of the record itself.
    pub repository: Did,
}

impl FetchedRecord {
    /// Decode the bytes as a record type. A record that exists but does not
    /// decode is a distinct outcome from "absent" — callers map it to
    /// [`Reason::Malformed`](super::verify::Reason::Malformed).
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, CodecError> {
        from_canonical_bytes(&self.bytes)
    }
}

/// Read records from subjects' repositories.
///
/// Implemented over `com.atproto.repo.getRecord` / `listRecords` (or a CAR
/// export, or a mirror). The implementation must set
/// [`FetchedRecord::repository`] to the repository it **actually read from**.
#[async_trait]
pub trait RepoReader: Send + Sync {
    /// One record by address. `Ok(None)` when the record does not exist.
    async fn get_record(&self, uri: &AtUri) -> Result<Option<FetchedRecord>, RepoError>;

    /// Every record of `collection` in `repo`. Empty when there are none.
    async fn list_records(
        &self,
        repo: &Did,
        collection: &str,
    ) -> Result<Vec<FetchedRecord>, RepoError>;
}

/// A DID's **current** key material: the signing keys from its document and,
/// for `did:plc`, the rotation keys from the directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyMaterial {
    /// Every `verificationMethod` key the document publishes (an attestor may
    /// sign with any of them; the verifier tries each).
    pub verification: Vec<VerifyingKey>,
    /// The `did:plc` rotation keys, **most senior first**, parsed at the port
    /// boundary so the verifier never parses and never silently drops one.
    /// Empty for methods without rotation keys (`did:web`). Used only for
    /// ownership-tier key control.
    ///
    /// These are **not** in the DID document — `did:plc` deliberately omits
    /// them. Read `https://plc.directory/<did>/data` (`rotationKeys`) or the
    /// audit log's last operation. An implementation that reads the document
    /// alone will leave this empty and every ownership pair will fail closed.
    pub rotation: Vec<VerifyingKey>,
}

/// Resolve a DID to its current keys.
///
/// Verification uses the *current* keys by design: an attestor that rotates
/// keys re-signs what it wants to keep alive (no historical-key verification,
/// as with `did:plc` itself). See [`KeyMaterial::rotation`] for where the
/// rotation keys come from.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// `Ok(None)` when the DID does not resolve (unknown, tombstoned). A key
    /// the port cannot parse is a port failure (`Err`), not a missing key.
    async fn keys(&self, did: &Did) -> Result<Option<KeyMaterial>, ResolveError>;
}

/// Fetch copies of a status-list artifact.
///
/// Returns **every copy it can find, unverified** — the origin, mirrors,
/// caches. The verifier checks each signature and takes the newest that
/// verifies; a stale or forged mirror can only lose, never win.
///
/// The verifier only calls this *after* its trust policy has accepted the
/// attestor, and only with a [`StatusUri`] (already `https`, DNS host, no
/// IP literal). An HTTP implementation should still route through an
/// egress-guarded client the deployment injects — DNS rebinding and
/// redirects are its concern, not the type's.
#[async_trait]
pub trait StatusSource: Send + Sync {
    /// All reachable copies of the artifact at `list`. Empty when none
    /// answered; `Err` only for a failure the caller should see.
    async fn fetch(&self, list: &StatusUri) -> Result<Vec<Vec<u8>>, StatusFetchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_errors_keep_their_source() {
        let err = RepoError::new(std::io::Error::other("pds on fire"));
        assert!(err.to_string().starts_with("repository read error: "));
        assert!(err.to_string().contains("pds on fire"));
        assert!(err.source().is_some());
        assert!(
            ResolveError::new("x")
                .to_string()
                .starts_with("DID resolution error")
        );
        assert!(
            StatusFetchError::new("x")
                .to_string()
                .starts_with("status artifact fetch error")
        );
    }
}
