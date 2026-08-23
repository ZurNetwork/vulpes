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

use async_trait::async_trait;
use serde::de::DeserializeOwned;

use crate::Did;
use crate::error::opaque_error;

use super::error::CodecError;
use super::record::{AtUri, RecordCid, StatusUri, from_canonical_bytes};
use super::sign::VerifyingKey;

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
///
/// The CID is **computed from the bytes** in [`FetchedRecord::new`], never
/// accepted from the response: step 1 of verification compares it to the
/// attestation's signed strongRef, and a CID taken from a side channel
/// would compare an attacker-supplied value to itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedRecord {
    bytes: Vec<u8>,
    /// The address it was fetched at.
    pub uri: AtUri,
    /// The DID of the repository it was retrieved from — the fetch context.
    /// This feeds [`Repository`](super::sign::Repository); it is never read
    /// out of the record itself.
    pub repository: Did,
    cid: RecordCid,
}

impl FetchedRecord {
    /// Wrap what a repository returned; the CID is derived from `bytes`
    /// here and nowhere else.
    pub fn new(bytes: Vec<u8>, uri: AtUri, repository: Did) -> Self {
        Self {
            cid: RecordCid::of(&bytes),
            bytes,
            uri,
            repository,
        }
    }

    /// Canonical DAG-CBOR of the record as the repository holds it. Read
    /// only, so it can never drift from [`cid`](Self::cid).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The CID of [`bytes`](Self::bytes).
    pub fn cid(&self) -> &RecordCid {
        &self.cid
    }

    /// Decode the bytes as a record type. A record that exists but does not
    /// decode is a distinct outcome from "absent" — callers map it to
    /// [`Reason::Malformed`](super::verify::Reason::Malformed).
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, CodecError> {
        from_canonical_bytes(&self.bytes)
    }
}

/// Read records from subjects' repositories.
///
/// Implemented over `com.atproto.repo.getRecord` (or a CAR export, or a
/// mirror). The implementation must set [`FetchedRecord::repository`] to the
/// repository it **actually read from**, and **must verify the repo's commit
/// signature** against that DID's signing key before returning anything —
/// a claim carries no signature of its own, so the commit signature is the
/// only cryptographic assertion that the repo owner said it.
#[async_trait]
pub trait RepoReader: Send + Sync {
    /// One record by address. `Ok(None)` when the record does not exist.
    async fn get_record(&self, uri: &AtUri) -> Result<Option<FetchedRecord>, RepoError>;
}

/// A DID's **current** key material: the signing keys from its document and,
/// for `did:plc`, the rotation keys from the directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyMaterial {
    /// Every `verificationMethod` key the document publishes (an attestor may
    /// sign with any of them; the verifier tries each).
    pub verification: Vec<VerifyingKey>,
    /// The `did:plc` rotation keys as `did:key` strings, in **directory
    /// order — most senior first**, exactly as the directory lists them.
    /// Empty for methods without rotation keys (`did:web`). Verification
    /// never reads them: they exist for the `acp::custody` helpers (the
    /// next PR, FORKS F45), which a consumer calls *after* an
    /// ownership-class attestation verifies.
    ///
    /// The rule those helpers check is `docs/ccs.md`'s senior-key rule
    /// (FORKS F45, F46): some rotation key of the owner's that is **not a
    /// custodian's** sits at a lower index than every custodian key in the
    /// owned DID's list. It is a comparison of positions and string
    /// equalities — never of key material — which is why these are strings
    /// and not parsed keys: parsing here would let one rotation key on an
    /// unsupported curve make the whole `keys()` call fail, breaking
    /// plain-signature verification for an attestor whose rotation keys it
    /// never uses.
    ///
    /// These are **not** in the DID document — `did:plc` deliberately omits
    /// them. Read `https://plc.directory/<did>/data` (`rotationKeys`) or the
    /// audit log's last operation, and preserve the order. An
    /// implementation that reads the document alone will leave this empty
    /// and every seniority check will fail closed.
    ///
    /// **Verbatim.** Each entry is the `did:key:…` string exactly as the
    /// directory holds it — no re-encoding, no case change, no stripping
    /// the prefix. The check is a string equality across two DIDs; any
    /// normalization applied to one and not the other would make a real
    /// owner fail it.
    pub rotation: Vec<String>,
}

/// Resolve a DID to its current keys.
///
/// Verification uses the *current* keys by design: an attestor that rotates
/// keys re-signs what it wants to keep alive (no historical-key verification,
/// as with `did:plc` itself). See [`KeyMaterial::rotation`] for where the
/// rotation keys come from.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// `Ok(None)` when the DID does not resolve (unknown, tombstoned). A
    /// verification key the port cannot parse is a port failure (`Err`),
    /// not a missing key. Rotation keys are passed through as strings in
    /// the directory's seniority order (see [`KeyMaterial::rotation`]).
    async fn keys(&self, did: &Did) -> Result<Option<KeyMaterial>, ResolveError>;
}

/// Fetch copies of a status-list artifact.
///
/// Returns **every copy it can find, unverified** — the origin, mirrors,
/// caches. The verifier checks each signature and takes the newest that
/// verifies; a stale or forged mirror can only lose, never win.
///
/// The verifier only calls this *after* its trust policy has accepted the
/// attestor and after [`StatusUri::fetchable`] passed (an `https` URL
/// with a public DNS host — no IP literal in any spelling, no special-use
/// name — or an `at://` identifier the implementation resolves through the
/// repo path).
///
/// That syntactic check is **necessary, not sufficient** (FORKS F42): the
/// list address is attacker-influenced input and a URL parser is not a
/// network policy. An HTTP implementation
///
/// - **MUST** disable redirects — a public host that 302s to
///   `169.254.169.254` is the classic bypass;
/// - **MUST** resolve the host (A and AAAA) and refuse to connect to any
///   non-global address — loopback, link-local, private, CGNAT, ULA,
///   IPv4-mapped — *at connect time*, against the resolved addresses, not
///   the name (DNS rebinding);
/// - **SHOULD** run behind an egress guard the deployment injects (the
///   `with_client` pattern of `HttpPlcDirectory`), so the network says no
///   even if the code is wrong;
/// - **SHOULD** cap the response at
///   [`MAX_STATUS_LIST_BYTES`](super::status::MAX_STATUS_LIST_BYTES) and
///   bound the copies it returns — the verifier skips oversize copies, but
///   it cannot un-download them.
#[async_trait]
pub trait StatusSource: Send + Sync {
    /// All reachable copies of the artifact at `list`. Empty when none
    /// answered; `Err` only for a failure the caller should see.
    async fn fetch(&self, list: &StatusUri) -> Result<Vec<Vec<u8>>, StatusFetchError>;
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

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
