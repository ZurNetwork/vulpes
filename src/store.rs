//! The storage seam — the three traits zurid persists through, and the record
//! shape the operation log carries.
//!
//! zurid owns no database. It names the *roles* it needs and lets you supply
//! them; ready [PostgreSQL implementations](crate::postgres) of all three ship
//! behind the `postgres` feature, and an in-memory fake is a dozen lines when
//! you need one for tests.
//!
//! All three are `async` object-safe traits (via `async_trait`), so a
//! `dyn KeyStore` can be shared behind an `Arc` — which is how the
//! [`Minter`](crate::Minter) holds them.
//!
//! # The one behavioural contract
//!
//! **Absent is `Ok(None)`; broken is `Err`.** A missing row must never surface
//! as a failure, and a failure must never surface as a missing row. Conflating
//! them turns a database outage into "this session does not exist" — which is a
//! fail-*open* on every path that treats absence as "nothing to check".

use async_trait::async_trait;

use crate::{Did, SealedKeys, StorageResult};

/// One submitted `did:plc` operation, as recorded in the operation log.
///
/// A `did:plc` is a signed chain: every non-genesis operation references the CID
/// of the DID's most recent operation as its `prev`, so building the next one
/// requires knowing the last one's CID. The log is *your own* record of what you
/// published — enough to chain the next operation and to audit it against the
/// directory later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlcOperationRecord {
    /// The `did:plc` this operation belongs to.
    pub did: Did,
    /// The content id of the signed operation — CIDv1, `dag-cbor` codec,
    /// `sha-256` multihash, base32 (`b…`). A subsequent operation references
    /// this as its `prev`.
    pub cid: String,
    /// The operation `type` discriminant:
    /// [`OP_TYPE_OPERATION`](crate::plc::OP_TYPE_OPERATION) or
    /// [`OP_TYPE_TOMBSTONE`](crate::plc::OP_TYPE_TOMBSTONE).
    pub op_type: String,
    /// The CID this operation chained onto, or `None` for a genesis operation.
    pub prev: Option<String>,
    /// The signed operation serialized as JSON — exactly the body submitted to
    /// the directory. Public material only (rotation and verification
    /// `did:key`s, handles, and a signature); **never** a private key.
    pub operation_json: String,
}

/// Custody of the private keys behind minted identities.
///
/// # A store never sees a plaintext key
///
/// The unit of trade is [`SealedKeys`] — AEAD ciphertext plus its envelope
/// version — never a plaintext [`CustodyKeys`](crate::CustodyKeys). Sealing and
/// opening live with whoever holds the [`SecretVault`](crate::SecretVault), the
/// [`Minter`](crate::Minter); a `KeyStore` persists opaque bytes and hands them
/// back. So a store that writes plaintext custody is not a store you can *write*
/// against this trait — the mirror of how the OAuth bridge keeps a token out of
/// [`OAuthStateStore`]. What a store still owns is the storage contract below.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Persist the sealed `keys` for `did`.
    ///
    /// One DID is minted once, so implementations should make a second `put`
    /// for the same DID an error (a primary key does this for free) rather than
    /// overwriting custody.
    async fn put(&self, did: &Did, keys: &SealedKeys) -> StorageResult<()>;

    /// Load the sealed keys held for `did`, or `Ok(None)` if none are.
    ///
    /// This is a byte round-trip: a store returns exactly what it was given,
    /// unopened. "There is no row" is `Ok(None)`; a database fault is `Err`. The
    /// blob only fails to *open* later, at the vault, which is where a wrong root
    /// key or a tampered blob surfaces — never as a `None` here.
    async fn get(&self, did: &Did) -> StorageResult<Option<SealedKeys>>;
}

/// The append-only log of operations submitted for each minted identity.
///
/// Two integrity properties make the chain safe to extend concurrently, and an
/// implementation is expected to enforce **both** at the storage layer rather
/// than in application code:
///
/// 1. **Content-addressed uniqueness** — a given `cid` is logged at most once.
///    This is what makes a replayed identical operation a detectable no-op.
/// 2. **No chain fork** — for one `did`, a non-null `prev` may be chained onto
///    at most once. Without it, two concurrent updates both read the same
///    `latest_cid`, build *different* operations (different `cid`, so property 1
///    does not catch them) and both append, forking the local chain — after
///    which the log permanently disagrees with the directory, which accepted
///    only the first.
///
/// The shipped [PostgreSQL implementation](crate::postgres::PgPlcOperationLog)
/// enforces both with a `UNIQUE(cid)` constraint and a partial
/// `UNIQUE(did, prev) WHERE prev IS NOT NULL` index.
#[async_trait]
pub trait PlcOperationLog: Send + Sync {
    /// Append one operation. Rejecting a duplicate `cid`, or a second operation
    /// chaining an already-used `prev`, is part of the contract — return an
    /// error rather than accepting either.
    async fn append(&self, record: &PlcOperationRecord) -> StorageResult<()>;

    /// The `cid` of the DID's most recent operation, or `None` if it has none.
    async fn latest_cid(&self, did: &Did) -> StorageResult<Option<String>>;

    /// The DID's most recent operation in full, or `None`.
    ///
    /// An update reads this to carry the prior operation's **public** document
    /// fields forward verbatim, so a routine update never needs to decrypt any
    /// key but the one that signs.
    async fn latest_op(&self, did: &Did) -> StorageResult<Option<PlcOperationRecord>>;
}

/// Durable storage for the AT Protocol OAuth handshake's two tiers of state.
///
/// Blobs are **opaque** here on purpose: the [`oauth`](crate::oauth) layer
/// serializes and seals them, so an implementation of this trait stores bytes
/// and never sees a token. That split is what lets a storage backend be written
/// without any OAuth knowledge — and keeps the sealing in exactly one place.
///
/// The two row families mirror the handshake:
///
/// - **client session** — an established grant (token set + DPoP key), keyed by
///   `(account_did, session_id)`. Persisting it is what lets a grant survive a
///   restart, lets refresh write rotated tokens durably, and lets two replicas
///   serve the same user.
/// - **auth request** — an in-flight authorization (PKCE verifier + DPoP key),
///   keyed by the OAuth `state`. Short-lived: written at sign-in, read and
///   deleted at the callback. Persisting it is what lets the redirect land on a
///   different process than the one that started the flow.
#[async_trait]
pub trait OAuthStateStore: Send + Sync {
    /// Read an established session's sealed blob.
    async fn get_session(
        &self,
        account_did: &str,
        session_id: &str,
    ) -> StorageResult<Option<Vec<u8>>>;

    /// Insert or replace an established session's sealed blob. Replacement is
    /// load-bearing: every token refresh overwrites the prior row, so a later
    /// request on any replica reads the freshest grant.
    async fn upsert_session(
        &self,
        account_did: &str,
        session_id: &str,
        data: &[u8],
    ) -> StorageResult<()>;

    /// Delete an established session — the "this grant ended honestly" path,
    /// called when refresh fails permanently.
    async fn delete_session(&self, account_did: &str, session_id: &str) -> StorageResult<()>;

    /// Read an in-flight authorization request's sealed blob by its `state`,
    /// **consuming it**.
    ///
    /// # Single-use is part of the contract
    ///
    /// A successful read must make every later read of the same `state` return
    /// `Ok(None)`, and the consumption must be **atomic** — one statement, one
    /// row lock, not a read followed by a delete. The blob holds the PKCE
    /// verifier and the DPoP key for one authorization; two concurrent
    /// callbacks carrying the same `state` must not both come away with it.
    ///
    /// Implementing this as a plain lookup and leaning on
    /// [`delete_auth_request`](OAuthStateStore::delete_auth_request) to clean up
    /// leaves exactly that window open, because the protocol library's own
    /// get-then-delete is two round trips. A `DELETE … RETURNING` (or the
    /// backend's equivalent) is the shape to reach for.
    async fn get_auth_request(&self, state: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Insert or replace an in-flight authorization request's sealed blob.
    async fn save_auth_request(&self, state: &str, data: &[u8]) -> StorageResult<()>;

    /// Delete an in-flight authorization request.
    ///
    /// Belt to [`get_auth_request`](OAuthStateStore::get_auth_request)'s braces:
    /// the read already consumed the row, so on the happy path this deletes
    /// nothing. It stays because an abandoned flow — a visitor who never
    /// returns from the PDS — is dropped here, and because deleting an absent
    /// row must never be an error.
    async fn delete_auth_request(&self, state: &str) -> StorageResult<()>;
}

/// Resolves an atproto handle to the DID it belongs to.
///
/// The read half of handle resolution: serving `/.well-known/atproto-did` for a
/// namespace you operate (see [`crate::axum`]) is one lookup through this trait.
#[async_trait]
pub trait HandleResolver: Send + Sync {
    /// The DID `handle` currently resolves to, or `None` if nothing holds it.
    async fn did_for_handle(&self, handle: &crate::Handle) -> StorageResult<Option<Did>>;
}
