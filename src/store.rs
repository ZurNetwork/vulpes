//! The storage seam — the two traits vulpes persists through, and the record
//! shape the operation log carries.
//!
//! vulpes owns no database. It names the *roles* it needs and lets you supply
//! them over whatever it persists with. An in-memory fake is a dozen lines
//! when you need one for tests.
//!
//! Both are `async` object-safe traits (via `async_trait`), so a
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
    /// The HMAC-SHA256 integrity tag over `(did, cid, prev, operation)`, keyed
    /// by the vault's operation-log subkey (see
    /// [`SecretVault::oplog_mac`](crate::SecretVault::oplog_mac)).
    ///
    /// This is what lets a reader trust a row it did not write: an attacker with
    /// database *write* access can alter the columns, but cannot mint a matching
    /// tag without the root key, so a tampered row fails verification. The
    /// [`Minter`](crate::Minter) sets it on append and checks it before trusting
    /// a prior operation's carried fields. Empty until
    /// [`mac_message`](PlcOperationRecord::mac_message) is computed and signed.
    pub op_mac: Vec<u8>,
}

impl PlcOperationRecord {
    /// The bytes the operation-log MAC authenticates: an unambiguous,
    /// length-prefixed encoding of `(did, cid, prev, operation)`.
    ///
    /// The operation is canonicalized by re-parsing its stored JSON and
    /// re-serializing it **with explicitly sorted keys**, so the encoding is
    /// stable across a store that hands the document back with its keys
    /// reordered (a Postgres `jsonb` column does) — the tag computed at write
    /// time verifies against the same message recovered at read time. The sort is done by hand, not left to serde_json: with
    /// default features serde_json happens to sort map keys, but any crate in
    /// the build graph can flip on `preserve_order` for the whole binary
    /// (Cargo features unify globally — a since-removed dependency did exactly
    /// that, FORKS F35), and
    /// this MAC must not care. Each field is length-prefixed, so no field
    /// boundary is ambiguous.
    ///
    /// `op_type` is deliberately not covered here: it is redundant with the
    /// operation's own `type`, which *is* covered, and the values a reader
    /// trusts (rotation keys, verification methods, services) all live in the
    /// operation.
    pub fn mac_message(&self) -> Result<Vec<u8>, serde_json::Error> {
        let operation: serde_json::Value = serde_json::from_str(&self.operation_json)?;
        let operation_bytes = serde_json::to_vec(&canonicalize(operation))?;

        let mut message = Vec::new();
        push_field(&mut message, self.did.as_str().as_bytes());
        push_field(&mut message, self.cid.as_bytes());
        match &self.prev {
            None => message.push(0),
            Some(prev) => {
                message.push(1);
                push_field(&mut message, prev.as_bytes());
            }
        }
        push_field(&mut message, &operation_bytes);
        Ok(message)
    }
}

/// Append `field` to `buf`, length-prefixed with its `u64` little-endian length
/// so two adjacent fields can never be re-split into a different pair.
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
    buf.extend_from_slice(field);
}

/// Recursively sort every object's keys, so serialization yields the same
/// bytes no matter what order the source text carried — the canonical form
/// [`PlcOperationRecord::mac_message`] authenticates. Byte-identical to what
/// default-feature serde_json (BTreeMap-backed maps) always produced, so tags
/// minted before this was explicit still verify.
fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::new();
            for (key, inner) in entries {
                sorted.insert(key, canonicalize(inner));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
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
/// against this trait. What a store still owns is the storage contract below.
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
/// In SQL that is a `UNIQUE(cid)` constraint and a partial
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

#[cfg(test)]
mod mac_message_tests {
    use super::*;

    fn record(operation_json: &str) -> PlcOperationRecord {
        PlcOperationRecord {
            did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
                .parse::<Did>()
                .expect("a valid did"),
            cid: "bafyexample".into(),
            op_type: "plc_operation".into(),
            prev: None,
            operation_json: operation_json.into(),
            op_mac: Vec::new(),
        }
    }

    /// The `jsonb` round-trip (and a `preserve_order`-unified serde_json) may
    /// hand back the same document with any key order; the MAC message must
    /// not move. This is the regression test for the B2 tag surviving global
    /// feature unification (FORKS F35).
    #[test]
    fn key_order_does_not_change_the_mac_message() {
        let a = record(r#"{"type":"plc_operation","sig":"s","services":{"b":1,"a":2}}"#);
        let b = record(r#"{"services":{"a":2,"b":1},"sig":"s","type":"plc_operation"}"#);
        assert_eq!(
            a.mac_message().expect("valid json"),
            b.mac_message().expect("valid json"),
        );
    }

    /// Different content must still yield different messages — sorting must
    /// canonicalize, never collapse.
    #[test]
    fn different_operations_yield_different_messages() {
        let a = record(r#"{"type":"plc_operation","sig":"s1"}"#);
        let b = record(r#"{"type":"plc_operation","sig":"s2"}"#);
        assert_ne!(
            a.mac_message().expect("valid json"),
            b.mac_message().expect("valid json"),
        );
    }
}
