//! Building, signing and hashing `did:plc` **operations** — the byte-exact core
//! of the crate.
//!
//! A `did:plc` is *defined by* the hash of its first (genesis) operation, so
//! every byte is load-bearing. Two serializations of the same operation are
//! used, and they are **not** the same bytes:
//!
//! 1. **Signing bytes** — DAG-CBOR of the operation *without* its `sig` field.
//!    This is what a rotation key signs (ECDSA-SHA256, low-S, 64-byte r‖s, then
//!    base64url no-pad).
//! 2. **Identifier bytes** — DAG-CBOR of the operation *including* that `sig`.
//!    Its SHA-256, base32-encoded (lowercase, no padding) and truncated to 24
//!    characters, is the `did:plc:` suffix.
//!
//! DAG-CBOR (RFC 8949 core-deterministic) canonically **sorts map keys by
//! length first, then bytewise** on serialize; `serde_ipld_dagcbor` does this
//! for struct keys too, so the field declaration order below is irrelevant to
//! the output. The unit tests below pin the whole pipeline to a real, published
//! vector (`did:plc:ewvi7nxzyoun6zhxrhs64oiz`).
//!
//! Nothing in this module performs I/O or crypto — it is pure serialization and
//! hashing, available with `--no-default-features`.
//!
//! Spec: <https://web.plc.directory/spec/v0.1/did-plc>.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The fixed `type` discriminant of a PLC operation.
pub const OP_TYPE_OPERATION: &str = "plc_operation";

/// The fixed `type` discriminant of a PLC tombstone.
pub const OP_TYPE_TOMBSTONE: &str = "plc_tombstone";

/// How many base32 characters of the genesis hash form the `did:plc:` suffix.
const DID_SUFFIX_LEN: usize = 24;

/// Failure serializing a PLC operation. The only way these arise is a value that
/// cannot be represented in the target encoding, which for the shapes in this
/// module means an allocation failure — but they are surfaced rather than
/// unwrapped, because a silent wrong-bytes path would mint a wrong DID.
#[derive(Debug, thiserror::Error)]
pub enum PlcError {
    /// The operation could not be encoded as DAG-CBOR (the signed/hashed form).
    #[error("failed to encode the PLC operation as DAG-CBOR: {0}")]
    DagCbor(String),
    /// The operation could not be encoded as JSON (the submission body).
    #[error("failed to encode the PLC operation as JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Encode `value` as canonical DAG-CBOR, mapping the encoder's error into
/// [`PlcError`]. One helper so every hash and signature in the crate goes
/// through the same call.
fn dag_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, PlcError> {
    serde_ipld_dagcbor::to_vec(value).map_err(|err| PlcError::DagCbor(err.to_string()))
}

/// A service entry in an operation's `services` map (e.g. an atproto PDS).
///
/// An *identity-only* DID — a valid, resolvable identity with no repository
/// behind it, the pattern feed generators and labelers use — declares an
/// **empty** services map. Attaching a PDS later is an operation on the same
/// DID, not a new one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PlcService {
    /// The service type, e.g. `AtprotoPersonalDataServer`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The service endpoint URL.
    pub endpoint: String,
}

/// The **public** fields of a DID document, as a PLC operation carries them.
///
/// This is the whole payload an operation asserts. A genesis operation
/// ([`PlcOperation::genesis`]) states it for the first time; an update
/// ([`PlcOperation::update`]) restates it — which is why an update must carry
/// forward every field it does not mean to change, rather than rebuilding a
/// default shape and silently dropping what was there.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PlcDocument {
    /// The `did:key` multikeys of the rotation keypairs, in **descending
    /// authority**. The spec allows 1–5, with no duplication; recovery works by
    /// a lower-indexed (higher-authority) key overriding a higher-indexed one
    /// within the directory's recovery window.
    pub rotation_keys: Vec<String>,
    /// Verification methods by id (e.g. `atproto` → a `did:key`). The spec caps
    /// the total at 10 per DID.
    pub verification_methods: BTreeMap<String, String>,
    /// The `at://<handle>` aliases this DID claims.
    pub also_known_as: Vec<String>,
    /// Services by id (e.g. `atproto_pds`). Empty for an identity-only DID.
    pub services: BTreeMap<String, PlcService>,
}

impl PlcDocument {
    /// An **identity-only** document: the given rotation keys, a single
    /// `atproto` verification method, one `at://<handle>` alias, and **no**
    /// services.
    ///
    /// ```
    /// # use vulpes::plc::PlcDocument;
    /// let document = PlcDocument::identity_only(
    ///     vec!["did:key:cold".into(), "did:key:hot".into()],
    ///     "did:key:sign".into(),
    ///     "alice.example.com",
    /// );
    /// assert!(document.services.is_empty());
    /// assert_eq!(document.also_known_as, vec!["at://alice.example.com".to_string()]);
    /// ```
    pub fn identity_only(
        rotation_keys: Vec<String>,
        atproto_signing_key: String,
        handle: &str,
    ) -> Self {
        let verification_methods = BTreeMap::from([("atproto".to_string(), atproto_signing_key)]);
        Self {
            rotation_keys,
            verification_methods,
            also_known_as: vec![format!("at://{handle}")],
            services: BTreeMap::new(),
        }
    }
}

/// The DAG-CBOR view of an operation **without** `sig` — the bytes a rotation
/// key signs. `prev` is `None` (serialized as CBOR `null`, never omitted) for a
/// genesis operation.
#[derive(Serialize)]
struct UnsignedView<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    #[serde(rename = "rotationKeys")]
    rotation_keys: &'a [String],
    #[serde(rename = "verificationMethods")]
    verification_methods: &'a BTreeMap<String, String>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: &'a [String],
    services: &'a BTreeMap<String, PlcService>,
    prev: Option<&'a str>,
}

/// The DAG-CBOR / JSON view of an operation **including** `sig` — hashed to
/// derive the DID, and serialized to JSON as the directory submission body.
#[derive(Serialize)]
struct SignedView<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    #[serde(rename = "rotationKeys")]
    rotation_keys: &'a [String],
    #[serde(rename = "verificationMethods")]
    verification_methods: &'a BTreeMap<String, String>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: &'a [String],
    services: &'a BTreeMap<String, PlcService>,
    prev: Option<&'a str>,
    sig: &'a str,
}

/// An unsigned `plc_operation`: a [`PlcDocument`] plus the `prev` it chains
/// onto, and the [`signing_bytes`](PlcOperation::signing_bytes) it must be
/// signed over.
///
/// One builder covers both operation kinds of this shape — a **genesis**
/// operation ([`genesis`](PlcOperation::genesis), `prev = null`) and an
/// **update** ([`update`](PlcOperation::update), `prev` = a CID) — so there is
/// exactly one DAG-CBOR path and the two can never drift byte-wise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlcOperation {
    document: PlcDocument,
    prev: Option<String>,
}

impl PlcOperation {
    /// Build a **genesis** operation asserting `document`. `prev` is `null`; the
    /// hash of the signed result *is* the DID.
    pub fn genesis(document: PlcDocument) -> Self {
        Self {
            document,
            prev: None,
        }
    }

    /// Build an **update** operation asserting `document`, chaining onto `prev`
    /// — the CID of the DID's most recent operation.
    ///
    /// An update **replaces** the document wholesale: whatever `document` omits
    /// is gone from the DID document. Carry forward every field you do not mean
    /// to change (the [`Minter`](crate::Minter) does exactly this, reading the
    /// prior operation out of its own log).
    pub fn update(document: PlcDocument, prev: String) -> Self {
        Self {
            document,
            prev: Some(prev),
        }
    }

    /// The document this operation asserts.
    pub fn document(&self) -> &PlcDocument {
        &self.document
    }

    /// The CID this operation chains onto, or `None` for a genesis operation.
    pub fn prev(&self) -> Option<&str> {
        self.prev.as_deref()
    }

    /// The DAG-CBOR bytes to sign: this operation **without** a `sig` field.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PlcError> {
        let view = UnsignedView {
            type_: OP_TYPE_OPERATION,
            rotation_keys: &self.document.rotation_keys,
            verification_methods: &self.document.verification_methods,
            also_known_as: &self.document.also_known_as,
            services: &self.document.services,
            prev: self.prev.as_deref(),
        };
        dag_cbor(&view)
    }

    /// Attach a computed signature (base64url, no padding), yielding the
    /// [`SignedOperation`] whose hash is the DID (for a genesis operation) and
    /// whose [`cid`](SignedOperation::cid) the next operation chains onto.
    pub fn into_signed(self, sig: String) -> SignedOperation {
        SignedOperation { op: self, sig }
    }
}

/// A signed `plc_operation` (genesis or update).
///
/// For a genesis operation the DID is derived from its DAG-CBOR hash; for both
/// kinds the JSON is the directory submission body and the
/// [`cid`](SignedOperation::cid) is what the next operation chains onto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOperation {
    op: PlcOperation,
    sig: String,
}

impl SignedOperation {
    /// A borrowed view over this operation's fields, used for both DAG-CBOR
    /// hashing and JSON submission — one source of truth for the byte layout.
    fn view(&self) -> SignedView<'_> {
        SignedView {
            type_: OP_TYPE_OPERATION,
            rotation_keys: &self.op.document.rotation_keys,
            verification_methods: &self.op.document.verification_methods,
            also_known_as: &self.op.document.also_known_as,
            services: &self.op.document.services,
            prev: self.op.prev.as_deref(),
            sig: &self.sig,
        }
    }

    /// Derive the `did:plc:` identifier: `base32(sha256(dag_cbor(op incl. sig)))`
    /// lowercased, unpadded, truncated to 24 characters. See [`derive_did`].
    ///
    /// Only a **genesis** operation defines a DID — calling this on an update
    /// yields a value that identifies nothing.
    pub fn did(&self) -> Result<crate::Did, PlcError> {
        Ok(derive_did(&dag_cbor(&self.view())?))
    }

    /// This operation's **CID** (CIDv1 / dag-cbor / sha-256) — recorded in the
    /// operation log so a later operation can reference it as `prev`. Distinct
    /// from [`did`](SignedOperation::did); see [`cid`].
    pub fn cid(&self) -> Result<String, PlcError> {
        Ok(cid(&dag_cbor(&self.view())?))
    }

    /// The signed operation as JSON — the body a PLC directory expects at
    /// `POST /:did`.
    pub fn to_json(&self) -> Result<serde_json::Value, PlcError> {
        Ok(serde_json::to_value(self.view())?)
    }
}

/// The DAG-CBOR view of a tombstone **without** `sig` — the bytes a rotation key
/// signs. A tombstone carries no data fields, only `type` and the **mandatory**
/// `prev` (not nullable, unlike a genesis operation's).
#[derive(Serialize)]
struct TombstoneUnsignedView<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    prev: &'a str,
}

/// The DAG-CBOR / JSON view of a tombstone **including** `sig` — the body
/// submitted to the directory to deactivate the DID.
#[derive(Serialize)]
struct TombstoneSignedView<'a> {
    #[serde(rename = "type")]
    type_: &'static str,
    prev: &'a str,
    sig: &'a str,
}

/// An unsigned `plc_tombstone`: it permanently deactivates a DID, chaining onto
/// the DID's most recent operation via `prev` (a mandatory CID). Signed with a
/// rotation key exactly like a genesis operation — DAG-CBOR without `sig`, then
/// ECDSA-SHA256 low-S, base64url no-pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneOperation {
    prev: String,
}

impl TombstoneOperation {
    /// Build a tombstone chaining onto `prev` — the CID of the DID's latest
    /// operation.
    pub fn new(prev: String) -> Self {
        Self { prev }
    }

    /// The DAG-CBOR bytes to sign: this tombstone **without** a `sig` field.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PlcError> {
        let view = TombstoneUnsignedView {
            type_: OP_TYPE_TOMBSTONE,
            prev: &self.prev,
        };
        dag_cbor(&view)
    }

    /// Attach a computed signature (base64url, no padding).
    pub fn into_signed(self, sig: String) -> SignedTombstone {
        SignedTombstone { op: self, sig }
    }
}

/// A signed `plc_tombstone`: its JSON is the directory submission body, and its
/// DAG-CBOR hash is its [`cid`](SignedTombstone::cid) — the audit chain's final
/// link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTombstone {
    op: TombstoneOperation,
    sig: String,
}

impl SignedTombstone {
    /// A borrowed view over this tombstone's fields, for both DAG-CBOR hashing
    /// and JSON submission (one source of truth for the byte layout).
    fn view(&self) -> TombstoneSignedView<'_> {
        TombstoneSignedView {
            type_: OP_TYPE_TOMBSTONE,
            prev: &self.op.prev,
            sig: &self.sig,
        }
    }

    /// This tombstone's CID (CIDv1 / dag-cbor / sha-256).
    pub fn cid(&self) -> Result<String, PlcError> {
        Ok(cid(&dag_cbor(&self.view())?))
    }

    /// The signed tombstone as JSON — the body a PLC directory expects at
    /// `POST /:did`.
    pub fn to_json(&self) -> Result<serde_json::Value, PlcError> {
        Ok(serde_json::to_value(self.view())?)
    }
}

/// Derive the `did:plc` from the DAG-CBOR bytes of a *signed genesis*
/// operation: `did:plc:` + the first 24 characters of the lowercase, unpadded
/// base32 of its SHA-256.
///
/// Isolated as a pure function so the safety-net vector test exercises the exact
/// derivation the minter uses.
pub fn derive_did(signed_op_cbor: &[u8]) -> crate::Did {
    let hash = Sha256::digest(signed_op_cbor);
    let base32 = data_encoding::BASE32_NOPAD.encode(&hash).to_lowercase();
    crate::Did::new(format!("did:plc:{}", &base32[..DID_SUFFIX_LEN]))
}

/// Compute the **CID** of a signed operation's DAG-CBOR bytes — the value a
/// subsequent operation references as its `prev`.
///
/// CIDv1, `dag-cbor` codec (`0x71`), `sha-256` multihash (`0x12`), multibase
/// base32 (lowercase, `b` prefix): `"b"` + base32(`0x01 0x71 0x12 0x20` ‖
/// `sha256(bytes)`). This is **not** [`derive_did`], which truncates a bare
/// base32 hash to the 24-character DID *suffix*; a `prev` is a full multiformats
/// CID (`bafyrei…`).
pub fn cid(signed_op_cbor: &[u8]) -> String {
    let hash = Sha256::digest(signed_op_cbor);
    // multibase `b` (base32) over: CIDv1 (0x01), dag-cbor (0x71), then the
    // multihash (sha2-256 = 0x12, length 0x20 = 32 bytes, then the hash bytes).
    let mut bytes = Vec::with_capacity(4 + hash.len());
    bytes.extend_from_slice(&[0x01, 0x71, 0x12, 0x20]);
    bytes.extend_from_slice(&hash);
    format!(
        "b{}",
        data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real, published genesis operation of `did:plc:ewvi7nxzyoun6zhxrhs64oiz`
    /// (the `atprotocol.bsky.social` account) — the vector both safety nets pin
    /// against. Built once so the DID and the CID are derived from identical
    /// bytes, exactly as the directory's audit log holds them.
    fn published_vector_cbor() -> Vec<u8> {
        let verification_methods = BTreeMap::from([(
            "atproto".to_string(),
            "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF".to_string(),
        )]);
        let services = BTreeMap::from([(
            "atproto_pds".to_string(),
            PlcService {
                type_: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://bsky.social".to_string(),
            },
        )]);
        let rotation_keys = vec![
            "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg".to_string(),
            "did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK".to_string(),
        ];
        let also_known_as = vec!["at://atprotocol.bsky.social".to_string()];
        let view = SignedView {
            type_: OP_TYPE_OPERATION,
            rotation_keys: &rotation_keys,
            verification_methods: &verification_methods,
            also_known_as: &also_known_as,
            services: &services,
            prev: None,
            sig: "lza4at_jCtGo_TYgL5PC1ZNP7lhF4DV8H50LWHhvdHcB143x1wEwqZ43xvV36Pws6OOnJLJrkibEUFDFqkhIhg",
        };
        dag_cbor(&view).unwrap()
    }

    // THE SAFETY NET. Derive the DID from a real, published genesis operation and
    // assert it equals the known value. If this fails, the byte pipeline
    // (DAG-CBOR canonical ordering + sha256 + base32/24) is wrong and nothing in
    // this crate must ship.
    #[test]
    fn derives_the_known_vector_did() {
        assert_eq!(
            derive_did(&published_vector_cbor()).as_str(),
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    // THE CID SAFETY NET. An update's or tombstone's `prev` is the CID of the
    // DID's last operation; a wrong CID computation means an unchainable
    // (directory-rejected) operation. Pinned to the REAL, published genesis-op
    // CID of the same vector DID, from its plc.directory audit log.
    #[test]
    fn computes_the_known_vector_cid() {
        assert_eq!(
            cid(&published_vector_cbor()),
            "bafyreibfvkh3n6odvdpwj54j4xxdsgnn4zo5utbyf7z7nfbyikhtygzjcq"
        );
    }

    fn identity_only_genesis() -> PlcOperation {
        let document = PlcDocument::identity_only(
            vec!["did:key:cold".to_string(), "did:key:hot".to_string()],
            "did:key:sign".to_string(),
            "alice.example.com",
        );
        PlcOperation::genesis(document)
    }

    // An identity-only operation carries an EMPTY services map (no atproto_pds).
    // Assert both the map is empty and the serialized JSON mentions no PDS.
    #[test]
    fn identity_only_op_has_no_pds() {
        let op = identity_only_genesis();
        assert!(
            op.document().services.is_empty(),
            "identity-only op must have no services"
        );
        assert_eq!(
            op.document().also_known_as,
            vec!["at://alice.example.com".to_string()]
        );

        let json = op.into_signed("sig".to_string()).to_json().unwrap();
        assert!(
            !json.to_string().contains("atproto_pds"),
            "identity-only op JSON must not mention atproto_pds"
        );
        // `services` is present as an (empty) object, per the operation shape.
        assert_eq!(json["services"], serde_json::json!({}));
    }

    // A genesis operation serializes `prev` as an explicit null — the spec says
    // the key must be present with value null, NOT omitted.
    #[test]
    fn genesis_prev_is_an_explicit_null() {
        let json = identity_only_genesis()
            .into_signed("sig".to_string())
            .to_json()
            .unwrap();
        assert!(
            json.as_object().unwrap().contains_key("prev"),
            "`prev` must be present on a genesis op"
        );
        assert_eq!(json["prev"], serde_json::Value::Null);
    }

    // The signed and unsigned serializations are DIFFERENT bytes: signing_bytes
    // omits `sig`, the DID hash includes it. Guards against ever hashing the
    // wrong one (which would derive a DID over bytes nobody signed).
    #[test]
    fn signing_bytes_exclude_sig() {
        let op = identity_only_genesis();
        let unsigned = op.signing_bytes().unwrap();
        let signed_cbor = dag_cbor(&op.into_signed("theSig".to_string()).view()).unwrap();
        assert_ne!(
            unsigned, signed_cbor,
            "signed and unsigned CBOR must differ (sig included vs excluded)"
        );
    }

    /// A prior-op CID for update tests to chain onto (the real vector genesis
    /// CID, so the value is shaped like production data).
    const PREV: &str = "bafyreibfvkh3n6odvdpwj54j4xxdsgnn4zo5utbyf7z7nfbyikhtygzjcq";

    fn update_op() -> PlcOperation {
        let document = PlcDocument::identity_only(
            vec!["did:key:cold".to_string(), "did:key:hot".to_string()],
            "did:key:sign".to_string(),
            "bob.example.com",
        );
        PlcOperation::update(document, PREV.to_string())
    }

    // An update signs over bytes that EXCLUDE `sig`, exactly like a genesis op —
    // both serialize through the same UnsignedView/SignedView pair, so this
    // guards the shared path from ever hashing/signing the wrong serialization.
    #[test]
    fn update_signing_bytes_exclude_sig() {
        let op = update_op();
        let unsigned = op.signing_bytes().unwrap();
        let signed_cbor = dag_cbor(&op.into_signed("theSig".to_string()).view()).unwrap();
        assert_ne!(unsigned, signed_cbor);
    }

    // REPLACE semantics: the update's `alsoKnownAs` is exactly the new handle —
    // the old one is dropped, never retained as a dead alias (a retained alias
    // fails bidirectional handle verification).
    #[test]
    fn update_replaces_also_known_as() {
        let json = update_op()
            .into_signed("sig".to_string())
            .to_json()
            .unwrap();
        assert_eq!(
            json["alsoKnownAs"],
            serde_json::json!(["at://bob.example.com"]),
            "alsoKnownAs is REPLACED with exactly the new handle"
        );
        assert!(
            !json.to_string().contains("alice.example.com"),
            "no stale alias may survive the update"
        );
    }

    // The update preserves the rest of the document: rotationKeys,
    // verificationMethods and the (empty) services map equal the genesis shape —
    // only `alsoKnownAs` and `prev` differ.
    #[test]
    fn update_preserves_rotation_keys_and_verification_methods() {
        let genesis = identity_only_genesis()
            .into_signed("sig".to_string())
            .to_json()
            .unwrap();
        let update = update_op()
            .into_signed("sig".to_string())
            .to_json()
            .unwrap();

        assert_eq!(update["type"], OP_TYPE_OPERATION, "same discriminant");
        assert_eq!(update["rotationKeys"], genesis["rotationKeys"]);
        assert_eq!(
            update["verificationMethods"],
            genesis["verificationMethods"]
        );
        assert_eq!(update["services"], serde_json::json!({}));
        assert_ne!(update["alsoKnownAs"], genesis["alsoKnownAs"]);
        assert_ne!(update["prev"], genesis["prev"]);
    }

    // The update chains: its `prev` is the supplied CID (a genesis op serializes
    // `prev: null`; an update never does).
    #[test]
    fn update_chains_on_prev() {
        let json = update_op()
            .into_signed("sig".to_string())
            .to_json()
            .unwrap();
        assert_eq!(json["prev"], PREV);
    }

    // A tombstone signs over bytes that EXCLUDE `sig` (like a genesis op), and
    // its JSON is the minimal `{type, prev, sig}` — no rotationKeys /
    // alsoKnownAs / services / verificationMethods, per the spec.
    #[test]
    fn tombstone_shape_and_signing_bytes() {
        let op = TombstoneOperation::new(PREV.to_string());
        let unsigned = op.signing_bytes().unwrap();
        let signed = op.into_signed("theSig".to_string());
        let signed_cbor = dag_cbor(&signed.view()).unwrap();
        assert_ne!(
            unsigned, signed_cbor,
            "signed and unsigned tombstone CBOR must differ"
        );

        let json = signed.to_json().unwrap();
        assert_eq!(json["type"], OP_TYPE_TOMBSTONE);
        assert_eq!(json["prev"], PREV);
        assert_eq!(json["sig"], "theSig");
        for absent in [
            "rotationKeys",
            "verificationMethods",
            "alsoKnownAs",
            "services",
        ] {
            assert!(
                json.get(absent).is_none(),
                "a tombstone must carry no `{absent}` field"
            );
        }
    }

    // The DID a genesis operation derives is a well-formed did:plc: the method
    // is `plc` and the suffix is exactly 24 base32 characters.
    #[test]
    fn derived_dids_are_well_formed() {
        let did = identity_only_genesis()
            .into_signed("sig".to_string())
            .did()
            .unwrap();
        assert!(did.is_plc());
        let suffix = did.as_str().strip_prefix("did:plc:").unwrap();
        assert_eq!(suffix.len(), DID_SUFFIX_LEN);
        assert!(
            suffix
                .bytes()
                .all(|b| b"abcdefghijklmnopqrstuvwxyz234567".contains(&b)),
            "the suffix is lowercase base32"
        );
    }
}
