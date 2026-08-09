//! [`Minter`] — the `did:plc` write path: mint, update handle, tombstone.
//!
//! This is the piece the Rust ecosystem was missing. Reading a DID document is
//! easy and several crates do it; *writing* one — generating rotation keys,
//! building a byte-exact genesis operation, signing it with the right key,
//! deriving the DID from its own hash, custodying the keys, and chaining every
//! later operation onto the last — is what lives here.
//!
//! # Ordering is the durability story
//!
//! A mint and a later operation deliberately order their writes differently:
//!
//! - **mint** — custody keys, then log the genesis, then submit. Keys are
//!   persisted *before* anything is published, so a failed submission never
//!   orphans an identity whose keys were lost.
//! - **update / tombstone** — submit, then log. A failed submission must not
//!   advance the local chain: a retry then re-reads the same `prev`, re-signs
//!   the *same* deterministic operation, and lands it once.
//!
//! Neither pair is ever one transaction. The directory is a different system;
//! treating a submission as a separate retryable step is what keeps a private
//! store and a public record from needing a distributed commit.
//!
//! # Idempotency rests on deterministic signing
//!
//! `atrium-crypto`'s secp256k1 signing is RFC 6979 deterministic, so the same
//! inputs produce the same signature and therefore the same CID. That is what
//! makes a replayed update detectable (it collides on `UNIQUE(cid)`) and a blind
//! retry safe.

use std::collections::BTreeMap;
use std::sync::Arc;

use atrium_crypto::keypair::{Did as _, Export as _, Secp256k1Keypair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::plc::{
    OP_TYPE_OPERATION, OP_TYPE_TOMBSTONE, PlcDocument, PlcError, PlcOperation, PlcService,
    TombstoneOperation,
};
use crate::{
    CustodyKeys, Did, DirectoryError, Handle, KeyRole, KeyStore, MAX_ROTATION_KEYS,
    MIN_ROTATION_KEYS, MintPolicy, PlcDirectory, PlcOperationLog, PlcOperationRecord, PolicyError,
    SecretKey, StorageError,
};

/// Why a mint, update or tombstone failed.
///
/// Most variants are retryable: a directory or storage failure leaves the chain
/// where it was, and the operations are deterministic, so the same call can be
/// made again. The exceptions are the policy and shape mismatches, which need a
/// configuration or data fix first.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The [`MintPolicy`] is not usable. Raised by [`Minter::new`].
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// An operation could not be serialized.
    #[error(transparent)]
    Plc(#[from] PlcError),
    /// A storage implementation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The directory refused or could not be reached. Retryable.
    #[error(transparent)]
    Directory(#[from] DirectoryError),
    /// Key generation, import or signing failed.
    #[error("secp256k1 key operation failed: {0}")]
    Crypto(String),
    /// No custody keys are held for the DID, so nothing can sign for it.
    #[error("no custody keys are held for {0}")]
    NoCustody(Did),
    /// The DID has no logged operation, so there is no `prev` to chain onto.
    #[error("no prior PLC operation to chain onto for {0}")]
    NoPriorOperation(Did),
    /// The DID's latest operation is not a chainable `plc_operation` — it is a
    /// tombstone, or some other type.
    #[error(
        "cannot update {did}: its latest operation is `{op_type}`, not a chainable {OP_TYPE_OPERATION}"
    )]
    NotChainable {
        /// The DID whose update was refused.
        did: Did,
        /// The operation type found at the tip of its chain.
        op_type: String,
    },
    /// The DID's latest operation does not have the shape this policy mints, so
    /// rebuilding it would silently drop or add document fields. Refused rather
    /// than guessed at.
    #[error("cannot update {did}: its latest operation does not match this mint policy ({detail})")]
    PolicyMismatch {
        /// The DID whose update was refused.
        did: Did,
        /// What differed.
        detail: String,
    },
    /// The DID's latest logged operation could not be read as a PLC operation.
    #[error("the prior operation for {did} is malformed: {detail}")]
    MalformedPriorOperation {
        /// The DID whose prior operation could not be parsed.
        did: Did,
        /// What was wrong with it.
        detail: String,
    },
    /// The prior operation's `rotationKeys` break the `did:plc` spec's limits
    /// (1–5 keys, no duplicates), so carrying them forward verbatim would sign
    /// an operation the directory refuses.
    #[error("cannot update {did}: its prior operation's `rotationKeys` are invalid ({detail})")]
    InvalidPriorRotationKeys {
        /// The DID whose update was refused.
        did: Did,
        /// Which limit was broken.
        detail: String,
    },
}

/// Map an `atrium-crypto` failure into [`MintError::Crypto`].
fn crypto(err: atrium_crypto::Error) -> MintError {
    MintError::Crypto(err.to_string())
}

/// The freshly generated keypairs of a mint, addressable by [`KeyRole`].
struct RoleKeypairs {
    cold_recovery: Secp256k1Keypair,
    operational: Secp256k1Keypair,
    signing: Secp256k1Keypair,
}

impl RoleKeypairs {
    /// Generate one independent secp256k1 keypair per role.
    ///
    /// All three are generated even when the policy does not reference every
    /// role, so the custody bundle's on-disk shape is fixed and a later policy
    /// change can use a key that already exists rather than needing a rotation.
    fn generate() -> Self {
        // Generated inside one block so the non-`Send` `ThreadRng` is dropped
        // before any `.await` in the caller (the keypairs themselves are `Send`).
        let mut rng = rand::thread_rng();
        Self {
            cold_recovery: Secp256k1Keypair::create(&mut rng),
            operational: Secp256k1Keypair::create(&mut rng),
            signing: Secp256k1Keypair::create(&mut rng),
        }
    }

    /// The keypair playing `role`.
    fn role(&self, role: KeyRole) -> &Secp256k1Keypair {
        match role {
            KeyRole::ColdRecovery => &self.cold_recovery,
            KeyRole::Operational => &self.operational,
            KeyRole::Signing => &self.signing,
        }
    }

    /// The private halves, for custody.
    fn to_custody(&self) -> CustodyKeys {
        CustodyKeys {
            cold_recovery: SecretKey::new(self.cold_recovery.export()),
            operational: SecretKey::new(self.operational.export()),
            signing: SecretKey::new(self.signing.export()),
        }
    }
}

/// Mints and operates `did:plc` identities.
///
/// Holds the three collaborators it writes through — custody
/// ([`KeyStore`]), the chain ([`PlcOperationLog`]) and publication
/// ([`PlcDirectory`]) — plus the [`MintPolicy`] that shapes what it signs. All
/// three are `Arc<dyn …>`, so a minter is cheap to clone and trivial to test
/// against fakes.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use zurid::{Minter, MintPolicy, NoopPlcDirectory, Handle};
/// # async fn example(
/// #     keys: Arc<dyn zurid::KeyStore>,
/// #     log: Arc<dyn zurid::PlcOperationLog>,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// let minter = Minter::new(keys, log, Arc::new(NoopPlcDirectory), MintPolicy::identity_only())?;
/// let did = minter.mint(&Handle::try_new("alice.example.com")?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Minter {
    key_store: Arc<dyn KeyStore>,
    op_log: Arc<dyn PlcOperationLog>,
    directory: Arc<dyn PlcDirectory>,
    policy: MintPolicy,
}

impl Minter {
    /// Build a minter. The `policy` is [validated](MintPolicy::validate) here,
    /// so a misconfiguration fails at construction rather than at the first
    /// mint.
    pub fn new(
        key_store: Arc<dyn KeyStore>,
        op_log: Arc<dyn PlcOperationLog>,
        directory: Arc<dyn PlcDirectory>,
        policy: MintPolicy,
    ) -> Result<Self, MintError> {
        policy.validate()?;
        Ok(Self {
            key_store,
            op_log,
            directory,
            policy,
        })
    }

    /// The policy this minter signs by.
    pub fn policy(&self) -> &MintPolicy {
        &self.policy
    }

    /// Mint a new `did:plc` bound to `handle`.
    ///
    /// In order: (1) generate one secp256k1 keypair per [`KeyRole`]; (2) build
    /// the genesis operation from the [`MintPolicy`] — `rotationKeys` in the
    /// policy's order, its verification methods and services, and
    /// `alsoKnownAs = ["at://<handle>"]`; (3) sign the operation's no-`sig`
    /// DAG-CBOR with the policy's signer key (ECDSA-SHA256, low-S, base64url
    /// no-pad); (4) derive the DID from the signed operation's hash;
    /// (5) **persist the keys**; (6) **log the genesis operation**; and only
    /// then (7) **submit** it to the directory.
    ///
    /// Steps 5–7 are independent writes, never one transaction. Keys land
    /// before publication so a submission retry can never orphan them.
    pub async fn mint(&self, handle: &Handle) -> Result<Did, MintError> {
        let keypairs = RoleKeypairs::generate();

        let rotation_keys = self
            .policy
            .rotation_keys
            .iter()
            .map(|role| keypairs.role(*role).did())
            .collect();
        let verification_methods = self
            .policy
            .verification_methods
            .iter()
            .map(|(id, role)| (id.clone(), keypairs.role(*role).did()))
            .collect();
        let document = PlcDocument {
            rotation_keys,
            verification_methods,
            also_known_as: vec![handle.at_uri()],
            services: self.policy.services.clone(),
        };

        let operation = PlcOperation::genesis(document);
        let signed = self.sign_operation(operation, keypairs.role(self.policy.signer))?;

        let did = signed.did()?;
        // The genesis CID — the `prev` a future operation chains onto.
        let genesis_cid = signed.cid()?;
        let operation_json = signed.to_json()?;

        // (5) Custody first: every private half, in role order.
        self.key_store.put(&did, &keypairs.to_custody()).await?;
        // (6) Then the chain, so a later operation knows its `prev`.
        let record = PlcOperationRecord {
            did: did.clone(),
            cid: genesis_cid,
            op_type: OP_TYPE_OPERATION.to_string(),
            prev: None,
            operation_json: operation_json.to_string(),
        };
        self.op_log.append(&record).await?;
        // (7) Publication last — a separate, retryable step.
        self.directory.submit(did.as_str(), &operation_json).await?;

        Ok(did)
    }

    /// Re-point `did`'s `alsoKnownAs` to `handle`, chaining onto the DID's most
    /// recent logged operation.
    ///
    /// The prior operation supplies the DID document's **public** fields —
    /// `rotationKeys`, `verificationMethods` and `services` are carried forward
    /// verbatim from the log, never re-derived from custody — so a routine
    /// update decrypts exactly one private key: the signer. Only `alsoKnownAs`
    /// changes, and it is **replaced**, not appended to: a retained stale alias
    /// fails bidirectional handle verification.
    ///
    /// The prior operation must be a `plc_operation` whose shape matches this
    /// minter's policy. A tombstone, or an operation carrying services or
    /// verification methods the policy does not declare, is **refused** — never
    /// silently rebuilt into an operation that drops them.
    ///
    /// **Idempotent by content address; the chain never forks.** An identical
    /// replay produces the same CID, so if the append is rejected *and* the
    /// log's tip already is this exact operation, the replay is benign and
    /// reported as success. A *different* concurrent update chaining the same
    /// `prev` is rejected by the log's no-fork constraint; the tip is then not
    /// our operation, so the error propagates and the caller's retry re-reads
    /// the new tip — serializing concurrent writers into one linear chain rather
    /// than forking it.
    pub async fn update_handle(&self, did: &Did, handle: &Handle) -> Result<(), MintError> {
        // (1) The DID's latest operation: its `cid` is our `prev`, and its
        // stored JSON holds the public fields we preserve unchanged.
        let prior = self
            .op_log
            .latest_op(did)
            .await?
            .ok_or_else(|| MintError::NoPriorOperation(did.clone()))?;
        let document = self.carry_forward(did, &prior, handle)?;

        // (2) Only the signer is decrypted into a keypair; the rest of custody
        // stays sealed for a routine update.
        let signer = self.signer_keypair(did).await?;

        // (3) Build the update — the prior document, `alsoKnownAs` replaced.
        let operation = PlcOperation::update(document, prior.cid.clone());
        let signed = self.sign_operation(operation, &signer)?;
        let cid = signed.cid()?;
        let operation_json = signed.to_json()?;

        // (4) Publication FIRST — a failed submit must not advance our chain.
        self.directory.submit(did.as_str(), &operation_json).await?;
        // (5) Then record the now-submitted update as the DID's latest op.
        let record = PlcOperationRecord {
            did: did.clone(),
            cid: cid.clone(),
            op_type: OP_TYPE_OPERATION.to_string(),
            prev: Some(prior.cid),
            operation_json: operation_json.to_string(),
        };
        if let Err(err) = self.op_log.append(&record).await {
            // Rejected — either a benign identical replay (duplicate `cid`) or a
            // fork attempt against an already-used `prev`. Benign ONLY if the
            // log's tip already IS our exact operation; then the work is done,
            // so blind retries stay safe. Otherwise the tip advanced to a
            // different operation: propagate, so the caller retries onto it.
            let tip = self.op_log.latest_cid(did).await?;
            if tip.as_deref() == Some(cid.as_str()) {
                return Ok(());
            }
            return Err(err.into());
        }
        Ok(())
    }

    /// Tombstone `did`: sign a `plc_tombstone` with the policy's signer key,
    /// chaining onto the DID's most recent operation.
    ///
    /// The tombstone clears the DID document and deactivates the identity, on
    /// the directory's native recovery window — during which a higher-authority
    /// rotation key can still reverse it, which is why the cold-recovery key is
    /// retained rather than destroyed.
    ///
    /// The prior operation must be a chainable `plc_operation`, exactly as an
    /// update requires. An already-tombstoned DID is **refused**: a tombstone
    /// chaining a tombstone is not a valid operation for the directory to
    /// accept, and signing one would burn the retry path an operator reaches for
    /// when they are unsure whether the first one landed.
    ///
    /// Submit-before-record, like [`update_handle`](Minter::update_handle): a
    /// failed submission never advances the local chain, so a retry re-reads the
    /// correct `prev` and re-signs the *same* tombstone.
    pub async fn tombstone(&self, did: &Did) -> Result<(), MintError> {
        let signer = self.signer_keypair(did).await?;
        let prior = self
            .op_log
            .latest_op(did)
            .await?
            .ok_or_else(|| MintError::NoPriorOperation(did.clone()))?;
        if prior.op_type != OP_TYPE_OPERATION {
            return Err(MintError::NotChainable {
                did: did.clone(),
                op_type: prior.op_type,
            });
        }
        let prev = prior.cid;

        let operation = TombstoneOperation::new(prev.clone());
        let signature = signer.sign(&operation.signing_bytes()?).map_err(crypto)?;
        let signed = operation.into_signed(URL_SAFE_NO_PAD.encode(&signature));
        let cid = signed.cid()?;
        let operation_json = signed.to_json()?;

        // Publication FIRST, then the record — see `update_handle`.
        self.directory.submit(did.as_str(), &operation_json).await?;
        let record = PlcOperationRecord {
            did: did.clone(),
            cid,
            op_type: OP_TYPE_TOMBSTONE.to_string(),
            prev: Some(prev),
            operation_json: operation_json.to_string(),
        };
        self.op_log.append(&record).await?;
        Ok(())
    }

    /// Sign `operation`'s no-`sig` DAG-CBOR with `keypair`.
    ///
    /// `atrium-crypto`'s secp256k1 `sign` already emits atproto's canonical form
    /// (ECDSA-SHA256, low-S, 64-byte r‖s); this base64url no-pad encodes it into
    /// the operation.
    fn sign_operation(
        &self,
        operation: PlcOperation,
        keypair: &Secp256k1Keypair,
    ) -> Result<crate::plc::SignedOperation, MintError> {
        let signing_bytes = operation.signing_bytes()?;
        let signature = keypair.sign(&signing_bytes).map_err(crypto)?;
        Ok(operation.into_signed(URL_SAFE_NO_PAD.encode(&signature)))
    }

    /// Load custody for `did` and import **only** the policy's signer key.
    ///
    /// The other private halves are never decrypted into a keypair for a routine
    /// operation — they are not needed, and every key that stays sealed is one
    /// that cannot leak from a crash dump.
    async fn signer_keypair(&self, did: &Did) -> Result<Secp256k1Keypair, MintError> {
        let keys = self
            .key_store
            .get(did)
            .await?
            .ok_or_else(|| MintError::NoCustody(did.clone()))?;
        Secp256k1Keypair::import(keys.role(self.policy.signer).expose()).map_err(crypto)
    }

    /// Rebuild the document an update asserts: every public field carried
    /// forward verbatim from `prior`, with `alsoKnownAs` replaced by `handle`.
    ///
    /// Refuses a prior operation that is not a chainable `plc_operation`, or
    /// whose shape does not match this minter's policy — carrying an unknown
    /// shape forward is exactly how a PDS binding gets silently dropped.
    fn carry_forward(
        &self,
        did: &Did,
        prior: &PlcOperationRecord,
        handle: &Handle,
    ) -> Result<PlcDocument, MintError> {
        if prior.op_type != OP_TYPE_OPERATION {
            return Err(MintError::NotChainable {
                did: did.clone(),
                op_type: prior.op_type.clone(),
            });
        }
        let malformed = |detail: String| MintError::MalformedPriorOperation {
            did: did.clone(),
            detail,
        };
        // SECURITY-TODO(engineer): B2 — operation log has no integrity binding;
        // mitigation (HMAC column / sig-verify / re-derive) is an Engineer
        // decision. Everything below is read out of a stored row and carried
        // into an operation this minter then SIGNS, so whoever can write that
        // row chooses what gets signed. `check_prior_rotation_keys` bounds the
        // blast radius (see its own note); it does not detect tampering.
        let json: serde_json::Value = serde_json::from_str(&prior.operation_json)
            .map_err(|err| malformed(format!("its stored JSON does not parse: {err}")))?;

        let rotation_keys: Vec<String> = serde_json::from_value(json["rotationKeys"].clone())
            .map_err(|err| malformed(format!("`rotationKeys` is not a string array: {err}")))?;
        self.check_prior_rotation_keys(did, &rotation_keys)?;
        let verification_methods: BTreeMap<String, String> =
            serde_json::from_value(json["verificationMethods"].clone()).map_err(|err| {
                malformed(format!("`verificationMethods` is not a string map: {err}"))
            })?;
        let services: BTreeMap<String, PlcService> =
            serde_json::from_value(json["services"].clone())
                .map_err(|err| malformed(format!("`services` is not a service map: {err}")))?;

        // The shape must be the one this policy mints. Verification methods are
        // compared by ID (the values are per-DID `did:key`s carried forward);
        // services are compared whole, because an endpoint IS the binding.
        let policy_method_ids: Vec<&String> = self.policy.verification_methods.keys().collect();
        let prior_method_ids: Vec<&String> = verification_methods.keys().collect();
        if policy_method_ids != prior_method_ids {
            return Err(MintError::PolicyMismatch {
                did: did.clone(),
                detail: format!(
                    "verification methods {prior_method_ids:?}, policy declares {policy_method_ids:?}"
                ),
            });
        }
        if services != self.policy.services {
            return Err(MintError::PolicyMismatch {
                did: did.clone(),
                detail: format!(
                    "services {:?}, policy declares {:?}",
                    services.keys().collect::<Vec<_>>(),
                    self.policy.services.keys().collect::<Vec<_>>()
                ),
            });
        }

        Ok(PlcDocument {
            rotation_keys,
            verification_methods,
            also_known_as: vec![handle.at_uri()],
            services,
        })
    }

    /// Re-check a prior operation's `rotationKeys` against the `did:plc` spec's
    /// own limits — 1–5 keys, no duplicates
    /// (<https://web.plc.directory/spec/v0.1/did-plc>) — before carrying them
    /// forward verbatim.
    ///
    /// [`MintPolicy::validate`](crate::MintPolicy::validate) checks the same
    /// limits for what this minter *mints*, but an update does not mint the
    /// rotation keys: it copies them out of a stored row. If that row is
    /// oversized or holds a duplicate, copying it signs an operation the
    /// directory refuses — and because a refused operation cannot advance the
    /// chain, the identity is then **wedged**: no handle change, no tombstone,
    /// no way back. Checked here so a bad row is one rejected call rather than a
    /// dead identity.
    // SECURITY-TODO(engineer): B2 — operation log has no integrity binding;
    // mitigation (HMAC column / sig-verify / re-derive) is an Engineer decision.
    // This check bounds what a tampered `rotationKeys` can do (it can no longer
    // wedge the identity); it does NOT detect tampering, and it says nothing
    // about `verificationMethods`, `services` or `prev`. Whether the log should
    // authenticate its own rows — and how — is the open call.
    fn check_prior_rotation_keys(
        &self,
        did: &Did,
        rotation_keys: &[String],
    ) -> Result<(), MintError> {
        let invalid = |detail: String| MintError::InvalidPriorRotationKeys {
            did: did.clone(),
            detail,
        };
        if rotation_keys.len() < MIN_ROTATION_KEYS {
            return Err(invalid(format!(
                "{} keys, the spec requires at least {MIN_ROTATION_KEYS}",
                rotation_keys.len()
            )));
        }
        if rotation_keys.len() > MAX_ROTATION_KEYS {
            return Err(invalid(format!(
                "{} keys, the spec allows at most {MAX_ROTATION_KEYS}",
                rotation_keys.len()
            )));
        }
        for (index, key) in rotation_keys.iter().enumerate() {
            if rotation_keys[..index].contains(key) {
                return Err(invalid(
                    "a rotation key is listed more than once".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::NoopPlcDirectory;
    use crate::memory::{MemoryKeyStore, MemoryPlcOperationLog};
    use crate::plc::cid as compute_cid;
    use async_trait::async_trait;
    use atrium_crypto::verify::verify_signature;
    use k256::ecdsa::Signature;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn handle() -> Handle {
        Handle::try_new("alice.example.com").unwrap()
    }

    fn new_handle() -> Handle {
        Handle::try_new("bob.example.com").unwrap()
    }

    /// A minter over fresh in-memory stores and the no-op directory.
    fn minter() -> (Minter, Arc<MemoryKeyStore>, Arc<MemoryPlcOperationLog>) {
        let keys = Arc::new(MemoryKeyStore::new());
        let log = Arc::new(MemoryPlcOperationLog::new());
        let minter = Minter::new(
            keys.clone(),
            log.clone(),
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .expect("the identity-only preset is valid");
        (minter, keys, log)
    }

    /// A directory that records the last operation JSON it was asked to submit.
    #[derive(Default)]
    struct CapturingDirectory {
        last: Mutex<Option<serde_json::Value>>,
    }
    impl CapturingDirectory {
        fn last(&self) -> serde_json::Value {
            self.last
                .lock()
                .unwrap()
                .clone()
                .expect("an operation was submitted")
        }
    }
    #[async_trait]
    impl PlcDirectory for CapturingDirectory {
        async fn submit(
            &self,
            _did: &str,
            operation: &serde_json::Value,
        ) -> crate::DirectoryResult<()> {
            *self.last.lock().unwrap() = Some(operation.clone());
            Ok(())
        }
    }

    /// A directory that records the DID it was asked to submit, then fails — to
    /// prove keys are persisted *before* submission.
    #[derive(Default)]
    struct FailingDirectory {
        seen_did: Mutex<Option<String>>,
    }
    #[async_trait]
    impl PlcDirectory for FailingDirectory {
        async fn submit(
            &self,
            did: &str,
            _operation: &serde_json::Value,
        ) -> crate::DirectoryResult<()> {
            *self.seen_did.lock().unwrap() = Some(did.to_string());
            Err(DirectoryError::new("simulated directory failure"))
        }
    }

    /// A directory that records whether it was reached at all.
    #[derive(Default)]
    struct RecordingDirectory {
        called: AtomicBool,
    }
    #[async_trait]
    impl PlcDirectory for RecordingDirectory {
        async fn submit(
            &self,
            _did: &str,
            _operation: &serde_json::Value,
        ) -> crate::DirectoryResult<()> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A key store whose write always fails — to prove submission is not reached.
    struct FailingKeyStore;
    #[async_trait]
    impl KeyStore for FailingKeyStore {
        async fn put(&self, _did: &Did, _keys: &CustodyKeys) -> crate::StorageResult<()> {
            Err(StorageError::new("simulated key-store failure"))
        }
        async fn get(&self, _did: &Did) -> crate::StorageResult<Option<CustodyKeys>> {
            Ok(None)
        }
    }

    // --- construction -------------------------------------------------------

    #[test]
    fn construction_rejects_an_invalid_policy() {
        let broken = MintPolicy {
            rotation_keys: vec![KeyRole::ColdRecovery],
            signer: KeyRole::Operational,
            ..MintPolicy::identity_only()
        };
        let result = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            Arc::new(MemoryPlcOperationLog::new()),
            Arc::new(NoopPlcDirectory),
            broken,
        );
        assert!(matches!(result, Err(MintError::Policy(_))));
    }

    // --- mint ---------------------------------------------------------------

    // A mint produces a well-formed did:plc and custodies three distinct keys.
    #[tokio::test]
    async fn mint_produces_a_well_formed_did_and_stores_keys() {
        let (minter, keys, _log) = minter();

        let did = minter.mint(&handle()).await.unwrap();

        assert!(did.is_plc());
        assert_eq!(
            did.as_str().strip_prefix("did:plc:").unwrap().len(),
            24,
            "a did:plc suffix is 24 base32 chars"
        );

        let custody = keys.get(&did).await.unwrap().expect("keys custodied");
        for role in KeyRole::ALL {
            assert_eq!(
                custody.role(role).expose().len(),
                32,
                "{role} key is 32 bytes"
            );
        }
        assert_ne!(custody.cold_recovery, custody.operational);
        assert_ne!(custody.operational, custody.signing);
    }

    // Distinct mints get distinct DIDs and distinct keys — no identity shares a
    // rotation key with another.
    #[tokio::test]
    async fn distinct_mints_are_independent() {
        let (minter, keys, _log) = minter();

        let first = minter.mint(&handle()).await.unwrap();
        let second = minter.mint(&handle()).await.unwrap();

        assert_ne!(first, second);
        let first_keys = keys.get(&first).await.unwrap().unwrap();
        let second_keys = keys.get(&second).await.unwrap().unwrap();
        assert_ne!(
            first_keys.operational, second_keys.operational,
            "per-identity keys, never shared"
        );
    }

    // The genesis operation follows the policy: rotationKeys in the policy's
    // order, the policy's verification method ids, no services, and the handle
    // as the sole alsoKnownAs.
    #[tokio::test]
    async fn the_genesis_operation_follows_the_policy() {
        let keys = Arc::new(MemoryKeyStore::new());
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            keys.clone(),
            Arc::new(MemoryPlcOperationLog::new()),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        let custody = keys.get(&did).await.unwrap().unwrap();
        let cold = Secp256k1Keypair::import(custody.cold_recovery.expose()).unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing = Secp256k1Keypair::import(custody.signing.expose()).unwrap();

        let submitted = directory.last();
        assert_eq!(
            submitted["rotationKeys"],
            serde_json::json!([cold.did(), operational.did()]),
            "rotationKeys are the policy's roles in the policy's order"
        );
        assert_eq!(submitted["verificationMethods"]["atproto"], signing.did());
        assert_eq!(submitted["services"], serde_json::json!({}));
        assert_eq!(
            submitted["alsoKnownAs"],
            serde_json::json!(["at://alice.example.com"])
        );
        assert_eq!(submitted["prev"], serde_json::Value::Null);
    }

    // The genesis operation is signed by the POLICY'S SIGNER (a listed rotation
    // key), low-S and 64-byte — a valid, verifiable genesis signature.
    #[tokio::test]
    async fn the_genesis_signature_is_valid_low_s_and_from_the_policy_signer() {
        let (minter, keys, _log) = minter();
        let handle = handle();

        let did = minter.mint(&handle).await.unwrap();
        let custody = keys.get(&did).await.unwrap().unwrap();

        // Rebuild the exact operation the minter signed, from the stored keys.
        let cold = Secp256k1Keypair::import(custody.cold_recovery.expose()).unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing = Secp256k1Keypair::import(custody.signing.expose()).unwrap();
        let document = PlcDocument::identity_only(
            vec![cold.did(), operational.did()],
            signing.did(),
            handle.as_str(),
        );
        let signing_bytes = PlcOperation::genesis(document).signing_bytes().unwrap();
        let signature = operational.sign(&signing_bytes).unwrap();

        assert_eq!(signature.len(), 64, "compact 64-byte r‖s");
        let parsed = Signature::from_slice(&signature).unwrap();
        assert!(
            parsed.normalize_s().is_none(),
            "the signature must already be low-S"
        );
        verify_signature(&operational.did(), &signing_bytes, &signature).unwrap();
    }

    // Closes the field-mapping gap the vector test cannot: re-signing is
    // deterministic, so reconstructing the operation from the stored keys must
    // reproduce the EXACT minted DID — pinning the whole production path.
    #[tokio::test]
    async fn the_minted_did_reproduces_from_the_stored_keys() {
        let (minter, keys, _log) = minter();
        let handle = handle();

        let did = minter.mint(&handle).await.unwrap();
        let custody = keys.get(&did).await.unwrap().unwrap();

        let cold = Secp256k1Keypair::import(custody.cold_recovery.expose()).unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing = Secp256k1Keypair::import(custody.signing.expose()).unwrap();
        let document = PlcDocument::identity_only(
            vec![cold.did(), operational.did()],
            signing.did(),
            handle.as_str(),
        );
        let operation = PlcOperation::genesis(document);
        let signature = operational
            .sign(&operation.signing_bytes().unwrap())
            .unwrap();
        let reproduced = operation
            .into_signed(URL_SAFE_NO_PAD.encode(&signature))
            .did()
            .unwrap();

        assert_eq!(reproduced, did, "the mint path must be reproducible");
    }

    // Failure ordering: keys are persisted BEFORE the operation is submitted, so
    // a submission failure leaves the keys in place (a retry never orphans them).
    #[tokio::test]
    async fn keys_persist_when_directory_submission_fails() {
        let keys = Arc::new(MemoryKeyStore::new());
        let directory = Arc::new(FailingDirectory::default());
        let minter = Minter::new(
            keys.clone(),
            Arc::new(MemoryPlcOperationLog::new()),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let result = minter.mint(&handle()).await;

        assert!(result.is_err(), "mint fails when submission fails");
        let did = directory
            .seen_did
            .lock()
            .unwrap()
            .clone()
            .expect("submission was reached, so keys were already written");
        assert!(
            keys.get(&Did::new(did)).await.unwrap().is_some(),
            "custody keys must remain persisted after a submission failure"
        );
    }

    // Failure ordering: if the key write fails, the directory is NEVER reached —
    // no operation is published for an identity whose keys were not custodied.
    #[tokio::test]
    async fn the_directory_is_not_reached_when_the_key_write_fails() {
        let directory = Arc::new(RecordingDirectory::default());
        let minter = Minter::new(
            Arc::new(FailingKeyStore),
            Arc::new(MemoryPlcOperationLog::new()),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let result = minter.mint(&handle()).await;

        assert!(result.is_err(), "mint fails when the key write fails");
        assert!(
            !directory.called.load(Ordering::SeqCst),
            "submit must not run when the key write fails"
        );
    }

    // --- tombstone ----------------------------------------------------------

    // The security-critical path: a tombstone (a) chains onto the DID's latest
    // op as its `prev` and (b) is signed by the policy's signer — a valid,
    // verifiable, low-S signature. Wrong on either count, the directory rejects.
    #[tokio::test]
    async fn a_tombstone_chains_onto_the_tip_and_is_signed_by_the_policy_signer() {
        let keys = Arc::new(MemoryKeyStore::new());
        let log = Arc::new(MemoryPlcOperationLog::new());
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            keys.clone(),
            log.clone(),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        let genesis_cid = log.latest_cid(&did).await.unwrap().expect("genesis logged");

        minter.tombstone(&did).await.unwrap();

        let submitted = directory.last();
        assert_eq!(submitted["type"], OP_TYPE_TOMBSTONE);
        assert_eq!(
            submitted["prev"], genesis_cid,
            "the tombstone chains onto the genesis CID"
        );
        assert_ne!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            genesis_cid,
            "the log's latest op is now the tombstone"
        );

        let custody = keys.get(&did).await.unwrap().unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing_bytes = TombstoneOperation::new(genesis_cid)
            .signing_bytes()
            .unwrap();
        let signature = URL_SAFE_NO_PAD
            .decode(submitted["sig"].as_str().unwrap())
            .unwrap();
        assert_eq!(signature.len(), 64, "compact 64-byte r‖s");
        assert!(
            Signature::from_slice(&signature)
                .unwrap()
                .normalize_s()
                .is_none(),
            "the signature must already be low-S"
        );
        verify_signature(&operational.did(), &signing_bytes, &signature).unwrap();
    }

    #[tokio::test]
    async fn a_tombstone_needs_custody_and_a_prior_operation() {
        let (minter, _keys, _log) = minter();
        let unknown = Did::new("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(matches!(
            minter.tombstone(&unknown).await,
            Err(MintError::NoCustody(_))
        ));
    }

    // A tombstone checks the prior op's TYPE, exactly as an update does. A
    // tombstone chaining a tombstone is not an operation the directory accepts,
    // and signing one burns the retry an operator reaches for when they are
    // unsure the first landed: the local chain would advance past a `prev` the
    // directory never saw.
    #[tokio::test]
    async fn a_tombstone_rejects_an_already_tombstoned_did() {
        let (minter, _keys, log) = minter();

        let did = minter.mint(&handle()).await.unwrap();
        minter.tombstone(&did).await.unwrap();
        let tombstone_cid = log.latest_cid(&did).await.unwrap().unwrap();

        let error = minter
            .tombstone(&did)
            .await
            .expect_err("a DID cannot be tombstoned twice");
        assert!(
            matches!(&error, MintError::NotChainable { op_type, .. } if op_type == OP_TYPE_TOMBSTONE),
            "the rejection names the tombstone clearly, got: {error}"
        );
        assert_eq!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            tombstone_cid,
            "the refused tombstone must not have advanced the chain"
        );
        assert_eq!(log.records().len(), 2, "genesis + the one tombstone");
    }

    // --- update_handle ------------------------------------------------------

    // The update chains onto the DID's latest LOGGED operation (never fetched
    // from the directory), REPLACES alsoKnownAs, and advances the log.
    #[tokio::test]
    async fn an_update_chains_onto_the_latest_logged_operation() {
        let log = Arc::new(MemoryPlcOperationLog::new());
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log.clone(),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        let genesis_cid = log.latest_cid(&did).await.unwrap().unwrap();

        minter.update_handle(&did, &new_handle()).await.unwrap();

        let submitted = directory.last();
        assert_eq!(submitted["type"], OP_TYPE_OPERATION);
        assert_eq!(submitted["prev"], genesis_cid);
        assert_eq!(
            submitted["alsoKnownAs"],
            serde_json::json!(["at://bob.example.com"]),
            "alsoKnownAs is REPLACED with the new handle"
        );
        assert_ne!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            genesis_cid,
            "the log's latest op is now the update"
        );
    }

    // The update is durably logged with the right `prev` and the exact
    // deterministic content id of the signed operation.
    #[tokio::test]
    async fn an_update_appends_a_plc_operation_record() {
        let (minter, keys, log) = minter();

        let did = minter.mint(&handle()).await.unwrap();
        let genesis_cid = log.latest_cid(&did).await.unwrap().unwrap();

        minter.update_handle(&did, &new_handle()).await.unwrap();

        // Recompute the expected CID from custody — signing is deterministic, so
        // this is the exact operation the minter signed.
        let custody = keys.get(&did).await.unwrap().unwrap();
        let cold = Secp256k1Keypair::import(custody.cold_recovery.expose()).unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing = Secp256k1Keypair::import(custody.signing.expose()).unwrap();
        let document = PlcDocument::identity_only(
            vec![cold.did(), operational.did()],
            signing.did(),
            new_handle().as_str(),
        );
        let operation = PlcOperation::update(document, genesis_cid.clone());
        let signature = operational
            .sign(&operation.signing_bytes().unwrap())
            .unwrap();
        let expected_cid = operation
            .into_signed(URL_SAFE_NO_PAD.encode(&signature))
            .cid()
            .unwrap();

        let records = log.records();
        assert_eq!(records.len(), 2, "genesis + the update");
        let update = &records[1];
        assert_eq!(update.did, did);
        assert_eq!(update.op_type, OP_TYPE_OPERATION);
        assert_eq!(update.prev.as_deref(), Some(genesis_cid.as_str()));
        assert_eq!(
            update.cid, expected_cid,
            "the logged cid is the signed operation's content id"
        );
    }

    // KEY HYGIENE: a routine update needs ONLY the signer key. Custody here holds
    // a valid operational key but GARBAGE (all-zero, un-importable) cold-recovery
    // and signing scalars; the update still succeeds — proving those keys are
    // never imported — by carrying the public fields forward from the log.
    #[tokio::test]
    async fn an_update_uses_only_the_signer_key_and_carries_public_fields_forward() {
        // A genesis operation signed with REAL keys, logged as the only op.
        let cold = Secp256k1Keypair::create(&mut rand::thread_rng());
        let operational = Secp256k1Keypair::create(&mut rand::thread_rng());
        let signing = Secp256k1Keypair::create(&mut rand::thread_rng());
        let document = PlcDocument::identity_only(
            vec![cold.did(), operational.did()],
            signing.did(),
            handle().as_str(),
        );
        let genesis = PlcOperation::genesis(document);
        let signature = operational.sign(&genesis.signing_bytes().unwrap()).unwrap();
        let signed = genesis.into_signed(URL_SAFE_NO_PAD.encode(&signature));
        let did = signed.did().unwrap();
        let genesis_cid = signed.cid().unwrap();
        let genesis_json = signed.to_json().unwrap();

        // Custody: a real operational key, but GARBAGE cold-recovery and signing
        // scalars that would fail `Secp256k1Keypair::import`.
        let keys = Arc::new(MemoryKeyStore::new());
        let custody = CustodyKeys {
            cold_recovery: SecretKey::new(vec![0u8; 32]),
            operational: SecretKey::new(operational.export()),
            signing: SecretKey::new(vec![0u8; 32]),
        };
        keys.put(&did, &custody).await.unwrap();

        let log = Arc::new(MemoryPlcOperationLog::new());
        let genesis_record = PlcOperationRecord {
            did: did.clone(),
            cid: genesis_cid.clone(),
            op_type: OP_TYPE_OPERATION.to_string(),
            prev: None,
            operation_json: genesis_json.to_string(),
        };
        log.append(&genesis_record).await.unwrap();

        let directory = Arc::new(CapturingDirectory::default());
        let minter =
            Minter::new(keys, log, directory.clone(), MintPolicy::identity_only()).unwrap();

        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("an update needs only the signer key; the rest is public");

        let submitted = directory.last();
        assert_eq!(
            submitted["rotationKeys"],
            serde_json::json!([cold.did(), operational.did()]),
            "rotationKeys carried forward from the log, not re-derived from custody"
        );
        assert_eq!(
            submitted["verificationMethods"]["atproto"],
            signing.did(),
            "verificationMethods carried forward from the log"
        );
    }

    // RETRYABLE FAILURE: a failed submission must not advance the local chain, so
    // a clean retry re-reads the SAME `prev`, re-signs the SAME operation, and
    // lands it once.
    #[tokio::test]
    async fn an_update_survives_a_submission_failure_retryably() {
        let keys = Arc::new(MemoryKeyStore::new());
        let log = Arc::new(MemoryPlcOperationLog::new());
        let minter = Minter::new(
            keys.clone(),
            log.clone(),
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();
        let did = minter.mint(&handle()).await.unwrap();
        let genesis_cid = log.latest_cid(&did).await.unwrap().unwrap();

        let failing = Minter::new(
            keys.clone(),
            log.clone(),
            Arc::new(FailingDirectory::default()),
            MintPolicy::identity_only(),
        )
        .unwrap();
        assert!(
            failing.update_handle(&did, &new_handle()).await.is_err(),
            "the update fails when submission fails"
        );
        assert_eq!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            genesis_cid,
            "a failed submit must not advance the local chain"
        );

        let directory = Arc::new(CapturingDirectory::default());
        let retrying = Minter::new(
            keys,
            log.clone(),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();
        retrying
            .update_handle(&did, &new_handle())
            .await
            .expect("the retry succeeds");

        assert_eq!(
            directory.last()["prev"],
            genesis_cid,
            "the retry chains onto the same prev the failed attempt read"
        );
        assert_ne!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            genesis_cid,
            "the retried update is now the DID's latest logged op"
        );
    }

    // RE-ASSERTING the current handle is NOT a replay: `prev` has advanced, so it
    // signs a NEW operation chaining onto the previous update.
    #[tokio::test]
    async fn re_asserting_the_current_handle_chains_a_new_operation() {
        let log = Arc::new(MemoryPlcOperationLog::new());
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log.clone(),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        minter.update_handle(&did, &new_handle()).await.unwrap();
        let first_update_cid = log.latest_cid(&did).await.unwrap().unwrap();

        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("re-asserting the current handle is valid");

        assert_eq!(
            directory.last()["prev"],
            first_update_cid,
            "the re-assertion chains onto the previous update"
        );
        assert_eq!(log.records().len(), 3, "genesis + two updates");
    }

    #[tokio::test]
    async fn an_update_needs_custody_and_a_prior_operation() {
        let (minter, _keys, _log) = minter();
        let unknown = Did::new("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(matches!(
            minter.update_handle(&unknown, &new_handle()).await,
            Err(MintError::NoPriorOperation(_))
        ));
    }

    /// A log that simulates losing the append race ONCE: while armed, the next
    /// `append` first lands the IDENTICAL record — as a concurrent retry of the
    /// same deterministic update would — so the minter's own append then hits
    /// the duplicate-`cid` rejection.
    struct RacingLog {
        inner: MemoryPlcOperationLog,
        armed: AtomicBool,
    }
    #[async_trait]
    impl PlcOperationLog for RacingLog {
        async fn append(&self, record: &PlcOperationRecord) -> crate::StorageResult<()> {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.inner.append(record).await?;
            }
            self.inner.append(record).await
        }
        async fn latest_cid(&self, did: &Did) -> crate::StorageResult<Option<String>> {
            self.inner.latest_cid(did).await
        }
        async fn latest_op(&self, did: &Did) -> crate::StorageResult<Option<PlcOperationRecord>> {
            self.inner.latest_op(did).await
        }
    }

    // IDEMPOTENT REPLAY: signing is deterministic, so an identical update has the
    // same CID. If the identical operation already landed — here a simulated
    // concurrent retry that wins the race — the duplicate-cid rejection is
    // treated as SUCCESS, so a caller can retry blindly: no error, no second row.
    #[tokio::test]
    async fn replaying_an_identical_update_is_idempotent() {
        let log = Arc::new(RacingLog {
            inner: MemoryPlcOperationLog::new(),
            armed: AtomicBool::new(false),
        });
        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log.clone(),
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();

        log.armed.store(true, Ordering::SeqCst);
        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("a benign replay (the identical op already logged) is success");

        assert_eq!(
            log.inner.records().len(),
            2,
            "genesis + exactly ONE update row — the replay appended nothing"
        );
    }

    /// A log that simulates a DIFFERENT concurrent writer winning the race: on
    /// the first `append` it first lands a pre-seeded winner chaining the SAME
    /// `prev`, so the minter's own append hits the no-fork constraint.
    struct ForkRaceLog {
        inner: MemoryPlcOperationLog,
        winner: Mutex<Option<PlcOperationRecord>>,
    }
    #[async_trait]
    impl PlcOperationLog for ForkRaceLog {
        async fn append(&self, record: &PlcOperationRecord) -> crate::StorageResult<()> {
            // Take the winner out of the lock BEFORE awaiting (never hold a std
            // Mutex guard across `.await`).
            let winner = self.winner.lock().unwrap().take();
            if let Some(winner) = winner {
                self.inner.append(&winner).await?;
            }
            self.inner.append(record).await
        }
        async fn latest_cid(&self, did: &Did) -> crate::StorageResult<Option<String>> {
            self.inner.latest_cid(did).await
        }
        async fn latest_op(&self, did: &Did) -> crate::StorageResult<Option<PlcOperationRecord>> {
            self.inner.latest_op(did).await
        }
    }

    // NO CHAIN FORK: two updates cannot both chain the same `prev`. When a
    // DIFFERENT concurrent writer lands first, our append is rejected; the tip is
    // not our operation, so the error propagates (never a silent fork), and a
    // retry re-reads the NEW tip — serializing the writers into ONE linear chain.
    #[tokio::test]
    async fn a_forking_update_is_rejected_and_the_chain_stays_linear() {
        let keys = Arc::new(MemoryKeyStore::new());
        let log = Arc::new(ForkRaceLog {
            inner: MemoryPlcOperationLog::new(),
            winner: Mutex::new(None),
        });
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            keys.clone(),
            log.clone(),
            directory.clone(),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        let genesis_cid = log.latest_cid(&did).await.unwrap().unwrap();

        // A DIFFERENT concurrent winner (a change to a THIRD handle) chaining the
        // same genesis `prev`, armed to land first on the next append.
        let custody = keys.get(&did).await.unwrap().unwrap();
        let cold = Secp256k1Keypair::import(custody.cold_recovery.expose()).unwrap();
        let operational = Secp256k1Keypair::import(custody.operational.expose()).unwrap();
        let signing = Secp256k1Keypair::import(custody.signing.expose()).unwrap();
        let winner_document = PlcDocument::identity_only(
            vec![cold.did(), operational.did()],
            signing.did(),
            "carol.example.com",
        );
        let winner_op = PlcOperation::update(winner_document, genesis_cid.clone());
        let winner_sig = operational
            .sign(&winner_op.signing_bytes().unwrap())
            .unwrap();
        let winner_signed = winner_op.into_signed(URL_SAFE_NO_PAD.encode(&winner_sig));
        let winner_cid = winner_signed.cid().unwrap();
        let winner_record = PlcOperationRecord {
            did: did.clone(),
            cid: winner_cid.clone(),
            op_type: OP_TYPE_OPERATION.to_string(),
            prev: Some(genesis_cid.clone()),
            operation_json: winner_signed.to_json().unwrap().to_string(),
        };
        *log.winner.lock().unwrap() = Some(winner_record);

        assert!(
            minter.update_handle(&did, &new_handle()).await.is_err(),
            "a fork (a second op chaining the same prev) is rejected, not accepted"
        );
        let records = log.inner.records();
        assert_eq!(
            records.len(),
            2,
            "genesis + the winner — no forked third op"
        );
        assert_eq!(records[1].cid, winner_cid);
        assert_eq!(
            log.latest_cid(&did).await.unwrap().unwrap(),
            winner_cid,
            "the winner is the DID's tip"
        );

        // Retry: now reads prev = winner and chains onto it — one linear chain.
        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("the retry serializes onto the new tip");
        assert_eq!(
            directory.last()["prev"],
            winner_cid,
            "the retry chains onto the winner, not the stale genesis"
        );
        assert_eq!(
            log.inner.records().len(),
            3,
            "genesis → winner → the retried update: one linear chain, never a fork"
        );
    }

    // --- carry-forward guards ----------------------------------------------

    // An update refuses a TOMBSTONED DID: its latest op is a tombstone, which
    // has no document to chain an update onto.
    #[tokio::test]
    async fn an_update_rejects_a_tombstoned_did() {
        let (minter, _keys, _log) = minter();

        let did = minter.mint(&handle()).await.unwrap();
        minter.tombstone(&did).await.unwrap();

        let error = minter
            .update_handle(&did, &new_handle())
            .await
            .expect_err("cannot update a tombstoned DID");
        assert!(
            matches!(&error, MintError::NotChainable { op_type, .. } if op_type == OP_TYPE_TOMBSTONE),
            "the rejection names the tombstone clearly, got: {error}"
        );
    }

    /// Log a hand-built prior operation for `did`, so a guard can be exercised
    /// against a shape the minter would never produce.
    async fn log_prior(log: &MemoryPlcOperationLog, did: &Did, operation: serde_json::Value) {
        let record = PlcOperationRecord {
            did: did.clone(),
            cid: compute_cid(operation.to_string().as_bytes()),
            op_type: OP_TYPE_OPERATION.to_string(),
            prev: None,
            operation_json: operation.to_string(),
        };
        log.append(&record).await.unwrap();
    }

    // If the prior operation carries a service the policy does not declare, the
    // update REFUSES it rather than rebuilding an empty-`services` operation that
    // would silently drop the PDS binding. The guard fires before custody is even
    // read (the key store is empty), so this proves the check itself.
    #[tokio::test]
    async fn an_update_rejects_a_prior_that_does_not_match_the_policy() {
        let did = Did::new("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(
            &log,
            &did,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": ["did:key:cold", "did:key:hot"],
                "verificationMethods": {"atproto": "did:key:sign"},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": "https://pds.example.com"
                    }
                },
                "prev": serde_json::Value::Null
            }),
        )
        .await;

        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log,
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();

        let error = minter
            .update_handle(&did, &new_handle())
            .await
            .expect_err("cannot rebuild an operation the policy does not describe");
        assert!(
            matches!(&error, MintError::PolicyMismatch { detail, .. } if detail.contains("services")),
            "the PDS binding is not silently dropped, got: {error}"
        );
    }

    // The mirror case: a prior operation with an EXTRA verification method the
    // policy does not declare is refused too.
    #[tokio::test]
    async fn an_update_rejects_an_unexpected_verification_method() {
        let did = Did::new("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(
            &log,
            &did,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": ["did:key:cold", "did:key:hot"],
                "verificationMethods": {"atproto": "did:key:sign", "extra": "did:key:other"},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {},
                "prev": serde_json::Value::Null
            }),
        )
        .await;

        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log,
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();

        assert!(matches!(
            minter.update_handle(&did, &new_handle()).await,
            Err(MintError::PolicyMismatch { .. })
        ));
    }

    /// A prior operation carrying `rotation_keys` verbatim, and a minter over it.
    async fn minter_over_prior_rotation_keys(
        did: &Did,
        rotation_keys: serde_json::Value,
    ) -> Minter {
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(
            &log,
            did,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": rotation_keys,
                "verificationMethods": {"atproto": "did:key:sign"},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {},
                "prev": serde_json::Value::Null
            }),
        )
        .await;
        Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log,
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap()
    }

    // The spec's rotationKeys limits (1–5, no duplicates) are re-run on the
    // CARRIED-FORWARD keys, not just on what this minter mints. An update does
    // not mint them — it copies them out of a stored row — and copying an
    // oversized or duplicated list signs an operation the directory refuses.
    // Because a refused operation cannot advance the chain, that would WEDGE the
    // identity: no handle change, no tombstone, no way back. One rejected call
    // beats a dead identity.
    #[tokio::test]
    async fn an_update_rejects_prior_rotation_keys_that_break_the_spec_limits() {
        let too_many: Vec<String> = (0..=MAX_ROTATION_KEYS)
            .map(|index| format!("did:key:k{index}"))
            .collect();
        let cases: [(&str, serde_json::Value, &str); 3] = [
            (
                "did:plc:eeeeeeeeeeeeeeeeeeeeeeee",
                serde_json::json!([]),
                "at least",
            ),
            (
                "did:plc:ffffffffffffffffffffffff",
                serde_json::json!(too_many),
                "at most",
            ),
            (
                "did:plc:gggggggggggggggggggggggg",
                serde_json::json!(["did:key:same", "did:key:same"]),
                "more than once",
            ),
        ];

        for (raw_did, rotation_keys, expected) in cases {
            let did = Did::new(raw_did);
            let minter = minter_over_prior_rotation_keys(&did, rotation_keys).await;

            let error = minter
                .update_handle(&did, &new_handle())
                .await
                .expect_err("rotationKeys breaking the spec must be refused");
            assert!(
                matches!(&error, MintError::InvalidPriorRotationKeys { detail, .. }
                    if detail.contains(expected)),
                "expected a rotationKeys rejection mentioning `{expected}`, got: {error}"
            );
        }
    }

    // The guard is a limit check, not a shape change: a prior operation whose
    // rotationKeys are legal still carries them forward untouched.
    #[tokio::test]
    async fn an_update_carries_legal_prior_rotation_keys_forward() {
        let did = Did::new("did:plc:hhhhhhhhhhhhhhhhhhhhhhhh");
        let rotation_keys = serde_json::json!(["did:key:cold", "did:key:hot", "did:key:third"]);
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(
            &log,
            &did,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": rotation_keys,
                "verificationMethods": {"atproto": "did:key:sign"},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {},
                "prev": serde_json::Value::Null
            }),
        )
        .await;

        // Real custody, so the update gets past the signer load and reaches the
        // directory with the document it built.
        let keys = Arc::new(MemoryKeyStore::new());
        let operational = Secp256k1Keypair::create(&mut rand::thread_rng());
        let custody = CustodyKeys {
            cold_recovery: SecretKey::new(vec![0u8; 32]),
            operational: SecretKey::new(operational.export()),
            signing: SecretKey::new(vec![0u8; 32]),
        };
        keys.put(&did, &custody).await.unwrap();

        let directory = Arc::new(CapturingDirectory::default());
        let minter =
            Minter::new(keys, log, directory.clone(), MintPolicy::identity_only()).unwrap();

        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("three distinct rotation keys are within the spec's limits");
        assert_eq!(
            directory.last()["rotationKeys"],
            rotation_keys,
            "legal rotation keys are carried forward untouched"
        );
    }

    // A prior operation whose stored JSON is not a PLC operation fails as
    // MALFORMED rather than as a confusing downstream error.
    #[tokio::test]
    async fn an_update_rejects_a_malformed_prior() {
        let did = Did::new("did:plc:cccccccccccccccccccccccc");
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(&log, &did, serde_json::json!({"type": "plc_operation"})).await;

        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log,
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();

        assert!(matches!(
            minter.update_handle(&did, &new_handle()).await,
            Err(MintError::MalformedPriorOperation { .. })
        ));
    }

    // A PDS-BEARING POLICY round-trips: the same policy that minted the operation
    // can update it, because the shapes match. This is the case Zurfur's
    // hard-coded identity-only guard could not express.
    #[tokio::test]
    async fn a_pds_bearing_policy_can_update_its_own_identities() {
        let policy = MintPolicy {
            services: BTreeMap::from([(
                "atproto_pds".to_string(),
                PlcService {
                    type_: "AtprotoPersonalDataServer".to_string(),
                    endpoint: "https://pds.example.com".to_string(),
                },
            )]),
            ..MintPolicy::identity_only()
        };
        let directory = Arc::new(CapturingDirectory::default());
        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            Arc::new(MemoryPlcOperationLog::new()),
            directory.clone(),
            policy,
        )
        .unwrap();

        let did = minter.mint(&handle()).await.unwrap();
        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("a policy can update the shape it mints");

        let submitted = directory.last();
        assert_eq!(
            submitted["services"]["atproto_pds"]["endpoint"], "https://pds.example.com",
            "the service binding is carried forward, not dropped"
        );
        assert_eq!(
            submitted["alsoKnownAs"],
            serde_json::json!(["at://bob.example.com"])
        );
    }

    // TODO(engineer decision): carrying an ARBITRARY prior shape forward.
    //
    // Today an update refuses a prior operation whose services or verification
    // methods differ from the minter's policy (the test above). The alternative —
    // carry whatever the prior operation declares forward verbatim, whatever it
    // is — is strictly more permissive and would let an identity whose document
    // was changed out of band still be updated. It is also how a foreign service
    // binding silently survives an operation the operator believes they control.
    //
    // Which of the two is right is a domain call, not an extraction call, so the
    // conservative behaviour is what ships. Un-ignore this test to adopt the
    // permissive one.
    #[tokio::test]
    #[ignore = "TODO(engineer decision): permissive verbatim carry-forward is not the shipped behaviour"]
    async fn an_update_carries_an_arbitrary_prior_shape_forward() {
        let did = Did::new("did:plc:dddddddddddddddddddddddd");
        let log = Arc::new(MemoryPlcOperationLog::new());
        log_prior(
            &log,
            &did,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": ["did:key:cold", "did:key:hot"],
                "verificationMethods": {"atproto": "did:key:sign", "extra": "did:key:other"},
                "alsoKnownAs": ["at://alice.example.com"],
                "services": {},
                "prev": serde_json::Value::Null
            }),
        )
        .await;

        let minter = Minter::new(
            Arc::new(MemoryKeyStore::new()),
            log,
            Arc::new(NoopPlcDirectory),
            MintPolicy::identity_only(),
        )
        .unwrap();

        minter
            .update_handle(&did, &new_handle())
            .await
            .expect("a permissive minter would carry the extra method forward");
    }
}
