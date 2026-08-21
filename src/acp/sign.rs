//! The attestation signature: pre-image, sign, verify.
//!
//! # What is signed
//!
//! Not the stored record. The **pre-image** is the [`UnsignedAttestation`]
//! plus one injected object that is never stored:
//!
//! ```text
//! $sig: { $type: "net.got-paws.acp.sigBinding", repository: <did> }
//! ```
//!
//! Its canonical DAG-CBOR is hashed into a CIDv1 ([`RecordCid`]) and **the
//! raw CID bytes are what the key signs** (ECDSA-SHA256 over the 36 CID
//! bytes, low-S, 64-byte `r‖s`). This is the CID-First Attestation
//! construction, so independent tooling can reproduce the bytes.
//!
//! # Where `repository` comes from
//!
//! Always from the caller, never from the record — the type [`Repository`]
//! exists so that is visible at every call site. The attestor passes the
//! subject's repo DID (where it intends the record to live). The verifier
//! passes the DID of the repo it **actually fetched the record from**. If a
//! record is copied into another repo, the verifier's pre-image differs from
//! the one that was signed and the signature fails at the arithmetic — there
//! is no transplant *check* to forget, because the transplanted record has no
//! valid pre-image at all. `tests::transplant_fails` pins this.
//!
//! # Algorithms
//!
//! The atproto cryptography profile: ES256 (P-256) and ES256K (secp256k1),
//! low-S only. High-S signatures are rejected on verify (`allow_malleable`
//! is never enabled outside tests). A key of one curve never verifies a
//! signature made on the other.

use atrium_crypto::Algorithm;
use atrium_crypto::keypair::{P256Keypair, Secp256k1Keypair};
use atrium_crypto::verify::Verifier;
use serde::Serialize;

use crate::Did;

use super::error::{CodecError, SigError, SignError};
use super::record::{Attestation, RecordCid, Sig, UnsignedAttestation, canonical_bytes};

/// The `$type` of the injected binding object. Minted under the ACP
/// authority; no ecosystem-fixed value exists (the CID-First spec leaves it
/// to the implementer).
pub const SIG_BINDING_TYPE: &str = "net.got-paws.acp.sigBinding";

/// The DID of the repository a record lives in — the signer's intended repo,
/// or the repo the verifier fetched from.
///
/// A distinct type, not a bare `&Did`, so a call site cannot hand over
/// `attestation.subject` by reflex: reading the binding out of the record is
/// exactly the bug the binding exists to make impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repository<'a>(pub &'a Did);

#[derive(Serialize)]
struct SigBinding<'a> {
    #[serde(rename = "$type")]
    type_: &'static str,
    repository: &'a Did,
}

/// Serialize-only view of the pre-image: the body's fields flattened, plus
/// `$sig`. `serde_ipld_dagcbor` sorts the resulting map, so `$sig` lands
/// where canonical order puts it regardless of this struct's shape.
#[derive(Serialize)]
struct Preimage<'a> {
    #[serde(flatten)]
    body: &'a UnsignedAttestation,
    #[serde(rename = "$sig")]
    sig: SigBinding<'a>,
}

/// The canonical DAG-CBOR of the pre-image for `body` living in `repo`.
pub fn preimage(body: &UnsignedAttestation, repo: Repository<'_>) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(&Preimage {
        body,
        sig: SigBinding {
            type_: SIG_BINDING_TYPE,
            repository: repo.0,
        },
    })
}

/// The CID of the pre-image — the 36 bytes the key actually signs.
pub fn preimage_cid(
    body: &UnsignedAttestation,
    repo: Repository<'_>,
) -> Result<RecordCid, CodecError> {
    Ok(RecordCid::of(&preimage(body, repo)?))
}

/// A signature algorithm of the atproto profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigAlg {
    /// ECDSA over P-256 with SHA-256.
    Es256,
    /// ECDSA over secp256k1 with SHA-256.
    Es256k,
}

impl SigAlg {
    fn atrium(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::P256,
            Self::Es256k => Algorithm::Secp256k1,
        }
    }

    fn from_atrium(alg: Algorithm) -> Self {
        match alg {
            Algorithm::P256 => Self::Es256,
            Algorithm::Secp256k1 => Self::Es256k,
        }
    }
}

/// Something that can produce an atproto-profile signature.
///
/// Implemented for `atrium-crypto`'s two keypairs. Implement it for an HSM or
/// remote signer to keep attestor keys out of process memory; the contract is
/// ECDSA-SHA256 over `msg`, low-S, 64-byte compact `r‖s`.
pub trait Signer {
    /// The algorithm the signature will verify under.
    fn alg(&self) -> SigAlg;
    /// Sign `msg`. Errors are stringified into [`SignError::Crypto`].
    fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
}

impl Signer for Secp256k1Keypair {
    fn alg(&self) -> SigAlg {
        SigAlg::Es256k
    }
    fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.sign(msg).map_err(|e| e.to_string())
    }
}

impl Signer for P256Keypair {
    fn alg(&self) -> SigAlg {
        SigAlg::Es256
    }
    fn sign_bytes(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.sign(msg).map_err(|e| e.to_string())
    }
}

/// Sign `body` as living in `repo`, producing the stored [`Attestation`].
///
/// `repo` must be the **subject's** repo DID — where the record will be
/// written. Signing for any other repo produces a record that verifies
/// nowhere useful.
pub fn sign(
    body: UnsignedAttestation,
    repo: Repository<'_>,
    key: &impl Signer,
) -> Result<Attestation, SignError> {
    let cid = preimage_cid(&body, repo)?;
    let sig = key.sign_bytes(cid.as_bytes()).map_err(SignError::Crypto)?;
    Ok(body.with_sig(Sig(sig)))
}

/// A public key taken from an attestor's DID document.
///
/// Built from the `did:key` or multikey (`publicKeyMultibase`) forms a DID
/// document carries; the orchestration layer resolves the document, this
/// module never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    alg: SigAlg,
    /// SEC1-encoded public point, as `atrium-crypto` hands it back.
    sec1: Vec<u8>,
}

impl VerifyingKey {
    /// From a `did:key:z…` string.
    pub fn from_did_key(did_key: &str) -> Result<Self, SigError> {
        let (alg, sec1) = atrium_crypto::did::parse_did_key(did_key)
            .map_err(|e| SigError::UnsupportedAlgorithm(e.to_string()))?;
        Ok(Self {
            alg: SigAlg::from_atrium(alg),
            sec1,
        })
    }

    /// From a multibase multikey (`z…`, multicodec-prefixed) — the
    /// `publicKeyMultibase` of a `Multikey` verification method.
    pub fn from_multikey(multikey: &str) -> Result<Self, SigError> {
        let (alg, sec1) = atrium_crypto::did::parse_multikey(multikey)
            .map_err(|e| SigError::UnsupportedAlgorithm(e.to_string()))?;
        Ok(Self {
            alg: SigAlg::from_atrium(alg),
            sec1,
        })
    }

    /// The algorithm this key verifies.
    pub fn alg(&self) -> SigAlg {
        self.alg
    }
}

/// Verify `att`'s signature as a record fetched from `repo`, against the
/// attestor's current keys.
///
/// `repo` is the DID of the repo the verifier **retrieved the record from**
/// — never `att.body.subject`. Any key in `keys` verifying is success; every
/// failure mode (wrong key, wrong curve, tampered field, high-S, transplant)
/// collapses to [`SigError::NoKeyVerified`] on purpose.
///
/// This is step 4 of the spec's verification; the caller owns steps 1–3 and
/// 5–7 (claim CID, subject, resolution, expiry, status, policy).
pub fn verify_sig(
    att: &Attestation,
    repo: Repository<'_>,
    keys: &[VerifyingKey],
) -> Result<(), SigError> {
    let cid = preimage_cid(&att.body, repo)?;
    verify_cid(&cid, &att.sig.0, keys)
}

/// Verify a 64-byte compact signature over the raw bytes of `cid` against
/// any of `keys` — the primitive under both the attestation signature and
/// the status-list signature.
pub(crate) fn verify_cid(
    cid: &RecordCid,
    sig: &[u8],
    keys: &[VerifyingKey],
) -> Result<(), SigError> {
    if sig.len() != 64 {
        return Err(SigError::Malformed(format!(
            "expected 64 bytes of compact r‖s, found {}",
            sig.len()
        )));
    }
    // Low-S only: `allow_malleable = false` rejects high-S and DER forms.
    let verifier = Verifier::new(false);
    let verified = keys.iter().any(|key| {
        verifier
            .verify(key.alg.atrium(), &key.sec1, cid.as_bytes(), sig)
            .is_ok()
    });
    if verified {
        Ok(())
    } else {
        Err(SigError::NoKeyVerified)
    }
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::Did as _;

    use super::*;
    use crate::acp::record::fixtures::*;
    use crate::acp::record::{Datetime, StatusRef};

    // Deterministic keys: fixed scalars, no RNG, so the vectors are stable.
    fn k256_key(seed: u8) -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[seed; 32]).unwrap()
    }
    fn p256_key(seed: u8) -> P256Keypair {
        P256Keypair::import(&[seed; 32]).unwrap()
    }
    fn key_of<C>(kp: &impl atrium_crypto::keypair::Did<C>) -> VerifyingKey {
        VerifyingKey::from_did_key(&kp.did()).unwrap()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ── the pre-image ───────────────────────────────────────────────────────

    #[test]
    fn preimage_has_binding_and_no_sig() {
        let kit = kit();
        let pre = preimage(&body(), Repository(&kit)).unwrap();
        let stored = canonical_bytes(&body().with_sig(Sig(vec![0; 64]))).unwrap();
        assert!(pre.windows(4).any(|w| w == b"$sig"));
        assert!(
            pre.windows(SIG_BINDING_TYPE.len())
                .any(|w| w == SIG_BINDING_TYPE.as_bytes())
        );
        assert!(pre.windows(10).any(|w| w == b"repository"));
        // No top-level `sig` key: a 3-char text key would encode as 0x63 "sig".
        assert!(!pre.windows(4).any(|w| w == [0x63, b's', b'i', b'g']));
        assert_ne!(pre, stored);
        // With `sig` gone, `$sig` (4 bytes) is the shortest key, so canonical
        // order puts it first: map(7) then text(4) "$sig".
        assert_eq!(&pre[..6], &[0xa7, 0x64, b'$', b's', b'i', b'g']);
    }

    #[test]
    fn preimage_differs_per_repository() {
        let (kit, mallory) = (kit(), mallory());
        assert_ne!(
            preimage_cid(&body(), Repository(&kit)).unwrap(),
            preimage_cid(&body(), Repository(&mallory)).unwrap()
        );
    }

    #[test]
    fn pinned_preimage_vector() {
        let kit = kit();
        let pre = preimage(&body(), Repository(&kit)).unwrap();
        println!("preimage: {}", hex(&pre));
        println!(
            "preimage cid: {}",
            preimage_cid(&body(), Repository(&kit)).unwrap()
        );
        assert_eq!(hex(&pre), vectors::PREIMAGE);
        assert_eq!(
            preimage_cid(&body(), Repository(&kit)).unwrap().to_string(),
            vectors::PREIMAGE_CID
        );
    }

    /// Cross-checked 2026-08-20 against python `cbor2` 6.1.4
    /// (`canonical=True`), same inputs as `record::fixtures` plus
    /// `$sig: {$type, repository: did:plc:kit…}`.
    mod vectors {
        pub const PREIMAGE: &str = "a76424736967a2652474797065781b6e65742e676f742d706177732e6163702e73696742696e64696e676a7265706f7369746f727978216469643a706c633a6b6974313233343536373839306162636465666768696a6b6c652474797065781c6e65742e676f742d706177732e6163702e6174746573746174696f6e65636c61696da263636964783b62616679726569687569687a7175673537697761696c6369616d737666637479727a373677346266356d6a7873666c34793573656a65357a69796163757269784b61743a2f2f6469643a706c633a6b6974313233343536373839306162636465666768696a6b6c2f6e65742e676f742d706177732e6163702e636c61696d2f336b7832767035716d656b3268677375626a65637478216469643a706c633a6b6974313233343536373839306162636465666768696a6b6c686174746573746f72766469643a7765623a6174746573742e6578616d706c6568697373756564417474323032362d30382d32305431303a30303a30305a6965787069726573417474323032362d30392d31395431303a30303a30305a";
        pub const PREIMAGE_CID: &str =
            "bafyreifuyo5xviext7t574iqese6n7mfecmaxqxrhrntp2tziyd5lr236i";
    }

    // ── sign / verify, happy paths ──────────────────────────────────────────

    #[test]
    fn sign_verify_k256() {
        let kit = kit();
        let key = k256_key(1);
        let att = sign(body_full(), Repository(&kit), &key).unwrap();
        assert_eq!(att.sig.0.len(), 64);
        verify_sig(&att, Repository(&kit), &[key_of(&key)]).unwrap();
    }

    #[test]
    fn sign_verify_p256() {
        let kit = kit();
        let key = p256_key(2);
        let att = sign(body(), Repository(&kit), &key).unwrap();
        assert_eq!(key.alg(), SigAlg::Es256);
        verify_sig(&att, Repository(&kit), &[key_of(&key)]).unwrap();
    }

    #[test]
    fn verifies_against_any_of_several_keys() {
        let kit = kit();
        let (a, b) = (k256_key(3), p256_key(4));
        let att = sign(body(), Repository(&kit), &b).unwrap();
        verify_sig(&att, Repository(&kit), &[key_of(&a), key_of(&b)]).unwrap();
        assert_eq!(
            verify_sig(&att, Repository(&kit), &[]).unwrap_err(),
            SigError::NoKeyVerified
        );
    }

    #[test]
    fn signature_is_low_s() {
        use k256::ecdsa::Signature;
        let kit = kit();
        let att = sign(body(), Repository(&kit), &k256_key(5)).unwrap();
        let parsed = Signature::from_slice(&att.sig.0).unwrap();
        assert!(parsed.normalize_s().is_none(), "must already be low-S");
    }

    #[test]
    fn multikey_form_is_accepted() {
        let kit = kit();
        let key = k256_key(6);
        let att = sign(body(), Repository(&kit), &key).unwrap();
        let did_key = key.did();
        let multikey = did_key.strip_prefix("did:key:").unwrap();
        let vk = VerifyingKey::from_multikey(multikey).unwrap();
        assert_eq!(vk, key_of(&key));
        verify_sig(&att, Repository(&kit), &[vk]).unwrap();
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 6979 nonces: same body, same repo, same key → same bytes.
        let kit = kit();
        let a = sign(body(), Repository(&kit), &k256_key(7)).unwrap();
        let b = sign(body(), Repository(&kit), &k256_key(7)).unwrap();
        assert_eq!(a, b);
    }

    // ── negatives ───────────────────────────────────────────────────────────

    /// THE TRANSPLANT TEST. Identical bytes, fetched from the wrong repo.
    #[test]
    fn transplant_fails() {
        let (kit, mallory) = (kit(), mallory());
        let key = k256_key(8);
        let att = sign(body(), Repository(&kit), &key).unwrap();
        verify_sig(&att, Repository(&kit), &[key_of(&key)]).unwrap();
        // Mallory copies the record byte-for-byte into Mallory's repo.
        let copied: Attestation =
            crate::acp::record::from_canonical_bytes(&canonical_bytes(&att).unwrap()).unwrap();
        assert_eq!(copied, att, "the bytes are identical");
        assert_eq!(
            verify_sig(&copied, Repository(&mallory), &[key_of(&key)]).unwrap_err(),
            SigError::NoKeyVerified
        );
    }

    /// The binding comes from the parameter, not from `subject`.
    #[test]
    fn binding_comes_from_parameter_not_subject() {
        let (kit, mallory) = (kit(), mallory());
        let key = k256_key(9);
        let mut b = body();
        b.subject = mallory.clone(); // lies about the subject
        let att = sign(b, Repository(&kit), &key).unwrap();
        // Verifies as fetched from kit (what was signed), not from mallory.
        verify_sig(&att, Repository(&kit), &[key_of(&key)]).unwrap();
        assert_eq!(
            verify_sig(&att, Repository(&mallory), &[key_of(&key)]).unwrap_err(),
            SigError::NoKeyVerified
        );
        // (Step 2 — subject == repo owner — catches the lie; that's the caller's.)
    }

    #[test]
    fn tamper_each_field_fails() {
        let kit = kit();
        let key = k256_key(10);
        let att = sign(body_full(), Repository(&kit), &key).unwrap();
        let keys = [key_of(&key)];
        type Mutation = Box<dyn Fn(&mut Attestation)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "claim.uri",
                Box::new(|a| {
                    a.body.claim.uri = crate::acp::AtUri::parse("at://did:plc:x/c/r").unwrap()
                }),
            ),
            (
                "claim.cid",
                Box::new(|a| a.body.claim.cid.replace_range(..1, "z")),
            ),
            ("attestor", Box::new(|a| a.body.attestor = mallory())),
            ("subject", Box::new(|a| a.body.subject = mallory())),
            (
                "issuedAt",
                Box::new(|a| a.body.issued_at = Datetime::parse("2026-08-20T10:00:01Z").unwrap()),
            ),
            (
                "expiresAt",
                Box::new(|a| a.body.expires_at = Datetime::parse("2099-09-19T10:00:00Z").unwrap()),
            ),
            (
                "status.index",
                Box::new(|a| a.body.status.as_mut().unwrap().index += 1),
            ),
            (
                "status.list",
                Box::new(|a| a.body.status.as_mut().unwrap().list.push('x')),
            ),
            ("status removed", Box::new(|a| a.body.status = None)),
            (
                "status added",
                Box::new(|a| {
                    a.body.status = Some(StatusRef {
                        list: "u".into(),
                        index: 0,
                    })
                }),
            ),
            ("method", Box::new(|a| a.body.method = Some("oauth".into()))),
            ("method removed", Box::new(|a| a.body.method = None)),
            ("sig byte", Box::new(|a| a.sig.0[10] ^= 1)),
        ];
        for (name, mutate) in mutations {
            let mut t = att.clone();
            mutate(&mut t);
            assert!(
                verify_sig(&t, Repository(&kit), &keys).is_err(),
                "tampering {name} still verified"
            );
        }
        verify_sig(&att, Repository(&kit), &keys).unwrap();
    }

    #[test]
    fn wrong_key_fails() {
        let kit = kit();
        let att = sign(body(), Repository(&kit), &k256_key(11)).unwrap();
        assert_eq!(
            verify_sig(&att, Repository(&kit), &[key_of(&k256_key(12))]).unwrap_err(),
            SigError::NoKeyVerified
        );
    }

    #[test]
    fn algorithm_confusion_fails() {
        let kit = kit();
        let (k, p) = (k256_key(13), p256_key(13));
        let by_k = sign(body(), Repository(&kit), &k).unwrap();
        let by_p = sign(body(), Repository(&kit), &p).unwrap();
        assert!(verify_sig(&by_k, Repository(&kit), &[key_of(&p)]).is_err());
        assert!(verify_sig(&by_p, Repository(&kit), &[key_of(&k)]).is_err());
        // and the honest pairings still hold
        verify_sig(&by_k, Repository(&kit), &[key_of(&k)]).unwrap();
        verify_sig(&by_p, Repository(&kit), &[key_of(&p)]).unwrap();
    }

    #[test]
    fn high_s_is_rejected() {
        use k256::ecdsa::Signature;
        let kit = kit();
        let key = k256_key(14);
        let att = sign(body(), Repository(&kit), &key).unwrap();
        let low = Signature::from_slice(&att.sig.0).unwrap();
        let (r, s) = low.split_scalars();
        // n − s: the other valid signature for the same message.
        let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        assert!(
            high.normalize_s().is_some(),
            "constructed signature is high-S"
        );
        let mut forged = att.clone();
        forged.sig = Sig(high.to_bytes().to_vec());
        assert_eq!(
            verify_sig(&forged, Repository(&kit), &[key_of(&key)]).unwrap_err(),
            SigError::NoKeyVerified
        );
    }

    #[test]
    fn malformed_sig_length_is_rejected() {
        let kit = kit();
        let key = k256_key(15);
        let mut att = sign(body(), Repository(&kit), &key).unwrap();
        att.sig.0.pop();
        assert!(matches!(
            verify_sig(&att, Repository(&kit), &[key_of(&key)]).unwrap_err(),
            SigError::Malformed(_)
        ));
    }

    #[test]
    fn unsupported_key_is_rejected() {
        assert!(matches!(
            VerifyingKey::from_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            Err(SigError::UnsupportedAlgorithm(_))
        ));
        assert!(VerifyingKey::from_did_key("not a did").is_err());
    }
}
