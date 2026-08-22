//! The status-list artifact — `net.got-paws.acp.statusList`.
//!
//! Revocation in ACP is a **signed, static, mirrorable file**, never a live
//! endpoint only the attestor can answer. The semantics are the IETF Token
//! Status List's: one bit per issued attestation, selected by
//! `status.index`; set means revoked. The envelope is ACP-native (FORKS
//! F39): canonical DAG-CBOR, signed CID-first with the same primitive as
//! attestations, so there is exactly one signature path to review and no new
//! dependency in the pure lane. The JWT/CWT envelope is a private-lane
//! concern.
//!
//! There is **no `$sig` repository binding** here: a status list is not a
//! repo record, so there is no repository to bind to. Its domain separation
//! from an attestation pre-image is the `$type` inside the signed bytes.
//! What the signed bytes *do* carry is the list's own identifier, `list`:
//! without it any validly-signed list of an attestor's would satisfy any
//! `status.list` pointer — the status-list analogue of the transplant the
//! `$sig` binding closes for attestations (FORKS F39, amended).
//!
//! "Newest verifiable copy wins": a verifier gathers every copy it can reach
//! and keeps the one with the latest `issuedAt` **whose signature verifies**.
//! A forged copy with a future timestamp fails its signature and is ignored;
//! a stale mirror simply loses to a fresher one. See [`newest_verifiable`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Did;

use super::error::{SigError, SignError};
use super::record::{
    Datetime, RecordCid, STATUS_LIST_TYPE, Sig, canonical_bytes, from_canonical_bytes, type_marker,
};
use super::sign::{Signer, VerifyingKey, verify_cid};

type_marker!(
    /// The `$type` of a [`StatusList`]: serializes as [`STATUS_LIST_TYPE`].
    StatusListType = STATUS_LIST_TYPE
);

/// A packed bitstring, LSB-first within each byte (bit `i` is byte `i / 8`,
/// mask `1 << (i % 8)`). A CBOR byte string on the wire.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct BitString(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl BitString {
    /// A bitstring with room for `bits` entries, all clear.
    pub fn with_capacity_bits(bits: u64) -> Self {
        Self(vec![0; bits.div_ceil(8) as usize])
    }

    /// Number of addressable bits.
    pub fn len(&self) -> u64 {
        self.0.len() as u64 * 8
    }

    /// No addressable bits at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `Some(bit)` or `None` if `index` is beyond the string.
    pub fn get(&self, index: u64) -> Option<bool> {
        let byte = self.0.get(usize::try_from(index / 8).ok()?)?;
        Some(byte & (1 << (index % 8)) != 0)
    }

    /// Set bit `index`; `false` if it is beyond the string.
    pub fn set(&mut self, index: u64) -> bool {
        match usize::try_from(index / 8)
            .ok()
            .and_then(|i| self.0.get_mut(i))
        {
            Some(byte) => {
                *byte |= 1 << (index % 8);
                true
            }
            None => false,
        }
    }
}

impl fmt::Debug for BitString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitString({} bits)", self.len())
    }
}

/// Everything in a status list but its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedStatusList {
    /// Always [`STATUS_LIST_TYPE`].
    #[serde(rename = "$type")]
    pub type_: StatusListType,
    /// The attestor whose attestations this list covers; its DID document
    /// holds the key that signs it.
    pub attestor: Did,
    /// This list's identifier. Every attestation it covers carries the same
    /// string in `status.list`; a verifier matches the two exactly. An
    /// identifier, not necessarily a fetch location — mirrors may serve the
    /// artifact from anywhere.
    pub list: String,
    /// When this version was published. Newest verifiable wins.
    pub issued_at: Datetime,
    /// One bit per attestation; set = revoked.
    pub bits: BitString,
}

impl UnsignedStatusList {
    /// An all-clear list named `list`, with room for `capacity_bits`
    /// attestations.
    pub fn new(
        attestor: Did,
        list: impl Into<String>,
        issued_at: Datetime,
        capacity_bits: u64,
    ) -> Self {
        Self {
            type_: StatusListType,
            attestor,
            list: list.into(),
            issued_at,
            bits: BitString::with_capacity_bits(capacity_bits),
        }
    }

    /// The CID the attestor signs.
    pub fn cid(&self) -> Result<RecordCid, super::error::CodecError> {
        Ok(RecordCid::of(&canonical_bytes(self)?))
    }
}

/// A signed status list — the artifact that gets mirrored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusList {
    /// The signed content.
    #[serde(flatten)]
    pub body: UnsignedStatusList,
    /// Signature over [`UnsignedStatusList::cid`].
    pub sig: Sig,
}

impl StatusList {
    /// Whether attestation `index` is revoked; `None` if the list does not
    /// cover that index (the verifier treats that as not checkable, never as
    /// "not revoked").
    pub fn is_set(&self, index: u64) -> Option<bool> {
        self.body.bits.get(index)
    }

    /// The artifact bytes to publish and mirror.
    pub fn to_bytes(&self) -> Result<Vec<u8>, super::error::CodecError> {
        canonical_bytes(self)
    }

    /// Parse an artifact. Does **not** verify — see [`verify_status_list`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::error::CodecError> {
        from_canonical_bytes(bytes)
    }
}

/// Sign a status list with a key published in the attestor's DID document.
pub fn sign_status_list(
    body: UnsignedStatusList,
    key: &impl Signer,
) -> Result<StatusList, SignError> {
    let cid = body.cid()?;
    let sig = key.sign_bytes(cid.as_bytes())?;
    Ok(StatusList {
        body,
        sig: Sig(sig),
    })
}

/// Verify a status list's signature against the attestor's current keys.
pub fn verify_status_list(list: &StatusList, keys: &[VerifyingKey]) -> Result<(), SigError> {
    let cid = list.body.cid()?;
    verify_cid(&cid, &list.sig.0, keys)
}

/// From every copy a [`StatusSource`](super::ports::StatusSource) returned,
/// the one with the latest `issuedAt` **that verifies** against `keys`,
/// names `attestor`, and names itself `list`. Undecodable, forged, foreign,
/// or differently-named copies are skipped — a signed copy of one list can
/// never stand in for another.
pub fn newest_verifiable(
    candidates: &[Vec<u8>],
    attestor: &Did,
    list: &str,
    keys: &[VerifyingKey],
) -> Option<StatusList> {
    candidates
        .iter()
        .filter_map(|bytes| StatusList::from_bytes(bytes).map(|l| (l, bytes)).ok())
        .filter(|(l, _)| &l.body.attestor == attestor && l.body.list == list)
        .filter(|(l, _)| verify_status_list(l, keys).is_ok())
        // `to_unix` truncates sub-seconds, so two copies can tie; the tie
        // breaks on the bytes, never on which mirror answered first.
        .max_by_key(|(l, bytes)| (l.body.issued_at.to_unix(), bytes.to_vec()))
        .map(|(l, _)| l)
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};

    use super::*;
    use crate::acp::record::fixtures::{attestor, mallory};

    fn key(seed: u8) -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[seed; 32]).unwrap()
    }
    fn vk(k: &Secp256k1Keypair) -> VerifyingKey {
        VerifyingKey::from_did_key(&k.did()).unwrap()
    }
    const LIST: &str = "https://attest.example/status/1";

    fn list_at(ts: &str, set: &[u64]) -> UnsignedStatusList {
        let mut l = UnsignedStatusList::new(attestor(), LIST, Datetime::parse(ts).unwrap(), 8192);
        for i in set {
            assert!(l.bits.set(*i));
        }
        l
    }

    #[test]
    fn bitstring_addressing_is_lsb_first() {
        let mut b = BitString::with_capacity_bits(12);
        assert_eq!(b.0.len(), 2);
        assert!(b.set(0) && b.set(9));
        assert_eq!(b.0, vec![0b0000_0001, 0b0000_0010]);
        assert_eq!(b.get(0), Some(true));
        assert_eq!(b.get(1), Some(false));
        assert_eq!(b.get(9), Some(true));
        assert_eq!(b.get(16), None);
        assert!(!b.set(16));
        assert_eq!(BitString::default().get(0), None);
    }

    #[test]
    fn sign_verify_round_trip_through_bytes() {
        let k = key(21);
        let signed = sign_status_list(list_at("2026-08-20T10:12:00Z", &[4127]), &k).unwrap();
        let bytes = signed.to_bytes().unwrap();
        let back = StatusList::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
        verify_status_list(&back, &[vk(&k)]).unwrap();
        assert_eq!(back.is_set(4127), Some(true));
        assert_eq!(back.is_set(4126), Some(false));
        assert_eq!(back.is_set(1 << 20), None);
        // bits is a CBOR byte string: "bits" then 0x59 0x04 0x00 (1024 bytes).
        let pos = bytes.windows(4).position(|w| w == b"bits").unwrap();
        assert_eq!(&bytes[pos + 4..pos + 7], &[0x59, 0x04, 0x00]);
        // Canonical key order: sig(3) < bits(4) < list(4) < $type(5) <
        // attestor(8) < issuedAt(8). `list` is inside the signed body.
        let mut last = 0;
        for k in ["sig", "bits", "list", "$type", "attestor", "issuedAt"] {
            let p = bytes
                .windows(k.len())
                .position(|w| w == k.as_bytes())
                .unwrap();
            assert!(p > last, "{k} out of order");
            last = p;
        }
        let body_bytes = canonical_bytes(&signed.body).unwrap();
        assert!(body_bytes.windows(LIST.len()).any(|w| w == LIST.as_bytes()));
    }

    #[test]
    fn same_second_copies_pick_deterministically() {
        let k = key(28);
        let a = sign_status_list(list_at("2026-08-20T00:00:00.100Z", &[1]), &k).unwrap();
        let b = sign_status_list(list_at("2026-08-20T00:00:00.900Z", &[2]), &k).unwrap();
        let (ab, ba) = (
            [a.to_bytes().unwrap(), b.to_bytes().unwrap()],
            [b.to_bytes().unwrap(), a.to_bytes().unwrap()],
        );
        let keys = [vk(&k)];
        assert_eq!(
            newest_verifiable(&ab, &attestor(), LIST, &keys),
            newest_verifiable(&ba, &attestor(), LIST, &keys)
        );
    }

    #[test]
    fn a_list_cannot_stand_in_for_another() {
        // The attestor runs two lists. A copy of list B — validly signed, same
        // attestor, newer — served where list A is expected, is not list A.
        let k = key(27);
        let a = sign_status_list(list_at("2026-08-20T00:00:00Z", &[4127]), &k).unwrap();
        let mut b_body = list_at("2026-08-21T00:00:00Z", &[]);
        b_body.list = "https://attest.example/status/2".into();
        let b = sign_status_list(b_body, &k).unwrap();
        let copies = [b.to_bytes().unwrap()];
        assert!(newest_verifiable(&copies, &attestor(), LIST, &[vk(&k)]).is_none());
        let copies = [a.to_bytes().unwrap(), b.to_bytes().unwrap()];
        let w = newest_verifiable(&copies, &attestor(), LIST, &[vk(&k)]).unwrap();
        assert_eq!(w, a);
        assert_eq!(w.is_set(4127), Some(true));
    }

    #[test]
    fn flipping_a_bit_after_signing_fails() {
        let k = key(22);
        let mut signed = sign_status_list(list_at("2026-08-20T10:12:00Z", &[]), &k).unwrap();
        verify_status_list(&signed, &[vk(&k)]).unwrap();
        signed.body.bits.set(4127);
        assert_eq!(
            verify_status_list(&signed, &[vk(&k)]).unwrap_err(),
            SigError::NoKeyVerified
        );
    }

    #[test]
    fn wrong_key_and_wrong_type_fail() {
        let (k, other) = (key(23), key(24));
        let signed = sign_status_list(list_at("2026-08-20T10:12:00Z", &[]), &k).unwrap();
        assert!(verify_status_list(&signed, &[vk(&other)]).is_err());
        // An attestation pre-image signed by the same key is not a status list.
        let mut bytes = signed.to_bytes().unwrap();
        let pos = bytes.windows(10).position(|w| w == b"statusList").unwrap();
        bytes[pos] = b'S';
        assert!(StatusList::from_bytes(&bytes).is_err());
    }

    #[test]
    fn newest_verifiable_wins_and_forgeries_lose() {
        let (k, forger) = (key(25), key(26));
        let keys = [vk(&k)];
        let old = sign_status_list(list_at("2026-08-19T00:00:00Z", &[]), &k).unwrap();
        let new = sign_status_list(list_at("2026-08-20T00:00:00Z", &[4127]), &k).unwrap();
        // Newer still, but signed by someone else; and a future-dated copy
        // whose bytes were tampered after signing.
        let forged = sign_status_list(list_at("2026-08-21T00:00:00Z", &[]), &forger).unwrap();
        let mut tampered = sign_status_list(list_at("2026-08-22T00:00:00Z", &[]), &k).unwrap();
        tampered.body.bits.set(1);
        // And a copy for another attestor, validly signed by `k`.
        let mut foreign_body = list_at("2026-08-23T00:00:00Z", &[]);
        foreign_body.attestor = mallory();
        let foreign = sign_status_list(foreign_body, &k).unwrap();

        let copies: Vec<Vec<u8>> = [&forged, &old, &tampered, &new, &foreign]
            .iter()
            .map(|l| l.to_bytes().unwrap())
            .chain(std::iter::once(b"garbage".to_vec()))
            .collect();
        let winner = newest_verifiable(&copies, &attestor(), LIST, &keys).unwrap();
        assert_eq!(winner, new);
        assert_eq!(winner.is_set(4127), Some(true));
        assert!(newest_verifiable(&[], &attestor(), LIST, &keys).is_none());
        // Keys decide: under the forger's key, the forger's copy is the one that verifies.
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &[vk(&forger)]).unwrap(),
            forged
        );
    }
}
