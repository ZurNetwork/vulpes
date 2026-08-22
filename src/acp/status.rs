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
    /// How long, in seconds after `issued_at`, the attestor vouches for
    /// this version — the issuer-declared freshness bound (IETF Token
    /// Status List's `ttl`; FORKS F39, amended). Past it a copy is *not
    /// checkable*, never "not revoked". Absent means the attestor declares
    /// no bound: the newest verifiable copy stands until the attestations
    /// it covers expire — a dead attestor's last list ages out with them
    /// (the kill test). A verifier's own
    /// [`max_status_age_secs`](super::policy::TrustPolicy::max_status_age_secs)
    /// applies on top; the tighter bound wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
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
            ttl: None,
            bits: BitString::with_capacity_bits(capacity_bits),
        }
    }

    /// Declare how long this version stays evidence (see
    /// [`UnsignedStatusList::ttl`]).
    pub fn with_ttl(mut self, secs: u64) -> Self {
        self.ttl = Some(secs);
        self
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

/// The largest status-list artifact a verifier will decode: 1 MiB, room for
/// eight million attestations. A mirror cannot make a verifier allocate
/// more than this per copy.
pub const MAX_STATUS_LIST_BYTES: usize = 1 << 20;

/// The most signature verifications a verifier will spend per fetch. The
/// cheap filters (size, decode, names, horizon) run over every copy —
/// an adversary cannot amplify those — and only the newest survivors are
/// verified, so junk at the head of a mirror's reply cannot bury the
/// genuine newest copy.
pub const MAX_STATUS_COPIES: usize = 16;

/// From every copy a [`StatusSource`](super::ports::StatusSource) returned,
/// the one with the latest `issuedAt` **that verifies** against `keys`,
/// names `attestor`, and names itself `list`. Undecodable, forged, foreign,
/// differently-named, oversize, or future-dated (past `now` plus
/// [`CLOCK_SKEW_SECS`](super::verify::CLOCK_SKEW_SECS)) copies are skipped
/// — a signed copy of one list can never stand in for another, and a list
/// dated 2030 cannot outrank every genuine one until then. Survivors are
/// verified newest-first, at most [`MAX_STATUS_COPIES`] of them.
pub fn newest_verifiable(
    candidates: &[Vec<u8>],
    attestor: &Did,
    list: &str,
    keys: &[VerifyingKey],
    now: &Datetime,
) -> Option<StatusList> {
    let horizon = (now.to_unix() + super::verify::CLOCK_SKEW_SECS) as i128 * 1_000_000_000;
    let mut survivors: Vec<(StatusList, &[u8])> = candidates
        .iter()
        .filter(|bytes| bytes.len() <= MAX_STATUS_LIST_BYTES)
        .filter_map(|bytes| {
            StatusList::from_bytes(bytes)
                .map(|l| (l, bytes.as_slice()))
                .ok()
        })
        .filter(|(l, _)| &l.body.attestor == attestor && l.body.list == list)
        .filter(|(l, _)| l.body.issued_at.to_unix_nanos() <= horizon)
        .collect();
    // Newest first at full precision; identical instants tie-break on the
    // bytes, never on which mirror answered first.
    survivors.sort_by(|(a, ab), (b, bb)| {
        b.body
            .issued_at
            .to_unix_nanos()
            .cmp(&a.body.issued_at.to_unix_nanos())
            .then_with(|| bb.cmp(ab))
    });
    survivors
        .into_iter()
        .take(MAX_STATUS_COPIES)
        .map(|(l, _)| l)
        .find(|l| verify_status_list(l, keys).is_ok())
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
    const LIST: &str = "https://attest.got-paws.net/status/1";

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
        // Without a ttl the field is absent, never null — the bytes above
        // are unchanged by its existence. With one it is inside the signed
        // body, ordered after `sig` (same length, 's' < 't').
        assert!(!bytes.windows(3).any(|w| w == b"ttl"));
        let with_ttl = sign_status_list(
            list_at("2026-08-20T10:12:00Z", &[4127]).with_ttl(7 * 86_400),
            &k,
        )
        .unwrap();
        let tb = with_ttl.to_bytes().unwrap();
        let back = StatusList::from_bytes(&tb).unwrap();
        assert_eq!(back.body.ttl, Some(7 * 86_400));
        verify_status_list(&back, &[vk(&k)]).unwrap();
        let sig_pos = tb.windows(3).position(|w| w == b"sig").unwrap();
        let ttl_pos = tb.windows(3).position(|w| w == b"ttl").unwrap();
        let bits_pos = tb.windows(4).position(|w| w == b"bits").unwrap();
        assert!(sig_pos < ttl_pos && ttl_pos < bits_pos);
        // And it is signed: changing it breaks the signature.
        let mut forged = back.clone();
        forged.body.ttl = Some(365 * 86_400);
        assert!(verify_status_list(&forged, &[vk(&k)]).is_err());
    }

    fn now() -> Datetime {
        Datetime::parse("2026-08-29T10:00:00Z").unwrap()
    }

    #[test]
    fn sub_second_ordering_is_real() {
        // A clear list at .100 and a revoking one at .900 in the same
        // second: the revoking one is newer and must win, whichever order
        // the mirrors answer in and whatever its bytes sort like.
        let k = key(28);
        let clear = sign_status_list(list_at("2026-08-20T00:00:00.100Z", &[]), &k).unwrap();
        let revoking = sign_status_list(list_at("2026-08-20T00:00:00.900Z", &[4127]), &k).unwrap();
        let (ab, ba) = (
            [clear.to_bytes().unwrap(), revoking.to_bytes().unwrap()],
            [revoking.to_bytes().unwrap(), clear.to_bytes().unwrap()],
        );
        let keys = [vk(&k)];
        let w1 = newest_verifiable(&ab, &attestor(), LIST, &keys, &now()).unwrap();
        let w2 = newest_verifiable(&ba, &attestor(), LIST, &keys, &now()).unwrap();
        assert_eq!(w1, revoking);
        assert_eq!(w2, revoking);
        // Identical instants, different content: deterministic on bytes.
        let a = sign_status_list(list_at("2026-08-20T00:00:00Z", &[1]), &k).unwrap();
        let b = sign_status_list(list_at("2026-08-20T00:00:00Z", &[2]), &k).unwrap();
        let (ab, ba) = (
            [a.to_bytes().unwrap(), b.to_bytes().unwrap()],
            [b.to_bytes().unwrap(), a.to_bytes().unwrap()],
        );
        assert_eq!(
            newest_verifiable(&ab, &attestor(), LIST, &keys, &now()),
            newest_verifiable(&ba, &attestor(), LIST, &keys, &now())
        );
    }

    #[test]
    fn future_dated_list_does_not_outrank_the_present() {
        // A clear list dated 2030 (a compromised key, say) would otherwise
        // pin "not revoked" until 2030. It is skipped; the genuine revoking
        // list wins. Inside the skew window is still fine.
        let k = key(29);
        let revoking = sign_status_list(list_at("2026-08-29T09:00:00Z", &[4127]), &k).unwrap();
        let future = sign_status_list(list_at("2030-01-01T00:00:00Z", &[]), &k).unwrap();
        let skewed = sign_status_list(list_at("2026-08-29T10:04:00Z", &[4127, 1]), &k).unwrap();
        let keys = [vk(&k)];
        let copies = [future.to_bytes().unwrap(), revoking.to_bytes().unwrap()];
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap(),
            revoking
        );
        let copies = [future.to_bytes().unwrap()];
        assert!(newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).is_none());
        let copies = [revoking.to_bytes().unwrap(), skewed.to_bytes().unwrap()];
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap(),
            skewed
        );
    }

    #[test]
    fn oversize_and_excess_copies_are_ignored() {
        let k = key(30);
        let keys = [vk(&k)];
        let good = sign_status_list(list_at("2026-08-20T00:00:00Z", &[]), &k).unwrap();
        // A multi-megabyte blob is never decoded, however well it is signed.
        let huge = sign_status_list(
            {
                let mut l = UnsignedStatusList::new(
                    attestor(),
                    LIST,
                    Datetime::parse("2026-08-21T00:00:00Z").unwrap(),
                    (MAX_STATUS_LIST_BYTES as u64 + 1) * 8,
                );
                l.bits.set(4127);
                l
            },
            &k,
        )
        .unwrap();
        let huge_bytes = huge.to_bytes().unwrap();
        assert!(huge_bytes.len() > MAX_STATUS_LIST_BYTES);
        let copies = [huge_bytes.clone(), good.to_bytes().unwrap()];
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap(),
            good
        );
        assert!(newest_verifiable(&[huge_bytes], &attestor(), LIST, &keys, &now()).is_none());
        // The bound is on verifications, not arrival order: a mirror that
        // fronts sixteen stale clear copies cannot bury the newer revoking
        // one behind them.
        let newest = sign_status_list(list_at("2026-08-22T00:00:00Z", &[4127]), &k).unwrap();
        let mut copies = vec![good.to_bytes().unwrap(); MAX_STATUS_COPIES];
        copies.push(newest.to_bytes().unwrap());
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap(),
            newest
        );
        // Nor can sixteen forged "newer" copies starve a genuine one: they
        // fail the cheap filters or burn verifications, but the sixteenth
        // slot still reaches a genuine copy only if it ranks within the cap —
        // so forgeries must be newer *and* decode *and* name the list to
        // cost anything, and even then the cap is on work, not on truth.
        let forger = key(31);
        let forged = sign_status_list(list_at("2026-08-23T00:00:00Z", &[]), &forger).unwrap();
        let mut copies = vec![forged.to_bytes().unwrap(); MAX_STATUS_COPIES - 1];
        copies.push(newest.to_bytes().unwrap());
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap(),
            newest
        );
    }

    #[test]
    fn a_list_cannot_stand_in_for_another() {
        // The attestor runs two lists. A copy of list B — validly signed, same
        // attestor, newer — served where list A is expected, is not list A.
        let k = key(27);
        let a = sign_status_list(list_at("2026-08-20T00:00:00Z", &[4127]), &k).unwrap();
        let mut b_body = list_at("2026-08-21T00:00:00Z", &[]);
        b_body.list = "https://attest.got-paws.net/status/2".into();
        let b = sign_status_list(b_body, &k).unwrap();
        let copies = [b.to_bytes().unwrap()];
        assert!(newest_verifiable(&copies, &attestor(), LIST, &[vk(&k)], &now()).is_none());
        let copies = [a.to_bytes().unwrap(), b.to_bytes().unwrap()];
        let w = newest_verifiable(&copies, &attestor(), LIST, &[vk(&k)], &now()).unwrap();
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
        let winner = newest_verifiable(&copies, &attestor(), LIST, &keys, &now()).unwrap();
        assert_eq!(winner, new);
        assert_eq!(winner.is_set(4127), Some(true));
        assert!(newest_verifiable(&[], &attestor(), LIST, &keys, &now()).is_none());
        // Keys decide: under the forger's key, the forger's copy is the one that verifies.
        assert_eq!(
            newest_verifiable(&copies, &attestor(), LIST, &[vk(&forger)], &now()).unwrap(),
            forged
        );
    }
}
