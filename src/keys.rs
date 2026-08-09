//! The private keys behind a minted `did:plc` — [`CustodyKeys`], their roles,
//! and their sealed on-disk form.
//!
//! Minting an identity generates a small set of **secp256k1** keypairs and keeps
//! the private halves, so the identity can be operated later: signing the
//! genesis operation now and, afterwards, handle updates, rotations and the
//! tombstone. These are the most sensitive bytes zurid touches, so they are
//! held **envelope-encrypted at rest** behind the [`KeyStore`](crate::KeyStore)
//! port and [`Zeroize`]d on drop in memory.
//!
//! Roles are named rather than positional because the order of a DID's
//! `rotationKeys` is **load-bearing** — they are listed in descending authority,
//! and recovery works by a higher-authority key overriding a lower one within
//! the directory's recovery window. Which role sits where is
//! [policy](crate::MintPolicy), not a hard-coded fact.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Did, SecretVault, VaultError};

/// The byte length of a secp256k1 private scalar.
pub const SECRET_KEY_LEN: usize = 32;

/// One secp256k1 private key, held as its raw 32-byte big-endian scalar (the
/// form `atrium_crypto`'s keypair `export`/`import` round-trips).
///
/// Zeroized on drop; its [`Debug`] is redacted so key material can never reach a
/// log line; and its [`PartialEq`] is **constant-time** (see the impl).
///
/// ```
/// # use zurid::SecretKey;
/// let key = SecretKey::new(vec![0xAB; 32]);
/// assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Vec<u8>);

/// Constant-time, on purpose.
///
/// The derived `PartialEq` compares `Vec<u8>` byte by byte and **returns at the
/// first difference**, so how long a comparison takes says how many leading
/// bytes of the key the other operand got right. Anywhere an attacker can
/// propose a key and time the answer, that turns a 2²⁵⁶ search into a
/// byte-at-a-time one. `subtle`'s `ct_eq` looks at every byte regardless.
///
/// Length is compared first and in the clear: a private scalar's length is
/// public (32 bytes), so it is not a secret to leak.
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    /// Wrap raw private-key bytes. No validation: the bytes come from a trusted
    /// place — a freshly generated keypair's `export`, or a decrypted
    /// [`KeyStore`](crate::KeyStore) record.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw private-key bytes, to hand to a crypto backend for signing or to
    /// a [`SecretVault`] for sealing. Treat as secret: never log, never persist
    /// unencrypted.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Redacted on purpose: printing key material — even in a debug log or a panic
/// message — would defeat the custody model. Shows only that a key is present.
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Which job a custodied key does. Referenced by [`MintPolicy`](crate::MintPolicy)
/// to say which keys become `rotationKeys` (and in what order), which one signs,
/// and which back the verification methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyRole {
    /// The highest-authority key, kept coldest — reserved for recovery and
    /// deliberately off the routine signing path.
    ColdRecovery,
    /// The day-to-day key that signs operations.
    Operational,
    /// The key behind a verification method (atproto's `#atproto` signing key);
    /// used to sign *records*, not operations.
    Signing,
}

impl KeyRole {
    /// Every role, in the order [`CustodyKeys`] stores them. The sealed bundle
    /// is this order concatenated, so it is part of the on-disk format.
    pub const ALL: [KeyRole; 3] = [
        KeyRole::ColdRecovery,
        KeyRole::Operational,
        KeyRole::Signing,
    ];
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            KeyRole::ColdRecovery => "cold-recovery",
            KeyRole::Operational => "operational",
            KeyRole::Signing => "signing",
        };
        f.write_str(name)
    }
}

/// Which envelope scheme a custody blob was sealed under.
///
/// Stored alongside every blob (the `key_version` column), so the bytes are
/// never opened by guesswork: a reader asks the row which scheme it is and gets
/// a value it can exhaustively match, or an error. That is what makes changing
/// the scheme possible at all — without it, "which AAD does this blob use?" has
/// no answer and every change is a flag day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CustodyEnvelope {
    /// Associated data is the **bare DID bytes**. Read-only: still opened for
    /// rows written before [`V2`](CustodyEnvelope::V2), never written.
    V1,
    /// Associated data is [`CUSTODY_AAD_TAG`] followed by the DID bytes.
    ///
    /// The tag is domain separation. One [`SecretVault`] seals every family of
    /// secret zurid holds, and V1's associated data was a bare DID — the same
    /// bytes another family could plausibly use for its own row key. Two
    /// families sharing an associated-data value means a blob from one opens as
    /// the other, and "which family is this blob?" is then answered by whichever
    /// code path happened to read it. A per-family tag makes the collision
    /// unrepresentable rather than merely unlikely — the same reason
    /// [`JacquardAuthStore`](crate::oauth::JacquardAuthStore) prefixes its own.
    V2,
}

/// The domain-separation tag [`CustodyEnvelope::V2`] prefixes its associated
/// data with. NUL-terminated, so the tag can never run into the DID that
/// follows it.
pub const CUSTODY_AAD_TAG: &[u8] = b"zurid.custody\0";

/// A `key_version` naming no envelope scheme this build knows.
///
/// Almost always a row written by a **newer** zurid than the one reading it —
/// a rolling deploy, or a rollback. Refused loudly rather than opened under a
/// guessed scheme, because the wrong guess is either a tag failure (best case)
/// or plaintext read as key material (worst).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("custody key_version {0} is not an envelope scheme this build of zurid knows")]
pub struct UnknownCustodyEnvelope(pub i32);

impl CustodyEnvelope {
    /// The scheme new custody is sealed under. Reads still accept every
    /// variant — that is how a V1 row keeps opening — but only this one is ever
    /// written.
    pub const CURRENT: Self = Self::V2;

    /// The AEAD associated data this scheme binds a blob to its DID with.
    fn aad(self, did: &Did) -> Vec<u8> {
        let did = did.as_str().as_bytes();
        match self {
            Self::V1 => did.to_vec(),
            Self::V2 => {
                let mut aad = Vec::with_capacity(CUSTODY_AAD_TAG.len() + did.len());
                aad.extend_from_slice(CUSTODY_AAD_TAG);
                aad.extend_from_slice(did);
                aad
            }
        }
    }
}

impl From<CustodyEnvelope> for i32 {
    fn from(envelope: CustodyEnvelope) -> Self {
        match envelope {
            CustodyEnvelope::V1 => 1,
            CustodyEnvelope::V2 => 2,
        }
    }
}

impl TryFrom<i32> for CustodyEnvelope {
    type Error = UnknownCustodyEnvelope;

    fn try_from(version: i32) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            other => Err(UnknownCustodyEnvelope(other)),
        }
    }
}

/// The full set of secp256k1 private keys held for one minted `did:plc`, named
/// by role.
///
/// Fixed arity on purpose: the sealed bundle is the three scalars concatenated
/// in [`KeyRole::ALL`] order, so it is a stable on-disk format that does not
/// carry a schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyKeys {
    /// Reserved for recovery; highest authority, coldest.
    pub cold_recovery: SecretKey,
    /// The day-to-day signer of operations.
    pub operational: SecretKey,
    /// Backs the `atproto` verification method.
    pub signing: SecretKey,
}

impl CustodyKeys {
    /// The key playing `role`.
    pub fn role(&self, role: KeyRole) -> &SecretKey {
        match role {
            KeyRole::ColdRecovery => &self.cold_recovery,
            KeyRole::Operational => &self.operational,
            KeyRole::Signing => &self.signing,
        }
    }

    /// Seal this bundle under `vault`, binding it to `did` as associated data,
    /// using [`CustodyEnvelope::CURRENT`].
    ///
    /// The DID is bound in as AEAD `aad`, so a sealed bundle is
    /// cryptographically tied to its row: an attacker with database write
    /// access cannot move one identity's custody blob onto another DID — the
    /// tag check fails on [`open`](CustodyKeys::open) under the moved-to DID.
    ///
    /// **Record [`CustodyEnvelope::CURRENT`] beside the blob** (the
    /// `key_version` column), and pass it back to `open`. Writes are pinned to
    /// the current scheme deliberately; there is no way to ask for an older one.
    pub fn seal(&self, vault: &SecretVault, did: &Did) -> Result<Vec<u8>, VaultError> {
        // `Zeroizing` wipes the concatenated plaintext bundle on drop, so raw
        // key bytes do not linger in the heap after sealing.
        let mut plaintext =
            zeroize::Zeroizing::new(Vec::with_capacity(KeyRole::ALL.len() * SECRET_KEY_LEN));
        for role in KeyRole::ALL {
            let bytes = self.role(role).expose();
            if bytes.len() != SECRET_KEY_LEN {
                return Err(VaultError::PlaintextLength {
                    expected: SECRET_KEY_LEN,
                    actual: bytes.len(),
                });
            }
            plaintext.extend_from_slice(bytes);
        }
        vault.seal(&CustodyEnvelope::CURRENT.aad(did), &plaintext)
    }

    /// Open a blob produced by [`seal`](CustodyKeys::seal). `did` must be the
    /// DID it was sealed under, and `envelope` the scheme recorded beside the
    /// blob — not a guess, and not an assumption that it is
    /// [`CURRENT`](CustodyEnvelope::CURRENT).
    pub fn open(
        vault: &SecretVault,
        did: &Did,
        blob: &[u8],
        envelope: CustodyEnvelope,
    ) -> Result<Self, VaultError> {
        let plaintext = vault.open(&envelope.aad(did), blob)?;
        let expected = KeyRole::ALL.len() * SECRET_KEY_LEN;
        if plaintext.len() != expected {
            return Err(VaultError::PlaintextLength {
                expected,
                actual: plaintext.len(),
            });
        }
        let scalar = |index: usize| {
            let start = index * SECRET_KEY_LEN;
            SecretKey::new(plaintext[start..start + SECRET_KEY_LEN].to_vec())
        };
        Ok(Self {
            cold_recovery: scalar(0),
            operational: scalar(1),
            signing: scalar(2),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> CustodyKeys {
        CustodyKeys {
            cold_recovery: SecretKey::new(vec![0xAA; SECRET_KEY_LEN]),
            operational: SecretKey::new(vec![0xBB; SECRET_KEY_LEN]),
            signing: SecretKey::new(vec![0xCC; SECRET_KEY_LEN]),
        }
    }

    fn vault() -> SecretVault {
        SecretVault::from_bytes(&[7u8; 32]).unwrap()
    }

    fn did() -> Did {
        Did::new("did:plc:alice")
    }

    // A SecretKey's Debug must never reveal its bytes — a debug log or panic
    // message carrying key material would defeat the custody model.
    #[test]
    fn secret_key_debug_is_redacted() {
        let key = SecretKey::new(vec![0xAB; SECRET_KEY_LEN]);
        let shown = format!("{key:?}");
        assert_eq!(shown, "SecretKey(<redacted>)");
        assert!(!shown.contains("ab") && !shown.contains("171"));
    }

    // CustodyKeys derives Debug, but every field is a redacted SecretKey — so
    // the whole bundle is safe to print.
    #[test]
    fn custody_keys_debug_redacts_every_field() {
        let shown = format!("{:?}", keys());
        assert_eq!(shown.matches("<redacted>").count(), 3);
        assert!(!shown.contains("[170, 170"));
    }

    // Equality still means equality — the constant-time comparison must agree
    // with the obvious one on every case that matters, including a difference
    // in the LAST byte (which a short-circuiting compare would reach late) and
    // one in the FIRST (which it would reach immediately).
    #[test]
    fn secret_key_equality_is_exact() {
        let key = SecretKey::new(vec![0xAB; SECRET_KEY_LEN]);
        assert_eq!(key, SecretKey::new(vec![0xAB; SECRET_KEY_LEN]));

        let mut last_differs = vec![0xAB; SECRET_KEY_LEN];
        last_differs[SECRET_KEY_LEN - 1] = 0xAC;
        assert_ne!(key, SecretKey::new(last_differs));

        let mut first_differs = vec![0xAB; SECRET_KEY_LEN];
        first_differs[0] = 0xAC;
        assert_ne!(key, SecretKey::new(first_differs));

        // A length mismatch is not equality either. Lengths are public (a
        // scalar is 32 bytes), so comparing them in the clear leaks nothing.
        assert_ne!(key, SecretKey::new(vec![0xAB; SECRET_KEY_LEN - 1]));
        assert_ne!(key, SecretKey::new(Vec::new()));
    }

    // The `key_version` column is a round trip, and an unknown value is an
    // explicit error rather than a fall-through to the current scheme. A row
    // written by a newer zurid — met during a rolling deploy or after a
    // rollback — must be refused, never opened under a guessed scheme.
    #[test]
    fn a_custody_envelope_round_trips_and_rejects_the_unknown() {
        assert_eq!(
            CustodyEnvelope::try_from(i32::from(CustodyEnvelope::CURRENT)),
            Ok(CustodyEnvelope::CURRENT)
        );
        assert_eq!(CustodyEnvelope::try_from(1), Ok(CustodyEnvelope::V1));
        assert_eq!(CustodyEnvelope::try_from(2), Ok(CustodyEnvelope::V2));

        for unknown in [0, -1, 99, i32::MAX] {
            assert_eq!(
                CustodyEnvelope::try_from(unknown),
                Err(UnknownCustodyEnvelope(unknown)),
                "key_version {unknown} names no scheme and must be refused"
            );
        }
    }

    // New custody is sealed under V2, whose associated data carries the
    // domain-separation tag. Asserted on the AAD itself, because that is the
    // property — a blob from another family sealed under a bare DID cannot be
    // mistaken for custody.
    #[test]
    fn the_current_envelope_is_domain_separated() {
        assert_eq!(CustodyEnvelope::CURRENT, CustodyEnvelope::V2);

        let v2 = CustodyEnvelope::V2.aad(&did());
        assert!(
            v2.starts_with(CUSTODY_AAD_TAG),
            "V2 associated data must carry the custody tag"
        );
        assert_eq!(&v2[CUSTODY_AAD_TAG.len()..], did().as_str().as_bytes());

        // V1 is the bare DID — exactly the collision V2 exists to remove.
        assert_eq!(CustodyEnvelope::V1.aad(&did()), did().as_str().as_bytes());
        assert_ne!(CustodyEnvelope::V1.aad(&did()), v2);
    }

    // Back-compat, and the reason the version column is read. A bundle sealed
    // under V1 — every custody row written before this change — still opens
    // when the row says V1, and does NOT open when read as V2.
    #[test]
    fn a_v1_bundle_still_opens_under_v1_and_not_under_v2() {
        // Seal a V1 blob the way the old code did: bare-DID associated data.
        let mut plaintext = Vec::new();
        for role in KeyRole::ALL {
            plaintext.extend_from_slice(keys().role(role).expose());
        }
        let legacy = vault().seal(did().as_str().as_bytes(), &plaintext).unwrap();

        assert_eq!(
            CustodyKeys::open(&vault(), &did(), &legacy, CustodyEnvelope::V1).unwrap(),
            keys(),
            "a pre-existing V1 row must keep opening"
        );
        assert!(
            matches!(
                CustodyKeys::open(&vault(), &did(), &legacy, CustodyEnvelope::V2),
                Err(VaultError::Open)
            ),
            "the schemes are genuinely different associated data, not a relabel"
        );
    }

    // And the mirror: a freshly sealed bundle opens under V2 and not under V1,
    // so a row mislabelled as legacy fails closed rather than opening.
    #[test]
    fn a_current_bundle_does_not_open_under_v1() {
        let blob = keys().seal(&vault(), &did()).unwrap();
        assert!(matches!(
            CustodyKeys::open(&vault(), &did(), &blob, CustodyEnvelope::V1),
            Err(VaultError::Open)
        ));
    }

    #[test]
    fn role_lookup_matches_the_named_fields() {
        let keys = keys();
        assert_eq!(keys.role(KeyRole::ColdRecovery), &keys.cold_recovery);
        assert_eq!(keys.role(KeyRole::Operational), &keys.operational);
        assert_eq!(keys.role(KeyRole::Signing), &keys.signing);
    }

    #[test]
    fn seal_open_round_trips() {
        let blob = keys().seal(&vault(), &did()).unwrap();
        assert_eq!(
            CustodyKeys::open(&vault(), &did(), &blob, CustodyEnvelope::CURRENT).unwrap(),
            keys()
        );
    }

    // The sealed blob must NOT contain the plaintext key bytes.
    #[test]
    fn sealed_bundle_is_not_plaintext() {
        let blob = keys().seal(&vault(), &did()).unwrap();
        for byte in [0xAAu8, 0xBB, 0xCC] {
            let run = vec![byte; SECRET_KEY_LEN];
            assert!(
                !blob.windows(SECRET_KEY_LEN).any(|w| w == run.as_slice()),
                "plaintext key bytes ({byte:#x}) leaked into the sealed blob"
            );
        }
    }

    // The DID is bound as AEAD associated data: a bundle sealed for one DID
    // cannot be opened under another, so custody rows cannot be swapped.
    #[test]
    fn bundle_cannot_be_opened_under_a_different_did() {
        let blob = keys().seal(&vault(), &did()).unwrap();
        let other = Did::new("did:plc:mallory");
        assert!(matches!(
            CustodyKeys::open(&vault(), &other, &blob, CustodyEnvelope::CURRENT),
            Err(VaultError::Open)
        ));
    }

    #[test]
    fn a_wrong_length_scalar_is_refused_before_sealing() {
        let malformed = CustodyKeys {
            cold_recovery: SecretKey::new(vec![0xAA; 16]),
            ..keys()
        };
        assert!(matches!(
            malformed.seal(&vault(), &did()),
            Err(VaultError::PlaintextLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    // A blob that authenticates but holds the wrong number of bytes (a foreign
    // or corrupt record) is refused rather than sliced into garbage keys. Sealed
    // under the CURRENT scheme's own associated data, so the tag genuinely
    // verifies and the length check is what does the rejecting.
    #[test]
    fn a_short_authenticated_bundle_is_refused() {
        let aad = CustodyEnvelope::CURRENT.aad(&did());
        let blob = vault().seal(&aad, &[0u8; 64]).unwrap();
        assert!(matches!(
            CustodyKeys::open(&vault(), &did(), &blob, CustodyEnvelope::CURRENT),
            Err(VaultError::PlaintextLength {
                expected: 96,
                actual: 64
            })
        ));
    }
}
