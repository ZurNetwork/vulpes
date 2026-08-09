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

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Did, SecretVault, VaultError};

/// The byte length of a secp256k1 private scalar.
pub const SECRET_KEY_LEN: usize = 32;

/// One secp256k1 private key, held as its raw 32-byte big-endian scalar (the
/// form `atrium_crypto`'s keypair `export`/`import` round-trips).
///
/// Zeroized on drop; its [`Debug`] is redacted so key material can never reach a
/// log line.
///
/// ```
/// # use zurid::SecretKey;
/// let key = SecretKey::new(vec![0xAB; 32]);
/// assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
/// ```
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Vec<u8>);

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

    /// Seal this bundle under `vault`, binding it to `did` as associated data.
    ///
    /// The DID is the AEAD `aad`, so a sealed bundle is cryptographically tied
    /// to its row: an attacker with database write access cannot move one
    /// identity's custody blob onto another DID — the tag check fails on
    /// [`open`](CustodyKeys::open) under the moved-to DID.
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
        vault.seal(did.as_str().as_bytes(), &plaintext)
    }

    /// Open a blob produced by [`seal`](CustodyKeys::seal). `did` must be the
    /// DID it was sealed under.
    pub fn open(vault: &SecretVault, did: &Did, blob: &[u8]) -> Result<Self, VaultError> {
        let plaintext = vault.open(did.as_str().as_bytes(), blob)?;
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
        assert_eq!(CustodyKeys::open(&vault(), &did(), &blob).unwrap(), keys());
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
            CustodyKeys::open(&vault(), &other, &blob),
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
    // or corrupt record) is refused rather than sliced into garbage keys.
    #[test]
    fn a_short_authenticated_bundle_is_refused() {
        let blob = vault().seal(did().as_str().as_bytes(), &[0u8; 64]).unwrap();
        assert!(matches!(
            CustodyKeys::open(&vault(), &did(), &blob),
            Err(VaultError::PlaintextLength {
                expected: 96,
                actual: 64
            })
        ));
    }
}
