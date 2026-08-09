//! [`SecretVault`] — envelope encryption of at-rest secrets under a **root key**.
//!
//! zurid holds two families of secret on your users' behalf, and both are sealed
//! by this one type before they touch a database:
//!
//! - **custody keys** — the secp256k1 private halves behind a minted `did:plc`
//!   ([`CustodyKeys`](crate::CustodyKeys)). Whoever holds these operates the
//!   identity.
//! - **OAuth state** — an established session's DPoP private signing key plus
//!   its refresh and access tokens, and an in-flight request's PKCE verifier.
//!   Reading those in the clear is a *renewable* PDS-session takeover.
//!
//! The envelope model is one 32-byte root key, held **outside** the database,
//! wrapping every per-row secret with an AEAD (XChaCha20-Poly1305). A database
//! compromise alone — a leaked backup, a read replica, an injection read gadget —
//! therefore yields no usable secret.
//!
//! # Root-key custody is the caller's problem
//!
//! The root key is [`Zeroize`]d when the vault drops — including every clone,
//! each of which holds its own copy — so it does not linger in freed heap for a
//! crash dump or a later allocation to pick up. That is hygiene, not a
//! boundary: while the process runs, the key is in its memory by definition.
//!
//! zurid takes 32 bytes and never asks where they came from. Sourcing them from
//! config or an environment variable is acceptable only for development: a
//! process-readable root key is not a hardware boundary. For anything holding
//! real identities, keep the root key in a cloud KMS or HSM. The
//! [`SecretVault`] type and the seal/open seam are deliberately narrow so that
//! swap is a change of *one* type, not a schema migration.
//!
//! # Associated data binds a blob to its row
//!
//! Every seal takes an `aad` — associated data that is authenticated but **not**
//! stored. The tag check on open fails unless the identical `aad` is supplied,
//! so passing each row's primary key as `aad` cryptographically ties a blob to
//! its row: an attacker with database *write* access cannot lift one row's
//! sealed secret onto another row. That is defense in depth on top of the core
//! property (a read alone yields nothing).

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The root key length in bytes (XChaCha20-Poly1305 takes a 256-bit key).
pub const ROOT_KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length (192-bit) — large enough that random nonces
/// never collide in practice, so no counter or stored state is needed even
/// though one root key seals every family of secret.
const NONCE_LEN: usize = 24;

/// Why a seal or open failed.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The supplied root key was not exactly [`ROOT_KEY_LEN`] bytes. Carries the
    /// length that was offered, so a misconfiguration fails loudly at boot
    /// rather than silently weakening encryption.
    #[error("root key must be exactly {ROOT_KEY_LEN} bytes, got {0}")]
    RootKeyLength(usize),
    /// The blob is shorter than the nonce it must start with.
    #[error("sealed blob is too short to hold a nonce")]
    BlobTooShort,
    /// Encryption failed.
    #[error("failed to seal the secret")]
    Seal,
    /// The AEAD tag did not verify: the wrong root key, the wrong associated
    /// data (a blob lifted onto another row), or tampering. Deliberately does
    /// not distinguish the cases — the distinction is only useful to an
    /// attacker.
    #[error("failed to open the secret (wrong root key, wrong row, or tampered)")]
    Open,
    /// The decrypted plaintext was not the length the caller expected — a
    /// corrupt or foreign record that authenticated but does not fit the shape.
    #[error("decrypted secret has unexpected length {actual} (expected {expected})")]
    PlaintextLength {
        /// The length that was expected.
        expected: usize,
        /// The length that was found.
        actual: usize,
    },
}

/// The 32-byte root key that seals every at-rest secret, held in memory only.
///
/// [`Debug`] is redacted so the root key can never reach a log line, and the
/// bytes are **zeroized on drop** — every clone independently, since each holds
/// its own copy. It is the one key whose disclosure loses every other secret at
/// once, so leaving it in freed heap for a crash dump or a later allocation to
/// pick up would undo the whole envelope model.
///
/// ```
/// # use zurid::SecretVault;
/// let vault = SecretVault::from_bytes(&[7u8; 32]).unwrap();
/// let blob = vault.seal(b"row-key", b"a secret").unwrap();
/// assert_eq!(vault.open(b"row-key", &blob).unwrap().as_slice(), b"a secret");
/// // The same blob will not open under a different row key.
/// assert!(vault.open(b"other-row", &blob).is_err());
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVault([u8; ROOT_KEY_LEN]);

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretVault(<redacted>)")
    }
}

impl SecretVault {
    /// Build the vault from exactly [`ROOT_KEY_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        let key: [u8; ROOT_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| VaultError::RootKeyLength(bytes.len()))?;
        Ok(Self(key))
    }

    /// The AEAD instance for this root key.
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.0).into())
    }

    /// Seal `plaintext` into an opaque blob: a fresh random nonce followed by
    /// the AEAD ciphertext. Only a holder of this root key can [`open`] it.
    ///
    /// `aad` is bound in as AEAD associated data — not stored, but required
    /// identically on open. Pass the row's primary key; see the module docs.
    ///
    /// [`open`]: SecretVault::open
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, payload)
            .map_err(|_| VaultError::Seal)?;

        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Open a blob produced by [`seal`](SecretVault::seal). `aad` must be
    /// identical to what it was sealed under.
    ///
    /// The plaintext comes back in a [`Zeroizing`] buffer, so the decrypted
    /// secret is wiped from the heap on drop.
    ///
    /// **Fails closed.** A malformed blob, a mismatched `aad`, a wrong root key
    /// or a failed tag all error, and never return plaintext. In particular a
    /// legacy *unencrypted* value sitting in the column is not valid ciphertext,
    /// so it errors here rather than being passed through as if it had been
    /// decrypted.
    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if blob.len() < NONCE_LEN {
            return Err(VaultError::BlobTooShort);
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let plaintext = self
            .cipher()
            .decrypt(nonce, payload)
            .map_err(|_| VaultError::Open)?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"oauth.client_session\0did:plc:alice";
    const PLAINTEXT: &[u8] = b"{\"refresh_token\":\"refresh-token\"}";

    fn vault() -> SecretVault {
        SecretVault::from_bytes(&[7u8; ROOT_KEY_LEN]).unwrap()
    }

    #[test]
    fn seal_open_round_trips() {
        let blob = vault().seal(AAD, PLAINTEXT).unwrap();
        assert_eq!(vault().open(AAD, &blob).unwrap().as_slice(), PLAINTEXT);
    }

    // The whole point of encryption at rest: the sealed blob must not contain
    // the plaintext bytes.
    #[test]
    fn sealed_blob_is_not_plaintext() {
        let blob = vault().seal(AAD, PLAINTEXT).unwrap();
        assert_ne!(blob.as_slice(), PLAINTEXT);
        let needle = b"refresh-token";
        assert!(
            !blob.windows(needle.len()).any(|w| w == needle),
            "plaintext secret leaked into the sealed blob"
        );
    }

    // Every seal draws a fresh random nonce, so sealing the same plaintext twice
    // yields different bytes — no ciphertext equality oracle across rows.
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let first = vault().seal(AAD, PLAINTEXT).unwrap();
        let second = vault().seal(AAD, PLAINTEXT).unwrap();
        assert_ne!(
            first, second,
            "identical plaintext must not seal to identical bytes"
        );
    }

    #[test]
    fn wrong_root_key_cannot_open() {
        let blob = vault().seal(AAD, PLAINTEXT).unwrap();
        let other = SecretVault::from_bytes(&[8u8; ROOT_KEY_LEN]).unwrap();
        assert!(matches!(other.open(AAD, &blob), Err(VaultError::Open)));
    }

    // The AAD is bound: a blob sealed under one row key cannot be opened under
    // another, so sealed secrets cannot be swapped across rows.
    #[test]
    fn blob_cannot_be_opened_under_a_different_aad() {
        let blob = vault().seal(AAD, PLAINTEXT).unwrap();
        assert!(matches!(
            vault().open(b"oauth.client_session\0did:plc:mallory", &blob),
            Err(VaultError::Open)
        ));
    }

    #[test]
    fn tampered_blob_fails() {
        let mut blob = vault().seal(AAD, PLAINTEXT).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(matches!(vault().open(AAD, &blob), Err(VaultError::Open)));
    }

    // A blob shorter than the nonce is rejected, not indexed out of bounds.
    #[test]
    fn short_blob_fails_closed() {
        assert!(matches!(
            vault().open(AAD, &[0u8; NONCE_LEN - 1]),
            Err(VaultError::BlobTooShort)
        ));
    }

    #[test]
    fn root_key_must_be_32_bytes() {
        assert!(matches!(
            SecretVault::from_bytes(&[0u8; 16]),
            Err(VaultError::RootKeyLength(16))
        ));
        assert!(SecretVault::from_bytes(&[0u8; ROOT_KEY_LEN]).is_ok());
    }

    // The root key is wiped on drop. Reading freed memory is not something a
    // test may do, so the property is pinned two ways: the type-level
    // `ZeroizeOnDrop` bound — which is exactly what makes `drop` wipe — and the
    // behaviour of the wipe itself, run explicitly on a live value.
    #[test]
    fn the_root_key_is_zeroized() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretVault>();

        let mut vault = vault();
        let blob = vault.seal(AAD, PLAINTEXT).unwrap();
        vault.zeroize();
        assert!(
            matches!(vault.open(AAD, &blob), Err(VaultError::Open)),
            "after the wipe the vault no longer holds the key it sealed under"
        );
    }

    // Each clone owns its own copy, so dropping one must not wipe another's key.
    // A vault shared behind an Arc-of-bytes would fail this: the first drop
    // would blind every remaining holder.
    #[test]
    fn dropping_a_clone_leaves_the_original_usable() {
        let vault = vault();
        let blob = vault.seal(AAD, PLAINTEXT).unwrap();

        drop(vault.clone());

        assert_eq!(
            vault.open(AAD, &blob).unwrap().as_slice(),
            PLAINTEXT,
            "a dropped clone must not take the original's key with it"
        );
    }

    // The vault's Debug must never reveal its bytes.
    #[test]
    fn vault_debug_is_redacted() {
        let shown = format!("{:?}", SecretVault::from_bytes(&[0xCD; 32]).unwrap());
        assert_eq!(shown, "SecretVault(<redacted>)");
        assert!(!shown.contains("cd") && !shown.contains("205"));
    }
}
