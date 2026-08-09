//! [`JacquardAuthStore`] — the bridge between jacquard's OAuth state and any
//! [`OAuthStateStore`].
//!
//! It owns no protocol logic and no storage: jacquard drives refresh, expiry
//! skew and the single-flight lock; the [`OAuthStateStore`] holds bytes. What
//! lives here is the layer between them — serialize, **seal**, hand over; and
//! on the way back, fetch, **open**, deserialize.
//!
//! Keeping the sealing here rather than in each storage backend means the
//! encryption is written once and a new backend cannot forget it.

use std::sync::Arc;

use jacquard_common::{bos::BosStr, session::SessionStoreError, types::did::Did as JacquardDid};
use jacquard_oauth::{
    authstore::ClientAuthStore,
    session::{AuthRequestData, ClientSessionData},
};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{OAuthStateStore, SecretVault};

/// A sealed, durable [`ClientAuthStore`] over any [`OAuthStateStore`].
///
/// Values are encoded as **JSON**, not MessagePack: both of jacquard's record
/// types use `#[serde(flatten)]`, which `rmp` cannot round-trip. The JSON is
/// then sealed, so the bytes that reach storage are ciphertext.
pub struct JacquardAuthStore<S: OAuthStateStore> {
    store: Arc<S>,
    vault: SecretVault,
}

impl<S: OAuthStateStore> Clone for JacquardAuthStore<S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            vault: self.vault.clone(),
        }
    }
}

impl<S: OAuthStateStore> std::fmt::Debug for JacquardAuthStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JacquardAuthStore { .. }")
    }
}

impl<S: OAuthStateStore> JacquardAuthStore<S> {
    /// Wrap `store` (where the bytes land) and `vault` (which seals them).
    pub fn new(store: S, vault: SecretVault) -> Self {
        Self {
            store: Arc::new(store),
            vault,
        }
    }

    /// AEAD associated data binding a session blob to its `(account_did,
    /// session_id)` primary key.
    ///
    /// The table-name prefix domain-separates it from an auth-request blob's
    /// associated data, and the DID is length-prefixed so the same bytes cannot
    /// be re-split into a *different* `(did, session_id)` pair — without the
    /// length prefix, `("ab", "c")` and `("a", "bc")` would produce identical
    /// associated data and a blob could be moved between those two rows.
    fn session_aad(account_did: &str, session_id: &str) -> Vec<u8> {
        let did = account_did.as_bytes();
        let mut aad = Vec::with_capacity(64 + did.len() + session_id.len());
        aad.extend_from_slice(b"atproto_oauth.client_session\0");
        aad.extend_from_slice(&(did.len() as u64).to_le_bytes());
        aad.extend_from_slice(did);
        aad.extend_from_slice(session_id.as_bytes());
        aad
    }

    /// AEAD associated data binding an auth-request blob to its `state` primary
    /// key. `state` is the sole variable field after the prefix, so no internal
    /// length prefix is needed.
    fn auth_request_aad(state: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + state.len());
        aad.extend_from_slice(b"atproto_oauth.auth_request\0");
        aad.extend_from_slice(state.as_bytes());
        aad
    }

    /// JSON-encode `value`, then seal it under `aad` so only ciphertext leaves
    /// this type. The transient plaintext — which holds live secrets — is
    /// zeroized as soon as it is sealed.
    fn encode<T: Serialize>(&self, aad: &[u8], value: &T) -> Result<Vec<u8>, SessionStoreError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        self.vault.seal(aad, &plaintext).map_err(boxed)
    }

    /// Open a sealed blob under `aad` and JSON-decode it.
    ///
    /// Fails **closed**: a value that is not valid ciphertext under this vault
    /// and this `aad` — tampered, sealed under a different key, grafted from
    /// another row, or a legacy plaintext row — errors rather than being read as
    /// plaintext.
    fn decode<T: DeserializeOwned>(&self, aad: &[u8], data: &[u8]) -> Result<T, SessionStoreError> {
        let plaintext = self.vault.open(aad, data).map_err(boxed)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

/// Map any zurid error into jacquard's store error.
///
/// Surfacing a failure as an error rather than a `None` is what makes an
/// unreadable blob fail closed: jacquard treats `None` as "no such session",
/// which would silently downgrade a decryption failure into a fresh sign-in
/// prompt at best, and a missing check at worst.
fn boxed<E: std::error::Error + Send + Sync + 'static>(err: E) -> SessionStoreError {
    SessionStoreError::Other(Box::new(err))
}

impl<S: OAuthStateStore> ClientAuthStore for JacquardAuthStore<S> {
    async fn get_session<D: BosStr + Send + Sync>(
        &self,
        did: &JacquardDid<D>,
        session_id: &str,
    ) -> Result<Option<ClientSessionData>, SessionStoreError> {
        let data = self
            .store
            .get_session(did.as_ref(), session_id)
            .await
            .map_err(boxed)?;
        let aad = Self::session_aad(did.as_ref(), session_id);
        data.map(|data| self.decode(&aad, &data)).transpose()
    }

    async fn upsert_session(&self, session: ClientSessionData) -> Result<(), SessionStoreError> {
        let account_did = session.account_did.as_ref();
        let session_id = AsRef::<str>::as_ref(&session.session_id);
        let aad = Self::session_aad(account_did, session_id);
        let data = self.encode(&aad, &session)?;
        self.store
            .upsert_session(account_did, session_id, &data)
            .await
            .map_err(boxed)
    }

    async fn delete_session<D: BosStr + Send + Sync>(
        &self,
        did: &JacquardDid<D>,
        session_id: &str,
    ) -> Result<(), SessionStoreError> {
        self.store
            .delete_session(did.as_ref(), session_id)
            .await
            .map_err(boxed)
    }

    async fn get_auth_req_info(
        &self,
        state: &str,
    ) -> Result<Option<AuthRequestData>, SessionStoreError> {
        let data = self.store.get_auth_request(state).await.map_err(boxed)?;
        let aad = Self::auth_request_aad(state);
        data.map(|data| self.decode(&aad, &data)).transpose()
    }

    async fn save_auth_req_info(
        &self,
        auth_req_info: &AuthRequestData,
    ) -> Result<(), SessionStoreError> {
        let state = AsRef::<str>::as_ref(&auth_req_info.state);
        let aad = Self::auth_request_aad(state);
        let data = self.encode(&aad, auth_req_info)?;
        self.store
            .save_auth_request(state, &data)
            .await
            .map_err(boxed)
    }

    async fn delete_auth_req_info(&self, state: &str) -> Result<(), SessionStoreError> {
        self.store.delete_auth_request(state).await.map_err(boxed)
    }

    // `list_session_keys` keeps the trait's default (empty): this store is not
    // enumerable — every lookup is keyed by DID + session id, and the trait
    // sanctions stores that do not support enumeration.
}

#[cfg(test)]
mod tests {
    use super::*;

    // The length prefix is what stops two different (did, session_id) pairs from
    // producing identical associated data — without it, a blob sealed for
    // ("ab", "c") would open under ("a", "bc").
    #[test]
    fn session_aad_is_unambiguous_across_the_split() {
        let first =
            JacquardAuthStore::<crate::memory::MemoryOAuthStateStore>::session_aad("ab", "c");
        let second =
            JacquardAuthStore::<crate::memory::MemoryOAuthStateStore>::session_aad("a", "bc");
        assert_ne!(
            first, second,
            "a re-split of the same bytes must not collide"
        );
    }

    // The two families are domain-separated, so a session blob can never be
    // opened as an auth request even if the key material lines up.
    #[test]
    fn the_two_families_are_domain_separated() {
        let session =
            JacquardAuthStore::<crate::memory::MemoryOAuthStateStore>::session_aad("x", "y");
        let request =
            JacquardAuthStore::<crate::memory::MemoryOAuthStateStore>::auth_request_aad("xy");
        assert_ne!(session, request);
    }
}
