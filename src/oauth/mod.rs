//! The AT Protocol OAuth handshake, with its state sealed and durable.
//!
//! Signing a visitor in over atproto means resolving their handle to a PDS,
//! running a Pushed Authorization Request, sending them there, and exchanging
//! the callback for a DPoP-bound token set. The protocol work is
//! [`jacquard`](https://docs.rs/jacquard)'s; what this module adds is the part
//! every deployment has to write itself:
//!
//! - **[`Authenticator`]** — a two-call surface ([`start`](Authenticator::start),
//!   [`complete`](Authenticator::complete)) over jacquard's client, so the
//!   protocol library stays behind one seam instead of spreading through your
//!   handlers.
//! - **[`JacquardAuthStore`]** — the bridge that makes the handshake's state
//!   durable *and* encrypted: it serializes jacquard's records, seals them with
//!   a [`SecretVault`], and hands opaque bytes to any [`OAuthStateStore`].
//!
//! # Why the state must be sealed
//!
//! An established session row holds the DPoP **private signing key**, the access
//! token and the long-lived **refresh token**; an in-flight row holds the PKCE
//! verifier and a DPoP key. Reading those in the clear is not "some session
//! data" — it is a renewable takeover of the user's PDS session, and it bypasses
//! every other control you have. So they never reach the database in the clear.
//!
//! # Why the state must be durable
//!
//! An in-process map works until the process restarts, until there are two
//! replicas, or until the redirect lands somewhere else. Persisting both tiers
//! is what lets a grant survive a deploy, lets `/callback` be served by a
//! different instance than `/login`, and gives jacquard's refresh machinery a
//! durable place to write rotated tokens.

mod store;

use std::sync::Arc;

use fluent_uri::Uri;
use jacquard::identity::JacquardResolver;
use jacquard_oauth::{
    atproto::AtprotoClientMetadata,
    client::OAuthClient,
    scopes::Scopes,
    session::ClientData,
    types::{AuthorizeOptions, CallbackParams},
};
use smol_str::SmolStr;

use crate::{Did, OAuthStateStore, SecretVault};

pub use store::JacquardAuthStore;

/// The scopes requested at sign-in by default.
///
/// `atproto` is the base AT Protocol scope; `transition:generic` is the
/// transitional grant covering the legacy XRPC surface still in wide use. Ask
/// for what you need and no more — narrower granular scopes exist, and a scope
/// you request at sign-in is a scope you must justify to the user.
pub const DEFAULT_SCOPES: &str = "atproto transition:generic";

/// Why an OAuth operation failed.
///
/// The underlying `jacquard` error is preserved as a
/// [`source`](std::error::Error::source) but not exposed as a type — the
/// protocol library stays an implementation detail of this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The configured scope string is not valid OAuth scope syntax.
    #[error("the configured OAuth scopes are not valid: {0}")]
    InvalidScopes(String),
    /// Resolving the handle, or the Pushed Authorization Request, failed.
    #[error("failed to start the authorization flow")]
    Start(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The callback did not exchange for a session: an unknown or expired
    /// `state`, a failed issuer check, or a failed token exchange.
    #[error("failed to complete the authorization flow")]
    Complete(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// How to configure the OAuth client.
///
/// # Loopback clients only, for now
///
/// zurid currently builds a **loopback** client: jacquard derives the
/// `client_id` from the redirect URI list, which is the localhost-development
/// shape of an atproto OAuth client. A production deployment eventually wants a
/// hosted `client_metadata.json` instead; wiring that is a small addition to
/// this type, not a redesign.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// The sole registered redirect target. jacquard sends `redirect_uris[0]`
    /// in the authorization request and derives the loopback `client_id` from
    /// this list, so this is the URI the PDS actually redirects back to — there
    /// is no per-request override.
    pub redirect_uri: Uri<String>,
    /// The space-separated scope string to request. Defaults to
    /// [`DEFAULT_SCOPES`].
    pub scopes: String,
}

impl OAuthConfig {
    /// A loopback client redirecting to `redirect_uri`, asking for
    /// [`DEFAULT_SCOPES`].
    pub fn loopback(redirect_uri: Uri<String>) -> Self {
        Self {
            redirect_uri,
            scopes: DEFAULT_SCOPES.to_string(),
        }
    }

    /// Request `scopes` instead of the default.
    #[must_use]
    pub fn with_scopes(mut self, scopes: impl Into<String>) -> Self {
        self.scopes = scopes.into();
        self
    }
}

/// The fully-applied jacquard client this module drives — a resolver over
/// `reqwest` paired with the sealed, durable auth store. Private, so no
/// protocol-library type appears in a public signature.
type Client<S> = Arc<OAuthClient<JacquardResolver<reqwest::Client>, JacquardAuthStore<S>>>;

/// The atproto OAuth authenticator: two calls, one per leg of the handshake.
///
/// ```no_run
/// # use fluent_uri::Uri;
/// # use zurid::{SecretVault, OAuthStateStore};
/// # use zurid::oauth::{Authenticator, OAuthConfig};
/// # async fn run<S: OAuthStateStore + 'static>(store: S, vault: SecretVault)
/// # -> Result<(), Box<dyn std::error::Error>> {
/// let redirect = Uri::parse("http://127.0.0.1:8080/callback")?.to_owned();
/// let auth = Authenticator::new(OAuthConfig::loopback(redirect), store, vault)?;
///
/// // Leg 1: send the visitor here.
/// let authorize_url = auth.start("alice.example.com").await?;
///
/// // Leg 2: at your redirect endpoint, with the query parameters it carried.
/// let did = auth.complete("the-code".into(), Some("the-state".into()), None).await?;
/// # Ok(())
/// # }
/// ```
pub struct Authenticator<S: OAuthStateStore + 'static> {
    oauth: Client<S>,
}

impl<S: OAuthStateStore + 'static> Authenticator<S> {
    /// Build the authenticator over `store` (where the handshake's state lands)
    /// and `vault` (which seals it before it gets there).
    pub fn new(config: OAuthConfig, store: S, vault: SecretVault) -> Result<Self, AuthError> {
        let scopes = Scopes::new(SmolStr::new(&config.scopes))
            .map_err(|err| AuthError::InvalidScopes(err.to_string()))?
            .convert();
        let metadata =
            AtprotoClientMetadata::new_localhost(Some(vec![config.redirect_uri]), Some(scopes));
        let client_data = ClientData {
            keyset: None,
            config: metadata,
        };
        let auth_store = JacquardAuthStore::new(store, vault);
        let oauth = OAuthClient::new(auth_store, client_data, reqwest::Client::new());
        Ok(Self {
            oauth: Arc::new(oauth),
        })
    }

    /// Leg 1 — resolve `handle` to its PDS, run the Pushed Authorization
    /// Request (minting and persisting the PKCE verifier and DPoP key against
    /// the OAuth `state`), and return the URL to send the visitor to.
    ///
    /// Errors if the handle cannot be resolved or the PDS is unreachable.
    pub async fn start(&self, handle: &str) -> Result<String, AuthError> {
        self.oauth
            .start_auth(handle, AuthorizeOptions::<jacquard::DefaultStr>::default())
            .await
            .map_err(|err| AuthError::Start(Box::new(err)))
    }

    /// Leg 2 — exchange the callback parameters for tokens and return the
    /// visitor's verified [`Did`].
    ///
    /// jacquard looks the in-flight request up by `state`, checks the issuer,
    /// runs the DPoP-bound token exchange against the PDS and persists the
    /// established session; the DID comes off that session, so it is the PDS's
    /// claim about who signed in, not the caller's.
    ///
    /// Errors if `state` matches no saved request (expired, unknown, or a
    /// forged callback), if the `iss` check fails, or if the exchange fails.
    pub async fn complete(
        &self,
        code: String,
        state: Option<String>,
        iss: Option<String>,
    ) -> Result<Did, AuthError> {
        let params = CallbackParams {
            code: code.into(),
            state: state.map(Into::into),
            iss: iss.map(Into::into),
        };
        let session = self
            .oauth
            .callback(params)
            .await
            .map_err(|err| AuthError::Complete(Box::new(err)))?;
        let account_did = session.data.read().await.account_did.clone();
        Ok(Did::new(account_did.to_string()))
    }
}
