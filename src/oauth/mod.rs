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
//!
//! # ⚠ Server-side request forgery: install a guarded connector
//!
//! Signing a visitor in is, by construction, **a server making HTTP requests to
//! a host the visitor named**. That is the shape of an SSRF, and it cannot be
//! designed away — resolving a handle means talking to that handle's domain.
//! What can be controlled is how much of the request an attacker steers.
//!
//! **What zurid closes.** [`Authenticator::start`] takes a validated
//! [`Handle`], not a string. A handle's charset is `[a-z0-9-]` plus dots, so it
//! can never carry a scheme or a path — which makes jacquard's
//! "an `https://…` input is a PDS/entryway URL, fetch it directly" branch
//! (`jacquard_oauth::resolver`) **unreachable** through this type. An attacker
//! cannot hand you `https://169.254.169.254/latest/meta-data/` and have the
//! server fetch it.
//!
//! That holds because **every** door into [`Handle`] validates, including
//! [`Deserialize`](serde::Deserialize) — a handle usually arrives in a JSON
//! login body, and a transparent derive there would have waved a URL straight
//! through the type that is supposed to be the guarantee.
//!
//! **What zurid does NOT close.** Once a handle is accepted, jacquard performs
//! the fetches the protocol requires, and it applies **no host or scheme guard
//! of its own**:
//!
//! - `https://<handle>/.well-known/atproto-did` — the handle's own domain, which
//!   the visitor chose, and which may resolve to a private address;
//! - the DID document's `serviceEndpoint` — an arbitrary URL published by
//!   whoever controls that DID;
//! - the authorization-server metadata and token endpoints derived from it.
//!
//! A DNS name under an attacker's control can point at `127.0.0.1`, at a link-local
//! metadata service, or at anything else your network reaches — including on a
//! re-resolve after a check (DNS rebinding).
//!
//! **So a security-conscious deployment must supply its own connector** via
//! [`Authenticator::with_client`]: a `reqwest::Client` whose resolver or
//! connector refuses private, loopback, link-local and unique-local addresses
//! (and re-checks on redirect). zurid's default client sets connect and overall
//! timeouts, which bound the damage; it does **not** filter addresses, because
//! which ranges are private is a deployment fact this crate cannot know.

mod store;

use std::sync::Arc;
use std::time::Duration;

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

use crate::{Did, Handle, OAuthStateStore, SecretVault};

pub use store::JacquardAuthStore;

/// The scopes requested at sign-in by default.
///
/// `atproto` is the base AT Protocol scope; `transition:generic` is the
/// transitional grant covering the legacy XRPC surface still in wide use. Ask
/// for what you need and no more — narrower granular scopes exist, and a scope
/// you request at sign-in is a scope you must justify to the user.
pub const DEFAULT_SCOPES: &str = "atproto transition:generic";

/// How long the default HTTP client waits to establish a TCP/TLS connection.
///
/// Every fetch on the sign-in path targets a host the visitor named, so an
/// unbounded connect is a request-pinning primitive: point a handle's domain at
/// a blackholed address and the worker never comes back.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The default HTTP client's total per-request budget — connect, send, and read
/// the whole response. Bounds a slow-drip response body just as
/// [`DEFAULT_CONNECT_TIMEOUT`] bounds a hanging connect.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// The default HTTP client could not be built. Only [`Authenticator::new`]
    /// raises this; [`Authenticator::with_client`] takes a client you built.
    #[error("failed to build the default HTTP client")]
    HttpClient(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The redirect URI is not a loopback target. Carries the URI as offered.
    #[error(
        "a loopback client's redirect_uri must be http://127.0.0.1 or http://[::1] \
         (with an optional port and path), got `{0}`"
    )]
    NotALoopbackRedirect(String),
    /// The callback carried no `iss`. The atproto OAuth profile requires the
    /// authorization-response `iss` parameter (RFC 9207 mix-up defense), so a
    /// callback without it is rejected before the token exchange.
    #[error("the OAuth callback is missing the required `iss` parameter")]
    MissingIssuer,
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

/// The only two hosts an atproto loopback client may redirect to.
///
/// The spec is explicit that these are **IP literals**, not names: `localhost`
/// is the shape of the `client_id`, while the redirect targets default to
/// "`http://127.0.0.1/` and `http://[::1]/`"
/// (<https://atproto.com/specs/oauth>). Compared as written, so an unusual
/// spelling of the same address (`127.000.000.001`, `[0:0:0:0:0:0:0:1]`) is
/// refused rather than guessed at — the safe direction for a check whose job is
/// to keep an authorization code off a host you do not control.
pub const LOOPBACK_HOSTS: [&str; 2] = ["127.0.0.1", "[::1]"];

impl OAuthConfig {
    /// A loopback client redirecting to `redirect_uri`, asking for
    /// [`DEFAULT_SCOPES`].
    ///
    /// The URI is **validated**: it must be `http` to one of
    /// [`LOOPBACK_HOSTS`], with an optional port and path and no userinfo. A
    /// redirect URI is where the authorization **code** is delivered, and
    /// jacquard derives the loopback `client_id` from this very list — so a
    /// non-loopback value here is not a typo that fails later, it is a client
    /// that hands codes to another origin. Rejected at construction.
    ///
    /// ```
    /// # use fluent_uri::Uri;
    /// # use zurid::oauth::OAuthConfig;
    /// let ok = Uri::parse("http://127.0.0.1:8080/callback".to_owned()).unwrap();
    /// assert!(OAuthConfig::loopback(ok).is_ok());
    ///
    /// // Not loopback: the code would be delivered to someone else.
    /// let evil = Uri::parse("http://evil.example.com/callback".to_owned()).unwrap();
    /// assert!(OAuthConfig::loopback(evil).is_err());
    /// ```
    pub fn loopback(redirect_uri: Uri<String>) -> Result<Self, AuthError> {
        let refuse = || AuthError::NotALoopbackRedirect(redirect_uri.as_str().to_owned());

        if !redirect_uri.scheme().as_str().eq_ignore_ascii_case("http") {
            return Err(refuse());
        }
        let authority = redirect_uri.authority().ok_or_else(refuse)?;
        // Userinfo is how `http://127.0.0.1@evil.example.com/` reads as
        // loopback to a human. `host()` already sees through it — this refuses
        // the shape outright, so nobody has to re-derive that it is safe.
        if authority.userinfo().is_some() {
            return Err(refuse());
        }
        if !LOOPBACK_HOSTS.contains(&authority.host()) {
            return Err(refuse());
        }

        Ok(Self {
            redirect_uri,
            scopes: DEFAULT_SCOPES.to_string(),
        })
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
/// # use zurid::{Handle, SecretVault, OAuthStateStore};
/// # use zurid::oauth::{Authenticator, OAuthConfig};
/// # async fn run<S: OAuthStateStore + 'static>(store: S, vault: SecretVault)
/// # -> Result<(), Box<dyn std::error::Error>> {
/// let redirect = Uri::parse("http://127.0.0.1:8080/callback")?.to_owned();
/// let auth = Authenticator::new(OAuthConfig::loopback(redirect)?, store, vault)?;
///
/// // Leg 1: send the visitor here. The handle is VALIDATED before it reaches
/// // the resolver — see this module's SSRF note.
/// let handle = Handle::try_new("alice.example.com")?;
/// let authorize_url = auth.start(&handle).await?;
///
/// // Leg 2: at your redirect endpoint, with the query parameters it carried.
/// // `iss` is required — a callback without it is rejected before the exchange.
/// let did = auth.complete("the-code".into(), Some("the-state".into()), Some("the-iss".into())).await?;
/// # Ok(())
/// # }
/// ```
pub struct Authenticator<S: OAuthStateStore + 'static> {
    oauth: Client<S>,
}

impl<S: OAuthStateStore + 'static> Authenticator<S> {
    /// Build the authenticator over `store` (where the handshake's state lands)
    /// and `vault` (which seals it before it gets there), driving a default
    /// `reqwest` client with [`DEFAULT_CONNECT_TIMEOUT`] and
    /// [`DEFAULT_REQUEST_TIMEOUT`].
    ///
    /// **That default client filters no addresses.** Every deployment holding
    /// real identities should build its own SSRF-guarded client and pass it to
    /// [`with_client`](Authenticator::with_client) instead — see this module's
    /// SSRF note for what the handle boundary does and does not close.
    pub fn new(config: OAuthConfig, store: S, vault: SecretVault) -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| AuthError::HttpClient(Box::new(err)))?;
        Self::with_client(config, store, vault, client)
    }

    /// Build the authenticator over an HTTP `client` you already configured —
    /// the seam an **SSRF-guarded connector** is installed through, and the
    /// place to set your own timeouts, proxy or connection pool.
    ///
    /// Mirrors [`HttpPlcDirectory::with_client`](crate::HttpPlcDirectory::with_client).
    /// jacquard performs the handle, DID-document and authorization-server
    /// fetches through this client and applies no host or scheme guard of its
    /// own, so a client that refuses private, loopback and link-local
    /// destinations is the only place that guard can live.
    pub fn with_client(
        config: OAuthConfig,
        store: S,
        vault: SecretVault,
        client: reqwest::Client,
    ) -> Result<Self, AuthError> {
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
        let oauth = OAuthClient::new(auth_store, client_data, client);
        Ok(Self {
            oauth: Arc::new(oauth),
        })
    }

    /// Leg 1 — resolve `handle` to its PDS, run the Pushed Authorization
    /// Request (minting and persisting the PKCE verifier and DPoP key against
    /// the OAuth `state`), and return the URL to send the visitor to.
    ///
    /// Takes a **validated** [`Handle`] rather than a string on purpose: the
    /// resolver treats an input beginning `https://` as a service URL to fetch
    /// directly, and a `Handle` cannot spell one. Converting at this boundary is
    /// what makes that branch unreachable — see the module's SSRF note for the
    /// fetches it does *not* close.
    ///
    /// Errors if the handle cannot be resolved or the PDS is unreachable.
    pub async fn start(&self, handle: &Handle) -> Result<String, AuthError> {
        self.oauth
            .start_auth(
                handle.as_str(),
                AuthorizeOptions::<jacquard::DefaultStr>::default(),
            )
            .await
            .map_err(|err| AuthError::Start(Box::new(err)))
    }

    /// Leg 2 — exchange the callback parameters for tokens and return the
    /// visitor's verified [`Did`].
    ///
    /// jacquard looks the in-flight request up by `state`, runs the DPoP-bound
    /// token exchange against the PDS and persists the established session; the
    /// DID comes off that session, so it is the PDS's claim about who signed in,
    /// not the caller's.
    ///
    /// # `iss` is required
    ///
    /// A callback carrying no `iss` is **rejected outright**, before the exchange
    /// — [`AuthError::MissingIssuer`]. The atproto OAuth profile mandates the
    /// `iss` authorization-response parameter (RFC 9207 mix-up defense), so a
    /// callback without it is malformed, and jacquard's own check only fires
    /// *conditionally* on what the server metadata advertised. zurid does not
    /// leave that to the server's say-so: no `iss`, no exchange. Verifying its
    /// *value* against the issuer is then jacquard's job.
    ///
    /// Errors if `iss` is absent, if `state` matches no saved request (expired,
    /// unknown, or a forged callback), if the `iss` value fails its check, or if
    /// the exchange fails.
    pub async fn complete(
        &self,
        code: String,
        state: Option<String>,
        iss: Option<String>,
    ) -> Result<Did, AuthError> {
        // Hard-require `iss`, ahead of jacquard's conditional check: an atproto
        // authorization response must carry it, so its absence is not something
        // the server metadata gets to excuse.
        let iss = iss.ok_or(AuthError::MissingIssuer)?;
        let params = CallbackParams {
            code: code.into(),
            state: state.map(Into::into),
            iss: Some(iss.into()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryOAuthStateStore;

    fn vault() -> SecretVault {
        SecretVault::from_bytes(&[7u8; crate::ROOT_KEY_LEN]).expect("a 32-byte test root key")
    }

    fn redirect_uri(raw: &str) -> Uri<String> {
        Uri::parse(raw.to_owned()).expect("a valid redirect uri")
    }

    fn config() -> OAuthConfig {
        OAuthConfig::loopback(redirect_uri("http://127.0.0.1:8080/callback"))
            .expect("a loopback redirect")
    }

    // Every loopback shape the spec sanctions: both literals, with and without
    // a port, with and without a path.
    #[test]
    fn a_loopback_redirect_is_accepted() {
        for uri in [
            "http://127.0.0.1",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/callback",
            "http://[::1]",
            "http://[::1]:8080/callback",
            "http://127.0.0.1:8080/callback?next=%2Fhome",
        ] {
            assert!(
                OAuthConfig::loopback(redirect_uri(uri)).is_ok(),
                "`{uri}` is a valid loopback redirect"
            );
        }
    }

    // A redirect URI is where the authorization CODE lands. Anything that is
    // not literally loopback-over-http is refused — including the shapes that
    // READ as loopback: a userinfo prefix, a look-alike name, and `localhost`
    // (which the atproto spec makes the client_id's host, not a redirect host).
    #[test]
    fn a_non_loopback_redirect_is_refused() {
        for uri in [
            "http://evil.example.com/callback",
            "http://127.0.0.1@evil.example.com/callback",
            "http://localhost:8080/callback",
            "http://127.0.0.1.evil.example.com/callback",
            "https://127.0.0.1:8080/callback",
            "http://[::2]:8080/callback",
            "http://169.254.169.254/callback",
            "urn:ietf:wg:oauth:2.0:oob",
        ] {
            assert!(
                matches!(
                    OAuthConfig::loopback(redirect_uri(uri)),
                    Err(AuthError::NotALoopbackRedirect(_))
                ),
                "`{uri}` must not pass as a loopback redirect"
            );
        }
    }

    // THE SSRF BOUNDARY. jacquard's resolver treats an input beginning
    // `https://` as a service URL and fetches it DIRECTLY — an attacker-chosen
    // URL the server would then request. `start` takes a `Handle`, so that
    // branch is unreachable only if EVERY door into `Handle` refuses a URL.
    //
    // Both doors are checked here on purpose. `try_new` is the obvious one;
    // `Deserialize` is the one that matters, because a JSON login body is how a
    // handle actually reaches a server, and a derived transparent impl would
    // have waved these straight through into the fetch.
    #[test]
    fn an_https_url_can_never_become_a_handle() {
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/",
            "https://example.com",
            "HTTPS://EXAMPLE.COM",
            "https://alice.example.com",
            "http://[::1]/",
        ] {
            assert!(
                Handle::try_new(url).is_err(),
                "`{url}` must not validate as a handle — it would reach jacquard's \
                 fetch-this-service-URL branch"
            );
            let json = serde_json::to_string(url).expect("a json string");
            assert!(
                serde_json::from_str::<Handle>(&json).is_err(),
                "`{url}` must not DESERIALIZE into a handle either — that is the \
                 door a JSON login body comes through"
            );
        }
    }

    // The default client is built with both timeouts, so a handle pointed at a
    // blackholed address cannot pin a worker forever.
    #[test]
    fn the_default_authenticator_builds() {
        Authenticator::new(config(), MemoryOAuthStateStore::default(), vault())
            .expect("the default authenticator builds");
    }

    // `with_client` is the seam an SSRF-guarded connector is installed through:
    // a caller-built client must be accepted and drive the handshake.
    #[test]
    fn with_client_accepts_a_caller_supplied_client() {
        let guarded = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(250))
            .build()
            .expect("a caller-configured client");
        Authenticator::with_client(config(), MemoryOAuthStateStore::default(), vault(), guarded)
            .expect("a caller-supplied client is accepted");
    }

    #[test]
    fn invalid_scopes_are_refused_at_construction() {
        let config = config().with_scopes("not a valid scope\u{7f}");
        assert!(matches!(
            Authenticator::new(config, MemoryOAuthStateStore::default(), vault()),
            Err(AuthError::InvalidScopes(_))
        ));
    }

    // S3: a callback with no `iss` is rejected BEFORE the exchange — stricter
    // than jacquard's conditional check, which only fires on what the server
    // metadata advertised. The atproto profile mandates `iss` (RFC 9207), so its
    // absence is malformed regardless. The guard runs before any network call,
    // so this exercises it without a PDS.
    #[tokio::test]
    async fn complete_rejects_a_callback_without_iss() {
        let auth = Authenticator::new(config(), MemoryOAuthStateStore::default(), vault()).unwrap();
        let result = auth
            .complete("the-code".into(), Some("the-state".into()), None)
            .await;
        assert!(
            matches!(result, Err(AuthError::MissingIssuer)),
            "a callback without `iss` must be refused, got: {result:?}"
        );
    }
}
