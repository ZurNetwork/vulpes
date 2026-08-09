//! `GET /.well-known/atproto-did` — serving handle resolution for a namespace
//! you operate, as a router you can merge into your app.
//!
//! A client resolving the handle `alice.example.com` fetches
//! `https://alice.example.com/.well-known/atproto-did`; the handle arrives in
//! the `Host` header, and the response is the bare DID as `text/plain`. That is
//! the HTTPS half of atproto handle resolution — the half you serve when you
//! issue subdomains of a domain you control, behind one wildcard DNS record and
//! certificate.
//!
//! The route carries no authentication, changes no state, and reads no cookie,
//! so mount it **outside** any CSRF or session layer — like a health check. A
//! resolver sends no `Origin` and holds no session.
//!
//! ```text
//! GET /.well-known/atproto-did    Host: alice.example.com
//! → 200 text/plain  did:plc:ewvi7nxzyoun6zhxrhs64oiz
//! → 404                            unknown handle, or a Host that is not ours
//! ```

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::{Handle, HandleError, HandleResolver};

/// The route path this module serves.
pub const ATPROTO_DID_PATH: &str = "/.well-known/atproto-did";

/// The domain whose subdomains you issue handles under — `example.com` if your
/// users are `alice.example.com`.
///
/// Validated on construction through the same [`Handle`] rules a handle itself
/// obeys, so the suffix comparison below is always against a normalized value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleDomain(String);

impl HandleDomain {
    /// Validate and normalize a handle domain.
    ///
    /// ```
    /// # use zurid::axum::HandleDomain;
    /// assert_eq!(HandleDomain::try_new("Example.COM").unwrap().as_str(), "example.com");
    /// assert!(HandleDomain::try_new("localhost").is_err());
    /// ```
    pub fn try_new(raw: impl Into<String>) -> Result<Self, HandleError> {
        Ok(Self(Handle::try_new(raw)?.as_str().to_owned()))
    }

    /// The normalized domain.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for HandleDomain {
    type Err = HandleError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_new(raw)
    }
}

impl std::fmt::Display for HandleDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The handler's state: who resolves handles, and which namespace is ours.
struct WellKnownState<R> {
    resolver: Arc<R>,
    handle_domain: HandleDomain,
}

// Derived `Clone` would demand `R: Clone`; the resolver is behind an `Arc`, so
// the state is always cheap to clone regardless.
impl<R> Clone for WellKnownState<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            handle_domain: self.handle_domain.clone(),
        }
    }
}

/// Build the `/.well-known/atproto-did` route, ready to merge.
///
/// The returned router has its state already applied, so it drops into an app
/// with any state of its own:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use axum::Router;
/// # use zurid::axum::{HandleDomain, atproto_did_router};
/// # fn build<R: zurid::HandleResolver + 'static>(accounts: Arc<R>) -> Router {
/// let domain = HandleDomain::try_new("example.com").unwrap();
/// Router::new()
///     // ... your routes, layers and state ...
///     .merge(atproto_did_router(accounts, domain))
/// # }
/// ```
pub fn atproto_did_router<R: HandleResolver + 'static>(
    resolver: Arc<R>,
    handle_domain: HandleDomain,
) -> Router {
    let state = WellKnownState {
        resolver,
        handle_domain,
    };
    Router::new()
        .route(ATPROTO_DID_PATH, get(atproto_did::<R>))
        .with_state(state)
}

/// Parse a request `Host` into the [`Handle`] it addresses, or `None` if the
/// host is not ours to resolve.
///
/// The host must be a **subdomain** of `handle_domain` — the apex itself, or any
/// other authority, yields `None`, so this only ever answers for handles in the
/// namespace it was told to serve. A handle on a domain the user brought
/// resolves at *their* domain, never here.
///
/// Exposed because the rules are worth testing directly, and because a caller
/// with its own routing may want the same parse.
///
/// ```
/// # use zurid::axum::{HandleDomain, handle_from_host};
/// let domain = HandleDomain::try_new("example.com").unwrap();
///
/// assert_eq!(
///     handle_from_host("Alice.Example.com:443", &domain).unwrap().as_str(),
///     "alice.example.com",
/// );
/// // The apex is not a handle in its own namespace.
/// assert!(handle_from_host("example.com", &domain).is_none());
/// // Neither is a look-alike that merely ends in the same letters.
/// assert!(handle_from_host("evil-example.com", &domain).is_none());
/// ```
pub fn handle_from_host(host: &str, handle_domain: &HandleDomain) -> Option<Handle> {
    // Drop an optional `:port`. A handle authority is a DNS name and holds no
    // colon of its own, so at most one is allowed: anything with more — an IPv6
    // literal like `[::1]:443`, or a malformed `host:port:junk` — is not a valid
    // handle authority. Fail closed rather than silently taking a prefix.
    let host = match host.split_once(':') {
        None => host,
        Some((authority, port)) if !authority.is_empty() && !port.contains(':') => authority,
        Some(_) => return None,
    };
    // Drop a single FQDN-root trailing dot, matching `Handle`'s normalization.
    let host = host.strip_suffix('.').unwrap_or(host);

    // Only answer for a subdomain of our namespace. The leading dot is what
    // makes this a label-boundary test rather than a substring one: without it,
    // `evil-example.com` would pass as a subdomain of `example.com`.
    let suffix = format!(".{handle_domain}");
    if !host.to_ascii_lowercase().ends_with(&suffix) {
        return None;
    }
    // Normalize and validate the whole host as a handle; a malformed or
    // punycode host is not a resolvable handle.
    Handle::try_new(host).ok()
}

/// `GET /.well-known/atproto-did` — resolve the handle in the `Host` header to
/// its DID, returned as a bare `text/plain` body.
///
/// A `Host` outside the configured namespace, or one no identity holds, is
/// `404`. A resolver failure is `500`: the request was fine, and the client may
/// retry.
async fn atproto_did<R: HandleResolver + 'static>(
    State(state): State<WellKnownState<R>>,
    headers: HeaderMap,
) -> Response {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(handle) = handle_from_host(host, &state.handle_domain) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match state.resolver.did_for_handle(&handle).await {
        Ok(Some(did)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            did.as_str().to_owned(),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> HandleDomain {
        HandleDomain::try_new("example.com").unwrap()
    }

    #[test]
    fn resolves_a_subdomain_of_the_handle_domain() {
        let handle = handle_from_host("alice.example.com", &domain()).expect("a valid subdomain");
        assert_eq!(handle.as_str(), "alice.example.com");
    }

    #[test]
    fn drops_an_optional_port() {
        let handle = handle_from_host("alice.example.com:443", &domain()).expect("port dropped");
        assert_eq!(handle.as_str(), "alice.example.com");
    }

    #[test]
    fn normalizes_a_mixed_case_host() {
        let handle = handle_from_host("Alice.Example.Com", &domain()).expect("normalized");
        assert_eq!(handle.as_str(), "alice.example.com");
    }

    #[test]
    fn strips_a_trailing_fqdn_dot() {
        let handle = handle_from_host("alice.example.com.", &domain()).expect("dot dropped");
        assert_eq!(handle.as_str(), "alice.example.com");
    }

    #[test]
    fn refuses_the_apex_itself() {
        assert!(handle_from_host("example.com", &domain()).is_none());
    }

    #[test]
    fn refuses_a_foreign_authority() {
        assert!(handle_from_host("alice.other.test", &domain()).is_none());
        // A look-alike that only contains the domain mid-string is refused too.
        assert!(handle_from_host("example.com.evil.net", &domain()).is_none());
    }

    // The suffix gate requires a real label boundary: a host ending in
    // `-example.com` or `xexample.com` is NOT a subdomain of `example.com`.
    #[test]
    fn refuses_a_dot_boundary_near_miss() {
        assert!(handle_from_host("evil-example.com", &domain()).is_none());
        assert!(handle_from_host("notexample.com", &domain()).is_none());
    }

    #[test]
    fn refuses_a_multi_colon_authority() {
        assert!(handle_from_host("alice.example.com:443:junk", &domain()).is_none());
    }

    #[test]
    fn refuses_an_ipv6_authority() {
        assert!(handle_from_host("[::1]:443", &domain()).is_none());
    }

    #[test]
    fn refuses_a_punycode_host() {
        assert!(handle_from_host("xn--80ak6aa92e.example.com", &domain()).is_none());
    }

    // A handle domain is itself validated, so a typo or a special-use name is
    // caught at configuration time rather than silently never matching.
    #[test]
    fn a_handle_domain_is_validated() {
        assert!(HandleDomain::try_new("localhost").is_err());
        assert!(HandleDomain::try_new("").is_err());
        assert_eq!(
            HandleDomain::try_new("  Example.COM. ").unwrap().as_str(),
            "example.com"
        );
    }
}
