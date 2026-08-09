//! `GET /.well-known/atproto-did` — serving handle resolution for a namespace
//! you operate, as a router you can merge into your app.
//!
//! A client resolving the handle `alice.example.com` fetches
//! `https://alice.example.com/.well-known/atproto-did`; the handle arrives as
//! the request's **authority**, and the response is the bare DID as
//! `text/plain`. That is the HTTPS half of atproto handle resolution — the half
//! you serve when you issue subdomains of a domain you control, behind one
//! wildcard DNS record and certificate.
//!
//! The route carries no authentication, changes no state, and reads no cookie,
//! so mount it **outside** any CSRF or session layer — like a health check. A
//! resolver sends no `Origin` and holds no session.
//!
//! ```text
//! GET /.well-known/atproto-did    Host: alice.example.com
//! → 200 text/plain  did:plc:ewvi7nxzyoun6zhxrhs64oiz
//!   Cache-Control: no-store       Vary: Host
//! → 404                            unknown handle, or an authority that is not ours
//! ```
//!
//! Both ways the authority can arrive are honored: HTTP/1.1's `Host` header and
//! HTTP/2 and HTTP/3's `:authority` pseudo-header, which hyper surfaces on the
//! request URI. The response is a function of that authority rather than of the
//! path — one URL, a different DID per handle — so it carries `Vary: Host` and
//! `Cache-Control: no-store`.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
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

/// The authority a request addressed, however the protocol version carried it.
///
/// HTTP/2 and HTTP/3 do **not** send a `Host` header: the authority travels in
/// the `:authority` pseudo-header, which hyper puts on the request URI. Reading
/// only `Host` therefore 404s every h2 request — the same handle resolving over
/// HTTP/1.1 and not over HTTP/2, which is the kind of bug that only shows up
/// once a load balancer negotiates h2 upstream.
///
/// The URI is preferred and the header is the fallback, matching RFC 9113
/// §8.3.1: where both are present, `:authority` is authoritative.
fn request_authority(request: &Request) -> Option<&str> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
        })
}

/// `GET /.well-known/atproto-did` — resolve the handle this request addressed
/// to its DID, returned as a bare `text/plain` body.
///
/// An authority outside the configured namespace, or one no identity holds, is
/// `404`. A resolver failure is `500`: the request was fine, and the client may
/// retry.
///
/// Every response carries `Cache-Control: no-store` and `Vary: Host`. The body
/// is a function of the **authority**, not of the path — one URL, a different
/// answer per handle — so a cache keyed on the path alone would serve one
/// user's DID for another's handle. `Vary` states the dependency and `no-store`
/// keeps an identity binding out of shared caches entirely.
async fn atproto_did<R: HandleResolver + 'static>(
    State(state): State<WellKnownState<R>>,
    request: Request,
) -> Response {
    // Parsed to an owned `Handle` before the first await: the request body is
    // `Send` but not `Sync`, so borrowing the request across one would make this
    // future non-`Send` and no longer a valid axum handler.
    let handle = request_authority(&request)
        .and_then(|authority| handle_from_host(authority, &state.handle_domain));

    let mut response = resolve(&state, handle).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::VARY, HeaderValue::from_static("Host"));
    response
}

/// The resolution itself, split out so the cache headers are applied on **every**
/// path — a hit, a miss and a failure alike — rather than once per `return`.
async fn resolve<R: HandleResolver + 'static>(
    state: &WellKnownState<R>,
    handle: Option<Handle>,
) -> Response {
    let Some(handle) = handle else {
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
    use crate::{Did, StorageResult};
    use async_trait::async_trait;

    fn domain() -> HandleDomain {
        HandleDomain::try_new("example.com").unwrap()
    }

    /// A resolver that answers for exactly one handle.
    struct OneHandle {
        handle: &'static str,
        did: &'static str,
    }

    #[async_trait]
    impl HandleResolver for OneHandle {
        async fn did_for_handle(&self, handle: &Handle) -> StorageResult<Option<Did>> {
            Ok((handle.as_str() == self.handle).then(|| Did::new(self.did)))
        }
    }

    fn state() -> WellKnownState<OneHandle> {
        WellKnownState {
            resolver: Arc::new(OneHandle {
                handle: "alice.example.com",
                did: "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
            }),
            handle_domain: domain(),
        }
    }

    /// An HTTP/1.1-shaped request: origin-form URI, authority in `Host`.
    fn http1_request(host: &str) -> Request {
        Request::builder()
            .uri(ATPROTO_DID_PATH)
            .header(header::HOST, host)
            .body(axum::body::Body::empty())
            .expect("a valid request")
    }

    /// An HTTP/2-shaped request: the authority on the URI (where hyper puts
    /// `:authority`) and **no** `Host` header at all.
    fn http2_request(authority: &str) -> Request {
        Request::builder()
            .uri(format!("https://{authority}{ATPROTO_DID_PATH}"))
            .body(axum::body::Body::empty())
            .expect("a valid request")
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the body reads");
        String::from_utf8(bytes.to_vec()).expect("a utf-8 body")
    }

    #[tokio::test]
    async fn an_http1_host_header_resolves() {
        let response = atproto_did(State(state()), http1_request("alice.example.com")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_text(response).await,
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    // HTTP/2 and HTTP/3 send NO `Host` header — the authority rides the
    // `:authority` pseudo-header, which hyper puts on the request URI. Reading
    // only `Host` would 404 every h2 request, so the same handle would resolve
    // over HTTP/1.1 and not over HTTP/2.
    #[tokio::test]
    async fn an_http2_authority_resolves_without_a_host_header() {
        let request = http2_request("alice.example.com");
        assert!(
            request.headers().get(header::HOST).is_none(),
            "the h2 shape carries no Host header — that is the point"
        );

        let response = atproto_did(State(state()), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_text(response).await,
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    // The URI authority wins where both are present (RFC 9113 §8.3.1), so a
    // spoofed `Host` cannot steer the answer away from the authority the
    // connection actually addressed.
    #[tokio::test]
    async fn the_uri_authority_wins_over_a_conflicting_host_header() {
        let request = Request::builder()
            .uri(format!("https://alice.example.com{ATPROTO_DID_PATH}"))
            .header(header::HOST, "mallory.example.com")
            .body(axum::body::Body::empty())
            .expect("a valid request");

        let response = atproto_did(State(state()), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_text(response).await,
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    // The body depends on the AUTHORITY, not the path: one URL, a different DID
    // per handle. Both headers must be present on every response — including the
    // 404s, which are just as cacheable a wrong answer.
    #[tokio::test]
    async fn every_response_is_uncacheable_and_varies_on_host() {
        let cases = [
            http1_request("alice.example.com"),  // 200
            http1_request("nobody.example.com"), // 404, unknown handle
            http1_request("alice.other.test"),   // 404, foreign authority
            Request::builder()
                .uri(ATPROTO_DID_PATH)
                .body(axum::body::Body::empty())
                .expect("a valid request"), // 404, no authority at all
        ];
        for request in cases {
            let response = atproto_did(State(state()), request).await;
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL),
                Some(&HeaderValue::from_static("no-store")),
            );
            assert_eq!(
                response.headers().get(header::VARY),
                Some(&HeaderValue::from_static("Host")),
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_handle_is_404() {
        let response = atproto_did(State(state()), http1_request("nobody.example.com")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_foreign_authority_is_404() {
        let response = atproto_did(State(state()), http2_request("alice.other.test")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
