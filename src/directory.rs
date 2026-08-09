//! Submitting a signed operation to a PLC directory.
//!
//! Registering a `did:plc` means POSTing its signed genesis operation to a
//! directory (`POST {base_url}/{did}`); every later operation for that DID goes
//! to the same endpoint. The directory is a *public* system of record, so a
//! submission is always a separate, retryable step — never inside whatever
//! transaction wrote your private rows.
//!
//! The [`PlcDirectory`] trait and the [`NoopPlcDirectory`] are always available;
//! the real HTTP client [`HttpPlcDirectory`] needs the `directory` feature.
//!
//! Spec: <https://web.plc.directory/spec/v0.1/did-plc>.

#[cfg(feature = "directory")]
use std::time::Duration;

use async_trait::async_trait;

use crate::DirectoryResult;

/// Submits a signed PLC operation for a DID.
///
/// The operation is passed as its already-serialized JSON body, so one
/// implementation handles a genesis operation, an update and a tombstone alike
/// without coupling to their Rust shapes.
#[async_trait]
pub trait PlcDirectory: Send + Sync {
    /// Submit `operation` (its JSON body) registering or updating `did`.
    ///
    /// `did` is a `&str` and [`Did::new`](crate::Did::new) validates nothing, so
    /// an implementation that puts it in a URL, a path or a shell command must
    /// **validate or escape it first** — see [`HttpPlcDirectory`], which parses
    /// it against the W3C DID ABNF before interpolating.
    async fn submit(&self, did: &str, operation: &serde_json::Value) -> DirectoryResult<()>;
}

/// A directory that accepts every operation and does nothing.
///
/// The right choice for local development and for tests, and for the phase of a
/// deployment where identities are being minted and logged but deliberately not
/// yet registered publicly. Logs only the DID — never key material, never the
/// operation body.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPlcDirectory;

#[async_trait]
impl PlcDirectory for NoopPlcDirectory {
    async fn submit(&self, _did: &str, _operation: &serde_json::Value) -> DirectoryResult<()> {
        #[cfg(feature = "directory")]
        tracing::debug!(did = %_did, "PLC directory submission skipped (no-op directory)");
        Ok(())
    }
}

/// The canonical PLC directory.
pub const CANONICAL_DIRECTORY: &str = "https://plc.directory";

/// The real submitter: `POST {base_url}/{did}` with the signed operation as
/// JSON.
///
/// Holds a shared `reqwest` client, so it is cheap to reuse across submissions.
#[cfg(feature = "directory")]
pub struct HttpPlcDirectory {
    /// The directory base URL, e.g. [`CANONICAL_DIRECTORY`] or a locally-run
    /// `@did-plc/server`. Stored without a trailing slash.
    base_url: String,
    /// Shared HTTP client (rustls), reused across submissions.
    client: reqwest::Client,
}

#[cfg(feature = "directory")]
impl HttpPlcDirectory {
    /// How long the default client waits to establish a connection.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// The default client's total per-submission budget — connect, send, and
    /// read the response.
    ///
    /// A submission sits in the middle of minting: [`Minter::mint`](crate::Minter::mint)
    /// has already written custody and logged the genesis when it calls this,
    /// and `update_handle` and `tombstone` block their log write on it. Without
    /// a timeout, one unresponsive directory pins those tasks indefinitely.
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Build a submitter targeting `base_url` (any trailing slash is trimmed, so
    /// the request path is a single-slashed `/{did}`), over a client with
    /// [`DEFAULT_CONNECT_TIMEOUT`](HttpPlcDirectory::DEFAULT_CONNECT_TIMEOUT)
    /// and [`DEFAULT_REQUEST_TIMEOUT`](HttpPlcDirectory::DEFAULT_REQUEST_TIMEOUT).
    ///
    /// Falls back to `reqwest`'s own defaults if the client cannot be built —
    /// which in practice means the TLS backend failed to initialize, and the
    /// first submission is going to fail anyway. Refusing to construct here
    /// would trade a clear submission error for an obscure one at boot; use
    /// [`with_client`](HttpPlcDirectory::with_client) when you want to see that
    /// failure yourself.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, Self::default_client())
    }

    /// Build a submitter targeting [`CANONICAL_DIRECTORY`], with the same
    /// default timeouts as [`new`](HttpPlcDirectory::new).
    pub fn canonical() -> Self {
        Self::new(CANONICAL_DIRECTORY)
    }

    /// The timeout-bearing client [`new`](HttpPlcDirectory::new) uses when the
    /// caller supplies none.
    fn default_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Self::DEFAULT_CONNECT_TIMEOUT)
            .timeout(Self::DEFAULT_REQUEST_TIMEOUT)
            .build()
            .unwrap_or_default()
    }

    /// Build a submitter over a `reqwest` client you already configured
    /// (timeouts, proxy, connection pool).
    pub fn with_client(base_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }
}

#[cfg(feature = "directory")]
#[async_trait]
impl PlcDirectory for HttpPlcDirectory {
    async fn submit(&self, did: &str, operation: &serde_json::Value) -> DirectoryResult<()> {
        // The DID is interpolated straight into a URL path, so it is validated
        // against the W3C DID ABNF FIRST. `Did::new` performs no validation and
        // the trait takes a `&str`, so without this a caller could hand over
        // `../../admin` or `x?query=` and steer the request off the endpoint
        // entirely. The ABNF's `idchar` set (ALPHA / DIGIT / `.` / `-` / `_` /
        // `%HH`) plus `:` is already URL-path-safe — a `/`, `?` or `#` cannot
        // survive the parse — so a value that passes needs no further escaping,
        // and one that fails was never a DID a directory would accept.
        let did = crate::Did::parse(did).map_err(crate::DirectoryError::new)?;
        let did = did.as_str();

        let url = format!("{}/{}", self.base_url, did);
        let response = self
            .client
            .post(&url)
            .json(operation)
            .send()
            .await
            .map_err(crate::DirectoryError::new)?;
        if !response.status().is_success() {
            let status = response.status();
            // The body may carry a PLC validation error; it holds no secret
            // (the operation's every field is public).
            let body = response.text().await.unwrap_or_default();
            return Err(crate::DirectoryError::new(format!(
                "PLC directory rejected {did}: {status} {body}"
            )));
        }
        tracing::debug!(%did, "PLC directory submission accepted");
        Ok(())
    }
}

#[cfg(all(test, feature = "directory"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The HTTP submitter must (1) trim a trailing slash on the base URL so the
    // target path is single-slashed `/{did}`, and (2) surface a non-2xx response
    // as an error rather than a silent success. A one-shot local server captures
    // the request line and replies 400.
    #[tokio::test]
    async fn http_directory_trims_trailing_slash_and_errors_on_non_2xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_line = Arc::new(Mutex::new(String::new()));
        let captured = request_line.clone();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 2048];
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            *captured.lock().unwrap() = request.lines().next().unwrap_or("").to_string();
            socket
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 3\r\nconnection: close\r\n\r\nbad",
                )
                .await
                .unwrap();
            let _ = socket.shutdown().await;
        });

        // The base URL carries a trailing slash on purpose — it must be trimmed.
        let directory = HttpPlcDirectory::new(format!("http://{addr}/"));
        let result = directory
            .submit("did:plc:x", &serde_json::json!({"type": "plc_operation"}))
            .await;

        assert!(result.is_err(), "a non-2xx response must be an error");
        server.await.unwrap();
        let line = request_line.lock().unwrap().clone();
        assert!(
            line.starts_with("POST /did:plc:x "),
            "path must be single-slashed `/did:plc:x`, got request line: {line:?}"
        );
    }

    // The DID lands in a URL PATH. `Did::new` validates nothing and the trait
    // takes a `&str`, so a caller can offer anything; a value that would escape
    // the `{base}/{did}` shape — a path traversal, a query or fragment, a whole
    // second URL — must be refused BEFORE a request is built. No listener is
    // started here on purpose: reaching the network at all would be the bug.
    #[tokio::test]
    async fn a_did_that_is_not_a_did_never_becomes_a_url() {
        let directory = HttpPlcDirectory::new("http://127.0.0.1:1/");
        for hostile in [
            "../../admin",
            "did:plc:x/../../admin",
            "did:plc:x?force=1",
            "did:plc:x#frag",
            "https://evil.example.com/",
            "did:plc:x evil",
            "",
            "not-a-did",
        ] {
            let result = directory.submit(hostile, &serde_json::json!({})).await;
            assert!(
                result.is_err(),
                "`{hostile}` must be refused before a request is built"
            );
        }
    }

    // The no-op directory accepts anything without touching the network — the
    // property every local/dev deployment relies on.
    #[tokio::test]
    async fn noop_directory_accepts_without_submitting() {
        NoopPlcDirectory
            .submit("did:plc:x", &serde_json::json!({}))
            .await
            .expect("the no-op directory never fails");
    }
}
