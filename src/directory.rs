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
    /// Build a submitter targeting `base_url` (any trailing slash is trimmed, so
    /// the request path is a single-slashed `/{did}`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Build a submitter targeting [`CANONICAL_DIRECTORY`].
    pub fn canonical() -> Self {
        Self::new(CANONICAL_DIRECTORY)
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
