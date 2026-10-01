//! Submitting a signed operation to a PLC directory.
//!
//! Registering a `did:plc` means POSTing its signed genesis operation to a
//! directory (`POST {base_url}/{did}`); every later operation for that DID goes
//! to the same endpoint. The directory is a *public* system of record, so a
//! submission is always a separate, retryable step — never inside whatever
//! transaction wrote your private rows.
//!
//! vulpes ships the seam, not the client: the caller implements [`PlcDirectory`]
//! over its own HTTP stack, timeouts and egress policy. [`NoopPlcDirectory`]
//! submits nowhere.
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
    ///
    /// `did` is a `&str` and [`Did::new`](crate::Did::new) validates nothing, so
    /// an implementation that puts it in a URL, a path or a shell command must
    /// **validate or escape it first**. Parsing it as a [`Did`](crate::Did)
    /// (`did.parse::<Did>()`) checks it against the W3C DID ABNF, whose
    /// characters are already URL-path-safe: a `/`, `?` or `#` cannot survive
    /// the parse.
    async fn submit(&self, did: &str, operation: &serde_json::Value) -> DirectoryResult<()>;
}

/// A directory that accepts every operation and does nothing.
///
/// The right choice for local development and for tests, and for the phase of a
/// deployment where identities are being minted and logged but deliberately not
/// yet registered publicly.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPlcDirectory;

#[async_trait]
impl PlcDirectory for NoopPlcDirectory {
    async fn submit(&self, _did: &str, _operation: &serde_json::Value) -> DirectoryResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
