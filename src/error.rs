//! The two **open** error types — the ones an implementation outside this crate
//! produces.
//!
//! Every other error in vulpes is a closed `enum` naming its own failure modes
//! ([`HandleError`](crate::HandleError), [`VaultError`](crate::VaultError),
//! [`PlcError`](crate::PlcError), …). Storage and directory errors cannot be
//! closed: the whole point of [`KeyStore`](crate::KeyStore),
//! [`PlcOperationLog`](crate::PlcOperationLog),
//! [`OAuthStateStore`](crate::OAuthStateStore) and
//! [`PlcDirectory`](crate::PlcDirectory) is that *you* supply the implementation,
//! and its failures are its own. Both types are therefore thin opaque wrappers
//! that preserve the underlying error as a [`source`](std::error::Error::source)
//! so `{:#}`-style chains and `anyhow` context still read end to end.

use std::error::Error as StdError;
use std::fmt;

/// A boxed, thread-safe error — what both wrappers carry.
type BoxError = Box<dyn StdError + Send + Sync>;

/// A failure inside a storage implementation ([`KeyStore`](crate::KeyStore),
/// [`PlcOperationLog`](crate::PlcOperationLog),
/// [`OAuthStateStore`](crate::OAuthStateStore)).
///
/// Deliberately opaque: vulpes never branches on *why* a store failed, only on
/// whether it did. The one behavioural contract callers rely on is that a store
/// error is **not** "absent" — a missing row is `Ok(None)`, a broken database is
/// `Err`. Conflating them would let a read failure read as "no session"
/// (fail-open); keeping them apart is what makes the OAuth and custody paths
/// fail closed.
///
/// ```
/// # use vulpes::StorageError;
/// let err = StorageError::new(std::io::Error::other("disk on fire"));
/// assert!(err.to_string().contains("disk on fire"));
/// ```
#[derive(Debug)]
pub struct StorageError(BoxError);

impl StorageError {
    /// Wrap any thread-safe error as a storage failure. `anyhow::Error`,
    /// `sqlx::Error`, `std::io::Error` and `String` all convert.
    pub fn new(source: impl Into<BoxError>) -> Self {
        Self(source.into())
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl StdError for StorageError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

/// The result a storage trait method returns.
pub type StorageResult<T> = Result<T, StorageError>;

/// A failure submitting an operation to a PLC directory
/// ([`PlcDirectory`](crate::PlcDirectory)).
///
/// Opaque for the same reason as [`StorageError`]: the transport is the
/// implementation's business. Every directory failure is treated as
/// **retryable** by the minter — the operation is deterministic, so re-signing
/// and re-submitting it is safe (see [`Minter`](crate::Minter)).
#[derive(Debug)]
pub struct DirectoryError(BoxError);

impl DirectoryError {
    /// Wrap any thread-safe error as a directory-submission failure.
    pub fn new(source: impl Into<BoxError>) -> Self {
        Self(source.into())
    }
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PLC directory error: {}", self.0)
    }
}

impl StdError for DirectoryError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

/// The result a [`PlcDirectory`](crate::PlcDirectory) method returns.
pub type DirectoryResult<T> = Result<T, DirectoryError>;

#[cfg(test)]
mod tests {
    use super::*;

    // The wrapped error survives as a `source`, so a caller's `{:#}` chain (or
    // anyhow's) still names the real cause rather than a bare "storage error".
    #[test]
    fn storage_error_preserves_its_source() {
        let err = StorageError::new(std::io::Error::other("connection reset"));
        assert!(err.to_string().contains("connection reset"));
        assert!(err.source().is_some(), "the cause must remain reachable");
    }

    #[test]
    fn directory_error_preserves_its_source() {
        let err = DirectoryError::new("rejected: 400");
        assert!(err.to_string().contains("rejected: 400"));
        assert!(err.source().is_some());
    }
}
