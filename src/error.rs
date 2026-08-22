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

/// A boxed, thread-safe error — what every opaque wrapper carries.
pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

/// Define an opaque error wrapper: a newtype over [`BoxError`] with `new`,
/// a prefixed `Display`, and the wrapped error preserved as `source`. Every
/// "the implementation is the caller's" error in the crate is one of these
/// (FORKS F1), so the shape is written once.
macro_rules! opaque_error {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name($crate::error::BoxError);

        impl $name {
            /// Wrap any thread-safe error. `anyhow::Error`, `sqlx::Error`,
            /// `std::io::Error` and `String` all convert.
            pub fn new(source: impl Into<$crate::error::BoxError>) -> Self {
                Self(source.into())
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, concat!($prefix, ": {}"), self.0)
            }
        }

        impl ::std::error::Error for $name {
            fn source(&self) -> Option<&(dyn ::std::error::Error + 'static)> {
                Some(self.0.as_ref())
            }
        }
    };
}
#[cfg(feature = "acp")]
pub(crate) use opaque_error;

opaque_error!(
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
    StorageError,
    "storage error"
);

/// The result a storage trait method returns.
pub type StorageResult<T> = Result<T, StorageError>;

opaque_error!(
    /// A failure submitting an operation to a PLC directory
    /// ([`PlcDirectory`](crate::PlcDirectory)).
    ///
    /// Opaque for the same reason as [`StorageError`]: the transport is the
    /// implementation's business. Every directory failure is treated as
    /// **retryable** by the minter — the operation is deterministic, so re-signing
    /// and re-submitting it is safe (see [`Minter`](crate::Minter)).
    DirectoryError,
    "PLC directory error"
);

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
