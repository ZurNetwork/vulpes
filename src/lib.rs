//! **zurid** — AT Protocol identity for Rust servers.
//!
//! Reading an atproto identity is well served in Rust. *Operating* one is not:
//! minting a `did:plc`, custodying its keys, re-pointing its handle and
//! tombstoning it are a byte-exact signing problem with a durability problem
//! wrapped around it, and until now every server that needed it wrote its own.
//! zurid is that code, extracted and made reusable.
//!
//! # What is here
//!
//! - **[`plc`]** — the `did:plc` operation format: canonical DAG-CBOR, the
//!   signing/identifier byte split, DID derivation, CIDs. Pure, no I/O, pinned
//!   to a published vector.
//! - **[`Minter`]** — mint, [`update_handle`](Minter::update_handle),
//!   [`tombstone`](Minter::tombstone), shaped by an explicit [`MintPolicy`].
//! - **[`SecretVault`]** — one AEAD envelope for every at-rest secret, whether
//!   custody keys or OAuth tokens.
//! - **[`Handle`]** — atproto handle syntax, and nothing but the syntax.
//! - **[`KeyStore`] / [`PlcOperationLog`] / [`OAuthStateStore`]** — the storage
//!   seam, with [PostgreSQL implementations](postgres) and migrations included.
//! - **[`oauth`]** — the atproto OAuth handshake over `jacquard`, with its state
//!   sealed and durable.
//! - **[`axum`]** — `/.well-known/atproto-did` as a router you can merge.
//!
//! # Features
//!
//! | feature | brings |
//! |---|---|
//! | *(core, always on)* | [`plc`], [`Did`], [`Handle`], [`SecretVault`], [`CustodyKeys`], the storage traits, [`MintPolicy`], [`NoopPlcDirectory`] |
//! | `minter` *(default)* | [`Minter`] — key generation and the write path |
//! | `directory` *(default)* | [`HttpPlcDirectory`] — submission over HTTP |
//! | `oauth` | [`oauth::Authenticator`] and the durable state bridge |
//! | `postgres` | [`postgres`] — sqlx stores plus the migration SQL |
//! | `axum` | [`axum`] — the handle-resolution route |
//!
//! # Quickstart
//!
//! ```no_run
//! # #[cfg(feature = "minter")]
//! # async fn run(
//! #     keys: std::sync::Arc<dyn zurid::KeyStore>,
//! #     log: std::sync::Arc<dyn zurid::PlcOperationLog>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use zurid::{Handle, MintPolicy, Minter, NoopPlcDirectory};
//!
//! // `keys` and `log` are your storage; with the `postgres` feature they are
//! // `PgKeyStore` and `PgPlcOperationLog`, both built from an `sqlx::PgPool`.
//! let minter = Minter::new(
//!     keys,
//!     log,
//!     Arc::new(NoopPlcDirectory), // swap for `HttpPlcDirectory::canonical()` to register
//!     MintPolicy::identity_only(),
//! )?;
//!
//! let handle = Handle::try_new("alice.example.com")?;
//! let did = minter.mint(&handle).await?;
//! println!("minted {did}");
//!
//! // Later: re-point the handle, or retire the identity.
//! minter.update_handle(&did, &Handle::try_new("alice.example.org")?).await?;
//! minter.tombstone(&did).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security posture
//!
//! Read [`SecretVault`]'s module documentation before deploying: zurid encrypts
//! every secret it stores, but the root key's custody is yours to get right.
//! Key material is [`Zeroize`](zeroize::Zeroize)d on drop and redacted in
//! `Debug`; the operation log's integrity constraints are what stop a chain from
//! forking under concurrency.
//!
//! # License
//!
//! MIT OR Apache-2.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod did;
mod directory;
mod error;
mod handle;
mod keys;
mod policy;
mod store;
mod vault;

pub mod plc;

#[cfg(test)]
mod memory;

#[cfg(feature = "minter")]
mod minter;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use did::{Did, DidError};
pub use directory::{CANONICAL_DIRECTORY, NoopPlcDirectory, PlcDirectory};
pub use error::{DirectoryError, DirectoryResult, StorageError, StorageResult};
pub use handle::{HANDLE_MAX_LEN, Handle, HandleError, LABEL_MAX_LEN};
pub use keys::{CustodyKeys, KeyRole, SECRET_KEY_LEN, SecretKey};
pub use policy::{
    MAX_ROTATION_KEYS, MAX_VERIFICATION_METHODS, MIN_ROTATION_KEYS, MintPolicy, PolicyError,
};
pub use store::{HandleResolver, KeyStore, OAuthStateStore, PlcOperationLog, PlcOperationRecord};
pub use vault::{ROOT_KEY_LEN, SecretVault, VaultError};

#[cfg(feature = "directory")]
pub use directory::HttpPlcDirectory;
#[cfg(feature = "minter")]
pub use minter::{MintError, Minter};
