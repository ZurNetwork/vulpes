//! **vulpes** — the ACP (Attested Claims Protocol) on AT Protocol, as a library.
//!
//! vulpes enforces the ACP as designed: claim and attestation records with
//! canonical bytes, signing and verification, status lists, and the
//! `did:plc` write path whose rotation layout the protocol's conformance
//! clauses bind. It carries no transport or framework of its own: storage and
//! the network arrive from the caller, through traits.
//!
//! # What is here
//!
//! - **[`acp`]** — the Attested Claims Protocol: records, signing, status
//!   lists, and the seven-step verifier over three caller-implemented ports.
//! - **[`plc`]** — the `did:plc` operation format: canonical DAG-CBOR, the
//!   signing/identifier byte split, DID derivation, CIDs. Pure, no I/O, pinned
//!   to a published vector.
//! - **[`Minter`]** — mint, [`update_handle`](Minter::update_handle),
//!   [`tombstone`](Minter::tombstone), shaped by an explicit [`MintPolicy`].
//! - **[`SecretVault`]** — the AEAD envelope custody keys are sealed in before
//!   any store sees them.
//! - **[`Handle`]** — atproto handle syntax, and nothing but the syntax.
//! - **[`KeyStore`] / [`PlcOperationLog`]** — the storage seam; the caller
//!   implements it over whatever it persists with.
//! - **[`PlcDirectory`]** — the seam a signed operation is submitted through;
//!   the caller implements it ([`NoopPlcDirectory`] submits nowhere).
//!
//! # Features
//!
//! | feature | brings |
//! |---|---|
//! | *(core, always on)* | [`plc`], [`Did`], [`Handle`], [`SecretVault`], [`CustodyKeys`], the storage traits, [`MintPolicy`], [`PlcDirectory`] |
//! | `minter` *(default)* | [`Minter`] — key generation and the write path |
//! | `acp` | [`acp`] — the Attested Claims Protocol: records, signing, status lists, the verifier |
//!
//! # Quickstart
//!
//! ```no_run
//! # #[cfg(feature = "minter")]
//! # async fn run(
//! #     keys: std::sync::Arc<dyn vulpes::KeyStore>,
//! #     log: std::sync::Arc<dyn vulpes::PlcOperationLog>,
//! #     vault: vulpes::SecretVault,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use vulpes::{Handle, MintPolicy, Minter, NoopPlcDirectory};
//!
//! // `keys` and `log` are your storage: implementations of `KeyStore` and
//! // `PlcOperationLog` over whatever you persist with.
//! // `vault` is the `SecretVault` — the minter seals custody and MACs the log
//! // with it, so a store never holds a plaintext key or an unauthenticated row.
//! let minter = Minter::new(
//!     keys,
//!     log,
//!     Arc::new(NoopPlcDirectory), // swap for your `PlcDirectory` to register
//!     MintPolicy::identity_only(),
//!     vault,
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
//! Read [`SecretVault`]'s module documentation before deploying: vulpes encrypts
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

#[cfg(feature = "acp")]
pub mod acp;

pub use did::{Did, DidError};
pub use directory::{NoopPlcDirectory, PlcDirectory};
pub use error::{DirectoryError, DirectoryResult, StorageError, StorageResult};
pub use handle::{HANDLE_MAX_LEN, Handle, HandleError, LABEL_MAX_LEN};
pub use keys::{
    CUSTODY_AAD_TAG, CustodyEnvelope, CustodyKeys, KeyRole, SECRET_KEY_LEN, SealedKeys, SecretKey,
    UnknownCustodyEnvelope,
};
pub use policy::{
    MAX_ROTATION_KEYS, MAX_VERIFICATION_METHODS, MIN_ROTATION_KEYS, MintPolicy, PolicyError,
};
pub use store::{KeyStore, PlcOperationLog, PlcOperationRecord};
pub use vault::{OPLOG_MAC_LABEL, OPLOG_MAC_LEN, ROOT_KEY_LEN, SecretVault, VaultError};

#[cfg(feature = "minter")]
pub use minter::{MintError, Minter};
