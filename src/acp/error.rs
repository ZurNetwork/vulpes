//! Errors of the ACP core — one closed enum per concern (FORKS F1).
//!
//! Foreign errors (the DAG-CBOR codec, `atrium-crypto`) are stringified into
//! owned variants rather than held as foreign types, so this crate's public
//! error surface does not change when a dependency's does. The one **open**
//! error here is [`SignerError`]: a [`Signer`](super::sign::Signer) is the
//! caller's (an HSM, a remote service), so its failure is wrapped opaque with
//! the source chain kept, like the ports' errors.

use crate::error::opaque_error;

opaque_error!(
    /// A [`Signer`](super::sign::Signer) refused — bad key material, an HSM
    /// saying no, a remote signer unreachable.
    SignerError,
    "signer error"
);

/// A record could not be encoded, decoded, or was rejected as malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The DAG-CBOR encoder failed. Practically unreachable for well-formed
    /// records; kept as a variant rather than a panic.
    #[error("failed to encode as DAG-CBOR: {0}")]
    Encode(String),
    /// The bytes were not a well-formed record of the expected shape.
    #[error("failed to decode DAG-CBOR record: {0}")]
    Decode(String),
    /// A field failed its syntax check on construction.
    #[error("invalid {field}: {detail}")]
    InvalidField {
        /// The record field, as it appears on the wire (`createdAt`, `claim.uri`, …).
        field: &'static str,
        /// What was wrong with it.
        detail: String,
    },
    /// A `payload` / `scope` value carried something the atproto data model
    /// forbids in a record: a float, a `null`, or an out-of-range integer.
    #[error("disallowed value at {path}: {detail}")]
    DisallowedValue {
        /// JSON-pointer-ish path into the value (`/address`, `/tags/2`).
        path: String,
        /// Which rule it broke.
        detail: &'static str,
    },
}

/// Signing an attestation or status list failed.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The pre-image could not be built.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The [`Signer`](super::sign::Signer) refused.
    #[error(transparent)]
    Crypto(#[from] SignerError),
}

/// An attestation signature did not verify.
///
/// Every variant means **not in force**; the distinction is diagnostic only.
/// A verifier must not treat any of them as "retry with a looser policy".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    /// The pre-image could not be rebuilt from the record.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// No supplied key verified the signature over the pre-image. This is
    /// also what a transplanted record, a tampered field, a high-S signature
    /// and a wrong-curve key all produce — by design they are
    /// indistinguishable from "wrong key".
    #[error("no supplied key verified the attestation signature")]
    NoKeyVerified,
    /// A key was offered whose algorithm the atproto profile does not allow.
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The `sig` bytes are not a 64-byte compact `r‖s` signature.
    #[error("malformed signature: {0}")]
    Malformed(String),
}

/// The verifier's **infrastructure** failed — a port returned `Err`.
///
/// Deliberately distinct from a [`Verdict::NotInForce`](super::verify::Verdict):
/// "the PDS timed out" is not "the vouch is bad". The caller decides whether
/// to retry or to deny; the verifier never converts one into the other.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The repository reader failed.
    #[error(transparent)]
    Repo(#[from] super::ports::RepoError),
    /// DID resolution failed.
    #[error(transparent)]
    Resolve(#[from] super::ports::ResolveError),
    /// Fetching a status artifact failed.
    #[error(transparent)]
    Status(#[from] super::ports::StatusFetchError),
}
