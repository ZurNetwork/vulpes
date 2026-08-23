//! The **ACP (Attested Claims Protocol)** core — record types with canonical
//! bytes, and the attestation signature.
//!
//! This module is the reference verifier of the public lane: it knows how
//! the two record types (`net.got-paws.acp.claim`, `.attestation`) and the
//! status-list artifact serialize, what an attestor signs, and runs the
//! spec's seven verification steps. It performs no I/O **of its own** —
//! every repo fetch, DID resolution and status-list read goes through the
//! three [`ports`], which the caller implements (a PDS client, a directory
//! client, a mirror fetch) and tests fake in memory.
//!
//! # Layout
//!
//! - [`record`] — the record structs, [`canonical_bytes`] and [`RecordCid`].
//! - [`sign`](mod@sign) — the pre-image with its injected `$sig` binding,
//!   [`sign`](fn@sign) and [`verify_sig`].
//! - [`ports`] — the I/O seams a verifier needs ([`RepoReader`],
//!   [`DidResolver`], [`StatusSource`]); implemented elsewhere, faked in tests.
//! - [`status`] — the signed, mirrorable status-list artifact.
//! - [`policy`] — [`TrustPolicy`], the verifier's own judgment (step 6,
//!   ahead of the status fetch it gates).
//! - [`verify`] — [`Verifier::verify_attestation`], the spec's seven steps.
//!   Relationships are attestations whose attestor is the counterpart
//!   (FORKS F45); there is no second path.
//! - [`error`] — one closed error enum per concern.
//!
//! # The binding, in one paragraph
//!
//! An attestation's signature does not cover the stored record. It covers a
//! **pre-image**: the record minus `sig`, plus a `$sig` object that is never
//! stored and names the **repository DID** the record lives in. The signer
//! supplies the subject's repo DID; the verifier supplies the DID of the repo
//! it *actually fetched the record from*. A record transplanted into another
//! repo therefore has no matching pre-image at all — the transplant defense is
//! unrepresentable, not a check that can be skipped. See
//! [`sign::Repository`] for the type that carries that DID, and
//! `docs/acp.md` §Signing for the normative text.

pub mod error;
pub mod policy;
pub mod ports;
pub mod record;
pub mod sign;
pub mod status;
pub mod verify;

#[cfg(test)]
pub(crate) mod memory;

pub use error::{CodecError, SigError, SignError, SignerError, VerifyError};
pub use policy::{BasicPolicy, Decision, PolicyContext, TrustPolicy};
pub use ports::{
    DidResolver, FetchedRecord, KeyMaterial, RepoError, RepoReader, ResolveError, StatusFetchError,
    StatusSource,
};
pub use record::{
    ATTESTATION_TYPE, AtUri, Attestation, CLAIM_TYPE, Claim, ClaimKind, Datetime, MAX_SAFE_INTEGER,
    RecordCid, STATUS_LIST_TYPE, Sig, StatusRef, StatusUri, StrongRef, UnsignedAttestation,
    canonical_bytes, check_opaque, from_canonical_bytes,
};
pub use sign::{
    Repository, SIG_BINDING_TYPE, SigAlg, Signer, VerifyingKey, preimage, preimage_cid, sign,
    verify_sig,
};
pub use status::{
    BitString, MAX_STATUS_COPIES, MAX_STATUS_LIST_BYTES, StatusList, StatusListType,
    UnsignedStatusList, newest_verifiable, sign_status_list, verify_status_list,
};
pub use verify::{CLOCK_SKEW_SECS, Reason, Verdict, Verifier};
