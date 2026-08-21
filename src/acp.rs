//! The **ACP (Attested Claims Protocol)** core — record types with canonical
//! bytes, and the attestation signature.
//!
//! This module is the pure heart of the public lane: it knows how the three
//! record types (`net.got-paws.acp.claim`, `.attestation`, `.relationship`)
//! serialize, what an attestor signs, and how a verifier checks that
//! signature. It performs **no I/O** — no repo fetches, no DID resolution, no
//! status lists. Those are the orchestration layer's job
//! (`verify_attestation`, a later roadmap line) and they plug in around this.
//!
//! # Layout
//!
//! - [`record`] — the record structs, [`canonical_bytes`] and [`RecordCid`].
//! - [`sign`](mod@sign) — the pre-image with its injected `$sig` binding,
//!   [`sign`](fn@sign) and [`verify_sig`].
//! - [`ports`] — the I/O seams a verifier needs ([`RepoReader`],
//!   [`DidResolver`], [`StatusSource`]); implemented elsewhere, faked in tests.
//! - [`status`] — the signed, mirrorable status-list artifact.
//! - [`policy`] — [`TrustPolicy`], the verifier's own judgment (step 7).
//! - [`verify`] — [`Verifier::verify_attestation`] (the spec's seven steps)
//!   and [`Verifier::verify_relationship`].
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

pub use error::{CodecError, SigError, SignError, VerifyError};
pub use policy::{BasicPolicy, Decision, PolicyContext, TrustPolicy};
pub use ports::{
    DidResolver, FetchedRecord, KeyMaterial, RepoError, RepoReader, ResolveError, StatusFetchError,
    StatusSource,
};
pub use record::{
    AtUri, Attestation, Claim, ClaimKind, Datetime, RecordCid, RelKind, Relationship, Sig,
    StatusRef, StrongRef, UnsignedAttestation, canonical_bytes,
};
pub use sign::{
    Repository, SIG_BINDING_TYPE, SigAlg, Signer, VerifyingKey, preimage, preimage_cid, sign,
    verify_sig,
};
pub use status::{
    StatusList, UnsignedStatusList, newest_verifiable, sign_status_list, verify_status_list,
};
pub use verify::{Reason, Verdict, Verifier};
