//! `verify_attestation` — the spec's seven steps as one function.
//!
//! Everything here reads through the [ports](super::ports) and nothing else.
//! There is no attestor port, so there is nothing to call back: the attestor
//! may be gone and every step still runs. That is the kill test, and
//! `tests::kill_test` exercises it literally.
//!
//! Two kinds of "no":
//!
//! - [`Verdict::NotInForce`] with a [`Reason`] — the protocol says this vouch
//!   does not count. Final for this input.
//! - [`VerifyError`] — a port failed. Not a statement about the vouch; the
//!   caller decides whether to retry or deny.
//!
//! Conflating them would let an outage read as "not revoked" (fail-open) or
//! as "revoked" (an outage becomes a denial of service on honest subjects).

use crate::Did;

use super::error::VerifyError;
use super::policy::{Decision, PolicyContext, TrustPolicy};
use super::ports::{DidResolver, FetchedRecord, RepoReader, StatusSource};
use super::record::{AtUri, Attestation, Claim, Datetime, canonical_bytes};
use super::sign::{Repository, verify_sig};
use super::status::newest_verifiable;

/// Tolerated clock skew when checking `issuedAt` is not in the future.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// Why an attestation is **not in force**. Every variant is final for the
/// inputs given; none is "try again".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// No record at the attestation's address.
    AttestationMissing,
    /// The referenced claim is gone (retracted) — step 1.
    ClaimMissing,
    /// The referenced claim exists but its CID changed (rewritten) — step 1.
    ClaimRewritten,
    /// The referenced claim was *read from* some other repo than the
    /// subject's — step 2. A claim carries no subject field; *whose* claim
    /// it is comes entirely from the repo it sits in, and a vouch must
    /// point at the subject's own so the subject keeps the retraction
    /// switch. [`ClaimUriNotSubject`](Self::ClaimUriNotSubject) catches
    /// the address before the fetch; this catches a reader that resolved
    /// it somewhere else anyway.
    ClaimNotInSubjectRepo,
    /// A record exists but does not decode as its type.
    Malformed(String),
    /// `subject` is not the owner of the repo the record came from — step 2.
    SubjectMismatch,
    /// `claim.uri` does not point into the subject's repo — checked
    /// *before* step 1 fetches it. The attestation's author chose that
    /// address; the verifier will not send a request to an authority other
    /// than the one the record itself names as subject.
    ClaimUriNotSubject,
    /// The attestor's DID does not resolve — step 3.
    AttestorUnresolvable,
    /// The signature does not verify under the attestor's current keys, as
    /// fetched from this repository — step 4 (tamper, rotation, transplant).
    BadSig,
    /// The stored bytes are not the canonical encoding of the record they
    /// decode to — step 4. Unknown fields ride along unsigned, or the CBOR
    /// is non-minimal / mis-ordered: either way the record's CID is not a
    /// stable identifier for what was signed, and a subject who holds the
    /// repo could plant attestor-attributed data the attestor never saw.
    NonCanonical,
    /// `expiresAt` has passed — step 5.
    Expired,
    /// `issuedAt` is further in the future than [`CLOCK_SKEW_SECS`].
    NotYetValid,
    /// The verifier's own policy declined — step 6.
    PolicyRejected(String),
    /// Freshness was demanded but `status.list` is not something this
    /// verifier will send a request for (an IP literal, a special-use name;
    /// [`StatusUri::fetchable`](super::record::StatusUri::fetchable)) —
    /// step 7. No fetch was made.
    StatusUnfetchable(String),
    /// Freshness was demanded and no copy of the status list was reachable — step 7.
    StatusUnavailable,
    /// Copies were reachable but none verified under the attestor's keys — step 7.
    StatusUnverifiable,
    /// The newest verifiable status list is older than a freshness bound
    /// — step 7: the attestor's own signed `ttl`, the policy's
    /// [`max_status_age_secs`](super::policy::TrustPolicy::max_status_age_secs),
    /// whichever is tighter. Only reachable when one of them is set; with
    /// either, an adversary withholding fresh copies lands here, never on
    /// in-force.
    StatusStale,
    /// The status list does not cover `status.index` — step 7.
    StatusIndexOutOfRange,
    /// The revocation bit is set — step 7.
    Revoked,
}

/// The outcome of verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every step passed.
    InForce {
        /// Who vouched.
        attestor: Did,
        /// The stated method, if any.
        method: Option<String>,
        /// Seconds until expiry — a freshness signal for the caller.
        remaining_secs: i64,
    },
    /// A step failed; see [`Reason`].
    NotInForce(Reason),
}

impl Verdict {
    /// `true` for [`Verdict::InForce`].
    pub fn is_in_force(&self) -> bool {
        matches!(self, Self::InForce { .. })
    }
}

/// The verifier: the four seams, borrowed.
pub struct Verifier<'a> {
    /// Subjects' repositories.
    pub repo: &'a dyn RepoReader,
    /// DID documents.
    pub dids: &'a dyn DidResolver,
    /// Status-list mirrors.
    pub status: &'a dyn StatusSource,
    /// This verifier's judgment.
    pub policy: &'a dyn TrustPolicy,
}

macro_rules! not_in_force {
    ($reason:expr) => {
        return Ok(Verdict::NotInForce($reason))
    };
}

/// What a record fetch came back with, once the port has answered.
///
/// A port *failure* is not one of these — it surfaces as [`VerifyError`]
/// from [`Verifier::fetch`] itself, so the two kinds of "no record" never
/// share a type.
enum Fetched<T> {
    /// The repo has no record at that address.
    Absent,
    /// The repo has bytes there, but they do not decode as `T`.
    Malformed(Reason),
    /// The record, with the bytes and repository it was read from.
    Found(FetchedRecord, T),
}

impl Verifier<'_> {
    /// Fetch and decode one record through the [`RepoReader`] port.
    async fn fetch<T: serde::de::DeserializeOwned>(
        &self,
        uri: &AtUri,
    ) -> Result<Fetched<T>, VerifyError> {
        let Some(fetched) = self.repo.get_record(uri).await? else {
            return Ok(Fetched::Absent);
        };
        Ok(match fetched.decode::<T>() {
            Ok(record) => Fetched::Found(fetched, record),
            Err(err) => Fetched::Malformed(Reason::Malformed(format!("{uri}: {err}"))),
        })
    }

    /// The spec's seven steps (`docs/acp.md` §Verification), for the
    /// attestation at `uri`, as of `now`.
    pub async fn verify_attestation(
        &self,
        uri: &AtUri,
        now: &Datetime,
    ) -> Result<Verdict, VerifyError> {
        // 1. The attestation and the exact claim it binds to.
        let (fetched, att) = match self.fetch::<Attestation>(uri).await? {
            Fetched::Absent => not_in_force!(Reason::AttestationMissing),
            Fetched::Malformed(reason) => not_in_force!(reason),
            Fetched::Found(fetched, att) => (fetched, att),
        };
        // `claim.uri` is an address the record's author wrote. Before any
        // request goes there, it must name the subject — the one authority
        // this verification is about. (Step 2 re-checks the repo it was
        // actually read from; this is the same fact, asked before the I/O.)
        if att.body.claim.uri.authority() != att.body.subject.as_str() {
            not_in_force!(Reason::ClaimUriNotSubject);
        }
        let (claim_fetched, claim) = match self.fetch::<Claim>(&att.body.claim.uri).await? {
            Fetched::Absent => not_in_force!(Reason::ClaimMissing),
            Fetched::Malformed(reason) => not_in_force!(reason),
            Fetched::Found(fetched, claim) => (fetched, claim),
        };
        if claim_fetched.cid() != &att.body.claim.cid {
            not_in_force!(Reason::ClaimRewritten);
        }

        // 2. The record says who it is about; the repo says whose it is —
        //    and the claim must be there too.
        if att.body.subject != fetched.repository {
            not_in_force!(Reason::SubjectMismatch);
        }
        if claim_fetched.repository != att.body.subject {
            not_in_force!(Reason::ClaimNotInSubjectRepo);
        }

        // 3. The attestor's *current* keys.
        let Some(keys) = self.dids.keys(&att.body.attestor).await? else {
            not_in_force!(Reason::AttestorUnresolvable);
        };

        // 4. The signature, bound to the repository we actually read from —
        //    and the stored bytes must be exactly the canonical form of what
        //    was signed, so nothing rides along outside the signature.
        if verify_sig(&att, Repository(&fetched.repository), &keys.verification).is_err() {
            not_in_force!(Reason::BadSig);
        }
        match canonical_bytes(&att) {
            Ok(canonical) if canonical == fetched.bytes() => {}
            Ok(_) => not_in_force!(Reason::NonCanonical),
            Err(err) => not_in_force!(Reason::Malformed(format!("{uri}: {err}"))),
        }

        // 5. Lifetime.
        let now_s = now.to_unix();
        let issued = att.body.issued_at.to_unix();
        let expires = att.body.expires_at.to_unix();
        if expires <= now_s {
            not_in_force!(Reason::Expired);
        }
        if issued > now_s + CLOCK_SKEW_SECS {
            not_in_force!(Reason::NotYetValid);
        }

        // 6. Judgment — before any fetch the attestation could steer.
        let ctx = PolicyContext {
            attestor: &att.body.attestor,
            method: att.body.method.as_deref(),
            claim_kind: &claim.kind,
            age_secs: now_s - issued,
            remaining_secs: expires - now_s,
            has_status: att.body.status.is_some(),
        };
        if let Decision::Reject(why) = self.policy.decide(&ctx) {
            not_in_force!(Reason::PolicyRejected(why));
        }

        // 7. Revocation, when there is a pointer and the policy cares.
        if let Some(status) = &att.body.status
            && self.policy.demands_freshness()
        {
            // The identifier was only syntax-checked on decode; whether it
            // may be *fetched* is decided here, right before the request.
            if let Err(err) = status.list.fetchable() {
                not_in_force!(Reason::StatusUnfetchable(err.to_string()));
            }
            let copies = self.status.fetch(&status.list).await?;
            if copies.is_empty() {
                not_in_force!(Reason::StatusUnavailable);
            }
            let Some(list) = newest_verifiable(
                &copies,
                &att.body.attestor,
                status.list.as_str(),
                &keys.verification,
                now,
            ) else {
                not_in_force!(Reason::StatusUnverifiable);
            };
            // Two freshness bounds, the tighter wins: the attestor's own
            // `ttl` inside the signed list, and the verifier's policy. A
            // list with neither stands however old it is (the kill test:
            // a dead attestor's last list ages out with its attestations).
            let list_age = now_s - list.body.issued_at.to_unix();
            let issuer_bound = list.body.ttl.and_then(|t| i64::try_from(t).ok());
            let bound = match (issuer_bound, self.policy.max_status_age_secs()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            // Strictly past the bound: at `age == bound` the copy still
            // counts (expiry, by contrast, is inclusive — `expires <= now`).
            if let Some(max) = bound
                && list_age > max
            {
                not_in_force!(Reason::StatusStale);
            }
            match list.is_set(status.index) {
                None => not_in_force!(Reason::StatusIndexOutOfRange),
                Some(true) => not_in_force!(Reason::Revoked),
                Some(false) => {}
            }
        }

        Ok(Verdict::InForce {
            attestor: att.body.attestor,
            method: att.body.method,
            remaining_secs: expires - now_s,
        })
    }
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};

    use super::super::kind::ClaimKind;
    use super::*;
    use crate::acp::VerifyingKey;
    use crate::acp::memory::{MemoryRepo, MemoryResolver, MemoryStatus};
    use crate::acp::policy::BasicPolicy;
    use crate::acp::ports::KeyMaterial;
    use crate::acp::record::fixtures::{attestor, kit, mallory};
    use crate::acp::record::{
        ATTESTATION_TYPE, CLAIM_TYPE, Claim, MAX_SAFE_INTEGER, StatusRef, StrongRef,
        UnsignedAttestation,
    };
    use crate::acp::sign::sign;
    use crate::acp::status::{UnsignedStatusList, sign_status_list};

    const NOW: &str = "2026-08-29T10:00:00Z"; // nine days after issuance
    const STATUS_URL: &str = "https://attest.got-paws.net/status/1";
    const INDEX: u64 = 4127;

    fn key(seed: u8) -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[seed; 32]).unwrap()
    }
    fn vk(k: &Secp256k1Keypair) -> VerifyingKey {
        VerifyingKey::from_did_key(&k.did()).unwrap()
    }
    fn keys_of(k: &Secp256k1Keypair) -> KeyMaterial {
        KeyMaterial {
            verification: vec![vk(k)],
            rotation: vec![],
        }
    }
    fn dt(s: &str) -> Datetime {
        Datetime::parse(s).unwrap()
    }

    /// Kit's story, wired: the claim in Kit's repo, the attestor's vouch
    /// (with a status pointer) in Kit's repo, the attestor's key in the
    /// directory, a clear status list on one mirror.
    struct World {
        repo: MemoryRepo,
        dids: MemoryResolver,
        status: MemoryStatus,
        policy: BasicPolicy,
        attestor_key: Secp256k1Keypair,
        claim_uri: AtUri,
        att_uri: AtUri,
    }

    impl World {
        fn new() -> Self {
            let repo = MemoryRepo::new();
            let dids = MemoryResolver::new();
            let status = MemoryStatus::new();
            let attestor_key = key(40);

            let claim = Claim::new(
                ClaimKind::EMAIL,
                serde_json::json!({ "address": "kit@example.com" }),
                dt("2026-08-20T09:00:00Z"),
            )
            .unwrap();
            let (claim_uri, claim_cid) = repo.put(&kit(), CLAIM_TYPE, "3kx2vp5qmek2h", &claim);

            let mut body = UnsignedAttestation::new(
                StrongRef::new(claim_uri.clone(), &claim_cid),
                attestor(),
                kit(),
                dt("2026-08-20T10:00:00Z"),
                dt("2026-09-19T10:00:00Z"),
            );
            body.method = Some("email-challenge".into());
            body.status = Some(StatusRef {
                list: STATUS_URL.parse().unwrap(),
                index: INDEX,
            });
            let att = sign(body, Repository(&kit()), &attestor_key).unwrap();
            let (att_uri, _) = repo.put(&kit(), ATTESTATION_TYPE, "3kx2vq7abcd2k", &att);

            dids.publish(&attestor(), keys_of(&attestor_key));

            let list = sign_status_list(
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T10:12:00Z"), 8192),
                &attestor_key,
            )
            .unwrap();
            status.publish(STATUS_URL, list.to_bytes().unwrap());

            Self {
                repo,
                dids,
                status,
                policy: BasicPolicy::permissive(),
                attestor_key,
                claim_uri,
                att_uri,
            }
        }

        fn verifier(&self) -> Verifier<'_> {
            Verifier {
                repo: &self.repo,
                dids: &self.dids,
                status: &self.status,
                policy: &self.policy,
            }
        }

        async fn verdict(&self) -> Verdict {
            self.verifier()
                .verify_attestation(&self.att_uri, &dt(NOW))
                .await
                .unwrap()
        }

        fn attestation(&self) -> Attestation {
            self.repo.get(&self.att_uri).unwrap().decode().unwrap()
        }

        fn revoke(&self, index: u64) {
            let mut body =
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-21T00:00:00Z"), 8192);
            body.bits.set(index);
            let list = sign_status_list(body, &self.attestor_key).unwrap();
            self.status.publish(STATUS_URL, list.to_bytes().unwrap());
        }
    }

    fn reason(v: Verdict) -> Reason {
        match v {
            Verdict::NotInForce(r) => r,
            other => panic!("expected NotInForce, got {other:?}"),
        }
    }

    // ── the happy path ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn in_force() {
        let w = World::new();
        match w.verdict().await {
            Verdict::InForce {
                attestor: a,
                method,
                remaining_secs,
            } => {
                assert_eq!(a, attestor());
                assert_eq!(method.as_deref(), Some("email-challenge"));
                assert_eq!(remaining_secs, 21 * 86_400);
            }
            other => panic!("{other:?}"),
        }
    }

    // ── one test per exit ───────────────────────────────────────────────────

    #[tokio::test]
    async fn attestation_missing() {
        let w = World::new();
        w.repo.delete(&w.att_uri);
        assert_eq!(reason(w.verdict().await), Reason::AttestationMissing);
    }

    #[tokio::test]
    async fn claim_missing() {
        let w = World::new();
        w.repo.delete(&w.claim_uri);
        assert_eq!(reason(w.verdict().await), Reason::ClaimMissing);
    }

    #[tokio::test]
    async fn claim_rewritten() {
        let w = World::new();
        let edited = Claim::new(
            ClaimKind::EMAIL,
            serde_json::json!({ "address": "kit@other.example" }),
            dt("2026-08-20T09:00:00Z"),
        )
        .unwrap();
        w.repo.replace(&w.claim_uri, &edited);
        assert_eq!(reason(w.verdict().await), Reason::ClaimRewritten);
    }

    #[tokio::test]
    async fn claim_in_another_repo_is_not_the_subjects() {
        // The address names Kit, but the reader hands back a record it
        // read from Mallory's repo (a re-assigned handle behind the
        // resolver, say). Same content, same CID — a Claim has no subject
        // field. Kit could never retract it; it is not Kit's claim.
        let w = World::new();
        w.repo.misfile(&w.claim_uri, &mallory());
        assert_eq!(reason(w.verdict().await), Reason::ClaimNotInSubjectRepo);
    }

    #[tokio::test]
    async fn claim_uri_outside_the_subject_is_never_fetched() {
        // The attestation points its claim at some other authority — a
        // handle that resolves wherever, an internal name. The verifier
        // refuses before the repo port is asked for it.
        let w = World::new();
        for elsewhere in [
            AtUri::record(&mallory(), CLAIM_TYPE, "3kx2vp5qmek2h"),
            AtUri::parse("at://internal.svc:8080/net.got-paws.acp.claim/x").unwrap(),
        ] {
            let mut body = w.attestation().body;
            body.claim.uri = elsewhere.clone();
            let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
            w.repo.replace(&w.att_uri, &att);
            let before = w.repo.read_count();
            assert_eq!(
                reason(w.verdict().await),
                Reason::ClaimUriNotSubject,
                "{elsewhere}"
            );
            assert_eq!(
                w.repo.read_count(),
                before + 1,
                "{elsewhere}: only the attestation itself was read"
            );
        }
    }

    #[tokio::test]
    async fn malformed_record() {
        let w = World::new();
        w.repo.replace_bytes(&w.att_uri, b"\xa0".to_vec()); // an empty map
        assert!(matches!(reason(w.verdict().await), Reason::Malformed(_)));
    }

    #[tokio::test]
    async fn subject_mismatch() {
        // A vouch that names mallory as subject (and points at a claim of
        // hers), but was signed for and lives in kit's repo: step 2 catches
        // the lie before the signature.
        let w = World::new();
        let claim_bytes = w.repo.get(&w.claim_uri).unwrap().bytes().to_vec();
        let mallory_claim = w
            .repo
            .put_bytes(&mallory(), CLAIM_TYPE, "3kx2vp5qmek2h", claim_bytes);
        let mut body = w.attestation().body;
        body.subject = mallory();
        body.claim.uri = mallory_claim;
        let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
        w.repo.replace(&w.att_uri, &att);
        assert_eq!(reason(w.verdict().await), Reason::SubjectMismatch);
    }

    #[tokio::test]
    async fn attestor_unresolvable() {
        let w = World::new();
        w.dids.remove(&attestor());
        assert_eq!(reason(w.verdict().await), Reason::AttestorUnresolvable);
    }

    #[tokio::test]
    async fn bad_sig_after_key_rotation_until_resigned() {
        let w = World::new();
        let new_key = key(41);
        w.dids.rotate(&attestor(), keys_of(&new_key));
        assert_eq!(reason(w.verdict().await), Reason::BadSig);
        // The attestor re-signs and Kit replaces the record.
        let att = sign(w.attestation().body, Repository(&kit()), &new_key).unwrap();
        w.repo.replace(&w.att_uri, &att);
        // …and republishes its status list under the new key.
        let list = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-22T00:00:00Z"), 8192),
            &new_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, list.to_bytes().unwrap());
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn transplant_not_in_force() {
        // Mallory copies Kit's vouch byte-for-byte into Mallory's repo.
        let w = World::new();
        let bytes = w.repo.get(&w.att_uri).unwrap().bytes().to_vec();
        let copied = w
            .repo
            .put_bytes(&mallory(), ATTESTATION_TYPE, "3kx2vq7abcd2k", bytes);
        let v = w
            .verifier()
            .verify_attestation(&copied, &dt(NOW))
            .await
            .unwrap();
        // Step 2 fires first (subject says kit, repo is mallory). Force past
        // it to prove step 4 holds on its own: a vouch whose subject *is*
        // mallory but which was signed for kit's repo.
        assert_eq!(reason(v), Reason::SubjectMismatch);
        let claim_bytes = w.repo.get(&w.claim_uri).unwrap().bytes().to_vec();
        let mallory_claim = w
            .repo
            .put_bytes(&mallory(), CLAIM_TYPE, "3kx2vp5qmek2h", claim_bytes);
        let mut body = w.attestation().body;
        body.subject = mallory();
        body.claim.uri = mallory_claim; // same CID, mallory's repo: steps 1–2 pass
        let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
        let planted = w
            .repo
            .put(&mallory(), ATTESTATION_TYPE, "3kx2vq7plant", &att)
            .0;
        let v = w
            .verifier()
            .verify_attestation(&planted, &dt(NOW))
            .await
            .unwrap();
        assert_eq!(reason(v), Reason::BadSig);
    }

    #[tokio::test]
    async fn unsigned_extra_field_is_not_canonical() {
        // Kit owns the repo. She appends a field the attestor never signed;
        // the eight known fields still verify, but the bytes on disk are
        // not the canonical form of the signed record.
        let w = World::new();
        #[derive(serde::Serialize)]
        struct Padded {
            #[serde(flatten)]
            att: Attestation,
            #[serde(rename = "assuranceLevel")]
            assurance_level: u8,
        }
        let padded = canonical_bytes(&Padded {
            att: w.attestation(),
            assurance_level: 9,
        })
        .unwrap();
        w.repo.replace_bytes(&w.att_uri, padded);
        assert_eq!(reason(w.verdict().await), Reason::NonCanonical);
    }

    #[tokio::test]
    async fn non_minimal_cbor_is_not_canonical() {
        // Same map, header written as 0xb8 0x08 (one-byte length) instead
        // of 0xa8: decodes identically, hashes differently.
        let w = World::new();
        let mut bytes = w.repo.get(&w.att_uri).unwrap().bytes().to_vec();
        assert_eq!(bytes[0], 0xa9, "nine-entry map, short form");
        bytes.splice(0..1, [0xb8, 0x09]);
        w.repo.replace_bytes(&w.att_uri, bytes);
        assert_eq!(reason(w.verdict().await), Reason::NonCanonical);
    }

    #[tokio::test]
    async fn expired_and_not_yet_valid() {
        let w = World::new();
        async fn at(w: &World, s: &str) -> Verdict {
            w.verifier()
                .verify_attestation(&w.att_uri, &dt(s))
                .await
                .unwrap()
        }
        assert_eq!(
            reason(at(&w, "2026-09-19T10:00:00Z").await),
            Reason::Expired
        );
        assert_eq!(
            reason(at(&w, "2027-01-01T00:00:00Z").await),
            Reason::Expired
        );
        assert!(at(&w, "2026-09-19T09:59:59Z").await.is_in_force());
        assert_eq!(
            reason(at(&w, "2026-08-20T09:00:00Z").await),
            Reason::NotYetValid
        );
        // Inside the skew window. The fixture's list is published 10:12,
        // so the verifier's clock has to be past that — a list from the
        // future is skipped too (see `newest_verifiable`).
        w.status.clear(STATUS_URL);
        w.status.publish(
            STATUS_URL,
            sign_status_list(
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T09:50:00Z"), 8192),
                &w.attestor_key,
            )
            .unwrap()
            .to_bytes()
            .unwrap(),
        );
        assert!(
            at(&w, "2026-08-20T09:56:00Z").await.is_in_force(),
            "inside skew"
        );
        // A status list ahead of the clock by more than the skew is not
        // evidence: only the future copy reachable → not checkable.
        w.status.clear(STATUS_URL);
        w.status.publish(
            STATUS_URL,
            sign_status_list(
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T10:12:00Z"), 8192),
                &w.attestor_key,
            )
            .unwrap()
            .to_bytes()
            .unwrap(),
        );
        assert_eq!(
            reason(at(&w, "2026-08-20T09:56:00Z").await),
            Reason::StatusUnverifiable
        );
    }

    #[tokio::test]
    async fn status_unavailable() {
        let w = World::new();
        w.status.clear(STATUS_URL);
        assert_eq!(reason(w.verdict().await), Reason::StatusUnavailable);
    }

    #[tokio::test]
    async fn status_unverifiable() {
        let w = World::new();
        w.status.clear(STATUS_URL);
        let forged = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-25T00:00:00Z"), 8192),
            &key(42),
        )
        .unwrap();
        w.status.publish(STATUS_URL, forged.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::StatusUnverifiable);
    }

    #[tokio::test]
    async fn status_index_out_of_range() {
        let w = World::new();
        w.status.clear(STATUS_URL);
        let tiny = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-25T00:00:00Z"), 8),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, tiny.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::StatusIndexOutOfRange);
    }

    #[tokio::test]
    async fn status_list_published_before_issuance_still_counts() {
        // The kill-test shape: the attestor pre-allocates a list, issues
        // attestations against it, then dies. The only copy anywhere is
        // older than the attestation — and it is the last word, so it is
        // evidence. (A floor here would strand every post-publish vouch.)
        let w = World::new();
        w.status.clear(STATUS_URL);
        let older = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-19T00:00:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, older.to_bytes().unwrap());
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn dead_attestor_with_a_pre_issuance_list_still_counts() {
        // Both halves of the kill-test shape at once: the list predates the
        // attestation *and* the attestor is gone. The pre-allocated list is
        // the last word; the vouch verifies until it expires.
        let w = World::new();
        w.status.clear(STATUS_URL);
        let older = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-19T00:00:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, older.to_bytes().unwrap());
        let World {
            repo,
            dids,
            status,
            policy,
            attestor_key,
            att_uri,
            ..
        } = w;
        drop(attestor_key);
        let v = Verifier {
            repo: &repo,
            dids: &dids,
            status: &status,
            policy: &policy,
        };
        assert!(
            v.verify_attestation(&att_uri, &dt(NOW))
                .await
                .unwrap()
                .is_in_force()
        );
        assert_eq!(
            reason(
                v.verify_attestation(&att_uri, &dt("2026-09-19T10:00:00Z"))
                    .await
                    .unwrap()
            ),
            Reason::Expired
        );
    }

    #[tokio::test]
    async fn withheld_fresh_copies_cannot_clear_a_revocation() {
        // The attestor revoked on the 21st; an adversary on the path serves
        // only the clear copy from the 20th. With a status-age bound, the
        // stale copy is not "not revoked" — it is not evidence.
        let mut w = World::new();
        w.policy.max_status_age_secs = Some(7 * 86_400); // NOW is the 29th
        assert_eq!(reason(w.verdict().await), Reason::StatusStale);
        let fresh = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-25T00:00:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, fresh.to_bytes().unwrap());
        assert!(w.verdict().await.is_in_force());
        // Without the bound, the verifier takes what it can get (the spec's
        // "newest verifiable wins"); only a policy that sets the bound is
        // protected from withholding.
        w.policy.max_status_age_secs = None;
        w.status.clear(STATUS_URL);
        w.status.publish(
            STATUS_URL,
            sign_status_list(
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T10:12:00Z"), 8192),
                &w.attestor_key,
            )
            .unwrap()
            .to_bytes()
            .unwrap(),
        );
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn issuer_declared_ttl_bounds_a_copy() {
        // The attestor signs "this version is good for seven days". NOW is
        // nine days after the fixture list: not checkable, whatever the
        // policy thinks. A thirty-day ttl is still evidence.
        let mut w = World::new();
        let publish = |w: &World, ttl: u64| {
            w.status.clear(STATUS_URL);
            let l =
                UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T10:12:00Z"), 8192)
                    .with_ttl(ttl);
            w.status.publish(
                STATUS_URL,
                sign_status_list(l, &w.attestor_key)
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
            );
        };
        publish(&w, 7 * 86_400);
        assert_eq!(reason(w.verdict().await), Reason::StatusStale);
        publish(&w, 30 * 86_400);
        assert!(w.verdict().await.is_in_force());
        // The tighter bound wins in both directions: a policy stricter than
        // the ttl, and a ttl stricter than the policy.
        w.policy.max_status_age_secs = Some(86_400);
        assert_eq!(reason(w.verdict().await), Reason::StatusStale);
        w.policy.max_status_age_secs = Some(365 * 86_400);
        publish(&w, 86_400);
        assert_eq!(reason(w.verdict().await), Reason::StatusStale);
        // A ttl at the data-model ceiling bounds nothing in practice — an
        // attestor saying "effectively forever" (the builder clamps anything
        // larger to it).
        publish(&w, MAX_SAFE_INTEGER);
        w.policy.max_status_age_secs = None;
        assert!(w.verdict().await.is_in_force());
        // A ttl of zero: evidence only in the second it was issued — stale
        // the moment any time has passed.
        publish(&w, 0);
        assert_eq!(reason(w.verdict().await), Reason::StatusStale);
    }

    #[tokio::test]
    async fn revoked_newest_mirror_wins() {
        let w = World::new();
        assert!(w.verdict().await.is_in_force());
        w.revoke(INDEX);
        // The clear copy is still on the mirror; the newer revoking copy wins.
        assert_eq!(reason(w.verdict().await), Reason::Revoked);
        // A stale clear copy republished later changes nothing.
        let stale = sign_status_list(
            UnsignedStatusList::new(attestor(), STATUS_URL, dt("2026-08-20T00:00:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, stale.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::Revoked);
    }

    #[tokio::test]
    async fn another_list_of_the_same_attestor_is_not_ours() {
        // Kit's bit is set in list 1. A mirror serves the attestor's list 2
        // (clear, newer, validly signed) at list 1's address: it does not
        // count as list 1, so the revocation stands.
        let w = World::new();
        w.revoke(INDEX);
        let other = sign_status_list(
            UnsignedStatusList::new(
                attestor(),
                "https://attest.got-paws.net/status/2",
                dt("2026-08-25T00:00:00Z"),
                8192,
            ),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, other.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::Revoked);
        // And with only list 2 on the mirror, list 1 is unverifiable — never
        // "not revoked".
        w.status.clear(STATUS_URL);
        w.status.publish(STATUS_URL, other.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::StatusUnverifiable);
    }

    #[tokio::test]
    async fn revoking_another_index_does_not_touch_ours() {
        let w = World::new();
        w.revoke(INDEX + 1);
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn policy_rejected() {
        let mut w = World::new();
        w.policy = BasicPolicy::trusting([mallory()]);
        assert!(matches!(
            reason(w.verdict().await),
            Reason::PolicyRejected(_)
        ));
        w.policy = BasicPolicy::trusting([attestor()]);
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn rejected_attestor_causes_no_fetch() {
        // Mallory self-attests in her own repo and points `status.list` at
        // something she would like the verifier to request. The policy does
        // not trust her, so the verifier never asks the mirror.
        let mut w = World::new();
        w.policy = BasicPolicy::trusting([attestor()]);
        let mallory_key = key(43);
        w.dids.publish(&mallory(), keys_of(&mallory_key));
        let claim = Claim::new(
            ClaimKind::EMAIL,
            serde_json::json!({ "address": "mallory@example.com" }),
            dt("2026-08-20T09:00:00Z"),
        )
        .unwrap();
        let (claim_uri, claim_cid) = w.repo.put(&mallory(), CLAIM_TYPE, "3kx2self", &claim);
        let mut body = UnsignedAttestation::new(
            StrongRef::new(claim_uri, &claim_cid),
            mallory(),
            mallory(),
            dt("2026-08-20T10:00:00Z"),
            dt("2026-09-19T10:00:00Z"),
        );
        body.status = Some(StatusRef {
            list: "https://metadata.internal.example/latest/".parse().unwrap(),
            index: 0,
        });
        let att = sign(body, Repository(&mallory()), &mallory_key).unwrap();
        let (uri, _) = w
            .repo
            .put(&mallory(), ATTESTATION_TYPE, "3kx2selfatt", &att);
        w.status.go_dark(); // would be Err — and counted — if consulted
        let before = w.status.fetch_count();
        let v = w
            .verifier()
            .verify_attestation(&uri, &dt(NOW))
            .await
            .unwrap();
        assert!(matches!(reason(v), Reason::PolicyRejected(_)));
        assert_eq!(
            w.status.fetch_count(),
            before,
            "no fetch for a rejected attestor"
        );
    }

    #[tokio::test]
    async fn unfetchable_list_is_never_requested() {
        // A trusted (or compromised) attestor names an address the verifier
        // must not touch. The attestation decodes fine — the name is only
        // an identifier at rest — but step 7 refuses before any request.
        let w = World::new();
        for inward in [
            "https://169.254.169.254/latest/meta-data/",
            "https://0x7f000001/",
            "https://localhost./",
            "https://metadata.internal/",
        ] {
            let mut body = w.attestation().body;
            body.status = Some(StatusRef {
                list: inward.parse().unwrap(),
                index: INDEX,
            });
            let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
            w.repo.replace(&w.att_uri, &att);
            let before = w.status.fetch_count();
            assert!(
                matches!(reason(w.verdict().await), Reason::StatusUnfetchable(_)),
                "{inward}"
            );
            assert_eq!(w.status.fetch_count(), before, "{inward}: fetched");
        }
        // An `at://` identifier is handed to the source as-is.
        let mut body = w.attestation().body;
        let at_list = "at://did:plc:attestor/net.got-paws.acp.statusList/1";
        body.status = Some(StatusRef {
            list: at_list.parse().unwrap(),
            index: INDEX,
        });
        let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
        w.repo.replace(&w.att_uri, &att);
        let list = sign_status_list(
            UnsignedStatusList::new(attestor(), at_list, dt("2026-08-20T10:12:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(at_list, list.to_bytes().unwrap());
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn no_status_pointer_skips_step_7() {
        let mut w = World::new();
        let mut body = w.attestation().body;
        body.status = None;
        let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
        w.repo.replace(&w.att_uri, &att);
        w.status.go_dark(); // would be Err if consulted
        assert!(w.verdict().await.is_in_force());
        // …unless this verifier insists on a pointer.
        w.policy.require_status = true;
        assert!(matches!(
            reason(w.verdict().await),
            Reason::PolicyRejected(_)
        ));
    }

    #[tokio::test]
    async fn policy_not_demanding_freshness_skips_step_7() {
        let mut w = World::new();
        w.policy.demand_freshness = false;
        w.revoke(INDEX);
        w.status.go_dark();
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn infra_failure_is_error_not_verdict() {
        let w = World::new();
        w.repo.go_dark();
        let err = w
            .verifier()
            .verify_attestation(&w.att_uri, &dt(NOW))
            .await
            .unwrap_err();
        assert!(matches!(err, VerifyError::Repo(_)));

        let w = World::new();
        w.dids.go_dark();
        assert!(matches!(
            w.verifier()
                .verify_attestation(&w.att_uri, &dt(NOW))
                .await
                .unwrap_err(),
            VerifyError::Resolve(_)
        ));

        let w = World::new();
        w.status.go_dark();
        assert!(matches!(
            w.verifier()
                .verify_attestation(&w.att_uri, &dt(NOW))
                .await
                .unwrap_err(),
            VerifyError::Status(_)
        ));
    }

    // ── THE KILL TEST ───────────────────────────────────────────────────────

    /// Tear the attestor down after issuance; every vouch still verifies,
    /// and then ages out on schedule.
    #[tokio::test]
    async fn kill_test() {
        let w = World::new();
        assert!(w.verdict().await.is_in_force());

        // The attestor dies. Its signing key is gone (dropped below), its
        // origin host is gone — only what it had already published survives:
        // the record in Kit's repo, its key in the DID directory, and a
        // mirror's copy of its last status list. Nothing in `Verifier` can
        // reach it anyway: there is no attestor port.
        let World {
            repo,
            dids,
            status,
            policy,
            attestor_key,
            att_uri,
            ..
        } = w;
        drop(attestor_key);
        let v = Verifier {
            repo: &repo,
            dids: &dids,
            status: &status,
            policy: &policy,
        };

        assert!(
            v.verify_attestation(&att_uri, &dt(NOW))
                .await
                .unwrap()
                .is_in_force(),
            "a dead attestor's vouch still verifies"
        );
        assert!(
            v.verify_attestation(&att_uri, &dt("2026-09-18T10:00:00Z"))
                .await
                .unwrap()
                .is_in_force(),
            "…right up to expiry"
        );
        assert_eq!(
            reason(
                v.verify_attestation(&att_uri, &dt("2026-09-19T10:00:00Z"))
                    .await
                    .unwrap()
            ),
            Reason::Expired,
            "…and then ages out: death is bounded, nothing lives forever unfalsifiable"
        );
    }

    /// The custodian dies: Kit restores the repo elsewhere under the same
    /// DID; everything still verifies.
    #[tokio::test]
    async fn kill_test_custodian() {
        let w = World::new();
        let new_host = MemoryRepo::new();
        for (uri, fetched) in w.repo.export(&kit()) {
            new_host.put_bytes(
                &kit(),
                uri.collection().unwrap(),
                uri.rkey().unwrap(),
                fetched.bytes().to_vec(),
            );
        }
        w.repo.go_dark();
        let v = Verifier {
            repo: &new_host,
            dids: &w.dids,
            status: &w.status,
            policy: &w.policy,
        };
        assert!(
            v.verify_attestation(&w.att_uri, &dt(NOW))
                .await
                .unwrap()
                .is_in_force()
        );
    }
}
