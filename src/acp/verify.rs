//! `verify_attestation` — the spec's seven steps as one function — and
//! `verify_relationship` for mutual claims.
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
use super::ports::{DidResolver, FetchedRecord, KeyMaterial, RepoReader, StatusSource};
use super::record::{
    AtUri, Attestation, Claim, Datetime, RELATIONSHIP_TYPE, RelKind, Relationship, canonical_bytes,
};
use super::sign::{Repository, verify_sig};
use super::status::newest_verifiable;

/// Tolerated clock skew when checking `issuedAt` is not in the future.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// Why an attestation or relationship is **not in force**. Every variant is
/// final for the inputs given; none is "try again".
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
    /// The newest verifiable status list is older than the policy's
    /// [`max_status_age_secs`](super::policy::TrustPolicy::max_status_age_secs)
    /// — step 7. Only reachable when a policy sets that bound; with it, an
    /// adversary withholding fresh copies lands here, never on in-force.
    StatusStale,
    /// The status list does not cover `status.index` — step 7.
    StatusIndexOutOfRange,
    /// The revocation bit is set — step 7.
    Revoked,

    /// A relationship half (or its counterpart) is absent.
    HalfMissing,
    /// The halves do not name each other.
    CounterpartMismatch,
    /// The two kinds are not a defined pair.
    KindsNotAPair,
    /// A kind this build does not know; ignored, not rejected wholesale.
    UnknownKind,
    /// Ownership-tier pair without key control over the owned DID: the
    /// owner's most senior rotation key is not the owned DID's most senior
    /// rotation key.
    NoKeyControl,
}

/// The outcome of verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every step passed.
    InForce {
        /// Who vouched (attestation), or — for a relationship — the
        /// counterpart the asked-about half turned out to be paired with.
        attestor: Did,
        /// The stated method, if any. Relationships have none.
        method: Option<String>,
        /// Seconds until expiry — a freshness signal for the caller.
        /// `None` for a relationship: it has no expiry, it is severed.
        remaining_secs: Option<i64>,
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

impl Verifier<'_> {
    /// Fetch and decode, mapping the three outcomes: absent → `None`,
    /// undecodable → `Err(Reason::Malformed)`, port failure → `VerifyError`.
    async fn fetch<T: serde::de::DeserializeOwned>(
        &self,
        uri: &AtUri,
    ) -> Result<Option<Result<(FetchedRecord, T), Reason>>, VerifyError> {
        let Some(fetched) = self.repo.get_record(uri).await? else {
            return Ok(None);
        };
        Ok(Some(match fetched.decode::<T>() {
            Ok(record) => Ok((fetched, record)),
            Err(err) => Err(Reason::Malformed(format!("{uri}: {err}"))),
        }))
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
            None => not_in_force!(Reason::AttestationMissing),
            Some(Err(reason)) => not_in_force!(reason),
            Some(Ok(pair)) => pair,
        };
        // `claim.uri` is an address the record's author wrote. Before any
        // request goes there, it must name the subject — the one authority
        // this verification is about. (Step 2 re-checks the repo it was
        // actually read from; this is the same fact, asked before the I/O.)
        if att.body.claim.uri.authority() != att.body.subject.as_str() {
            not_in_force!(Reason::ClaimUriNotSubject);
        }
        let (claim_fetched, claim) = match self.fetch::<Claim>(&att.body.claim.uri).await? {
            None => not_in_force!(Reason::ClaimMissing),
            Some(Err(reason)) => not_in_force!(reason),
            Some(Ok(pair)) => pair,
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
            let list_issued = list.body.issued_at.to_unix();
            if let Some(max) = self.policy.max_status_age_secs()
                && now_s - list_issued > max
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
            remaining_secs: Some(expires - now_s),
        })
    }

    /// A mutual claim, starting from either half: both halves exist, name
    /// each other, form a defined pair, and — for ownership-tier kinds — the
    /// owner's senior rotation key is the owned DID's senior rotation key.
    pub async fn verify_relationship(&self, half: &AtUri) -> Result<Verdict, VerifyError> {
        let (a_fetched, a) = match self.fetch::<Relationship>(half).await? {
            None => not_in_force!(Reason::HalfMissing),
            Some(Err(reason)) => not_in_force!(reason),
            Some(Ok(pair)) => pair,
        };
        let Some(expected_kind) = a.relationship.pair() else {
            not_in_force!(Reason::UnknownKind);
        };

        // The other half: by its declared address, else by search. The
        // search accepts the first half that matches *completely* (kind,
        // counterpart, and — when it declares one — counterpart record);
        // a half that merely points elsewhere does not end the search, and
        // a record that does not decode is skipped rather than vetoing the
        // search — so the verdict never depends on the order a PDS lists
        // records in, nor on junk sitting in the same collection. Only the
        // *declared* address is held to "exists ⇒ decodes". Listing the
        // counterpart's repo is inherent: the other half lives there.
        let other = match &a.counterpart_record {
            Some(uri) => {
                // The declared address is written by this half's author. It
                // must sit in the counterpart's repo — decided *before* the
                // read, so a half naming `at://internal.svc/…` never makes
                // the verifier fetch there. The post-fetch repository check
                // below stays as defense in depth.
                if uri.authority() != a.counterpart.as_str() {
                    not_in_force!(Reason::CounterpartMismatch);
                }
                match self.fetch::<Relationship>(uri).await? {
                    None => None,
                    Some(Err(reason)) => not_in_force!(reason),
                    Some(Ok(pair)) => Some(pair),
                }
            }
            None => {
                let mut found = None;
                let mut near_miss = false;
                for fetched in self
                    .repo
                    .list_records(&a.counterpart, RELATIONSHIP_TYPE)
                    .await?
                {
                    let Ok(r) = fetched.decode::<Relationship>() else {
                        continue;
                    };
                    if r.relationship != expected_kind || r.counterpart != a_fetched.repository {
                        continue;
                    }
                    match &r.counterpart_record {
                        Some(declared) if declared != &a_fetched.uri => near_miss = true,
                        _ => {
                            found = Some((fetched, r));
                            break;
                        }
                    }
                }
                if found.is_none() && near_miss {
                    not_in_force!(Reason::CounterpartMismatch);
                }
                found
            }
        };
        let Some((b_fetched, b)) = other else {
            not_in_force!(Reason::HalfMissing);
        };

        if b.relationship != expected_kind {
            not_in_force!(if matches!(b.relationship, RelKind::Unknown(_)) {
                Reason::UnknownKind
            } else {
                Reason::KindsNotAPair
            });
        }
        if a.counterpart != b_fetched.repository || b.counterpart != a_fetched.repository {
            not_in_force!(Reason::CounterpartMismatch);
        }
        if let Some(declared) = &b.counterpart_record
            && declared != &a_fetched.uri
        {
            not_in_force!(Reason::CounterpartMismatch);
        }

        if a.relationship.is_ownership_tier() {
            let (owner, owned) = if a.relationship == RelKind::Owns {
                (&a_fetched.repository, &b_fetched.repository)
            } else {
                (&b_fetched.repository, &a_fetched.repository)
            };
            let owned_keys = self.dids.keys(owned).await?.unwrap_or_default();
            let owner_keys = self.dids.keys(owner).await?.unwrap_or_default();
            if !holds_senior_rotation_key(&owner_keys, &owned_keys) {
                not_in_force!(Reason::NoKeyControl);
            }
        }

        Ok(Verdict::InForce {
            attestor: b_fetched.repository,
            method: None,
            remaining_secs: None,
        })
    }
}

/// Key control (FORKS F40, amended 2026-08-21): the owner's **most senior**
/// rotation key is the owned DID's **most senior** rotation key.
///
/// Why this shape and not "some key in both lists": a custodian's rotation
/// key sits in *both* lists whenever the two DIDs share a host (bsky.social
/// puts one operator key on every account), so set intersection proved
/// nothing and matched the very key the senior-key rule exists to exclude.
/// The only position the verifier can read without knowing who the
/// custodian is, is the top: under the senior-key custody rule
/// (`docs/ccs.md`) the owner's own key is always above the custodian's in
/// the owner's list, and an owner who controls the owned DID has that same
/// key above every custodian in the owned DID's list. Verification keys do
/// not count: `did:plc` gives them no control over the identity. The
/// comparison is on the `did:key` strings as the directory lists them —
/// the port's contract is to preserve that order.
///
/// Both sides must be the verbatim `did:key:` strings the directory holds;
/// the port contract forbids re-encoding, so there is nothing to normalize.
///
/// Residuals, stated plainly: a junior co-owner (key below another owner's)
/// does not pass from this check alone; and two DIDs that are both *purely*
/// custodied by the same operator (no owner key at all — a violation of the
/// senior-key rule on both) are indistinguishable from public data.
fn holds_senior_rotation_key(owner: &KeyMaterial, owned: &KeyMaterial) -> bool {
    match (owner.rotation.first(), owned.rotation.first()) {
        // Equality on verbatim `did:key:` strings. Anything else on top —
        // empty, a placeholder, an unprefixed multikey — is not a key the
        // directory would hold, and two equal non-keys must not pass.
        (Some(own), Some(top)) => own == top && own.starts_with("did:key:") && own.len() > 8,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};

    use super::*;
    use crate::acp::VerifyingKey;
    use crate::acp::memory::{MemoryRepo, MemoryResolver, MemoryStatus};
    use crate::acp::policy::BasicPolicy;
    use crate::acp::record::fixtures::{attestor, kit, mallory};
    use crate::acp::record::{
        ATTESTATION_TYPE, CLAIM_TYPE, Claim, ClaimKind, StatusRef, StrongRef, UnsignedAttestation,
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
    fn rotation(keys: &[&Secp256k1Keypair]) -> KeyMaterial {
        KeyMaterial {
            verification: vec![],
            rotation: keys.iter().map(|k| k.did()).collect(),
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
                ClaimKind::Email,
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
                assert_eq!(remaining_secs, Some(21 * 86_400));
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
            ClaimKind::Email,
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
            ClaimKind::Email,
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

    // ── mutual claims ───────────────────────────────────────────────────────

    fn fox() -> Did {
        Did::new("did:plc:fox1234567890abcdefghijkl")
    }

    struct Pair {
        repo: MemoryRepo,
        dids: MemoryResolver,
        status: MemoryStatus,
        policy: BasicPolicy,
        kit_half: AtUri,
        fox_half: AtUri,
    }

    impl Pair {
        /// Kit owns Fox; both halves written, each naming the other's
        /// address; Kit holds Fox's senior rotation key.
        fn new() -> Self {
            let repo = MemoryRepo::new();
            let dids = MemoryResolver::new();
            let kit_key = key(50);
            let host_key = key(51);

            let fox_half_uri = AtUri::record(&fox(), RELATIONSHIP_TYPE, "ab12");
            let kit_half_uri = AtUri::record(&kit(), RELATIONSHIP_TYPE, "cd34");

            let mut owns =
                Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
            owns.counterpart_record = Some(fox_half_uri.clone());
            let mut owned_by =
                Relationship::new(RelKind::OwnedBy, kit(), dt("2026-08-20T11:00:00Z"), None)
                    .unwrap();
            owned_by.counterpart_record = Some(kit_half_uri.clone());

            let (kit_half, _) = repo.put(&kit(), RELATIONSHIP_TYPE, "cd34", &owns);
            let (fox_half, _) = repo.put(&fox(), RELATIONSHIP_TYPE, "ab12", &owned_by);

            // Kit's own account: her key senior to her host's (bsky, say).
            // Fox, custodied by Zurfur: Kit's key senior to Zurfur's.
            dids.publish(&kit(), rotation(&[&kit_key, &key(52)]));
            dids.publish(&fox(), rotation(&[&kit_key, &host_key]));
            Self {
                repo,
                dids,
                status: MemoryStatus::new(),
                policy: BasicPolicy::permissive(),
                kit_half,
                fox_half,
            }
        }

        async fn verdict_from(&self, half: &AtUri) -> Verdict {
            Verifier {
                repo: &self.repo,
                dids: &self.dids,
                status: &self.status,
                policy: &self.policy,
            }
            .verify_relationship(half)
            .await
            .unwrap()
        }
    }

    #[tokio::test]
    async fn shared_custodian_key_is_not_ownership() {
        // Kit and Fox on the same host, which lists its one operator key on
        // every account. Kit's key is senior on Fox; the host's sits below.
        // Mallory — same host, no key of her own — writes both records
        // (she cannot, but suppose she did): the host key is in both her
        // list and Fox's, and that must prove nothing.
        let p = Pair::new();
        let host = key(51);
        p.dids.publish(&mallory(), rotation(&[&host]));
        let mut owns =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        owns.counterpart_record = Some(p.fox_half.clone());
        let (mallory_half, _) = p.repo.put(&mallory(), RELATIONSHIP_TYPE, "ef56", &owns);
        let mut owned_by = Relationship::new(
            RelKind::OwnedBy,
            mallory(),
            dt("2026-08-20T11:00:00Z"),
            None,
        )
        .unwrap();
        owned_by.counterpart_record = Some(mallory_half.clone());
        p.repo.replace(&p.fox_half, &owned_by);
        assert_eq!(
            reason(p.verdict_from(&mallory_half).await),
            Reason::NoKeyControl
        );
        // Same with a different owner key on top of Fox: as long as Fox
        // honours the senior-key rule, no co-hosted stranger passes. (Two
        // DIDs *both* purely custodied by one operator are the documented
        // residual — nothing in public data tells them apart.)
        p.dids.rotate(&fox(), rotation(&[&key(55), &host]));
        assert_eq!(
            reason(p.verdict_from(&mallory_half).await),
            Reason::NoKeyControl
        );
    }

    #[tokio::test]
    async fn custodian_senior_is_not_ownership() {
        // Fox lists the host above Kit: Kit's key is present but junior. The
        // senior-key rule is violated and the verifier says so.
        let p = Pair::new();
        p.dids.rotate(&fox(), rotation(&[&key(51), &key(50)]));
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::NoKeyControl
        );
        assert_eq!(
            reason(p.verdict_from(&p.fox_half).await),
            Reason::NoKeyControl
        );
    }

    #[tokio::test]
    async fn verification_keys_do_not_confer_control() {
        // Kit's signing key is Fox's senior *rotation* key (someone
        // misconfigured it); Kit's rotation list does not contain it.
        let p = Pair::new();
        let signing = key(53);
        p.dids.rotate(
            &kit(),
            KeyMaterial {
                verification: vec![vk(&signing)],
                rotation: vec![key(50).did()],
            },
        );
        p.dids.rotate(&fox(), rotation(&[&signing, &key(51)]));
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::NoKeyControl
        );
    }

    #[tokio::test]
    async fn co_owner_ordering() {
        // Two owners, priority-ordered on Fox: [kit, bo, host]. The senior
        // co-owner passes; the junior one does not from this check alone
        // (documented residual — key priority implies seniority).
        let p = Pair::new();
        let (kit_key, bo_key, host) = (key(50), key(54), key(51));
        let bo = Did::new("did:plc:bo12345678901234567890ab");
        p.dids.rotate(&fox(), rotation(&[&kit_key, &bo_key, &host]));
        p.dids.publish(&bo, rotation(&[&bo_key, &key(52)]));
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());

        let mut owns =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        owns.counterpart_record = Some(p.fox_half.clone());
        let (bo_half, _) = p.repo.put(&bo, RELATIONSHIP_TYPE, "gh78", &owns);
        let mut owned_by = Relationship::new(
            RelKind::OwnedBy,
            bo.clone(),
            dt("2026-08-20T11:00:00Z"),
            None,
        )
        .unwrap();
        owned_by.counterpart_record = Some(bo_half.clone());
        p.repo.replace(&p.fox_half, &owned_by);
        assert_eq!(reason(p.verdict_from(&bo_half).await), Reason::NoKeyControl);
    }

    #[tokio::test]
    async fn placeholder_rotation_entries_are_not_keys() {
        // A resolver that answers with an empty or non-did:key top entry for
        // both DIDs produces two *equal* strings — which is not key control.
        let p = Pair::new();
        for junk in [
            "",
            "zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg",
            "did:key:",
        ] {
            let km = |_: &Did| KeyMaterial {
                verification: vec![],
                rotation: vec![junk.to_string()],
            };
            p.dids.rotate(&kit(), km(&kit()));
            p.dids.rotate(&fox(), km(&fox()));
            assert_eq!(
                reason(p.verdict_from(&p.kit_half).await),
                Reason::NoKeyControl,
                "{junk:?} passed as a rotation key"
            );
        }
    }

    #[tokio::test]
    async fn declared_counterpart_outside_the_counterpart_repo_is_not_fetched() {
        // Kit's half names a counterpartRecord in some other authority — a
        // handle, an internal host, Mallory's repo. The verifier decides
        // CounterpartMismatch without reading it.
        let p = Pair::new();
        for foreign in [
            AtUri::record(&mallory(), RELATIONSHIP_TYPE, "ab12"),
            AtUri::parse("at://internal.svc:8080/net.got-paws.acp.relationship/x").unwrap(),
            AtUri::parse("at://fox.got-paws.net/net.got-paws.acp.relationship/ab12").unwrap(),
        ] {
            let mut owns =
                Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
            owns.counterpart_record = Some(foreign.clone());
            p.repo.replace(&p.kit_half, &owns);
            let before = p.repo.read_count();
            assert_eq!(
                reason(p.verdict_from(&p.kit_half).await),
                Reason::CounterpartMismatch,
                "{foreign}"
            );
            assert_eq!(
                p.repo.read_count(),
                before + 1,
                "only Kit's own half was read for {foreign}"
            );
        }
    }

    #[tokio::test]
    async fn pair_in_force_from_either_half() {
        let p = Pair::new();
        match p.verdict_from(&p.kit_half).await {
            Verdict::InForce {
                attestor,
                method,
                remaining_secs,
            } => {
                assert_eq!(attestor, fox(), "the counterpart is what was learned");
                assert_eq!(method, None);
                assert_eq!(remaining_secs, None, "relationships do not expire");
            }
            other => panic!("{other:?}"),
        }
        match p.verdict_from(&p.fox_half).await {
            Verdict::InForce { attestor, .. } => assert_eq!(attestor, kit()),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn pair_found_by_search_without_counterpart_record() {
        let p = Pair::new();
        let owns =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        p.repo.replace(&p.kit_half, &owns); // no counterpartRecord
        let owned_by =
            Relationship::new(RelKind::OwnedBy, kit(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        p.repo.replace(&p.fox_half, &owned_by);
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
    }

    #[tokio::test]
    async fn search_is_not_order_dependent() {
        // Fox's repo holds a stale half (pointing at a record Kit deleted)
        // listed *before* the live one. The live one must be found.
        let p = Pair::new();
        let owns =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        p.repo.replace(&p.kit_half, &owns); // no counterpartRecord → search
        let mut stale =
            Relationship::new(RelKind::OwnedBy, kit(), dt("2026-08-19T11:00:00Z"), None).unwrap();
        stale.counterpart_record = Some(AtUri::record(&kit(), RELATIONSHIP_TYPE, "gone"));
        p.repo.put(&fox(), RELATIONSHIP_TYPE, "aa00", &stale); // sorts first
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
        // With only the stale half present, it is a mismatch, not "missing".
        p.repo.delete(&p.fox_half);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::CounterpartMismatch
        );
    }

    #[tokio::test]
    async fn junk_in_the_collection_does_not_veto_the_search() {
        // Fox's repo holds an undecodable relationship record (old schema,
        // corruption) that lists *before* the live half. The search skips
        // it; swapping rkeys must not change the verdict.
        let p = Pair::new();
        let owns =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        p.repo.replace(&p.kit_half, &owns); // no counterpartRecord → search
        let owned_by =
            Relationship::new(RelKind::OwnedBy, kit(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        p.repo.replace(&p.fox_half, &owned_by);
        p.repo
            .put_bytes(&fox(), RELATIONSHIP_TYPE, "aa00", b"\xa0".to_vec()); // sorts first
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
        p.repo
            .put_bytes(&fox(), RELATIONSHIP_TYPE, "zz99", b"\xa0".to_vec()); // sorts last
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
        // With no live half at all, junk alone is "missing", not malformed.
        p.repo.delete(&p.fox_half);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::HalfMissing
        );
        // The *declared* address is held to a higher bar: exists ⇒ decodes.
        let mut declared =
            Relationship::new(RelKind::Owns, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        declared.counterpart_record = Some(AtUri::record(&fox(), RELATIONSHIP_TYPE, "aa00"));
        p.repo.replace(&p.kit_half, &declared);
        assert!(matches!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn one_half_missing_is_severance() {
        let p = Pair::new();
        p.repo.delete(&p.fox_half);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::HalfMissing
        );
        assert_eq!(
            reason(p.verdict_from(&p.fox_half).await),
            Reason::HalfMissing
        );
    }

    #[tokio::test]
    async fn counterpart_mismatch() {
        let p = Pair::new();
        let mut owned_by = Relationship::new(
            RelKind::OwnedBy,
            mallory(),
            dt("2026-08-20T11:00:00Z"),
            None,
        )
        .unwrap();
        owned_by.counterpart_record = Some(p.kit_half.clone());
        p.repo.replace(&p.fox_half, &owned_by);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::CounterpartMismatch
        );
    }

    #[tokio::test]
    async fn kinds_not_a_pair_and_unknown() {
        let p = Pair::new();
        let mut wrong =
            Relationship::new(RelKind::MemberOf, kit(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        wrong.counterpart_record = Some(p.kit_half.clone());
        p.repo.replace(&p.fox_half, &wrong);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::KindsNotAPair
        );

        let mut unknown = Relationship::new(
            RelKind::from("sponsors"),
            kit(),
            dt("2026-08-20T11:00:00Z"),
            None,
        )
        .unwrap();
        unknown.counterpart_record = Some(p.kit_half.clone());
        p.repo.replace(&p.fox_half, &unknown);
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::UnknownKind
        );
        assert_eq!(
            reason(p.verdict_from(&p.fox_half).await),
            Reason::UnknownKind
        );
    }

    #[tokio::test]
    async fn ownership_requires_key_control() {
        let p = Pair::new();
        // The host rotates Kit out: two records, no key control, no ownership.
        p.dids.rotate(&fox(), rotation(&[&key(51)]));
        assert_eq!(
            reason(p.verdict_from(&p.kit_half).await),
            Reason::NoKeyControl
        );
        // A non-ownership pair needs no key control at all.
        let mut a =
            Relationship::new(RelKind::MemberOf, fox(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        a.counterpart_record = Some(p.fox_half.clone());
        let mut b =
            Relationship::new(RelKind::HasMember, kit(), dt("2026-08-20T11:00:00Z"), None).unwrap();
        b.counterpart_record = Some(p.kit_half.clone());
        p.repo.replace(&p.kit_half, &a);
        p.repo.replace(&p.fox_half, &b);
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
    }
}
