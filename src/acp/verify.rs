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
    AtUri, Attestation, Claim, Datetime, RELATIONSHIP_TYPE, RelKind, Relationship,
};
use super::sign::{Repository, VerifyingKey, verify_sig};
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
    /// A record exists but does not decode as its type.
    Malformed(String),
    /// `subject` is not the owner of the repo the record came from — step 2.
    SubjectMismatch,
    /// The attestor's DID does not resolve — step 3.
    AttestorUnresolvable,
    /// The signature does not verify under the attestor's current keys, as
    /// fetched from this repository — step 4 (tamper, rotation, transplant).
    BadSig,
    /// `expiresAt` has passed — step 5.
    Expired,
    /// `issuedAt` is further in the future than [`CLOCK_SKEW_SECS`].
    NotYetValid,
    /// Freshness was demanded and no copy of the status list was reachable — step 6.
    StatusUnavailable,
    /// Copies were reachable but none verified under the attestor's keys — step 6.
    StatusUnverifiable,
    /// The status list does not cover `status.index` — step 6.
    StatusIndexOutOfRange,
    /// The revocation bit is set — step 6.
    Revoked,
    /// The verifier's own policy declined — step 7.
    PolicyRejected(String),

    /// A relationship half (or its counterpart) is absent.
    HalfMissing,
    /// The halves do not name each other.
    CounterpartMismatch,
    /// The two kinds are not a defined pair.
    KindsNotAPair,
    /// A kind this build does not know; ignored, not rejected wholesale.
    UnknownKind,
    /// Ownership-tier pair without key control over the owned DID.
    NoKeyControl,
}

/// The outcome of verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every step passed.
    InForce {
        /// Who vouched (attestation) or the two parties (relationship: the
        /// half that was asked about first).
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
        let (claim_fetched, claim) = match self.fetch::<Claim>(&att.body.claim.uri).await? {
            None => not_in_force!(Reason::ClaimMissing),
            Some(Err(reason)) => not_in_force!(reason),
            Some(Ok(pair)) => pair,
        };
        if claim_fetched.cid.to_string() != att.body.claim.cid {
            not_in_force!(Reason::ClaimRewritten);
        }

        // 2. The record says who it is about; the repo says whose it is.
        if att.body.subject != fetched.repository {
            not_in_force!(Reason::SubjectMismatch);
        }

        // 3. The attestor's *current* keys.
        let Some(keys) = self.dids.keys(&att.body.attestor).await? else {
            not_in_force!(Reason::AttestorUnresolvable);
        };

        // 4. The signature, bound to the repository we actually read from.
        if verify_sig(&att, Repository(&fetched.repository), &keys.verification).is_err() {
            not_in_force!(Reason::BadSig);
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

        // 6. Revocation, when there is a pointer and the policy cares.
        let mut status_checked = false;
        if let Some(status) = &att.body.status
            && self.policy.demands_freshness()
        {
            let copies = self.status.fetch(&status.list).await?;
            if copies.is_empty() {
                not_in_force!(Reason::StatusUnavailable);
            }
            let Some(list) = newest_verifiable(&copies, &att.body.attestor, &keys.verification)
            else {
                not_in_force!(Reason::StatusUnverifiable);
            };
            match list.is_set(status.index) {
                None => not_in_force!(Reason::StatusIndexOutOfRange),
                Some(true) => not_in_force!(Reason::Revoked),
                Some(false) => status_checked = true,
            }
        }

        // 7. Judgment.
        let ctx = PolicyContext {
            attestor: &att.body.attestor,
            method: att.body.method.as_deref(),
            claim_kind: &claim.kind,
            age_secs: now_s - issued,
            remaining_secs: expires - now_s,
            status_checked,
        };
        match self.policy.decide(&ctx) {
            Decision::Reject(why) => not_in_force!(Reason::PolicyRejected(why)),
            Decision::Accept => Ok(Verdict::InForce {
                attestor: att.body.attestor,
                method: att.body.method,
                remaining_secs: expires - now_s,
            }),
        }
    }

    /// A mutual claim, starting from either half: both halves exist, name
    /// each other, form a defined pair, and — for ownership-tier kinds — the
    /// owner holds a rotation key of the owned DID.
    pub async fn verify_relationship(&self, half: &AtUri) -> Result<Verdict, VerifyError> {
        let (a_fetched, a) = match self.fetch::<Relationship>(half).await? {
            None => not_in_force!(Reason::HalfMissing),
            Some(Err(reason)) => not_in_force!(reason),
            Some(Ok(pair)) => pair,
        };
        let Some(expected_kind) = a.relationship.pair() else {
            not_in_force!(Reason::UnknownKind);
        };

        // The other half: by its declared address, else by search.
        let other = match &a.counterpart_record {
            Some(uri) => match self.fetch::<Relationship>(uri).await? {
                None => None,
                Some(Err(reason)) => not_in_force!(reason),
                Some(Ok(pair)) => Some(pair),
            },
            None => {
                let mut found = None;
                for fetched in self
                    .repo
                    .list_records(&a.counterpart, RELATIONSHIP_TYPE)
                    .await?
                {
                    if let Ok(r) = fetched.decode::<Relationship>()
                        && r.relationship == expected_kind
                        && r.counterpart == a_fetched.repository
                    {
                        found = Some((fetched, r));
                        break;
                    }
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
            if !holds_rotation_key(&owner_keys, &owned_keys) {
                not_in_force!(Reason::NoKeyControl);
            }
        }

        Ok(Verdict::InForce {
            attestor: a_fetched.repository,
            method: None,
            remaining_secs: i64::MAX,
        })
    }
}

/// Key control, v0.1 rule: at least one of the owner's keys (rotation or
/// verification) appears among the owned DID's rotation keys. The spec's
/// "equal or senior to any custodian" refinement needs the custodian's
/// identity, which no port supplies yet — recorded in FORKS F40.
fn holds_rotation_key(owner: &KeyMaterial, owned: &KeyMaterial) -> bool {
    if owned.rotation.is_empty() {
        return false;
    }
    let owned_keys: Vec<VerifyingKey> = owned
        .rotation
        .iter()
        .filter_map(|k| VerifyingKey::from_did_key(k).ok())
        .collect();
    owner
        .rotation
        .iter()
        .filter_map(|k| VerifyingKey::from_did_key(k).ok())
        .chain(owner.verification.iter().cloned())
        .any(|k| owned_keys.contains(&k))
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};

    use super::*;
    use crate::acp::memory::{MemoryRepo, MemoryResolver, MemoryStatus};
    use crate::acp::policy::BasicPolicy;
    use crate::acp::record::fixtures::{attestor, kit, mallory};
    use crate::acp::record::{
        ATTESTATION_TYPE, CLAIM_TYPE, Claim, ClaimKind, StatusRef, StrongRef, UnsignedAttestation,
    };
    use crate::acp::sign::sign;
    use crate::acp::status::{UnsignedStatusList, sign_status_list};

    const NOW: &str = "2026-08-29T10:00:00Z"; // nine days after issuance
    const STATUS_URL: &str = "https://attest.example/status/1";
    const INDEX: u64 = 4127;

    fn key(seed: u8) -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[seed; 32]).unwrap()
    }
    fn keys_of(k: &Secp256k1Keypair) -> KeyMaterial {
        KeyMaterial {
            verification: vec![VerifyingKey::from_did_key(&k.did()).unwrap()],
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
                list: STATUS_URL.into(),
                index: INDEX,
            });
            let att = sign(body, Repository(&kit()), &attestor_key).unwrap();
            let (att_uri, _) = repo.put(&kit(), ATTESTATION_TYPE, "3kx2vq7abcd2k", &att);

            dids.publish(&attestor(), keys_of(&attestor_key));

            let list = sign_status_list(
                UnsignedStatusList::new(attestor(), dt("2026-08-20T10:12:00Z"), 8192),
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
            let mut body = UnsignedStatusList::new(attestor(), dt("2026-08-21T00:00:00Z"), 8192);
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
            ClaimKind::Email,
            serde_json::json!({ "address": "kit@other.example" }),
            dt("2026-08-20T09:00:00Z"),
        )
        .unwrap();
        w.repo.replace(&w.claim_uri, &edited);
        assert_eq!(reason(w.verdict().await), Reason::ClaimRewritten);
    }

    #[tokio::test]
    async fn malformed_record() {
        let w = World::new();
        w.repo.replace_bytes(&w.att_uri, b"\xa0".to_vec()); // an empty map
        assert!(matches!(reason(w.verdict().await), Reason::Malformed(_)));
    }

    #[tokio::test]
    async fn subject_mismatch() {
        // A vouch that names mallory as subject, but was signed for and
        // lives in kit's repo: step 2 catches the lie before the signature.
        let w = World::new();
        let mut body = w.attestation().body;
        body.subject = mallory();
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
            UnsignedStatusList::new(attestor(), dt("2026-08-22T00:00:00Z"), 8192),
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
        let bytes = w.repo.get(&w.att_uri).unwrap().bytes;
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
        let mut body = w.attestation().body;
        body.subject = mallory();
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
        assert!(
            at(&w, "2026-08-20T09:56:00Z").await.is_in_force(),
            "inside skew"
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
            UnsignedStatusList::new(attestor(), dt("2026-08-25T00:00:00Z"), 8192),
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
            UnsignedStatusList::new(attestor(), dt("2026-08-25T00:00:00Z"), 8),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, tiny.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::StatusIndexOutOfRange);
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
            UnsignedStatusList::new(attestor(), dt("2026-08-20T00:00:00Z"), 8192),
            &w.attestor_key,
        )
        .unwrap();
        w.status.publish(STATUS_URL, stale.to_bytes().unwrap());
        assert_eq!(reason(w.verdict().await), Reason::Revoked);
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
    async fn no_status_pointer_skips_step_6() {
        let w = World::new();
        let mut body = w.attestation().body;
        body.status = None;
        let att = sign(body, Repository(&kit()), &w.attestor_key).unwrap();
        w.repo.replace(&w.att_uri, &att);
        w.status.go_dark(); // would be Err if consulted
        assert!(w.verdict().await.is_in_force());
    }

    #[tokio::test]
    async fn policy_not_demanding_freshness_skips_step_6() {
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
                fetched.bytes,
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

            dids.publish(
                &kit(),
                KeyMaterial {
                    verification: vec![],
                    rotation: vec![kit_key.did()],
                },
            );
            dids.publish(
                &fox(),
                KeyMaterial {
                    verification: vec![],
                    rotation: vec![kit_key.did(), host_key.did()],
                },
            );
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
    async fn pair_in_force_from_either_half() {
        let p = Pair::new();
        assert!(p.verdict_from(&p.kit_half).await.is_in_force());
        assert!(p.verdict_from(&p.fox_half).await.is_in_force());
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
        p.dids.rotate(
            &fox(),
            KeyMaterial {
                verification: vec![],
                rotation: vec![key(51).did()],
            },
        );
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
