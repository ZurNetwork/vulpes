//! Step 6: the verifier's own judgment.
//!
//! Steps 1–5 of verification are facts the protocol lets anyone check. Step
//! 6 is not: *is this attestor, using this method, at this age, sufficient
//! for this decision?* The protocol supplies signals; the verifier supplies
//! judgment — and the protocol never ranks attestors, so a policy that
//! trusts "anyone" is as legitimate as one that trusts three names.
//!
//! Judgment comes **before** the status fetch (step 7) on purpose: the
//! fetch goes to an address the attestation chose, and an attestor this
//! verifier would reject anyway must not be able to make it perform I/O.
//!
//! [`TrustPolicy`] is the seam; [`BasicPolicy`] is the obvious
//! implementation (allow-lists and an age cap). Anything richer — reputation,
//! per-kind rules, "two independent attestors" — implements the trait.

use std::collections::BTreeSet;

use crate::Did;

use super::record::ClaimKind;

/// What step 6 concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The signals suffice for this verifier's purpose.
    Accept,
    /// They do not; the string is the verifier's own reason, surfaced as
    /// [`Reason::PolicyRejected`](super::verify::Reason::PolicyRejected).
    Reject(String),
}

/// The signals steps 1–5 established, handed to the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyContext<'a> {
    /// Who vouched.
    pub attestor: &'a Did,
    /// The attestor's stated diligence, if any.
    pub method: Option<&'a str>,
    /// What kind of claim it is about.
    pub claim_kind: &'a ClaimKind,
    /// Seconds since `issuedAt`.
    pub age_secs: i64,
    /// Seconds until `expiresAt` — remaining lifetime is a freshness signal.
    pub remaining_secs: i64,
    /// Whether the attestation carries a status pointer at all. The lookup
    /// itself runs after this decision (step 7), when
    /// [`TrustPolicy::demands_freshness`] says so.
    pub has_status: bool,
}

/// The verifier's trust policy.
pub trait TrustPolicy: Send + Sync {
    /// Whether step 7 (status-list lookup) runs when a status pointer is
    /// present. A policy that does not care about same-day revocation can
    /// skip the fetch; expiry still applies regardless.
    fn demands_freshness(&self) -> bool;

    /// Step 6.
    fn decide(&self, ctx: &PolicyContext<'_>) -> Decision;

    /// The oldest status list this verifier will act on, in seconds since
    /// its `issuedAt`. `None` (the default) bounds nothing: the newest
    /// verifiable copy wins however old it is, and an adversary who can
    /// withhold fresh copies can pin a stale all-clear. High-stakes
    /// verifiers set this: with it, withholding can only push a verdict to
    /// *not checkable*, never to "not revoked" (`docs/acp.md`
    /// §Stale-status attacks). There is no structural floor — a list
    /// published before an attestation is still that attestor's last word
    /// after it dies (the kill test).
    fn max_status_age_secs(&self) -> Option<i64> {
        None
    }
}

/// Allow-lists and an age cap — enough for most relying parties.
///
/// Every field `None` means "no constraint". `Default` and
/// [`BasicPolicy::permissive`] are the same thing: any attestor, any
/// method, **revocation checked when a pointer is present** (status age
/// bounded only when `max_status_age_secs` is set) — the std-trait entry
/// point is never the more dangerous one, so `BasicPolicy {
/// trusted_attestors: …, ..Default::default() }` does not silently disable
/// step 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicPolicy {
    /// Attestors this verifier accepts. `None` = any.
    pub trusted_attestors: Option<BTreeSet<Did>>,
    /// `method` values this verifier accepts. `None` = any, including absent.
    pub accepted_methods: Option<BTreeSet<String>>,
    /// Run step 7 when a status pointer is present.
    pub demand_freshness: bool,
    /// Reject attestations older than this many seconds, whatever their
    /// `expiresAt` — the verifier's own, tighter freshness bar.
    pub max_age_secs: Option<i64>,
    /// Reject a status list older than this many seconds; see
    /// [`TrustPolicy::max_status_age_secs`].
    pub max_status_age_secs: Option<i64>,
}

impl Default for BasicPolicy {
    /// Revocation checked; nothing else constrained.
    fn default() -> Self {
        Self {
            trusted_attestors: None,
            accepted_methods: None,
            demand_freshness: true,
            max_age_secs: None,
            max_status_age_secs: None,
        }
    }
}

impl BasicPolicy {
    /// Any attestor, any method, revocation checked — the same as `Default`.
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Only these attestors.
    pub fn trusting(attestors: impl IntoIterator<Item = Did>) -> Self {
        Self {
            trusted_attestors: Some(attestors.into_iter().collect()),
            ..Self::permissive()
        }
    }
}

impl TrustPolicy for BasicPolicy {
    fn demands_freshness(&self) -> bool {
        self.demand_freshness
    }

    fn max_status_age_secs(&self) -> Option<i64> {
        self.max_status_age_secs
    }

    fn decide(&self, ctx: &PolicyContext<'_>) -> Decision {
        if let Some(trusted) = &self.trusted_attestors
            && !trusted.contains(ctx.attestor)
        {
            return Decision::Reject(format!("attestor {} is not trusted here", ctx.attestor));
        }
        if let Some(accepted) = &self.accepted_methods {
            match ctx.method {
                Some(m) if accepted.contains(m) => {}
                Some(m) => return Decision::Reject(format!("method {m:?} is not accepted here")),
                None => return Decision::Reject("attestation states no method".into()),
            }
        }
        if let Some(max) = self.max_age_secs
            && ctx.age_secs > max
        {
            return Decision::Reject(format!(
                "attestation is {}s old; this verifier accepts at most {max}s",
                ctx.age_secs
            ));
        }
        Decision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::record::fixtures::{attestor, mallory};

    fn ctx<'a>(att: &'a Did, method: Option<&'a str>, kind: &'a ClaimKind) -> PolicyContext<'a> {
        PolicyContext {
            attestor: att,
            method,
            claim_kind: kind,
            age_secs: 9 * 86_400,
            remaining_secs: 21 * 86_400,
            has_status: true,
        }
    }

    #[test]
    fn default_demands_freshness() {
        // The footgun: `..Default::default()` must not switch revocation off.
        let p = BasicPolicy {
            trusted_attestors: Some([attestor()].into()),
            ..Default::default()
        };
        assert!(p.demands_freshness());
        assert_eq!(BasicPolicy::default(), BasicPolicy::permissive());
    }

    #[test]
    fn permissive_accepts_anyone() {
        let p = BasicPolicy::permissive();
        assert!(p.demands_freshness());
        let (a, k) = (mallory(), ClaimKind::Email);
        assert_eq!(p.decide(&ctx(&a, None, &k)), Decision::Accept);
    }

    #[test]
    fn untrusted_attestor_is_rejected() {
        let p = BasicPolicy::trusting([attestor()]);
        let k = ClaimKind::Email;
        assert_eq!(p.decide(&ctx(&attestor(), None, &k)), Decision::Accept);
        assert!(matches!(
            p.decide(&ctx(&mallory(), None, &k)),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn method_filter() {
        let p = BasicPolicy {
            accepted_methods: Some(["email-challenge".to_string()].into()),
            ..BasicPolicy::permissive()
        };
        let (a, k) = (attestor(), ClaimKind::Email);
        assert_eq!(
            p.decide(&ctx(&a, Some("email-challenge"), &k)),
            Decision::Accept
        );
        assert!(matches!(
            p.decide(&ctx(&a, Some("oauth"), &k)),
            Decision::Reject(_)
        ));
        assert!(matches!(p.decide(&ctx(&a, None, &k)), Decision::Reject(_)));
    }

    #[test]
    fn max_age_is_the_verifiers_own_bar() {
        let p = BasicPolicy {
            max_age_secs: Some(86_400),
            ..BasicPolicy::permissive()
        };
        let (a, k) = (attestor(), ClaimKind::Email);
        let mut c = ctx(&a, None, &k);
        assert!(matches!(p.decide(&c), Decision::Reject(_)));
        c.age_secs = 3_600;
        assert_eq!(p.decide(&c), Decision::Accept);
    }
}
