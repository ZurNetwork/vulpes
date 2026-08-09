//! [`MintPolicy`] — the shape of the identities you mint, as explicit data.
//!
//! Everything about a genesis operation that is a *choice* rather than a
//! protocol rule lives here: which custodied keys become `rotationKeys` and in
//! what order, which one signs, which back the verification methods, and what
//! services (if any) the DID declares. The [`Minter`](crate::Minter) reads this
//! struct and never hard-codes any of it.
//!
//! [`MintPolicy::identity_only`] is the preset most deployments want and the one
//! this crate was extracted from — see its docs for exactly what it says.

use std::collections::BTreeMap;

use crate::KeyRole;
use crate::plc::PlcService;

/// The fewest `rotationKeys` an operation may declare.
///
/// Spec: an operation's `rotationKeys` "must include least 1 key and at most 5
/// keys, with no duplication"
/// (<https://web.plc.directory/spec/v0.1/did-plc>).
pub const MIN_ROTATION_KEYS: usize = 1;

/// The most `rotationKeys` an operation may declare. See [`MIN_ROTATION_KEYS`].
pub const MAX_ROTATION_KEYS: usize = 5;

/// The most verification methods a DID may carry, per the same spec: "A total
/// limit of 10 `verificationMethods` (per DID) has been added."
pub const MAX_VERIFICATION_METHODS: usize = 10;

/// Why a [`MintPolicy`] is not usable. Checked once, at
/// [`Minter`](crate::Minter) construction, so a misconfiguration fails at boot
/// rather than at the first mint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Fewer than [`MIN_ROTATION_KEYS`] rotation keys.
    #[error("a mint policy needs at least {MIN_ROTATION_KEYS} rotation key")]
    NoRotationKeys,
    /// More than [`MAX_ROTATION_KEYS`] rotation keys. Carries the count.
    #[error("a mint policy may declare at most {MAX_ROTATION_KEYS} rotation keys, got {0}")]
    TooManyRotationKeys(usize),
    /// The same role appears twice in `rotation_keys`; the spec forbids
    /// duplicate rotation keys.
    #[error("the {0} key is listed as a rotation key more than once")]
    DuplicateRotationKey(KeyRole),
    /// The signer is not among the rotation keys. Only a listed rotation key
    /// can sign an operation, so such a policy would mint operations the
    /// directory rejects.
    #[error("the {0} key signs operations but is not listed as a rotation key")]
    SignerNotARotationKey(KeyRole),
    /// More than [`MAX_VERIFICATION_METHODS`] verification methods. Carries the
    /// count.
    #[error("a DID may carry at most {MAX_VERIFICATION_METHODS} verification methods, got {0}")]
    TooManyVerificationMethods(usize),
}

/// How to shape the genesis operation of a newly minted `did:plc`.
///
/// Every field is explicit, and [`MintPolicy::identity_only`] is the named
/// preset. Construct it by starting from a preset and adjusting, or by naming
/// every field yourself.
///
/// ```
/// use std::collections::BTreeMap;
/// use zurid::{KeyRole, MintPolicy};
///
/// let policy = MintPolicy::identity_only();
/// assert_eq!(policy.rotation_keys, vec![KeyRole::ColdRecovery, KeyRole::Operational]);
/// assert_eq!(policy.signer, KeyRole::Operational);
/// assert_eq!(policy.verification_methods, BTreeMap::from([("atproto".to_string(), KeyRole::Signing)]));
/// assert!(policy.services.is_empty());
/// assert!(policy.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintPolicy {
    /// Which custodied keys become the DID's `rotationKeys`, in **descending
    /// authority** — index 0 is the highest.
    ///
    /// Recovery works by a lower-indexed key overriding a higher-indexed one
    /// within the directory's recovery window, so this order is the whole
    /// recovery story. 1–5 entries, no duplicates.
    pub rotation_keys: Vec<KeyRole>,

    /// Which key signs operations. Must appear in [`rotation_keys`]; any listed
    /// rotation key is a valid signer, so choosing a *lower*-authority one keeps
    /// the recovery key off the routine signing path.
    ///
    /// [`rotation_keys`]: MintPolicy::rotation_keys
    pub signer: KeyRole,

    /// The DID document's verification methods, by id — which custodied key
    /// backs each. At most [`MAX_VERIFICATION_METHODS`].
    pub verification_methods: BTreeMap<String, KeyRole>,

    /// The services the DID declares, by id (e.g. `atproto_pds`). **Empty** for
    /// an identity-only DID.
    pub services: BTreeMap<String, PlcService>,
}

impl MintPolicy {
    /// The **identity-only** preset: a valid, resolvable `did:plc` with no
    /// repository behind it — the pattern feed generators and labelers use, and
    /// the one this crate was extracted from.
    ///
    /// - `rotationKeys = [cold-recovery, operational]`, descending authority.
    ///   Index 0 is deliberately left to the coldest key, so a future
    ///   *user-held* recovery key can be enrolled above the platform's own.
    /// - The **operational** key signs. The spec allows any listed rotation key
    ///   to sign, and signing with the lower-authority one keeps the recovery
    ///   key off the signing path from birth.
    /// - One `atproto` verification method, backed by the signing key —
    ///   forward-compatibility for the day a repository is attached.
    /// - **No** services: the defining property of identity-only.
    pub fn identity_only() -> Self {
        Self {
            rotation_keys: vec![KeyRole::ColdRecovery, KeyRole::Operational],
            signer: KeyRole::Operational,
            verification_methods: BTreeMap::from([("atproto".to_string(), KeyRole::Signing)]),
            services: BTreeMap::new(),
        }
    }

    /// Check the policy against the `did:plc` spec's limits and its own internal
    /// consistency. Called for you by [`Minter::new`](crate::Minter::new).
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.rotation_keys.len() < MIN_ROTATION_KEYS {
            return Err(PolicyError::NoRotationKeys);
        }
        if self.rotation_keys.len() > MAX_ROTATION_KEYS {
            return Err(PolicyError::TooManyRotationKeys(self.rotation_keys.len()));
        }
        for (index, role) in self.rotation_keys.iter().enumerate() {
            if self.rotation_keys[..index].contains(role) {
                return Err(PolicyError::DuplicateRotationKey(*role));
            }
        }
        if !self.rotation_keys.contains(&self.signer) {
            return Err(PolicyError::SignerNotARotationKey(self.signer));
        }
        if self.verification_methods.len() > MAX_VERIFICATION_METHODS {
            return Err(PolicyError::TooManyVerificationMethods(
                self.verification_methods.len(),
            ));
        }
        Ok(())
    }
}

/// The identity-only preset — see [`MintPolicy::identity_only`].
impl Default for MintPolicy {
    fn default() -> Self {
        Self::identity_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_only_preset_validates() {
        assert_eq!(MintPolicy::default(), MintPolicy::identity_only());
        assert!(MintPolicy::identity_only().validate().is_ok());
    }

    // The preset's exact shape is a contract, not an accident: descending
    // authority with the cold key first, the operational key signing, one
    // atproto verification method, and no services.
    #[test]
    fn the_identity_only_preset_has_the_documented_shape() {
        let policy = MintPolicy::identity_only();
        assert_eq!(
            policy.rotation_keys,
            vec![KeyRole::ColdRecovery, KeyRole::Operational],
            "rotation keys are listed in DESCENDING authority"
        );
        assert_eq!(policy.signer, KeyRole::Operational);
        assert_eq!(
            policy.verification_methods,
            BTreeMap::from([("atproto".to_string(), KeyRole::Signing)])
        );
        assert!(
            policy.services.is_empty(),
            "identity-only means no services"
        );
    }

    #[test]
    fn rejects_an_empty_rotation_key_list() {
        let policy = MintPolicy {
            rotation_keys: Vec::new(),
            ..MintPolicy::identity_only()
        };
        assert_eq!(policy.validate(), Err(PolicyError::NoRotationKeys));
    }

    // The spec caps rotationKeys at 5; there are only three roles, so the cap is
    // reached by repetition — which the duplicate check catches first. Assert
    // the duplicate rule, and the cap on a synthetic over-long list.
    #[test]
    fn rejects_duplicate_rotation_keys() {
        let policy = MintPolicy {
            rotation_keys: vec![KeyRole::Operational, KeyRole::Operational],
            ..MintPolicy::identity_only()
        };
        assert_eq!(
            policy.validate(),
            Err(PolicyError::DuplicateRotationKey(KeyRole::Operational))
        );
    }

    #[test]
    fn rejects_more_than_five_rotation_keys() {
        let policy = MintPolicy {
            rotation_keys: vec![KeyRole::Operational; MAX_ROTATION_KEYS + 1],
            ..MintPolicy::identity_only()
        };
        assert_eq!(
            policy.validate(),
            Err(PolicyError::TooManyRotationKeys(MAX_ROTATION_KEYS + 1))
        );
    }

    // Only a listed rotation key may sign an operation, so a policy whose signer
    // is not listed would mint operations the directory rejects.
    #[test]
    fn rejects_a_signer_that_is_not_a_rotation_key() {
        let policy = MintPolicy {
            rotation_keys: vec![KeyRole::ColdRecovery],
            signer: KeyRole::Operational,
            ..MintPolicy::identity_only()
        };
        assert_eq!(
            policy.validate(),
            Err(PolicyError::SignerNotARotationKey(KeyRole::Operational))
        );
    }

    #[test]
    fn rejects_more_than_ten_verification_methods() {
        let verification_methods = (0..=MAX_VERIFICATION_METHODS)
            .map(|index| (format!("method{index}"), KeyRole::Signing))
            .collect::<BTreeMap<_, _>>();
        let policy = MintPolicy {
            verification_methods,
            ..MintPolicy::identity_only()
        };
        assert_eq!(
            policy.validate(),
            Err(PolicyError::TooManyVerificationMethods(
                MAX_VERIFICATION_METHODS + 1
            ))
        );
    }

    // A policy WITH a service is legal — identity-only is a preset, not a
    // constraint.
    #[test]
    fn a_pds_bearing_policy_is_valid() {
        let policy = MintPolicy {
            services: BTreeMap::from([(
                "atproto_pds".to_string(),
                PlcService {
                    type_: "AtprotoPersonalDataServer".to_string(),
                    endpoint: "https://pds.example.com".to_string(),
                },
            )]),
            ..MintPolicy::identity_only()
        };
        assert!(policy.validate().is_ok());
    }
}
