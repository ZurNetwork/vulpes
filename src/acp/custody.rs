//! Administrative health — the administration lane's due-diligence helpers.
//!
//! **Never an ownership gate.** `verify_attestation` does not call this
//! module and nothing here changes a verdict: ownership is the owner's claim
//! plus the owned DID's attestation, two facts, verified as any attestation
//! (FORKS F45, F47; `docs/acp.md` §Relationships are attestations). What this
//! module answers is the *other* lane's question — "can this owner win a key
//! war over the owned DID?" (`docs/ccs.md` §The senior-key custody rule) — for
//! a consumer that wants it: a buyer's due diligence before a transfer settles,
//! a client's health read on its own characters. A key compromise forges no
//! history; a hostile claim touches no keys; the two lanes share no verdicts.
//!
//! Inputs are the [`KeyMaterial`] the [`DidResolver`] port already returns.
//! Rotation entries are compared as verbatim `did:key:` strings in directory
//! order (see [`KeyMaterial::rotation`]) — positions and string equality,
//! never key material. Custodian keys are **discovered, never shipped**
//! (FORKS F44): vulpes has no line that knows who Bluesky is.

use std::collections::BTreeSet;

use crate::Did;

use super::ports::{DidResolver, KeyMaterial, ResolveError};
use super::sign::is_did_key_shaped;

/// The rotation keys a host operator holds on the accounts it custodies,
/// as verbatim `did:key:z…` strings.
///
/// Which keys are custodians' is the caller's to say: `did:plc` lets one
/// key sit on any number of DIDs and records nothing about who holds it, so
/// no rule over the lists alone can tell an owner's key from an operator's.
/// The set must be **complete** for the hosts in play — an operator key it
/// does not name counts as personal and sets no floor (the documented
/// completeness caveat, asserted in this module's tests). [`Self::discover`]
/// is the route that keeps it complete without a registry (FORKS F44).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustodianKeys(BTreeSet<String>);

impl CustodianKeys {
    /// No custodians named. The seniority read then has no floor and
    /// degrades to "some rotation key in both lists" — the permissive mode,
    /// documented at [`holds_senior_rotation_key`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Discover a host's custodian keys from the directory (FORKS F44): the
    /// rotation keys **common to every sample** are the operator's. Name two
    /// or more unrelated accounts on the host; one sample takes everything on
    /// it (the documented caveat). An unresolvable sample is `Err`, never a
    /// quietly empty set; no samples is the empty set. Entries not shaped like
    /// a `did:key:z…` string are dropped before intersecting.
    pub async fn discover(
        resolver: &dyn DidResolver,
        samples: impl IntoIterator<Item = &Did>,
    ) -> Result<Self, ResolveError> {
        // A sample's rotation keys, shaped ones only: a placeholder two
        // resolvers happen to share must never be "discovered" as a key.
        async fn rotation_of(
            resolver: &dyn DidResolver,
            did: &Did,
        ) -> Result<BTreeSet<String>, ResolveError> {
            let Some(keys) = resolver.keys(did).await? else {
                return Err(ResolveError::new(format!(
                    "custodian sample {did} does not resolve"
                )));
            };
            Ok(keys
                .rotation
                .into_iter()
                .filter(|k| is_did_key_shaped(k))
                .collect())
        }
        let mut samples = samples.into_iter();
        let Some(first) = samples.next() else {
            return Ok(Self::empty());
        };
        let mut common = rotation_of(resolver, first).await?;
        for did in samples {
            common = &common & &rotation_of(resolver, did).await?;
        }
        Ok(Self(common))
    }

    /// Whether `key` (verbatim) is a custodian's.
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }

    /// The named keys, sorted.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// Name custodian keys by hand. Entries are verbatim `did:key:z…` strings
/// as the PLC directory lists them; anything else matches no rotation entry
/// and silently protects nothing, so debug builds assert the shape.
impl<S: Into<String>> FromIterator<S> for CustodianKeys {
    fn from_iter<I: IntoIterator<Item = S>>(keys: I) -> Self {
        let mut set = BTreeSet::new();
        for key in keys {
            let key = key.into();
            debug_assert!(
                is_did_key_shaped(&key),
                "custodian entry {key:?} is not a did:key:z… string and will never match"
            );
            set.insert(key);
        }
        Self(set)
    }
}

impl<'a> IntoIterator for &'a CustodianKeys {
    type Item = &'a str;
    type IntoIter =
        std::iter::Map<std::collections::btree_set::Iter<'a, String>, fn(&String) -> &str>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(String::as_str)
    }
}

/// The seniority read: the owner holds a rotation key that sits **above
/// every custodian's** in the owned DID's list — `docs/ccs.md`'s senior-key
/// rule, checked literally.
///
/// The owner is administratively senior iff some `K` in the owner's rotation
/// list, with `K` not a custodian key, appears in the owned DID's rotation
/// list at an index lower (more senior) than every custodian key there — or
/// there is no custodian key there at all. "Some key in both lists" matched
/// bsky.social's operator key on every co-hosted pair, and "top equals top"
/// both failed junior co-owners and passed two accounts with *only* operator
/// keys; position conventions differ by tool, too (Bluesky's signup puts a
/// user key first; `goat` appends one last), so only the order relative to
/// the named custodians is meaningful.
///
/// Consequences: a junior co-owner passes as long as they are above the
/// custodian; two DIDs carrying nothing but custodian keys fail closed
/// (nobody personal holds either); with an **empty** custodian set the read
/// degrades to "some key in both lists"; and an operator key the set does
/// not name counts as personal and sets no floor — the completeness caveat.
/// Verification keys never count: `did:plc` gives them no control over the
/// identity. Both lists are the verbatim `did:key:` strings the directory
/// holds, in its order — nothing to normalize — and an entry not shaped like
/// a `did:key:z…` string is never a key.
///
/// This is a health read, not a verdict: see the module docs.
pub fn holds_senior_rotation_key(
    owner: &KeyMaterial,
    owned: &KeyMaterial,
    custodians: &CustodianKeys,
) -> bool {
    CustodyReport::inspect(owner, owned, custodians).owner_senior
}

/// What a due-diligence read sees — enough to name each incomplete-handover
/// shape in `docs/ccs.md` §Transfer (buyer added junior; seller's key left
/// in the list; attestation only, no rotation at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyReport {
    /// [`holds_senior_rotation_key`].
    pub owner_senior: bool,
    /// Indices in `owned.rotation` held by the owner's non-custodian keys,
    /// ascending. Empty = the owner holds no rotation key on the owned DID.
    pub owner_positions: Vec<usize>,
    /// `owned.rotation` minus custodians, in directory order — "two personal
    /// keys where one was promised" is visible here.
    pub non_custodian_keys: Vec<String>,
    /// The most senior custodian position in `owned.rotation`, if any.
    pub custodian_floor: Option<usize>,
}

impl CustodyReport {
    /// The full read behind [`holds_senior_rotation_key`], for consumers
    /// that present findings rather than a bool.
    pub fn inspect(owner: &KeyMaterial, owned: &KeyMaterial, custodians: &CustodianKeys) -> Self {
        // A *personal* entry: key-shaped and not a custodian's.
        let personal = |k: &&String| is_did_key_shaped(k) && !custodians.contains(k);
        // The most senior custodian position in the owned list, if any.
        let custodian_floor = owned
            .rotation
            .iter()
            .position(|k| is_did_key_shaped(k) && custodians.contains(k));
        let mut owner_positions: Vec<usize> = owner
            .rotation
            .iter()
            .filter(personal)
            .filter_map(|k| owned.rotation.iter().position(|o| o == k))
            .collect();
        owner_positions.sort_unstable();
        owner_positions.dedup();
        let owner_senior = owner_positions
            .iter()
            .any(|&idx| custodian_floor.is_none_or(|floor| idx < floor));
        let non_custodian_keys = owned.rotation.iter().filter(personal).cloned().collect();
        Self {
            owner_senior,
            owner_positions,
            non_custodian_keys,
            custodian_floor,
        }
    }
}

#[cfg(test)]
mod tests {
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};

    use super::*;
    use crate::acp::memory::MemoryResolver;
    use crate::acp::sign::VerifyingKey;

    fn key(seed: u8) -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[seed; 32]).unwrap()
    }
    fn vk(k: &Secp256k1Keypair) -> VerifyingKey {
        VerifyingKey::from_did_key(&k.did()).unwrap()
    }
    fn rotation(keys: &[&Secp256k1Keypair]) -> KeyMaterial {
        KeyMaterial {
            verification: vec![],
            rotation: keys.iter().map(|k| k.did()).collect(),
        }
    }
    fn custodians(keys: &[&Secp256k1Keypair]) -> CustodianKeys {
        keys.iter().map(|k| k.did()).collect()
    }
    fn did(s: &str) -> Did {
        Did::new(s)
    }

    // --- the seniority read (recovered from 7045189^, minus the attestations) ---

    #[test]
    fn owner_above_custodian_is_senior() {
        // Kit [kit, host] owns Fox [kit, host].
        let (kit, host) = (key(50), key(51));
        assert!(holds_senior_rotation_key(
            &rotation(&[&kit, &host]),
            &rotation(&[&kit, &host]),
            &custodians(&[&host]),
        ));
    }

    #[test]
    fn custodian_senior_is_not_control() {
        // Fox lists the host above Kit: present but junior.
        let (kit, host) = (key(50), key(51));
        assert!(!holds_senior_rotation_key(
            &rotation(&[&kit, &host]),
            &rotation(&[&host, &kit]),
            &custodians(&[&host]),
        ));
    }

    #[test]
    fn verification_keys_do_not_confer_control() {
        // Kit's *signing* key is Fox's senior rotation key; Kit's rotation
        // list does not contain it.
        let (signing, kit_rot, host) = (key(53), key(50), key(51));
        let owner = KeyMaterial {
            verification: vec![vk(&signing)],
            rotation: vec![kit_rot.did()],
        };
        assert!(!holds_senior_rotation_key(
            &owner,
            &rotation(&[&signing, &host]),
            &custodians(&[&host]),
        ));
    }

    #[test]
    fn co_owner_ordering() {
        // [kit, bo, host]: both above the custodian, both senior. Bo below
        // the host is not.
        let (kit, bo, host) = (key(50), key(54), key(51));
        let c = custodians(&[&host]);
        let bo_keys = rotation(&[&bo, &key(52)]);
        assert!(holds_senior_rotation_key(
            &rotation(&[&kit]),
            &rotation(&[&kit, &bo, &host]),
            &c
        ));
        assert!(holds_senior_rotation_key(
            &bo_keys,
            &rotation(&[&kit, &bo, &host]),
            &c
        ));
        assert!(!holds_senior_rotation_key(
            &bo_keys,
            &rotation(&[&kit, &host, &bo]),
            &c
        ));
    }

    #[test]
    fn only_custodian_keys_fail_closed() {
        let host = key(51);
        assert!(!holds_senior_rotation_key(
            &rotation(&[&host]),
            &rotation(&[&host]),
            &custodians(&[&host]),
        ));
    }

    #[test]
    fn empty_custodian_set_degrades_to_any_shared_key() {
        // Documented permissive mode: the host key is "shared", so it passes.
        let host = key(51);
        assert!(holds_senior_rotation_key(
            &rotation(&[&host]),
            &rotation(&[&host]),
            &CustodianKeys::empty(),
        ));
    }

    #[test]
    fn unnamed_operator_key_is_the_completeness_hole() {
        // The set names host_b only; host_a sits above it on both DIDs and
        // counts as personal. This PASSES — the caveat, kept visible.
        let (host_a, host_b) = (key(51), key(52));
        assert!(holds_senior_rotation_key(
            &rotation(&[&host_a, &host_b]),
            &rotation(&[&host_a, &host_b]),
            &custodians(&[&host_b]),
        ));
    }

    #[test]
    fn malformed_rotation_entry_is_never_a_key() {
        let owner = KeyMaterial {
            verification: vec![],
            rotation: vec!["not-a-key".into()],
        };
        let owned = owner.clone();
        assert!(!holds_senior_rotation_key(
            &owner,
            &owned,
            &CustodianKeys::empty()
        ));
    }

    // --- discovery (FORKS F44) ---

    #[tokio::test]
    async fn discover_intersects_samples() {
        let (host, a, b) = (key(51), key(60), key(61));
        let r = MemoryResolver::new();
        r.publish(
            &did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
            rotation(&[&a, &host]),
        );
        r.publish(
            &did("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
            rotation(&[&b, &host]),
        );
        let c = CustodianKeys::discover(
            &r,
            [
                &did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
                &did("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(c, custodians(&[&host]));
    }

    #[tokio::test]
    async fn discover_one_sample_takes_everything() {
        let (host, a) = (key(51), key(60));
        let r = MemoryResolver::new();
        r.publish(
            &did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
            rotation(&[&a, &host]),
        );
        let c = CustodianKeys::discover(&r, [&did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")])
            .await
            .unwrap();
        assert_eq!(c, custodians(&[&a, &host]));
    }

    #[tokio::test]
    async fn discover_unresolvable_sample_is_err_not_empty() {
        let r = MemoryResolver::new();
        assert!(
            CustodianKeys::discover(&r, [&did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn discover_drops_malformed_entries() {
        // Two resolvers emitting the same placeholder must not "discover" it.
        let host = key(51);
        let r = MemoryResolver::new();
        let placeholder = KeyMaterial {
            verification: vec![],
            rotation: vec!["did:key:unknown".into(), host.did()],
        };
        r.publish(
            &did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
            placeholder.clone(),
        );
        r.publish(&did("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"), placeholder);
        let c = CustodianKeys::discover(
            &r,
            [
                &did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"),
                &did("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(c, custodians(&[&host]));
    }

    #[tokio::test]
    async fn discover_no_samples_is_empty() {
        let r = MemoryResolver::new();
        let c = CustodianKeys::discover(&r, []).await.unwrap();
        assert_eq!(c, CustodianKeys::empty());
    }

    // --- inspect: the ccs.md handover checklist ---

    #[test]
    fn inspect_sam_added_junior_to_kit() {
        // [kit, sam, vulpes, zurfur] — Sam is not senior; Kit still is.
        let (kit, sam, vulpes, zurfur) = (key(50), key(55), key(52), key(51));
        let c = custodians(&[&vulpes, &zurfur]);
        let fox = rotation(&[&kit, &sam, &vulpes, &zurfur]);
        let r = CustodyReport::inspect(&rotation(&[&sam]), &fox, &c);
        assert!(r.owner_senior); // above the custodians…
        assert_eq!(r.owner_positions, vec![1]); // …but not at the top: Kit can still fire Sam
        assert_eq!(r.non_custodian_keys, vec![kit.did(), sam.did()]);
        assert_eq!(r.custodian_floor, Some(2));
    }

    #[test]
    fn inspect_kits_key_left_in_the_list() {
        // [sam, kit, vulpes, zurfur] — two personal keys where one was promised.
        let (kit, sam, vulpes, zurfur) = (key(50), key(55), key(52), key(51));
        let r = CustodyReport::inspect(
            &rotation(&[&sam]),
            &rotation(&[&sam, &kit, &vulpes, &zurfur]),
            &custodians(&[&vulpes, &zurfur]),
        );
        assert!(r.owner_senior);
        assert_eq!(r.non_custodian_keys.len(), 2);
    }

    #[test]
    fn inspect_attestation_only_no_rotation() {
        // Sam owns Fox in every verifier's eyes and holds no key on it.
        let (kit, sam, vulpes, zurfur) = (key(50), key(55), key(52), key(51));
        let r = CustodyReport::inspect(
            &rotation(&[&sam]),
            &rotation(&[&kit, &vulpes, &zurfur]),
            &custodians(&[&vulpes, &zurfur]),
        );
        assert!(!r.owner_senior);
        assert!(r.owner_positions.is_empty());
    }
}
