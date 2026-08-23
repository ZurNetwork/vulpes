# vulpes — the identity model (DRAFT, in design)

> Working design doc. Answers to the open questions go **inline** under each one.
> Nothing here is settled until the Engineer marks it `RULED`. This becomes the
> DD once it firms.

## The point

> **Scope (Engineer, 2026-08-10):** vulpes is PRIMARY and stands on its own. Zurfur
> (and any other project) is a *downstream consumer* — it depends on vulpes, never
> the reverse. vulpes's design is NOT constrained by Zurfur's DDs; Zurfur adapts to
> vulpes later. This doc is vulpes's own design record, not a Zurfur artifact.

vulpes is the authority that says **"this Holder has these identities."** The
did:plc write path (mint / update / tombstone) is what _one kind_ of identity is
made of underneath — not the whole of what vulpes is. vulpes is the aggregator.

> Quick edit to add on this. Vulpes is also the one that is supposed to say "Yes. This is THIS person". This may change how we see these, as we may need to actually allow people to login rather than just claim, but that's the point of Vulpes. Vulpes should also be the one that keeps the claims that someone is +18 based on other entities claiming so.

## vulpes's responsibilities — sharpened (2026-08-10, from the answers below)

Four responsibilities, not one:

1. **Aggregation** — a Holder, anchored by **one base DID** (Zurfur-minted or
   Bluesky), owns a set of identities. `RULED: base = one DID`.
2. **Verification** — "yes, this is that Holder." Proof of who someone is, likely
   via real **login** (control), not a bare claim.
3. **Attestation-holding** — vulpes keeps claims _other entities_ make about a
   Holder ("+18", verified-by-X). Verifiable-credentials shape: issuer → Holder
   (vulpes holds) → verifier.
4. **Granular, consented disclosure** — a relying party sees an identity or an
   attribute (e.g. "is this Holder +18?") only when the Holder grants it, **per
   relying party**. Selective disclosure; private/unlinkable until granted.

`RULED`: every identity is **proven theirs** — **controlled** (vulpes holds the
keys, a did:plc) or **connected** (OAuth-proven, keys elsewhere). The earlier
"merely claimed / unproven" tier is **OUT** — proof is required (that is what the
"allow login rather than just claim" note means).

## Vocabulary (locked)

- **Holder** `RULED 2026-08-10` — the thing that holds identities. Entity-neutral:
  a person, a business, an org, an automated agent. Not "Person" (a business
  holds identities too). VC-native term; pairs with "identities may be _given_."
- **Identity** — a way a Holder identifies itself _anywhere_. Plural per Holder,
  plural per platform, platform-agnostic. did:plc is one _kind_.

## Identity properties (from the Engineer, 2026-08-10 — being refined)

- **Visibility**: public or private, per the Holder's wish.
- **Disclosure**: "given or not freely" — the Holder controls whether an identity
  is handed out. _(exact meaning = OPEN Q1)_
- **Not platform-unique**: several identities may come from one platform.
- **Not necessarily connected**: having an identity ≠ OAuth-linking it. An
  identity may be merely _claimed_, not proven. _(spectrum = OPEN Q2)_

## Open questions

### Q1 — "given or not freely" means…

(a) selective **disclosure/linking** — the Holder chooses who is told "this is
mine"; and/or (b) identities can be **conferred by others** — issued/granted to a
Holder, not only self-created.

**Answer:** (a) specifically. Not only that, but identities must be granularly given permission to be looked at. If a platform may seek to know if someone is +18, they may connect that identity (for that platform) and the holder may already have +18 attached to it. The base identity is one DID (probably BlueSky or minted by Zurfur).

### Q2 — the control spectrum

Is an Identity any of: **controlled** (vulpes holds the keys — a minted did:plc) /
**connected** (OAuth-proven, keys live elsewhere) / **merely claimed** (asserted,
no proof)? And are did:plc, a Bluesky handle, an email, a Twitter handle all just
_kinds_ of Identity to vulpes?

**Answer:** Partially responded in Q1. It is controlled or connected, but must be proven as theirs. The main account is a DID, either ours (Zurfur) or Bsky's

### Q3 — is the _link_ itself private?

When two of a Holder's identities are both public, can an outside observer still
be unable to learn they are the _same Holder_ unless the Holder reveals the link?
If yes: vulpes is not a public directory — it is the authority on "these
identities are one Holder," and **unlinkability-by-default** is its core
invariant. (Suspected to be the real point.)

**Answer:** Partially replied by accident as a comment on `The Point`

> Claude's read: **yes** — the granular, per-relying-party disclosure in Q1 IS the
> Q3 answer. Nothing (identity or attribute) is visible without a grant, so the
> link is private by default. Correct me if that overreaches.

---

## New forks the sharpening opens (need the Engineer)

### NQ1 — disclosure architecture: online mediator vs offline wallet

The biggest one. Two very different crates:

- **Online IdP** — a relying party asks _vulpes_ ("is this Holder +18?"), the
  Holder consents, vulpes answers. vulpes is live in every disclosure (OIDC-ish).
- **Offline VC wallet** — vulpes issues the Holder verifiable credentials; the
  Holder _presents_ them to the relying party directly; vulpes isn't in the loop
  at disclosure time. More private, more moving parts, standards-heavy (W3C VC).

**Answer:** I believe Online IdP makes more sense in my mind. Offline seems very hard and hackable, but can probably be done in the future

`RULED 2026-08-10`: **Online IdP.** vulpes is live in every disclosure; offline VC
presentation is a deferred future mode. See **T1** — this choice puts vulpes _in_
the disclosure path, which reintroduces the correlation risk the unlinkability
invariant exists to prevent. Not a reason to reverse; a duty it imposes.

`REOPENED 2026-08-11`: **holder-held direction.** See "The pivot" section at the
end of this doc — decentralization became first-class, and holder-binding answers
the "offline is hackable" objection that produced this ruling.

### NQ2 — attestation trust: who may assert "+18"?

vulpes holds claims other entities make. Who is allowed to be an issuer, and how
does a verifier trust one? An issuer allow-list? A labeler model (atproto
Labelers)? Is vulpes the Holder's **wallet + verifier**, or also an **issuer**?
(Strong overlap with Zurfur's **Seals** DD 29622321 — attestations as labels,
institutional labelers + peer grants. This may be the generalization of Seals.)

**Answer:** Anybody may claim. The role of vulpes is only to save these claims. It is up to everybody else to trust or not these claims. That's the decentralized way.

`RULED 2026-08-10`: **vulpes is a neutral claim STORE, never a judge.** No issuer
allow-list; no verification verdict. A disclosure returns the claim **with its
signed provenance** ("entity X asserts +18"), and the relying party decides
whether it trusts X. vulpes is wallet + store, **not** verifier, **not** issuer.
Trust lives at the edge. See **T2** — one thing still open: whether _storing_ a
claim about a Holder needs the Holder's consent, or anyone may deposit one.

### NQ3 — relationship to Zurfur (architectural)

This model generalizes what Zurfur already has: `actor_identity` (the actor
super-table, DD 34013187), Seals (DD 29622321), the private↔public boundary +
cross-persona unlinkability, maturity labels (DD 29982722). Does **Zurfur become
a consumer of vulpes** for its identity + attestation layer — i.e. vulpes is the
generalization Zurfur adopts? That is a large, reversible-only-early call.

**Answer:** Yes, but that will change in its time. In my opinion, because of what this is, the supertable needs to move. Support for each identity is also in-code, not infinitely created.

`RULED 2026-08-10`: **Zurfur becomes a consumer of vulpes** (in time, not now).
Two consequences the Engineer stated:

- The `actor_identity` **supertable moves** out of Zurfur into vulpes — vulpes
  becomes its home. (Touches DD 34013187; needs a DD + `/design-sync` when acted.)
- **Identity kinds are a closed, in-code catalog** — each supported kind (did:plc,
  Bluesky, email, …) is defined in code and added by a code change, not created
  at runtime. Instances are unbounded; _kinds_ are enumerated. (Mirrors Zurfur's
  kind-checked-references / type-catalog pattern.)

---

## Tensions to resolve (opened by the rulings)

### T1 — online IdP vs the unlinkability invariant

Online IdP (NQ1) means a relying party asks _vulpes_ live, so **vulpes sees every
disclosure**: which RP asked what attribute about which Holder, when. That makes
vulpes itself the one party able to correlate all of a Holder's disclosures — the
exact correlation the core invariant forbids others from doing. The invariant
therefore has to bind vulpes too: minimize or **don't retain** disclosure
metadata, consider blinded/one-time disclosure tokens, keep the RP↔Holder mapping
out of any durable log. **How hard is this duty — a design constraint now, or a
later hardening?**

**Answer:** Later hardening. We can start with the concept.

`RULED 2026-08-10`: **deferred hardening** — ship the concept first. Caveat: the
architecture must not _preclude_ it. Concretely, don't make a durable RP↔Holder
disclosure log load-bearing; keep the disclosure path stateless enough that
minimization/blinding can be added later without a redesign.

### T2 — does storing a claim need the Holder's consent?

"Anybody may claim, vulpes only saves" (NQ2) + "disclosure is always Holder-
consented" (Q1/Q3) are consistent only if we pin who controls _storage_:

- **Open write, gated read** — anyone may deposit a signed claim about any Holder;
  the Holder governs who may _read_ it. An unsolicited/hostile claim is stored but
  inert (never disclosed without a grant). Fully decentralized; matches "anybody
  may claim."
- **Holder-accepted** — a claim only attaches when the Holder accepts it into
  their wallet (Zurfur's Seals "shelf" model, DD 29622321). "Anybody may _offer_";
  the Holder chooses what to hold.

Which? (This is the last thing between the model and a first responsibilities cut.)

**Answer:** Holder-accepted is the most decentralized AND it also closes to what we already had on Zurfur: Stuff has to be consented to.

`RULED 2026-08-10`: **Holder-accepted.** Anyone may _offer_ a signed claim; it
enters the Holder's record only on the Holder's acceptance (the Seals "shelf",
DD 29622321). Disclosure is then per-RP consented on top. Consent gates both
attach and read. Nothing about a Holder exists in vulpes without their say-so.

---

## Responsibilities — first cut (2026-08-10)

The model is firm enough for this. vulpes is a **verifiable identity broker**: a
consent-based claim wallet + online IdP, anchored on did:plc. What v0.1.0 shipped
(the did:plc write path) is the substrate of _one identity kind_, not the whole.

### vulpes OWNS

1. **Holder anchoring** — a Holder, anchored by one base DID (Zurfur-minted or
   Bluesky). Home of the `actor_identity` supertable (moves in from Zurfur, NQ3).
2. **Identity aggregation + proof** — binds _proven_ identities (controlled = keys
   / connected = OAuth) to a Holder, from a **closed in-code catalog** of kinds.
   Authority on "these identities are one Holder."
3. **Verification / login** — "yes, this is that Holder," via control of the
   anchor. Answers the identity question to relying parties, on consent.
4. **Consent-based claim wallet** — stores claims other entities _offer_, attaching
   only on Holder acceptance; preserves each claim's **signed provenance**; never
   judges trust (NQ2).
5. **Granular consented disclosure (online IdP)** — mediates live disclosure: RP
   asks, Holder consents per-RP/per-attribute, vulpes returns claim + provenance.
   Under the T1 duty (correlation-minimization stays possible).
6. **The did:plc write path** — custody, HMAC-bound log, sealed keys, mint/update/
   tombstone. Unchanged; now framed as what a _controlled_ did:plc identity is.
7. **Storage seam + one Postgres backend** — the traits + a shipped impl.

### vulpes does NOT own (edge / consumer)

- **Trust** — whether to believe issuer X. Entirely the relying party's (NQ2).
- **Issuing claims** — issuers are external; vulpes is wallet + store, not issuer.
- **What a claim _means_** — "+18" semantics, maturity policy, how a platform acts
  on a disclosure. The consumer's.
- **Offline VC presentation** — deferred (NQ1).
- **Consumer policy** — handle namespace, rate limits, session/CSRF, provisioning.

### Biggest downstream design areas (not yet decided)

- **Holder identity vs anchor** — is the Holder keyed _by_ the anchor DID, or a
  local id the anchor attaches to (so the anchor can change)? Affects rotation.
- **Claim data model** — VC / SD-JWT / a vulpes-native signed-claim shape?
- **Disclosure protocol** — OIDC-shaped, or custom? (this is the IdP surface)

These are the next design session; none blocks recording the model as a DD.

---

## Round 2 — the questions I still need (2026-08-10)

### Q4 — anchor keying & lifecycle

Is a Holder keyed **by** its anchor DID, or by a **local id** that the anchor DID
attaches to? And: can the anchor **change** (Bluesky→Zurfur, key rotation, a lost
DID), and is it strictly **one** anchor or can several DIDs be co-equal anchors of
the same Holder? (Keyed-by-DID is simpler but freezes the anchor forever; local-id
lets the anchor move — which the credible-exit story probably wants.)

**Answer:** The DID is our **Main and most important single ID**. I think the correct way to do this is by using one anchor, but I am willing to talk about it.

`PROVISIONAL 2026-08-10` (Engineer open to discussion): **one anchor, the DID is
the primary id.** Sharpening the discussion — two "changes" are being conflated:

- **Key rotation**: did:plc is built for it. The DID string is STABLE while keys
  rotate; keyed-by-DID does not block key rotation or credible-exit of keys. ✅
- **Anchor swap**: replacing the anchor DID with a _different_ DID (Bluesky-
  anchored Holder later wants a Zurfur-minted anchor). Keyed-by-DID **forbids**
  this — the DID _is_ the Holder.
  Only real question: **do you need anchor-swap?** No → keyed-by-DID is clean.
  Yes → a stable local Holder id, anchor as a swappable pointer. (Research thread 4
  informs this.)

`RULED 2026-08-10`: **NO swap — keyed-by-DID.** A DID's whole purpose is to be
decentralized and permanent; a swappable anchor would contradict it. did:plc key
rotation + credible-exit still work (the DID string is stable). The Holder IS its
anchor DID.

### Q5 — revocation

Consent gates attach + read (T2). But:

- Can a Holder **revoke** a disclosure already granted to an RP — and do we care
  that the RP may have cached the answer (online IdP makes re-check possible)?
- Can an **issuer revoke** a claim it made (a "+18" issued in error, a
  "verified-employee" that ended)? Does the wallet track claim **validity/expiry**,
  or is a claim eternal once accepted?

**Answer:** Yes and Yes. Both of them have to be revokable. That's consent. Revoked at any point.

`RULED 2026-08-10`: **everything revocable, any time.** Holder revokes a granted
disclosure; issuer revokes a claim; claims carry validity/expiry, not eternal.
Note: this is a _point in favour_ of the online-IdP ruling (NQ1) — because vulpes
is live in every disclosure, revocation takes effect on the next check with no
stale-cache problem. Revocation is a first-class op in the store + protocol.

### Q6 — predicate vs raw attribute (the privacy fork in the claim model)

For "+18": does vulpes store the **derived predicate** ("+18 = true, per X"), or the
**underlying attribute** ("DOB = …, per X") and compute the predicate at disclosure?
Storing the predicate leaks less if vulpes is breached; storing the raw attribute is
more flexible (any RP can ask any age question) but makes vulpes hold the sensitive
value. This directly shapes what the store contains.

**Answer:** It stores the **type**. It is a claim, but the type is **opaque**.

`RULED 2026-08-10`: **a claim = { type tag, OPAQUE payload, signed provenance }.**
vulpes does not interpret the payload — it stores and relays it. Consistent with
NQ2 (never judges) and with Zurfur's `opaque_json` + type-catalog pattern. Two
consequences:

- **vulpes is a RELAY, not a computer of predicates.** It cannot derive "+18" from
  a DOB it can't read. So predicate disclosure must be **issuer-baked** (the
  issuer mints an opaque "+18=true" claim) and selective disclosure lives **in
  the claim format**, not in vulpes. This directly constrains the claim-format
  choice → pick a format that carries its own selective disclosure.
- **Breach blast-radius is minimized by construction** — vulpes holds opaque
  blobs, not a pile of DOBs.

### Deferred to research, not asked cold

- **Claim data model** — VC / SD-JWT / a vulpes-native signed shape. I'll bring
  weighed options (standards maturity, Rust support, selective-disclosure fit).
- **Disclosure protocol** — OIDC-shaped vs custom. Same: researched options.

---

## Research synthesis (2026-08-10) — RECOMMENDATIONS, Engineer decides

Two independent threads (claim formats · disclosure protocols) converged on the
same shape. Full citations in the agents' reports.

### Decision A — claim format

- **Ruled-out-by-your-invariant reality:** _no_ mature, standards-track,
  hardware-friendly format gives BOTH true multi-show unlinkability AND
  predicate-without-raw-value. Only BBS (pairing crypto, W3C track, no range
  proofs) or AnonCreds (does both, non-standard, heavy) get close.
- **Recommendation:** model claims as a **W3C VCDM 2.0 envelope** (proof-suite-
  agnostic) → issue/present as **SD-JWT-VC** for the interop MVP → add **BBS Data
  Integrity** as the deferred unlinkable tier. Predicates = **issuer-baked
  booleans** ("+18=true"), which fits your Q6 opaque-relay ruling exactly (vulpes
  never computes; the issuer bakes; vulpes relays). AnonCreds held in reserve only
  if a true ZK range proof over a continuous value is ever required.

### Decision B — disclosure protocol

- **Recommendation:** **OID4VP (presentation) + OID4VCI (acquisition)**, both
  _Final_ 2025 standards, EUDI-proven. vulpes = a **custodial cloud wallet**.
  Format-agnostic, so SD-JWT-VC-now / BBS-later ride the same pipes; the did:plc
  anchor is the credential subject. Revocation (Q5) rides Token Status List.

### The crux both threads land on (this is the real Engineer call)

"Online IdP" (NQ1) + "custodial wallet" **re-centralizes correlation onto vulpes**.
OID4VP kills RP↔RP and issuer↔RP linkage — but does **nothing** about the wallet
operator seeing every who-asked-what. So the invariant's second half (**vulpes ≠
correlator**, our T1) is NOT protocol-given; it must be _engineered_:

- **Now:** batch single-use credentials (OID4VCI `proofs`), pairwise/ephemeral
  subject ids, and **retention-minimization as the load-bearing control** (no
  durable `(RP, Holder, question, time)` log; prefer artifacts the RP verifies
  without calling vulpes back).
- **The "+18" boolean specifically:** consider a **Privacy Pass** track
  (RFC 9474/9578 blinded tokens) — cryptographic issuer↔redemption unlinkability
  that batch-issuance only approximates. Tokens carry a _property_ not a rich
  claim, which is exactly right for a yes/no gate.
- **Deferred:** BBS as the named cryptographic-unlinkability upgrade for
  structured claims.

### Genuine forks the research surfaced (→ likely `/design-decision`)

1. **Custodial cloud wallet vs issuer topology** — does vulpes hold credentials
   (custodial, re-centralizes correlation) or stay closer to an issuer/relay?
2. **Does the "+18" class ride OID4VP, or a separate Privacy Pass track?**

### Rust ecosystem verdict (thread 3, 2026-08-10) — ⚠️ the OID4VC layer is IMMATURE

No single maintained crates.io library gives OID4VCI **+** OID4VP cleanly:

- **walt.id** — JVM/Kotlin only, no Rust.
- **Procivis `one-core`** — real Rust, both flows, but a backend _service_, not a
  crates.io dependency; its library form (`one-open-core`) is **archived**.
- **`identity_iota`** (IOTA) — genuine published crate (1.5.1), solid W3C DID/VC +
  SD-JWT core, but **no OID4VC** at all.
- **SpruceID `ssi`** — the mature Rust VC-core (DID/VC/SD-JWT); `spruceid/openid4vp`
  is the OID4VP piece (maturity check still owed by the parked ssi deep-dive).
- **`credibil-vc`** (ex-vercre) — OID4VCI only, **OID4VP = TODO**, idle since 2025-09.
- Other crates.io OID4VC: impierce `oid4vci`/`oid4vp`/`oid4vc`, `sicpa-dlab/openid4vc-rs`.

**Implication (matches your wrap-if-healthy / hand-roll-the-gap doctrine):** the VC
_core_ is wrappable (`ssi` or `identity_iota` + an SD-JWT crate). The OID4VP/VCI
_protocol surface_ is the gap — either wrap an early crate (impierce/spruceid) and
contribute upstream, or hand-roll it on a solid VC core, the way did:plc was
hand-rolled. This argues for **phasing**: VC-core + SD-JWT-VC + a minimal
disclosure surface first; full OID4VP conformance as it matures.

### Build stack — RESOLVED (SpruceID deep-dive, 2026-08-10)

The whole credential/protocol layer is **wrappable on SpruceID** — one coherent
`ssi` 0.16 across all three layers. vulpes hand-rolls almost nothing new (did:plc
is already done in v0.1.0); it wraps the VC/OID4VC stack and builds only vulpes's
own layer (private aggregation graph, Holder-accept + consent, custody, per-RP
minting) on top.

| Layer | Verdict | Crate(s) |
|---|---|---|
| VC core + SD-JWT-VC | **WRAP** | `ssi` 0.16.0 (`ssi-vc`, `ssi-vc-jose-cose` 0.7, `ssi-sd-jwt` 0.6); active, VCDM 2.0 + SD-JWT, SpruceID leads the SD-JWT-VC spec |
| OID4VP / OID4VCI | **WRAP as pinned git revs** | `spruceid/openid4vp` + `spruceid/oid4vci-rs` — only actively-maintained Rust OID4VC pair, OID4VP 1.0 + DCQL, share `ssi` 0.16 |
| BBS unlinkable tier | **WAIT-then-WRAP, feature-gated OFF** | `ssi-bbs` 0.2 → `bbs-2023` (zkryptium 0.2.2); path exists in-stack but young |

**Gotchas to honor:** OID4VC crates are **git-only** (pin exact revs; expect pre-1.0
churn) · `ssi`'s only audit is **2022, pre-rewrite** → run our own `/security-review`
on the crypto/verification paths before trusting them · the BBS path drags heavy
exact-pinned `bls12_381` crypto → keep `bbs` features OFF for the SD-JWT-VC MVP so
the dep tree stays lean · `ssi`/OID4VC are edition 2021 (vulpes is 2024 — fine) ·
`ssi` MSRV unverified (check against CI pin). Unverified: whether `vc-jose-cose`
does the full IETF SD-JWT-VC `vct` typed profile — confirm against our issuance shape.

**Research is now complete — every layer has a wrap/hand-roll/wait verdict.**

---

## atproto + prior-art synthesis (2026-08-10) — thread 4 (all four threads now in)

### Build ON (atproto already gives us)

- **did:plc as the Holder anchor is ideal for Q4.** The DID is derived from the
  genesis-op hash → **immutable for life** across every key/handle/PDS change;
  native **72h credible-exit/recovery** (the exact custody Zurfur runs, DD 26804226);
  the **DID survives PDS migration**. So keyed-by-DID gives key rotation + credible
  exit for free. **Anchor-SWAP (Bluesky↔Zurfur) has NO atproto support** — it would
  be a pure vulpes-side construct. → your "one anchor, DID-keyed" is well-founded
  _if you don't need swap_; that's the whole of the Q4 question.
- Bidirectional handle verification (Zurfur's `*.zurfur.app` well-known already
  mirrors it).

### GAPS vulpes must fill (atproto offers NOTHING reusable)

- **No cross-DID "same person" linking** — `alsoKnownAs` aliases one DID's handles
  only. The aggregation graph is unmodeled on-protocol → a vulpes private construct.
- **NQ2 refined — atproto Labels are the WRONG primitive for "+18".** Labels are
  public-to-subscribers, name the subject DID in cleartext, no consent, no
  selective disclosure — a durable **correlation beacon**, the opposite of the
  invariant. vulpes builds its OWN private attestation store. (⚠️ tension with
  Zurfur's Seals DD 29622321, which leaned on atproto Labelers — the NQ3 adoption
  will have to reconcile that.)
- **No VC / selective-disclosure / ZK anywhere in atproto** — vulpes supplies the
  entire private-attestation layer.

### HARD RULE the public PLC log forces (unlinkability implementation)

The PLC audit log is public + unredactable + firehose-indexed. Therefore, **by
construction**: never share a key across a Holder's personas; treat any handle
ever in `alsoKnownAs` as permanently public+linked; **the aggregation graph and
every claim live ONLY in vulpes's private store — never in a DID doc or public
repo record.**

### The central tension — RESOLVED by prior art (this is the payoff)

Farcaster deliberately makes identity-linking **public/linkable**; EUDI's core is
**unlinkability**. vulpes wants BOTH (aggregate many identities AND stay unlinkable).
Resolution the research converged on:

> **Aggregate privately, disclose unlinkably.** The aggregation graph exists
> Holder-side only and is NEVER a presentable artifact. Bind identities with
> **two-signature, domain-separated, nonce-fresh proofs** (Farcaster L3) stored in
> the Holder's vulpes vault, never public. Disclose to an RP only via **per-RP,
> single-use, selective-disclosure** credentials (EUDI L4) that **never expose the
> graph**. Per-RP **pairwise identifiers**; SIWE-style domain-scoped consent
> handshake. Reject ENS's single-public-name aggregation entirely.

### Prior-art lessons → decisions (each cited in the agent report)

- **L1 Gitcoin/Human Passport** — disclose a **derived verdict**, never raw claims;
  Sybil via **salted hashes/nullifiers**; use an order-INDEPENDENT dedup rule
  (Passport's LIFO is a bug). Confirms Q6.
- **L2 EAS** — split a **public claim-TYPE registry** (additive, mirrors Zurfur
  lexicon DD 29818896) from **private attestation INSTANCES**; **revoke-don't-delete**
  (fact-anchored, Zurfur's model); `refUID` supersession; fix `revocable` at type level.
- **L3 Farcaster** — cross-identifier links = **two mutually-consented signatures**,
  domain/scheme-tagged with a freshness nonce; split anchor key from revocable
  delegate keys → this is the proof mechanism for a **connected** identity (Q2).
- **L4 EUDI** — unlinkability is a **minting/spending** property (batch one-time-use +
  per-RP pseudonyms), not a disclosure filter; salted hashes defeat colluding RPs
  **but not the issuer** → leave an **additive ZKP (BBS+) seam**, exactly as the EU
  deferred it. Matches the make-unsoundness-unreachable doctrine.
- **L5 SIWE/ENS** — fresh domain-scoped nonce proof-of-control per RP; reject
  single-public-name aggregation.

### Where this leaves the design

Research-complete. The model is coherent and prior-art-backed end to end. Next:
formalize as a **DD**, and settle the two remaining Engineer forks below. The
did:plc write path already shipped (v0.1.0) is the anchor substrate; everything
above it is new build.

---

## The two remaining forks (explanations for the Engineer)

### F-A — how much does vulpes hold at rest? (custodial wallet vs lighter relay)

Your NQ1 (online IdP) + Q6 (vulpes stores the accepted claim) already lean
**custodial**: vulpes is the live party in every disclosure and holds the claims.
The remaining knob is _how much credential material sits in vulpes at rest_:

- **Full custodial cloud wallet** — vulpes durably holds each Holder's issuer-signed
  credentials and presents them. Most convenient (any device, no client wallet),
  fully matches "online IdP". Cost: vulpes becomes the single juiciest breach +
  correlation target; "vulpes ≠ correlator" (T1) is pure engineering discipline.
- **Lighter live relay** — vulpes holds minimal state (accepted-claim records +
  references), and re-derives/re-mints a fresh per-RP presentation at disclosure
  rather than storing the full credential. Smaller breach blast-radius, still
  online. Cost: more moving parts; needs the issuer reachable or a re-mint path.

**Recommendation:** custodial is consistent with your rulings — go custodial, but
**minimize what's held at rest** (store accepted opaque claims + provenance, mint
per-RP single-use presentations live, no durable RP↔Holder log). That gets the
convenience without making vulpes a honeypot of raw credentials.

**Answer:** This is a very hard thing to answer. I think custodial with the most possible minimum is fine. I think we should never store a log of who asked what, out of privacy.

`RULED 2026-08-10`: **custodial, minimal-at-rest, NO who-asked-what log.** vulpes
holds accepted opaque claims + provenance, mints per-RP single-use presentations
live, and never persists a `(RP, Holder, question, time)` record. This is the
engineered form of the T1 "vulpes ≠ correlator" duty.

### F-B — does "+18" ride OID4VP, or a separate Privacy Pass track?

Two ways to answer a yes/no gate like "is this Holder +18?":

- **OID4VP (uniform)** — "+18" is a credential like any other; unlinkability across
  RPs comes from batch single-use credentials + pairwise ids. One pipe for
  everything, simpler — but the guarantee is _operational_ (issuer mints N one-time
  creds), and issuer-collusion can still link. The strongest-privacy case (an age
  gate, checked everywhere) gets the weakest guarantee.
- **+ Privacy Pass (RFC 9474/9578 blinded tokens)** — for a pure boolean, blind
  signatures give _cryptographic_ issuer↔redemption unlinkability: the issuer
  literally cannot link a token's issuance to its use, even under collusion. Perfect
  for yes/no gates (+18, "verified human", "member"); cannot carry structured data.
  Cost: a second mechanism + code path alongside OID4VP.

**Recommendation:** OID4VP as the backbone for all _structured_ claims; add a
Privacy Pass track for the high-stakes _boolean gates_ (age especially — the
canonical "prove a predicate, reveal nothing, don't be tracked" case). It's
**additive**, so it can be deferred: ship OID4VP-only, add Privacy Pass when the
boolean-gate volume justifies it. Given unlinkability is your core invariant, the
strongest guarantee for the most-checked claim is well-aligned.

**Answer:** (Engineer 2026-08-10) "+18" is a CLAIMS problem, not a boolean —
answering it is *find a YES **and** believe whoever issued the yes*. Provenance is
inseparable from the claim (NQ2 in action).
`RULED-leaning`: **"+18" rides OID4VP like every other claim, carrying its
issuer's signed provenance; the RP evaluates the issuer per-disclosure.** Privacy
Pass drops to a **deferred, optional** add-on for the narrow case where an RP has
already pre-committed to a single trusted issuer for a boolean gate and just wants
the most-private proof — it *cannot* do per-disclosure provenance evaluation
(that's the price of its unlinkability), so it is NOT the model, only an
optimization.

**Correction this forces (fixes L1 / the disclosure contract):** vulpes NEVER
discloses a computed "verdict." Gitcoin computes a score — it is a *judge*; vulpes
is NOT. vulpes discloses **"[issuer X's signed claim]" + provenance** and the RP
judges X. This is the OIDC Distributed/Aggregated-Claims shape (native to OID4VP)
and the concrete form of Q6 (opaque, provenance-carrying) + NQ2 (never judges).

---

## The pivot (2026-08-11) — decentralization first-class, NQ1 reopened

Decided in conversation the night of 2026-08-10/11; recorded here 2026-08-11.

**Decentralization is now a first-class value, and it reopened NQ1.**

1. **No lock-in, by design.** Zurfur (and anyone) must be able to swap vulpes
   out. vulpes deliberately gives up being a chokepoint; swappability is the
   point.
2. **NQ1 REOPENED → holder-held.** Move from online-IdP-mediator to holder-held
   credentials presented peer-to-peer (offline VC / OID4VP). vulpes *issues* and
   *publishes revocation status* (Token Status List) but is **not in the
   disclosure loop**: a verifier checks the issuer signature + status list
   without calling vulpes. The old "offline is hackable" objection is largely
   answered by **holder-binding**, already ruled in. This dissolves T1
   structurally — vulpes exits the disclosure path instead of having to be
   disciplined inside it.
3. **vulpes = three layers** (the reframed role):
   - **The library (the real product)** — did:plc anchor + custody + the
     Holder/aggregation model + the claims discipline + wrapped VC/OID4VP.
   - **The open protocol/format** — VC 2.0 / SD-JWT-VC / OID4VP / status lists,
     plus vulpes's own contribution, the **Consensual Claims System**
     (`docs/ccs.md`).
   - **An optional, exitable reference instance** — hosted wallet + issuer +
     status host for people who won't self-host. Use it or leave it.
4. **Language: "broker" → "toolkit / layer / framework."** "Broker" implies a
   mediator in the middle — exactly what was removed.
5. **The atproto public/private boundary** (same line as Zurfur's Class A/B
   Boundary Contract, DD 29622283):
   - **Public → atproto-native**: did:plc, atproto OAuth, handle resolution,
     public claims as records/labels in the Holder's PDS repo.
   - **Private → open W3C/OpenID VC standards, holder-held**: private claims,
     the aggregation graph, consented disclosure. atproto has no private/VC/SD
     mechanism, so the IETF/W3C stack is both the standards-compliant choice
     and the only one.
   - **Bridge**: a private VC the Holder consents to publish becomes a public
     atproto record/label.
   - **Hard floor**: the private, unlinkable, consented core can never be
     atproto-native — and that core is why vulpes exists. Framing: *vulpes is
     the standards-based private complement to atproto's public world, with a
     consented bridge into it.*

### The format decision — OPEN, pressure reduced (2026-08-11)

Holder-held forces the unlinkability trade (**decentralized + unlinkable +
simple: pick two**):

- **Path A — BBS now.** Cryptographic multi-show unlinkability; BBS is young in
  Rust (`ssi-bbs` 0.2 / zkryptium, W3C draft). Pulls the deferred tier forward.
- **Path B — SD-JWT-VC interim, BBS later.** Ship now; weaker unlinkability
  (issuer signature is a correlator, mitigated by batch single-use); BBS added
  when it matures without reshaping the Holder↔RP contract.

Still undecided — and the 2026-08-11 characters/CCS work *reduced the
pressure*: public relationships need no VC at all (CCS is atproto-native record
pairs), so the VC stack now serves only private claims and the
anonymous-owner flow (`docs/characters-atproto.md`, flow 13).

### New on 2026-08-11 — CCS and characters

The pivot's first fruits, specified in their own docs:

- **`docs/ccs.md`** — the **Consensual Claims System**: claims attested by
  the counterpart (F45), the complement to atproto labels' unilateral
  broadcast. Includes the senior-key custody rule and the kill test.
- **`docs/characters-atproto.md`** — Zurfur characters as ATProto subjects:
  did:plc per character, default public, ownership via CCS, transfers by key
  rotation, galleries as consensual claims. Post-alpha roadmap.
