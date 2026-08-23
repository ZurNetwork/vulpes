# The Consensual Claims System (CCS) — spec draft

> Named 2026-08-11; reshaped 2026-08-22 (FORKS F45). vulpes's original
> contribution to the open-protocol layer: **mutual** assertions between
> DIDs, the complement to atproto labels' **unilateral** broadcast. Status:
> design draft — a claim-kind catalog + per-kind consumer rules over the ACP
> primitive, with the `vulpes` crate as reference implementation.

## The idea in one line

atproto labels let anyone broadcast a one-sided statement *about* a subject.
CCS is the missing complement: a relationship that exists only when **both**
sides say so. Broadcast : label :: handshake : CCS.

CCS is **not a second system**. One side *claims* the relationship; the
other side *attests* the claim. That is the ACP primitive (`docs/acp.md`)
with the counterpart as attestor — nothing else is added.

## The spec (five rules)

1. **A consensual claim exists iff one party claims it and the counterpart
   attests it.** The claimant writes an ordinary ACP self-claim in its own
   repo (`kind` from the catalog below, e.g. `owns`, with the counterpart's
   DID in the payload); the counterpart signs an ordinary ACP attestation of
   that claim, which lives in the claimant's repo like every attestation. An
   unattested claim is a mere claim, not a relationship. Third parties may
   attest the same claim too — a registry, an app, a witness — and the
   verifier's trust policy decides whose signature counts.
2. **Authority is partitioned by the kind.** Each kind names which party
   claims and which attests; the claim's payload carries only what the
   claimant is authoritative for, and the attestor's signature over the
   claim's CID is its agreement to exactly that content and nothing more.
   Where the counterpart has something of its own to assert (an account's
   *role* for a member), the kind defines a reciprocal claim in the
   counterpart's repo, attested by the first party — two claims, two
   attestations, still one primitive. Nobody asserts on the other's behalf.
3. **Severance is asymmetric, and both routes are unilateral.** The
   claimant deletes the claim; every attestation of it stops resolving and
   the relationship is over, instantly. The counterpart cannot delete a
   record in another repo: it revokes (its status list) or declines to
   renew. A human counterpart without infrastructure attests with a short
   `expiresAt` and lets silence do the rest. No mediator either way.
4. **Ownership adds a third fact, checked by the consumer.** Kinds that are
   *ownership* require, beyond the attestation, that the owner holds a
   rotation key on the owned DID senior to every custodian's (the senior-key
   rule below). The attestation proves *consent* — the owned DID's signing
   key agreed, and whoever operates that DID holds that key; the seniority
   proves *control* — no custodian can take the DID away. Kinds that are
   *membership* stop at the attestation.
5. **Trust stays at the edge, and meaning stays out of vulpes.** CCS defines
   which party says what; it never ranks attestors. vulpes verifies the
   attestation and never decides what a kind *means* — the ownership check
   is a helper it provides (`acp::custody`), not a step it applies. The
   consumer (Zurfur, any app) decides that `owns` requires it.

## The verification rule

A consumer accepts a consensual claim of kind *K* between A and B iff:

- A's repo contains a valid ACP claim of kind *K* naming B, AND
- that claim carries an attestation whose attestor is B, **in force** per
  `docs/acp.md` §Verification (signature, binding, expiry, status, and the
  consumer's trust policy), AND
- (ownership kinds only) A holds a rotation key on B senior to every key the
  consumer names as a custodian's, per the PLC directory's rotation list.

All three checks run against public infrastructure (PDS repos + PLC
directory). No service — vulpes included — is in the loop.

This is also the impersonation defense: a rando publishing `owns:
did:character` has no attestation from the character and holds no senior
key. A self-loop (A claims a relationship with A, attested by A) is
`attestor == subject` — valid and adding no trust (ruled 2026-08-12); the
consumer's policy decides what to make of it.

## Claim kinds — closed, in-code catalog

Per the NQ3 discipline (identity kinds are enumerated in code, instances are
unbounded), CCS kinds are a closed lexicon catalog of ACP claim kinds. Each
names who claims and who attests. First instances:

- **`owns`** (ownership) — claimed by the owner, attested by the character.
  See `docs/characters-atproto.md`.
- **`memberOf`** (membership) — claimed by the user, attested by the account.
  The reciprocal **`hasMember`** — claimed by the account (payload: the
  role, the account's authority), attested by the user — carries what the
  account asserts. A verifier reads the role only from the account's claim.
- **`consentsTo`** (membership) — a character's consent to a displayed piece:
  claimed by the character (payload: the artwork's **strongRef**, at-uri +
  CID), attested by the artist. See `docs/characters-atproto.md`.

## The senior-key custody rule (HARD REQUIREMENT)

Wherever a service (vulpes reference instance, Zurfur PDS, anyone) custodies a
DID's rotation keys on a user's behalf:

> **The owner must always hold a rotation key of equal-or-senior priority to
> the custodian's key.**

did:plc supports priority-ordered rotation keys, so this is directly
expressible. Consequence: a custodian's disappearance (or misbehavior) costs
the owner *convenience, never control* — they rotate away without the
custodian's cooperation.

Three keys, three layers, in the vocabulary of `KeyRole`: the **signing**
key is the pen (every post, every record; held by whoever runs the account);
the **operational** rotation key is the custodian's admin key (handle
changes, migrations it performs for you); the **cold** rotation key is the
deed — used almost never, and the only thing that survives everyone else.
Seniority is the tiebreak: for 72 hours a higher key can nullify what a
lower one did. That is why the owner's must outrank the custodian's, and
why `MintPolicy` writes the layout in that order.

## Rotation-key layout (FORKS F46)

A DID carries up to five rotation keys; holding one is not exclusive. The
design question is the *order*. Minted by default:

```
rotationKeys = [ user_cold, vulpes_recovery, zurfur_operational ]   // layout D
```

- **User senior.** Nobody can take the DID from them; anything a junior key
  does, they can undo within the window.
- **Vulpes at index 1** is the net for a lost user key: it can still recover
  the DID *from Zurfur* (move it, re-key it) but cannot beat the user. A
  breach of Vulpes is survivable — the user reverts.
- **Zurfur at index 2** runs the day to day and can be fired by either key
  above it.

Layout E, `[user, user_backup, vulpes, zurfur]`, is offered by the client
for users who want a second cold key (the "save these codes" they already
know). A user who has not yet made a cold key starts on the floor,
`[vulpes, zurfur]`, and the client nags them up. Never minted: Vulpes junior
to Zurfur (the net cannot recover) or Vulpes senior to the user (the
reference instance becomes the landlord). The user's key is **generated
client-side and never transits Zurfur or Vulpes**.

### Slots, order, and who can change it

- **Five keys, hard cap** (did:plc). Layout D spends three, so two slots are
  free: a backup cold key (layout E) and co-owners, in any mix. Every owner
  key sits above every custodian key; among owners, order is the tiebreak.
- **Any listed key can rewrite the whole list** — insert, remove, reorder,
  at any position. Seniority never restricts *signing* an operation; it
  restricts *undoing* one: the directory accepts a nullification only from a
  key more senior than the one that signed the operation being undone,
  judged against the list *before* that operation, and only within 72 h.
  So yes: the user inserts a key between themselves and Vulpes by signing one
  operation with their own key, and the list becomes
  `[user, new, vulpes, zurfur]`.
- **The same rule is the threat.** Zurfur's operational key can sign an
  operation that puts itself first. For 72 h the user (senior in the list
  that operation replaced) can nullify it; after that it stands. The layout
  is only as stable as the user's ability to notice — which is what the
  PLC-log watcher is for.

### Transfer and co-ownership

A transfer of Fox from Kit to Sam is a rotation-key change plus a claim
swap, in this order:

1. An operation adds Sam's cold key **senior to Kit's**:
   `[sam, kit, vulpes, zurfur]`.
2. Sam writes `owns: did:fox`; Fox attests it. Kit deletes their `owns`.
3. An operation removes Kit's key: `[sam, vulpes, zurfur]`.

Who signs step 1 decides finality. Signed by Zurfur's operational key (the
normal client flow), Kit — senior to it in the list it replaced — can
nullify for 72 h: the seller's undo, which is why a sale settles only after
the window. Signed by Kit's own key, nothing outranks the signer and the
transfer is final at once. Either is legitimate; the client must say which
it did.

What an insecure transfer looks like, and what catches it:

- **Sam added junior to Kit** — Kit can still fire Sam. Not a transfer; the
  consumer's seniority check sees Kit above Sam.
- **Kit's key left in the list** — Kit retains control. The buyer's client
  reads the final list; the seniority check against *all* non-custodian
  keys shows two owners where one was promised.
- **Attestation only, no rotation** — Fox attests `sam owns fox` but the
  keys never moved. Custodian-grade proof at best; the seniority check fails
  it outright.
- **Paid before the window closed** — the only hazard no check catches; it
  is a timing rule for the client, not a protocol fact.

How many owners can a character have: the five slots minus the custodians
(Vulpes and Zurfur) leave **three** owner positions — three co-owners with
no backup key, or two plus a backup. Co-owners are ordered: the first is
the tiebreak, and a senior co-owner can remove a junior one, so equal
partners should decide who holds index 0 before minting.

Multi-owner characters are the exception, and the intended shape for them
is **account-owned**: an Account DID at index 0, the sharing expressed as
that account's membership (`memberOf` / `hasMember`), not as extra keys on
the character. Co-owner keys on a character are allowed — they are just not
the path the client leads with.

The 72-hour nullification window is did:plc's, enforced by the directory;
it protects only against a stolen *junior* key, and a longer one would delay
every transfer's finality by the same amount. The lever that matters is
**detection**: a watcher on the PLC log that alerts the user to any
operation on their DID they did not initiate (Zurfur roadmap).

## The kill test (steward, not owner)

If vulpes vanished tomorrow:

- every identity persists (PLC directory is not vulpes),
- every consensual claim still verifies (the claim and its attestation live
  in the claimant's repo; the rule is a published spec; any implementation
  runs it),
- seniority is still checkable from the directory's public rotation lists,
- the library keeps working and can be forked; the spec is forkable text.

Damage is confined to users of the *reference instance*: custodied wallet
contents must be exported, its status lists go dark (its own issuances only),
and users whose layout had Vulpes at index 1 lose their net until they add
another. The senior-key rule bounds even the custody case to inconvenience.

vulpes therefore *stewards* the CCS catalog and ships its canonical
implementation, but owns nothing the system needs to function. Enforcement is
the verification rule itself, and anyone can run it — vulpes enforces CCS the
way a compiler enforces a language spec, not the way a court enforces a law.

## Position in the three-layer role

- **Library** — mint the layout, verify the attestation, check seniority on
  request (`acp::custody`). Never decide what a kind means.
- **Protocol** — this document: the kind catalog + per-kind consumer rules
  over the ACP primitive. Candidate contribution *to* the atproto ecosystem,
  implementable by any AppView.
- **Reference instance** — optionally hosts custody for those who won't
  self-host, at index 1 and never above the user. Exitable by construction
  (senior-key rule).
