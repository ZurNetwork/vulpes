# The Consensual Claims System (CCS) — spec draft

> Named 2026-08-11; reshaped 2026-08-22 (FORKS F45); the claims and
> administration lanes separated 2026-08-23 (FORKS F47). vulpes's original
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

1. **A consensual claim exists iff the counterpart has answered it** — in
   one of two shapes (FORKS F48). **Paired** (recommended): each party
   writes an ordinary ACP self-claim of the same `kind` in its *own* repo,
   naming the other as `subject` with its own `role`, and the two halves
   share an edge `id` computed from the two DIDs, the agreed `expiresAt`
   and a shared `nonce`; consent is the other half existing. **Asymmetric**
   (still valid): one party claims, the counterpart signs an ordinary ACP
   attestation of that claim, stored in the claimant's repo. An unanswered
   claim is a mere claim, not a relationship. Third parties may attest
   either half, or sign it as a **witness** (an embedded signature on the
   half itself — a notary, never required); the verifier's trust policy
   decides whose signature counts.
2. **One kind, two roles; authority is partitioned by role.** Both sides
   of a relationship use the *same* kind and say which side they are in the
   payload's `role` — never an `owns`/`ownedBy` pair of kinds. Each side's
   claim carries only what that side is authoritative for, and the
   attestor's signature over the claim's CID is its agreement to exactly
   that content and nothing more. Where the counterpart has something of
   its own to assert (an account's grant to a member), that is simply its
   half of the pair — its role, its content. Nobody asserts on the
   other's behalf.
3. **Severance is unilateral, instant, and never waits on the calendar.**
   Paired, each side holds its own lever: delete my half, or set one bit
   on my status list, and the edge is over for any verifier that fetches.
   Asymmetric, the claimant deletes and every attestation stops resolving;
   the counterpart revokes through its status list — which is why
   relationship attestations **must carry `status`** (FORKS F47).
   `expiresAt` bounds the relationship's lifetime and is the backstop,
   never the exit; it is required on every record and there is no
   permanent mode — a far-future date is semantically permanent (F48).
   No mediator either way. A half gone from a reachable repo is severed;
   a half in an unreachable repo is *not checkable* — never severed, never
   in force.
4. **Ownership is claims-only, and a subject has one owner** (FORKS F47,
   F48). The ownership verdict is the pair — the owner's `owner` half and
   the character's `owned` half, same `id`, both in force — nothing else. Rotation-key seniority belongs to the administration
   lane (below): it answers "who can recover this DID", never "who owns
   it", and whoever administers the owned repo could grant or revoke the
   consent regardless, so a key gate would remove no power. A subject has
   at most **one** in-force ownership edge — a user, or an account where
   several humans share it; consumers treat more than one as a conflict
   state. The humans behind an account-owned character need no roster
   kind (F48): each is an `owner` half paired against the character —
   character-scoped, so two of five collective members may own this
   character and it is never derived from account membership; "who owns
   me" is answered from the character's own repo. Co-owner churn adds or
   deletes halves: no keys, no transfer, no 72 h window.
5. **Trust stays at the edge, and meaning stays out of vulpes.** CCS defines
   which party says what; it never ranks attestors. vulpes verifies the
   attestation and never decides what a kind *means* — the seniority
   check is an administrative-health helper it provides (`acp::custody`),
   not a step it applies and not part of any ownership verdict. A
   consumer with stakes (a buyer) may still run it as due diligence.

## The verification rule

A consumer accepts a consensual claim of kind *K* between A and B iff
**either**:

- *paired* — A's repo holds a valid claim of kind *K* with `subject` B and
  A's `role`, B's repo holds one with `subject` A and B's `role`, the two
  `id`s are equal and recompute, and both are **in force** per
  `docs/acp.md` §Verification (canonical bytes, `claimant` = repo, expiry,
  status); **or**
- *asymmetric* — A's repo holds such a claim AND it carries an attestation
  whose attestor is B, in force (signature, binding, expiry, status, and
  the consumer's trust policy).

Witness signatures on either half are reported, never required. That is
the whole verdict, ownership included (FORKS F47, F48); the verifier
returns a report — which shape held, each half's state, the attestations
and witnesses seen — not a bare boolean. Both checks
run against public repos; no service — vulpes included — is in the loop.
A consumer may additionally consult the administration lane —
`acp::custody`'s seniority check against the PLC directory — as due
diligence on recoverability; that check informs no relationship verdict.

This is also the impersonation defense: a rando publishing an `ownership`
claim (role `owner`) naming a character has no attestation from the
character — consent is the gate. A self-loop (A claims a relationship
with A, attested by A) is `attestor == subject` — valid and adding no
trust (ruled 2026-08-12); the consumer's policy decides what to make of
it.

## Claim kinds — closed categories, authority-owned names

A kind is a five-segment NSID, `<tld>.<domain>.acp.<category>.<name>`
(`docs/acp.md` §Claim kinds): the authority owns the name and publishes its
definition; the category — a closed ACP list — fixes who claims, who attests
and what the payload must carry. Per the NQ3 discipline (kinds enumerated,
instances unbounded). **One kind per relationship**: both sides use it and
differ only in `role`. The seeds:

| kind | roles | who claims | who attests (asymmetric) | consumer rule |
|---|---|---|---|---|
| `net.got-paws.acp.relationship.ownership` | `owner` / `owned` | **paired** (F48): the owner writes `{role: owner, subject: <character>}`; the character writes `{role: owned, subject: <owner>}` | — (the pair is the consent; asymmetric still accepted) | at most **one** in force per character (F47); more is a conflict state. N humans behind an account-owned character = N `owner` halves; transfer = sever + new term (new `id`). |
| `net.got-paws.acp.relationship.membership` | `member` / `account` | paired: the member `{role: member, subject: <account>}`; the account `{role: account, subject: <member>, grant: …}` | — | a consumer reads the grant only from the account's half. |
| `app.zurfur.acp.identity.character` | — | the character DID | Zurfur | Zurfur's kind, not ACP's: "this DID is a character". |

The identity kinds (`net.got-paws.acp.identity.email`, `….externalAccount`)
are ACP's, not CCS's: one party, a verifier of the fact, no counterpart.

---

Everything below this line is the **administration lane** (FORKS F47):
who can write, rotate, recover, and survive — mechanism, never meaning.
It shares no verdict with the claims lane above; its one contact point is
that the administrative controller holds the pen for a subject's side of
the claims. A key compromise forges no history; a hostile claim touches
no keys.

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

The *ownership* transfer of Fox from Kit to Sam is the claim swap alone
(FORKS F47): Sam writes an `ownership` claim (role `owner`, `did` = Fox);
Fox attests it; Kit deletes theirs — one edge revoked and re-issued, and
the one-owner rule is momentarily what makes the order matter (Kit
deletes before Fox attests Sam, or a consumer sees a conflict state).
The **administrative accompaniment** hands over recoverability, in this
order:

1. An operation adds Sam's cold key **senior to Kit's**:
   `[sam, kit, vulpes, zurfur]`.
2. The claim swap above.
3. An operation removes Kit's key: `[sam, vulpes, zurfur]`.

A buyer who skips the key steps owns Fox in every verifier's eyes and
cannot recover Fox from anyone — which is why a buying client runs
`acp::custody` as due diligence even though no verdict requires it.

Who signs step 1 decides finality. Signed by Zurfur's operational key (the
normal client flow), Kit — senior to it in the list it replaced — can
nullify for 72 h: the seller's undo, which is why a sale settles only after
the window. Signed by Kit's own key, nothing outranks the signer and the
transfer is final at once. **The default is custodian-signed**: the buyer
waits out the window, the seller is protected from a reversed payment.
Self-signed is the explicit "final now" option, and the client must say
which it did.

What an incomplete handover looks like, and what the buyer's due
diligence (`acp::custody`, no verdict involved) catches:

- **Sam added junior to Kit** — Kit can still fire Sam administratively.
  The seniority read shows Kit above Sam.
- **Kit's key left in the list** — Kit retains recovery power. The read
  shows two non-custodian keys where one was promised.
- **Attestation only, no rotation** — Sam owns Fox (claims-only, F47) but
  cannot recover Fox from anyone; the read shows Sam holding nothing.
  Fine between friends, malpractice in a sale.
- **Paid before the window closed** — the only hazard no read catches; it
  is a timing rule for the client, not a protocol fact.

How many owners can a character have: **one edge, any number of humans**
(FORKS F47). A multi-human character is account-owned — the account DID
holds the single ownership edge and sits at index 0 of the character's
rotation list — and the humans are its N paired `owner` halves (rule 4, F48).
Adding a co-owner adds a half; the keys and the ownership edge never
move. Extra owner keys on the character's own list are legal
administration (the five slots leave room) but express nothing about
ownership and are not the path the client leads with.

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
- the administration lane still works from the directory's public
  rotation lists (seniority readable by anyone),
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

- **Library** — mint the layout, verify the attestation, read
  administrative health on request (`acp::custody`; never wired into a
  verdict). Never decide what a kind means.
- **Protocol** — this document: the kind catalog + per-kind consumer rules
  over the ACP primitive. Candidate contribution *to* the atproto ecosystem,
  implementable by any AppView.
- **Reference instance** — optionally hosts custody for those who won't
  self-host, at index 1 and never above the user. Exitable by construction
  (senior-key rule).
