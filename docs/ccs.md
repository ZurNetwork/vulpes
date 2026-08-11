# The Consensual Claims System (CCS) — spec draft

> Named 2026-08-11. vulpes's original contribution to the open-protocol layer:
> **mutual** assertions between DIDs, the complement to atproto labels'
> **unilateral** broadcast. Status: design draft — becomes a lexicon family +
> verification rule with the `vulpes` crate as reference implementation.

## The idea in one line

atproto labels let anyone broadcast a one-sided statement *about* a subject.
CCS is the missing complement: a relationship that exists only when **both**
sides say so. Broadcast : label :: handshake : CCS.

## The spec (five rules)

1. **A consensual claim exists iff both DIDs assert it.** Each side publishes a
   record in its *own* repo referencing the other; a single unanswered record
   is a mere claim, not a relationship.
2. **Authority is partitioned.** Each side may only assert what it is
   authoritative for. The account grants the role; the member grants the
   consent to belong. Nobody asserts on the other's behalf, and a verifier
   reads each attribute only from its authoritative side.
3. **Either side severs unilaterally.** Delete your record and the claim dies.
   No mediator, no cooperation required, no takedown request.
4. **Optional custody tier.** Relationships that are *ownership* add a third
   fact: the owner controls the subject's did:plc rotation keys. Relationships
   that are *membership* stop at the two-record handshake. (Ownership =
   membership + key control.)
5. **Trust stays at the edge.** CCS defines the existence and shape of claims,
   never their worth. Verifiers decide what any claim means to them.

## The verification rule

A verifier accepts a consensual claim iff:

- side A's repo contains a valid CCS record referencing side B (and the
  relationship kind), AND
- side B's repo contains the reciprocal record referencing side A, AND
- (custody tier only) side A demonstrably controls side B's rotation keys per
  the PLC log.

All three checks run against public infrastructure (PDS repos + PLC log). No
service — vulpes included — is in the loop.

This is also the impersonation defense: a rando publishing `owns:
did:character` fails the check because the character's repo does not
reciprocate and the rando holds no keys.

## Relationship kinds — closed, in-code catalog

Per the NQ3 discipline (identity kinds are enumerated in code, instances are
unbounded), CCS relationship kinds are a closed lexicon catalog. First
instances:

- **`owns` / `ownedBy`** (custody tier) — character ownership. See
  `docs/characters-atproto.md`.
- **`member` / `memberOf`** (handshake tier) — Account↔User membership. The
  account's record carries the **role** (its authority); the user's record
  carries only consent. Either side leaving severs it.
- **gallery consent** (handshake tier) — an artwork record (identified by
  strongRef, at-uri + CID) ↔ a featured character's consent record. See
  `docs/characters-atproto.md`.

## The senior-key custody rule (HARD REQUIREMENT)

Wherever a service (vulpes reference instance, Zurfur PDS, anyone) custodies a
DID's rotation keys on a user's behalf:

> **The owner must always hold a rotation key of equal-or-senior priority to
> the custodian's key.**

did:plc supports priority-ordered rotation keys, so this is directly
expressible. Consequence: a custodian's disappearance (or misbehavior) costs
the owner *convenience, never control* — they rotate away without the
custodian's cooperation.

## The kill test (steward, not owner)

If vulpes vanished tomorrow:

- every identity persists (PLC directory is not vulpes),
- every consensual claim still verifies (records live in the parties' repos;
  the rule is a published spec; any implementation runs it),
- the library keeps working and can be forked; the spec is forkable text.

Damage is confined to users of the *reference instance*: custodied wallet
contents must be exported, its status lists go dark (its own issuances only).
The senior-key rule bounds even the custody case to inconvenience.

vulpes therefore *stewards* the CCS spec and ships its canonical
implementation, but owns nothing the system needs to function. Enforcement is
the verification rule itself, and anyone can run it — vulpes enforces CCS the
way a compiler enforces a language spec, not the way a court enforces a law.

## Position in the three-layer role

- **Library** — mint the records, run the verification check, sever cleanly.
- **Protocol** — this spec: the lexicon family + verification rule. Candidate
  contribution *to* the atproto ecosystem, implementable by any AppView.
- **Reference instance** — optionally hosts custody for those who won't
  self-host. Exitable by construction (senior-key rule).
