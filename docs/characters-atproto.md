# Characters on ATProto (via CCS) — RULED 2026-08-11, reshaped 2026-08-22

> Zurfur characters become first-class ATProto subjects, with ownership
> expressed through the Consensual Claims System (`docs/ccs.md`).
> **Alpha** (amended 2026-09-12, Engineer): the PDS half ships in the alpha
> for public Characters, and Accounts get repos too. Zurfur mints first with
> its own minter; the repo attaches afterwards. First repo content at
> publicize is the CCS `owned` half alone — art records follow the Gallery.
> This file is the source of record for Zurfur DD 54427650.

## The rulings

- **A character is an ATProto subject**: one did:plc per character.
  "character" is a new **in-code identity kind** (NQ3 catalog) —
  `app.zurfur.acp.identity.character`, Zurfur's kind.
- **Default PUBLIC.** Public characters live on ATProto. **Private characters
  live in the Index** (Zurfur-internal) **in content** — no repo, no published
  records — but every character, private ones included, mints its did:plc at
  creation, handle-less (amended 2026-08-30). Private characters need none of
  the VC machinery; per-character rotation-key material keeps the public PLC
  log from correlating one owner's characters.
- **Public characters get a PDS account** — a full repo (ref sheets, bio, art
  records via custom lexicons). Zurfur-hosted by default, **migratable** per
  no-lock-in.
- **Ownership is atproto-native — no VC needed.** Three facts must agree
  (FORKS F45, F47, F48; `docs/ccs.md`). The first two are the two halves of
  one paired edge, sharing one edge `id`:
  1. the owner's repo: the `owner` half — an `ownership` claim
     (`net.got-paws.acp.relationship.ownership`, role `owner`, `did` = the
     character),
  2. the character's repo: the `owned` half — the same kind, role `owned`,
     `did` = the owning user,
  3. the owner holds a rotation key on the character senior to every
     custodian's (PLC directory). This fact is administrative and never
     rendered; the consumer checks it, not the verifier. The two halves
     prove consent; seniority proves control.
- **Transfer = PLC key rotation + claim swap** (the new owner's `ownership`
  claim, attested by the character; the old owner's deleted). The PLC
  log is the free, native provenance chain. **72h finality rule:** did:plc's recovery window
  lets a senior old key undo a rotation for ~72 hours, so sales/transfers are
  final only after the window closes (escrow or hold).
- **One ownership edge per character, always character ↔ user** (amended
  2026-09-12, Engineer; supersedes the co-owner-claims shape). Ownership has
  two lanes, the F47 split: **administrative** — who holds a rotation key,
  never rendered; **semantic** — the claims, which are what renders. The
  character's `owned` half names a **user** DID, never an account.
  **Co-ownership is not expressed in claims.** A shared character puts the
  **account** in the owner slot of the rotation list as administrative
  custodian, while the claims keep pointing at the real owning user. Key
  priority still implies seniority, and the owner must sit above the
  custodian to count.
- **Publicize = consent-gated one-way door.** Index → ATProto (attach the
  repo to the DID the character has had since creation, publish, link). The
  PLC log is append-only and public history may be archived; accepted.
- **De-publicize = teardown, not rollback**: delete the repo records,
  deactivate/tombstone the account, revoke/remove ownership records, **NULL
  the Index's ATProto repo pointers**. The character continues internally on
  its unchanged DID; the DID husk stays in the PLC log asserting nothing.
- **Senior-key rule + CAR export (HARD REQUIREMENTS)**: every Zurfur-hosted
  account (characters included) — the owner holds an equal-or-senior rotation
  key; routine CAR export/mirroring so restore-elsewhere is a real path.
  The user's key is generated client-side (FORKS F46). vulpes's own
  `MintPolicy` default stays layout D (Engineer, 2026-09-13); Zurfur mints
  its hosted repos as `[owner, pds, zurfur]` — `vulpes_recovery` is dropped
  because a stateless crate holding no keys cannot hold index 1. Where
  Zurfur also operates the PDS, that is a **one-operator list**, not layout
  D: one breach reaches both custodian keys. The owner stays senior either
  way, so the senior-key rule and recovery-against-the-custodian hold.

## The validated flows (13)

Lifecycle:

1. **Create public character** — Zurfur mints the did:plc with its own
   minter (`[owner, pds, zurfur]`, above), the PDS account attaches to it,
   and the ownership edge is written as its two halves: the `owned` half in
   the character's repo, the `owner` half in the owning user's. Fully
   atproto-native; vulpes is just the toolkit (the claim halves, their
   checks and the custody read).
2. **Create private character** — Zurfur mints the handle-less did:plc and
   writes the Index row. No repo, no published records.
3. **Publicize** — consent gate → the PDS account attaches to the existing
   DID and the two halves are written, as in flow 1 → Index links the repo.
4. **De-publicize** — teardown per the ruling above.

Ownership operations:

5. **Transfer / sale** — key rotation + claim swap; **final after 72h** (the
   sharpest finding: a scam seller could otherwise reclaim via the recovery
   window). The window is did:plc's; the defense against a silent hostile
   rotation is a PLC-log watcher that alerts the owner (Zurfur roadmap).
6. **Shared characters** — an administrative arrangement, not a claims one:
   the account takes the owner slot in the rotation list; the ownership edge
   stays character ↔ user and renders that user alone.
7. **Key loss** — custodied: the custodian's recovery flow (bounded by the
   senior-key rule); self-held: native rotation-window recovery.

Ecosystem:

8. **Art attribution** — artists reference the character's DID/at-uri from
   records in *their own* repos. Native; the Seals/labeler pattern again.
9. **Moderation** — character accounts/records are labelable by any labeler
   (maturity, disputes). Keycard rides it.
10. **Cross-app portability** — any app resolves the DID, reads the PDS,
    verifies the attestation, checks seniority. No Zurfur, no vulpes in the
    loop.
11. **Impersonation** — an unattested `ownership` claim is a mere claim; a
    custodian-signed attestation without seniority is consent without
    control. No authority needed; trust at the edge (NQ2).

Privacy hybrids:

12. **Which persona owns publicly** — the Holder picks which persona DID
    issues the public `ownership` claim; Holder-level aggregation stays private in
    vulpes. Cross-persona unlinkability holds.
13. **Public character, anonymous owner** — the ONLY character flow needing
    the VC stack: no public owner record; ownership proven on demand via a
    holder-held vulpes credential (`owns did:X`) disclosed by consent, or a
    live key-control challenge.

## Feeds (free consequence)

A character with a PDS account is a full actor: it posts (the owner speaking
in-character), is followable and @-mentionable, and renders in any AppView —
including Bluesky. Feed generators compose over it: "everything by this
character," "all art referencing this DID" (flow 8 as a timeline).
In-character vs out-of-character = different DIDs, natively; the link between
them is exactly the ownership claim — public or anonymous per flow 13.

## Account↔User membership (the generalization)

The same CCS pattern, handshake tier (no key custody — membership, not
property):

- user repo: a `membership` claim (role `member`, `did` = the account),
  attested by the account (the user is authoritative for their own consent;
  the account's signature is its agreement),
- account repo: a `membership` claim (role `account`, `did` = the user,
  `grant` = what it granted), attested by the user (the account is
  authoritative for who belongs and what it granted).

Membership exists only when both agree; either side severs unilaterally —
by deleting its own claim, or by revoking / not renewing its attestation of
the other's; a verifier reads the grant only from the account's claim. Org membership/roles
become portable — verifiable without asking Zurfur.

## The gallery — deferred (ruled 2026-08-22)

Gallery permission was to be a `consent` claim — the character's repo
consenting to the artwork's **strongRef (at-uri + CID)**, attested by the
artist — so that removal is severance (delete the claim, the piece leaves
every compliant gallery) and multi-character pieces are N consents with the
strongRef as the dedup key. **Deferred**: takedown requests cover the need
for now, and the `consent` category stays reserved in `docs/acp.md`
§Possible future changes so it lands additively when gallery work starts.
The partial-consent question (one of three featured characters revokes)
is parked with it.

## Kill tests

- **vulpes vanishes**: every claim still verifies (see `docs/ccs.md`);
  vulpes holds no key on any Zurfur-minted DID — none is on layout D — so
  nothing at all is lost.
- **Zurfur also vanishes**: DIDs persist (PLC directory); repos on other
  PDSes untouched; public data survives via relays and renders in any other
  AppView. Zurfur-hosted accounts re-point their DIDs elsewhere (senior-key
  rule) and restore from CAR backups. A private character's **content** dies
  with the Index — nothing of it was ever published — but its **DID and
  creation timestamp persist in the PLC directory permanently**, an empty
  identity asserting nothing (amended 2026-08-30; an accepted cost).
  Per-character key material means the husk cannot be correlated to its
  owner or its siblings.
