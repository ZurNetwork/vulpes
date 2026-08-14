# ACP: The Attested Claims Protocol

**Specification v0.1 (draft) · 2026-08-11 · reference implementation: Vulpes**

ACP is an open standard for identity claims on the AT Protocol that survive
their infrastructure. It defines how a subject asserts something about itself,
how any party vouches for that assertion, how two subjects assert a
relationship together, and how all of it remains verifiable after any single
operator — including the reference implementation — disappears.

> **The governing rule:** the death of any ACP participant, including an
> attestor, is an inconvenience, never a breaking factor.

This document follows the structure and conventions of ecosystem
specifications such as [did:plc]; it uses plain imperative language
("must", "should") without formally invoking RFC 2119. The values this
specification serves are stated in the ACP manifesto (`docs/manifesto.md`);
where a design choice here seems arbitrary, the manifesto is why.

---

## Design principles (the axioms)

Six axioms govern every mechanism in this specification. The first three are
facts about a decentralized world that no protocol can change; the last
three are this protocol's laws in response. They were derived from first
principles in [The Claim Handshake](the-claim-handshake.md); a design change
that violates one of them is wrong until proven otherwise.

**Facts:**

1. **Everybody may be lying, for no apparent reason at all.** The protocol
   authenticates who said what; it never rules on truth.
2. **Valid claims may be made by entities that no longer exist, or may just
   be unreachable.** Verification must not require the attestor to be alive
   or responsive (the kill test).
3. **Systems decide how to process data under their own rules.** Claim
   modes and expiry are the attestor's *recommendation*; every verifier
   applies its own policy. Democratization of processing is how
   centralization is fought.

**Laws:**

4. **Information that is not explicit may as well not be information at
   all.** Everything a verification depends on is either in the signed
   bytes or injected from the verifier's own observed context — never
   assumed.
5. **Information for claims must be signed. Always.** Unsigned material has
   no standing anywhere in the protocol.
6. **Referenced data is never to be treated as permanent, but rather as
   temporary. Absence doesn't mean malice.** An unreachable reference
   degrades freshness; it implies nothing else.

## How it works

1. A **subject** (any DID) writes a **self-claim** — a record in its own PDS
   repo stating something about itself ("I control this email", "this is my
   character"). Self-claims are free and prove nothing.
2. An **attestor** (any other DID) verifies the claim by whatever diligence it
   chooses, then signs an **attestation** — a statement that the claim was
   verified, bound to the claim by content address, with a required expiry.
3. The attestation is **delivered to the subject**, who stores it as a record
   in their own repo. The attestor keeps no load-bearing copy.
4. A **verifier** checks an attestation with public infrastructure alone:
   resolve the attestor's DID, fetch its key, verify the signature, check
   expiry, optionally check a mirrorable **status list**. No call to the
   attestor is made.
5. Relationships between two subjects are the same primitive (the
   Consensual Claims System): one party's self-claim, **attested by the
   counterpart**. The relationship exists only while the claim stands and
   an attestation from the counterpart is in force.

Trust is decided entirely at the edge: any DID may attest, and each verifier
chooses which attestors it honors. ACP defines shapes, never authorities.

## Use with the AT Protocol

ACP is built from primitives the AT Protocol already provides:

- **Identity**: subjects and attestors are DIDs (did:plc or did:web); signing
  keys are published in DID documents; key rotation and recovery come from the
  [PLC directory].
- **Storage**: claims and attestations are records in the owning subject's
  repo, addressed by at-uri and content-hash
  ([strongRef]), under the ACP Lexicons.
- **Complement, not overlap**: ATProto labels are unilateral third-party
  broadcast; ACP attestations are subject-held and expiring, and a relationship is
  an attestation whose attestor is the counterpart — consent *is* the
  signature. ACP adds what labels cannot express and
  reuses everything else.

This version of ACP specifies the **public lane** only. Records in PDS repos
are public by ATProto's architecture; publishing is linking, and that is the
point of publishing. Claims whose *existence* must stay private are out of
scope for v0.1 (see [Possible future changes](#possible-future-changes)).

## Terminology

| Term | Meaning |
|---|---|
| **Subject** | The DID a claim is about (person, account, character, service). |
| **Self-claim** | A record in the subject's own repo asserting something about itself. |
| **Attestor** | Any DID that verifies a self-claim and signs an attestation of it. |
| **Attestation** | A signed, expiring statement by an attestor that a specific claim was verified. Colloquially: a *vouch* (the manifesto's term). |
| **Relationship** | A claim attested by its counterpart (CCS). Not a record type of its own. |
| **Verifier** | Any party deciding whether to rely on a claim, and on whose attestations. |
| **Status list** | A signed, mirrorable artifact stating which attestations an attestor has revoked. |
| **Custodian** | An operator hosting a subject's repo or keys on its behalf. |

## Record types (Lexicons)

Lexicon NSIDs use the authority `net.got-paws.acp.*` (ruled 2026-08-12;
authority domain `got-paws.net`, held by the standard's author — chosen
deliberately at the same rank as any other attestor's domain, because the
standard grants no authority a privileged position). Schema publication
resolves via a `_lexicon` TXT record on `acp.got-paws.net`. Field syntax is
Lexicon-style; all datetimes are ISO 8601 strings; all DIDs are full DID
strings.

### Self-claim — `net.got-paws.acp.claim`

A record in the subject's repo. The subject is the repo owner; it is not
repeated in the record.

```
record net.got-paws.acp.claim {
  kind:      string   // a five-segment NSID naming the claim kind, e.g.
                      // net.got-paws.acp.identity.email (see Claim kinds)
  payload:   object   // kind-defined content, e.g. { "address": "a@b.c" }
  createdAt: datetime
}
```

- The record key should be a TID (timestamp identifier), per ATProto
  convention.
- A claim is retracted by deleting the record. Deleting a claim does not
  delete attestations that reference it, but it breaks their strongRef
  resolution — verifiers must treat an attestation whose claim is gone as
  no longer in force.

### Attestation — `net.got-paws.acp.attestation`

Also a record **in the subject's repo** — the attestation is the subject's
property. The record carries an attestor-signed inner object; the repo commit
signature (the subject's) governs custody, the inner signature governs truth.

```
record net.got-paws.acp.attestation {
  claim:     strongRef  // { uri: at-uri of the claim, cid: content hash }
  attestor:  did        // the attestor's DID
  subject:   did        // the subject's DID (explicit, so the object is
                        // self-contained when exported from the repo)
  issuedAt:  datetime
  expiresAt: datetime   // REQUIRED — see Expiry
  status:    object?    // { list: uri, index: integer } — see Status lists
  method:    string?    // attestor's stated diligence, e.g. "email-challenge",
                        // "oauth", informational only
  sig:       bytes      // attestor signature, see Signing
}
```

**Signing.** The signature is computed over a **pre-image**, serialized as
canonical DAG-CBOR, using a signing key published in the attestor's DID
document (`verificationMethod`). The pre-image is the record object *without*
the `sig` field, **plus an injected `$sig` binding object that is never
stored**:

```
$sig: {
  $type:      "net.got-paws.acp.sigBinding"   // the binding marker (fixed)
  repository: did     // the DID of the repo this record lives in
}
```

What the key signs is the **CIDv1 of the pre-image** (dag-cbor `0x71`,
sha2-256 — 36 raw bytes), not the DAG-CBOR bytes directly. This is the
CID-First Attestation construction (Gerakines, badge.blue), adopted 2026-08-20
so independent tooling can reproduce the signed bytes; the `$type` value is
minted under the ACP authority because that construction leaves it to the
implementer. Reference: `src/acp/sign.rs`.

At signing time the attestor injects the **subject's repo DID** as
`repository`. At verification time the verifier injects **the DID of the repo
it actually retrieved the record from — never a value read from the record
itself**. A record transplanted into any other repo therefore cannot produce
a matching pre-image at all: the transplant defense is unrepresentable, not
a skippable validation step. The stored record carries only the plain `sig`
bytes; the `$sig` object exists only in the pre-image.

With `repository` carrying the transplant defense, the explicit `subject`
field's rationale is **export self-containment**: an attestation exported
from its repo (CAR backup, migration) still names who it is about.

Allowed algorithms follow the atproto cryptography profile (ES256 / ES256K,
low-S). The signature is stored as raw bytes (base64url when rendered in
JSON).

**Delivery.** How the signed object travels from attestor to subject is not
specified (an XRPC endpoint, OAuth-mediated write, or out-of-band transfer
are all acceptable); what is normative is the end state: the record exists in
the subject's repo, and the attestor is not the sole holder of any attestation
it has issued.

**Binding.** The `claim` strongRef binds the attestation to the exact claim
content (CID). If the subject rewrites the claim, existing attestations no
longer resolve and are no longer in force. Attest the new version or live
without.

### Relationships are attestations

A relationship between two DIDs is **not a separate record type**
(ruled 2026-08-22, FORKS F45). The party asserting it writes an ordinary
self-claim — a `relationship`-category `kind`
(`net.got-paws.acp.relationship.ownership`, …), the counterpart's DID and
this side's `role` in the payload — and the counterpart signs an
ordinary attestation of it, stored in the claimant's repo like every
attestation. A verifier checks it exactly as it checks any attestation.
Third parties may attest the same claim; trust policy decides whose
signature counts.

- **One kind, two roles**: both sides use the same kind and differ only
  in the payload's `role`; each side's claim carries only what that side is
  authoritative for, and the attestor's signature over the claim's CID is
  agreement to exactly that content. Where the counterpart has something of
  its own to assert (an account's grant to a member), it writes its own
  claim of the same kind — its role, its content — attested by the first
  party.
- **Severance is asymmetric.** The claimant deletes the claim and every
  attestation of it stops resolving (§Self-claim). The counterpart cannot
  delete a record in another repo: it revokes (§Status lists) or declines
  to renew. A human counterpart without infrastructure uses a short
  `expiresAt` and silence.
- **Ownership-class kinds** (`net.got-paws.acp.relationship.ownership`)
  require a third fact the protocol does not check:
  the owner holds a rotation key on the owned DID senior to every
  custodian's. The attestation proves consent (the owned DID's signing
  key agreed — whoever operates that DID holds that key); seniority proves
  control (no custodian can take the DID). That check is the **consumer's**,
  run after the attestation verifies, against a custodian set the consumer
  keeps complete; vulpes provides it as a helper, never as a verification
  step. The rule, the rotation-key layout it relies on, and the custodian
  discovery route are in `docs/ccs.md`.
- **Lifetime**: ownership-kind attestations may carry a far-future
  `expiresAt`; the permanent mode stays deferred and additive (§Possible
  future changes).

### Claim kinds

A `kind` is an **NSID** of exactly five segments, read general → specific:

```
<tld> . <domain> . acp . <category> . <name>
 net    got-paws   acp   relationship   ownership
```

| segment | set by | rule |
|---|---|---|
| `<tld>.<domain>` | DNS | the **authority**. Whoever controls the domain owns every kind under it; two authorities cannot mint the same name, so collisions are impossible by construction. |
| `acp` | this spec | always `acp` for an ACP kind, under any authority. |
| `<category>` | this spec, **closed list** | fixes who claims, who attests and what the payload must carry — the same under every authority. Extended only by specification change. |
| `<name>` | the authority | camelCase; the kind itself, defined and published by its authority. |

The categories, with the invariant each carries:

| category | payload must carry | claimed by | attested by |
|---|---|---|---|
| `identity` | the fact | the subject | a verifier of the fact — anyone; trust policy decides who counts |
| `relationship` | `did` — the counterpart; `role` — this side's role | either party | **the DID named in `did`** (the CCS rule, `docs/ccs.md`) |

A third category, `consent` — a DID agreeing to a specific *record* (`ref`,
a strongRef) attested by that record's author — is **deferred** (§Possible
future changes): v0.1's consumers handle object-level permission through
takedown requests, and a category earns its place only when its attestor
rule is distinct and needed.

**One kind per relationship.** Both sides use the *same* kind and say which
side they are in `role` — `net.got-paws.acp.relationship.ownership` with
`owner` or `owned`, never an `owns`/`ownedBy` pair. What a side may carry
beyond `did` and `role` is for the kind's definition to state.

**Resolution.** A kind resolves like any lexicon: `_lexicon.<category>.acp.<domain>`
TXT → the authority's DID → the `com.atproto.lexicon.schema` record keyed by
the NSID in that repo. That record *is* the kind's definition — payload
schema, the roles, whether the kind is ownership-class (carries the
consumer's seniority check), its default lifetime. A verifier validates the
five-segment shape and treats the kind as opaque; a consumer acts on the
kinds it defines or trusts. Records of an unrecognised kind are ignored,
never rejected (forward compatibility). **Use the generic kind where one
exists; define your own only when none fits; never redefine a generic
notion under your own authority** — the generic kinds are the shared
vocabulary, usable by any authority without permission, the way
`app.bsky.feed.post` is.

Seeds:

| kind | roles | claimed by | attested by |
|---|---|---|---|
| `net.got-paws.acp.identity.email` | — | the subject | whoever verified the address |
| `net.got-paws.acp.identity.externalAccount` | — | the subject | whoever verified the account |
| `net.got-paws.acp.relationship.ownership` | `owner` / `owned` | the owner, naming the owned DID | the owned DID — ownership-class |
| `net.got-paws.acp.relationship.membership` | `member` / `account` | the member, naming the account; the account, naming the member, with its `grant` | the account; the member |
| `app.zurfur.acp.identity.character` | — | the character | Zurfur's kind, not this spec's |

The reference implementation's `ClaimKind` parses the shape — exactly five
well-formed segments — and exposes authority, protocol, category and name as
typed values: the two categories and the seeded names it knows, and an
`Other` holding the syntax-checked segment for everything else, carried
verbatim. Shape, not meaning.

## Status lists

- An attestor that supports revocation publishes status as a **signed,
  static, mirrorable artifact** compatible with [Token Status List]
  semantics: a bitstring where `status.index` selects the attestation's bit.
  Never a live query endpoint that only the attestor can answer.
- The artifact is signed with a key from the attestor's DID document and
  carries its own issuance timestamp.
- Anyone may mirror status artifacts. Verifiers may accept a mirrored copy;
  the newest verifiable copy wins.
- An attestation without a `status` pointer is irrevocable until expiry —
  attestors should size `expiresAt` accordingly.

**Artifact shape (v0.1).** The envelope is ACP-native — canonical DAG-CBOR,
signed CID-first with the same primitive as attestations (FORKS F39); the
IETF Token Status List JWT/CWT envelope is deferred to the private lane.
Semantics are TSL's: bit `status.index` of `bits` (packed LSB-first within
each byte), set = revoked.

```
record net.got-paws.acp.statusList {
  attestor: did       // whose attestations this covers; its DID document
                      // holds the signing key
  list:     string    // this list's identifier — MUST equal the `status.list`
                      // of every attestation it covers (a signed copy of one
                      // list cannot stand in for another)
  issuedAt: datetime  // newest verifiable copy wins
  ttl?:     integer   // seconds after issuedAt the attestor vouches for this
                      // version; past it a copy is not checkable. Absent: no
                      // issuer bound — the newest verifiable copy stands until
                      // the attestations it covers expire
  bits:     bytes     // one bit per issued attestation
  sig:      bytes     // signature over the CIDv1 of the record minus `sig`
}
```

There is no `$sig` repository binding: a status list is not a repo record,
so there is no repository to bind to; its domain separation from an
attestation pre-image is the `$type` inside the signed bytes. A verifier
takes every copy it can reach, discards those larger than 1 MiB, that do
not decode, do not name the expected attestor **and the expected `list`**,
or are dated further ahead of the verifier's clock than its skew
tolerance (a future-dated list must not outrank every genuine one until
then) — all cheap checks an adversary cannot amplify — then orders the
survivors newest-first by `issuedAt` at full precision (ties broken on the
canonical bytes) and verifies signatures in that order, keeping the first
that verifies under the attestor's current keys. The bound is on
**signature verifications** (at most 16), never on arrival position: a
mirror cannot bury the genuine newest copy under junk, and it cannot make
a verifier do unbounded work either.
Attestors SHOULD set `ttl` to their republish cadence; the reference
verifier's default policy treats a copy older than 30 days as not checkable
(FORKS F43), and a tighter `ttl` wins over it.
`list` is an identifier, not necessarily a fetch location: mirrors may serve
a list from any address, but the identifier the attestor signed is the one
an attestation must point at. Identity-over-location is what lets mirrors
outlive the attestor's domain (the kill test). An index beyond the bitstring is
**not checkable** (treated as not in force when freshness is demanded),
never "not revoked". Both `list` and `ttl` follow the IETF Token Status
List's `sub` and `ttl` (FORKS F39): the issuer names the list and may bound
how long a copy is evidence; a verifier applies the tighter of `ttl` and its
own policy bound, and a list with neither stands until the attestations it
covers expire. Reference: `src/acp/status.rs`.

## Expiry and renewal

Every attestation must carry `expiresAt`. This is the graceful-degradation
floor: if an attestor and every mirror of its status vanish, stale
attestations age out instead of living forever unfalsifiable. Verifiers
must reject expired attestations regardless of status.

This section defines v0.1's one and only vouch mode: **passive** — freshness
is pre-committed at issuance as an expiry window, and nothing is asked of
anyone at verification time. Further modes (*active*: freshness established
by asking at use; *permanent*: freshness moot because the fact is immutable)
are deliberately additive and out of scope for v0.1 (ruled 2026-08-12; see
Possible future changes).

Lifetimes are **short by default, per claim kind** — validity is a pulse,
not a stored fact:

- **Mechanically checkable claims** (email control, external-account
  linkage): short-lived and automatically renewed. Renewal must re-run the
  attestor's diligence, not merely re-sign — a renewal nobody re-checked is
  false freshness. For these kinds, revocation collapses into *declining to
  renew*, and a status list is optional.
- **Human vouches** (endorsements, peer attestations): must not auto-renew —
  renewal requires the human re-affirming. They may carry longer lifetimes
  and should carry a status pointer, since declining-to-renew reacts too
  slowly for them.
- **Identity anchors**: long-lived; churn there is itself a risk signal.

**Renewal flow**: the subject's agent re-requests before expiry; the
attestor re-checks and re-signs; the subject replaces the record in its
repo. The transport is unspecified (as with delivery); the end state is
normative. Verifiers may treat remaining lifetime as a freshness signal —
a short-lived attestation renewed yesterday is stronger evidence than a
year-long one signed eleven months ago.

**Short lifetimes are a deliberate decentralization pressure.** An
attestor's disappearance strands its subjects within days — and that is
accepted, because re-attestation elsewhere is cheap, routine, and
*practiced*. Softening attestor death with long lifetimes would treat
attestors as irreplaceable, which is centralization by another name. No
attestor may matter enough that its death is more than an inconvenience;
the expiry policy is what enforces that economically, not just
architecturally.

## Verification

To verify an attestation, a verifier:

1. Fetches the `net.got-paws.acp.attestation` record from the subject's repo.
   Before fetching the referenced claim, checks `claim.uri`'s authority
   **is** the `subject` DID — the author wrote that address, and a
   verifier sends no request to any authority the record does not name as
   its subject (a handle authority is rejected: handles re-assign). Then
   fetches the claim; checks its CID matches `claim.cid`. If the claim is
   missing or rewritten → **not in force**.
2. Checks `subject` matches the repo owner's DID, and that the claim was
   fetched from that same repo — a claim carries no subject field, so the
   repo it sits in is the only fact that says whose it is.
3. Resolves `attestor` to its DID document; obtains the verification key(s).
4. Verifies `sig` over the pre-image: the canonical DAG-CBOR of the record
   minus `sig`, plus the injected `$sig` binding object whose `repository`
   is **the DID of the repo the verifier retrieved the record from** (see
   §Signing) — never a value read from the record. A transplanted record
   fails here structurally.
   Key rotation note: verification uses the *current* DID document; an
   attestor that rotates keys re-signs or re-issues attestations it wants to
   keep alive (as with did:plc, no historical-key verification is defined).
   The stored bytes MUST be the canonical DAG-CBOR of the record they decode
   to (re-encode and compare): nothing rides along outside the signature,
   and the attestation's CID is a stable identifier for what was signed.
5. Checks `expiresAt` is in the future.
6. Applies local trust policy: is this `attestor`, using this `method`, at
   this age, sufficient for this decision? The protocol supplies signals;
   the verifier supplies judgment. A verifier that would reject here
   performs no further I/O on the attestation's behalf.
7. If `status` is present and the verifier's policy demands freshness:
   fetches the status artifact (any mirror), verifies its signature against
   the attestor's DID document, checks the bit at `index` is not set.
   `status.list` is an identifier at rest (§Status lists) and
   attacker-influenced input: verifiers MUST validate it immediately
   before fetching — `https` with a public DNS host: no IP literal in any
   spelling (including hex, octal, decimal and trailing-dot forms), no
   loopback, link-local or private-range host, no special-use name
   (`localhost`, `.local`, `.internal`, `.onion`, `.arpa`, `.localdomain`,
   …), at least two labels (a bare name resolves through the search list
   into the verifier's own network); an `at://` list is addressed by DID,
   never by handle — and SHOULD
   route the fetch through an egress guard. A list the verifier will not
   fetch is *not checkable*, never malformed and never "not revoked". The
   trust decision precedes the fetch precisely so that an untrusted
   attestor cannot cause a verifier to make a request. Syntactic validation
   is necessary, not sufficient: an HTTP fetcher MUST disable redirects,
   MUST resolve the host and refuse non-global addresses at connect time
   (DNS rebinding), SHOULD sit behind an egress guard, SHOULD cap the
   response size, and SHOULD bound the number of copies it returns (the
   reference verifier verifies at most a fixed number, newest first)
   (FORKS F42).
   Strictly past the list's own `ttl` (when it declares one; `age > ttl`)
   or the verifier's policy bound, whichever is tighter, a copy is *not
   checkable*.
   The newest verifiable copy wins however old it is — a list published
   before the attestation was issued is still the attestor's last word,
   and must stay checkable after the attestor dies (§The kill test).
   Verifiers with high stakes bound the list's age (§Stale-status
   attacks): past the bound a copy is *not checkable*, never "not
   revoked".

A relationship is verified as the attestation it is — there is no second
procedure. Kinds that carry a consumer-side check (ownership: rotation-key
seniority, `docs/ccs.md`) run it *after* the attestation is in force.

## Conformance

Conformance is per role:

**Subjects / holders**
- must store their claims and attestations in a repo they can export (CAR)
  and migrate;
- should export or mirror routinely (custody is theirs).

**Attestors**
- must sign with keys published in their DID document;
- must set `expiresAt` on every attestation;
- must deliver every attestation to its subject and must not be the sole
  holder of attestations they issue;
- must publish revocation, if supported, as mirrorable signed artifacts;
- should publish the verification `method` they used.

**Verifiers**
- must verify using only public infrastructure (DID resolution, repo fetch,
  status artifacts) with no callback to the attestor;
- must reject expired attestations and unresolved claim references;
- must treat an unattested relationship claim as a mere claim;
- must not treat any attestor — including the reference instance — as
  privileged by protocol;
- must decide trust before fetching a status list, and must not fetch an
  unvalidated `status.list` (step 7); its HTTP fetcher must disable
  redirects and must refuse non-global resolved addresses at connect time,
  and should sit behind an egress guard, cap the response size and bound
  the number of copies it returns (FORKS F42).

**Consumers** (applications acting on what a kind means)
- must, before acting on an ownership kind, check that the owner holds a
  rotation key on the owned DID senior to every custodian's, against a
  custodian set kept complete for every host in play (`docs/ccs.md`); an
  attestation alone proves consent, never control;
- must not mint a rotation layout that places a recovery custodian below the
  operating custodian, or any custodian above the user (FORKS F46).

**Custodians** (PDS hosts, wallet services)
- must not hold rotation keys senior to the subject's own for any DID they
  custody (the senior-key rule);
- must support standard export (CAR) and migration away.

### The kill test

An implementation conforms only if, upon the permanent disappearance of any
operator (attestor, custodian, or the reference instance itself):

- every subject's identity remains resolvable (PLC directory);
- every claim remains (subjects' own repos);
- every attestation signature remains verifiable (keys in DID documents,
  artifacts in subject custody);
- the last-published status remains checkable (mirrors);
- subjects migrate custody without anyone's permission;
- only *freshness* (new status) and *future issuance* stop — both replaceable
  by any other attestor.

An operator's private index (e.g. a holder-aggregation graph) is explicitly
outside the kill test: private data shares its custodian's fate by design,
because publishing it for survivability would be the very correlation the
private layer exists to prevent.

## Trust model

- **The PLC directory** is trusted for DID→key resolution, with the same
  trust profile (and audit-log accountability) as every other ATProto
  component. ACP inherits, and does not enlarge, this dependency.
- **Attestors** are trusted only by verifier choice, only for the claims they
  attest, and only as far as their stated method warrants. An attestor's own
  reputation is edge-decided, like a labeler's.
- **Custodians** are trusted for availability, never for authority: the
  senior-key rule keeps every custodied DID recoverable against its
  custodian, and repo signatures keep content authentic regardless of host.
- **No party** is trusted for the truth of a claim by protocol. The protocol
  authenticates *who said what, about what, when, and whether it still
  stands* — whether to believe them is the verifier's judgment.

## Privacy and security concerns

- **Everything in v0.1 is public.** Repos, claims and attestations —
  relationships included — are world-readable and permanently linkable to their DIDs. Users
  must understand that publishing a claim is publishing a link. Claims
  requiring private existence must wait for the private lane; do not model
  them as public records with obscure names.
- **Cross-persona correlation.** Nothing in ACP links two DIDs unless a
  relationship claim does so explicitly. Implementations must not require, and
  should not encourage, publishing links between personas a user keeps
  separate. Aggregation of many identities under one holder is an
  implementation-private concern, never an ACP record.
- **Attestor key compromise.** A stolen attestor key forges attestations
  until rotation. Mitigations: PLC rotation (which invalidates the old key
  for step-4 verification), short expiries, status lists. Attestors should
  keep signing keys distinct from rotation keys.
- **The attestor's custodian.** On a hosted PDS the custodian holds a
  `verificationMethod` key of the attestor's DID and can sign attestations
  in its name. This is inherent to custody, not to ACP; an attestor that
  cannot accept it self-hosts its signing key (the senior-key rule keeps
  the DID recoverable from a custodian either way).
- **Replay/transplant.** Attestations bind claim CID, expiry, and — through
  the `$sig` repository binding (§Signing) — the very repo they live in, so
  they cannot be transplanted to another subject, claim version, or repo:
  a transplanted record cannot produce a matching pre-image at all. The
  explicit `subject` field is retained for export self-containment, and the
  `subject`-matches-repo-owner check (§Verification step 2) remains as
  defense in depth. Implementations must carry a **transplant negative
  test**: copy a valid attestation into a second repo and verification must
  fail.
- **Stale-status attacks.** A verifier relying on an old mirrored status
  artifact may miss a recent revocation. Bounding acceptable status age is
  what closes this, and the artifact's issuance timestamp exists for it: the
  reference verifier's default policy bounds it at 30 days (FORKS F43) and
  takes the attestor's signed `ttl` when that is tighter. Verifiers with
  high stakes lower the bound; the verifier that sets no bound at all
  accepts that a withheld republish pins an all-clear indefinitely.
- **De-anonymization via history.** As with did:plc audit logs, deleted
  records may persist in caches, mirrors, and repo history. Deletion is
  prospective severance, not retroactive erasure; the CCS finality rules
  (e.g. transfer windows) are designed around this.
- **Coercion asymmetry in relationships.** Unilateral severance is the
  safety valve, and it is asymmetric: the claimant deletes; the counterpart
  revokes or declines to renew — so a counterpart who cannot run a status
  list must attest with an expiry short enough that silence is a real
  exit. No party can be held in a relationship they no longer assert.
  Ownership transfer adds the PLC recovery window as a scam-defense delay.

## Possible future changes

- **The `consent` category**: a DID agreeing to a specific record — an
  artwork featuring a character, a document, a list — with `ref` a
  strongRef (the CID pins the version consented to) and the record's author
  as attestor. Deferred 2026-08-22: takedown requests cover the need for
  now; the category slot is reserved so it lands additively.
- **Kind equivalence**: a kind's definition record may declare
  `equivalentTo` another kind, so a consumer resolving an unfamiliar
  authority-specific kind learns it may treat it as a generic one
  (JSON-LD's `sameAs`). Structural interop is already free through the
  category invariants; this would add semantic interop without a registry.
- **The private lane**: holder-held verifiable credentials presented
  peer-to-peer (VC 2.0 via OID4VP; SD-JWT-VC and/or BBS — the open Path A/B
  ruling) for claims whose existence must stay unlinkable. ACP claims are
  deliberately VCDM-shaped envelopes so this lane attaches without
  reshaping the claim model.
- **Further vouch modes** (additive to v0.1's passive mode): *active* —
  freshness established by asking the attestor at use, which is an attestor
  endpoint artifact, never a PDS answer, and stays within trust boundaries
  (cross-boundary actives are a correlation oracle); *permanent* — immutable
  facts, living in the subject's repo with status mandatory instead of
  expiry (the honest carve-out from the pulse doctrine: no switching exists
  to exercise there). Until it lands, ownership-kind attestations use a
  far-future `expiresAt` (FORKS F45). Taxonomy details parked on The Claims Model page.
- **Predicate attestations**: issuer-baked booleans ("+18: true") as a claim
  kind, and possibly blinded-token (Privacy Pass) issuance for yes/no gates.
- DNS publication of the lexicon schemas (`_lexicon` TXT on
  `acp.got-paws.net` → the hosting repo's DID).
- Historical-key verification, if the ecosystem develops a standard for it.
- A governance / standards-body process, as the AT Protocol itself intends.

## Changelog

- **v0.1 (2026-08-11)** — first draft: public lane; self-claims,
  attestations, mutual claims (CCS), status lists, kill-test conformance.
- **2026-08-12** — `$sig` repository binding adopted (prior-art session
  ruling): the signing pre-image injects a never-stored `{$type, repository}`
  object; transplant defense becomes unrepresentable; `subject` re-rationalized
  as export self-containment; transplant negative test mandatory.
- **2026-08-12** — v0.1 scoped to the **passive** vouch mode only; active and
  permanent modes ruled additive, deferred (§Expiry and renewal, §Possible
  future changes).
- **2026-08-13** — the six design axioms adopted (§Design principles),
  transcribed from the independent first-principles derivation
  ([The Claim Handshake](the-claim-handshake.md)), which converged on the
  recorded design without consulting it — treated as validation evidence.
- **2026-08-12** — lexicon namespace settled: `net.got-paws.acp.*`
  (authority domain `got-paws.net`). No longer provisional.
- **2026-08-20** — signing pinned to the CID-First construction: the key signs
  the CIDv1 of the pre-image; `$sig.$type` fixed as
  `net.got-paws.acp.sigBinding`; strongRef `cid` confirmed a text string on
  the wire (§Signing; FORKS F36–F38; reference `src/acp/`).
- **2026-08-21** — ship-gates review rulings: the trust decision moves
  ahead of the status fetch (steps 6/7 swapped) and `status.list` must be
  validated before any request — an untrusted attestor must not be able to
  make a verifier perform I/O (§Verification; FORKS F29 precedent). Ownership
  key control re-specified as *senior to every key the owner does not hold*
  (FORKS F40, amended). The status-list body gains a signed `list`
  identifier so one attestor's lists are not interchangeable
  (§Status lists; FORKS F39, amended).
- **2026-08-22** — research-backed rulings on the three review forks.
  Ownership key control: the verifier names the custodians (policy
  `custodian_keys`); an owner key that is not a custodian's must sit above
  every custodian key in the owned DID's rotation list — did:plc allows
  key reuse across DIDs and public data never says who holds a key, so no
  rule over the lists alone could work (§Mutual claims, §Verification;
  FORKS F40). Status lists gain an issuer-declared signed `ttl`, after
  IETF Token Status List `sub`/`ttl` (§Status lists; FORKS F39). The
  status fetch's HTTP contract is pinned — redirects off, resolve-then-
  check, egress guard, size cap — after OWASP's SSRF guidance and the JWT
  `jku`/`x5u` history (§Verification step 7, §Conformance; FORKS F42).
- **2026-08-22** — **relationships are attestations** (FORKS F45): the
  `relationship` record type and the mutual-claim verification procedure
  are retired; a relationship is a self-claim attested by its counterpart,
  verified as any attestation. Ownership's key-control check leaves the
  verifier and becomes the consumer's, with vulpes supplying the helper.
  Severance is asymmetric and stated. The rotation-key layout
  `[user, vulpes, zurfur]` is the minted default and the user's key is
  client-generated (FORKS F46; `docs/ccs.md`). Dissolved: the "unanswered
  half" fork and the self-ownership question. Claim kinds are five-segment
  NSIDs, `<tld>.<domain>.acp.<category>.<name>`, under a closed category
  list; one kind per relationship, both sides differing by `role` in the
  payload (§Claim kinds).

## References

**Normative**
- [did:plc] — https://github.com/did-method-plc/did-method-plc
- AT Protocol specifications (repo, lexicon, strongRef, cryptography) —
  https://atproto.com/specs/atp
- [Token Status List] — IETF OAuth WG, draft-ietf-oauth-status-list

**Informative**
- `docs/manifesto.md` — the ACP manifesto (the values this spec serves)
- W3C Verifiable Credentials Data Model 2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- OpenID for Verifiable Presentations (OID4VP)
- `docs/ccs.md` — the Consensual Claims System (full semantics)
- `docs/identity-model.md` — the design interview this standard grew from

[did:plc]: https://github.com/did-method-plc/did-method-plc
[PLC directory]: https://web.plc.directory
[strongRef]: https://atproto.com/specs/lexicon
[Token Status List]: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
