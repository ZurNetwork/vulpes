# FORKS — judgment calls made during the extraction

Every decision here is one the source code did not settle: a name, a module
boundary, an error shape, a packaging choice. Each was resolved by the rule the
extraction was given — **choose the option that keeps the originating service's
later consumption diff smallest** — except where that rule pointed at something
actively wrong for a public library, in which case the reasoning is spelled out.

Nothing here changes protocol behaviour. The one place where a behavioural fork
appeared is **F8**, which the Engineer has ruled **strict** (see "Ruled by the
Engineer" below). Every fork raised for the Engineer — B2, S3, S7, F8, F13,
F32, F36–F48 — is now ruled; no decision is left open.

Source: `zurfur/backend/crates/{adapter-atproto,adapter-pg,domain,api}`.
Spec facts cited below were verified against
<https://web.plc.directory/spec/v0.1/did-plc> and the W3C DID Core ABNF, not
recalled.

---

## Standing notes

### F31. Migration files are edited in place, pre-1.0

**Where:** `migrations/`.

The three migrations were **modified after they were first written** (the
`IF NOT EXISTS` removal, the `auth_request.created_at` index). sqlx checksums
migration files, so any database that already applied an older copy will fail
`migrate` with a version mismatch rather than silently diverging — which is the
correct behaviour, and safe while vulpes is unreleased and unadopted. From the
first tagged release, a change to shipped DDL must be a **new** migration
instead. Called out here rather than assumed.

---

## Ruled by the Engineer

### F48. Consent has four shapes — paired claims are the recommended one; witnesses are embedded signatures; the ownership kind is the first paired kind

**Where:** `docs/acp.md` §Self-claim, §Signing, §Relationships are
consent (four shapes), §Verification, §Conformance; `docs/ccs.md` (rules,
verification rule, kinds); `lexicons/net.got-paws.acp.claim.json`; the
code PR that follows (record fields, fixtures, the paired verifier, the
report).

Defining `relationship.ownership` by writing the two records out surfaced
a shape the spec did not have: **both** parties write a claim of the same
kind in their own repo — `{role: owner, subject: fox}` in Kit's, `{role:
owned, subject: kit}` in Fox's — and the pair is the relationship. No
attestation record is needed for consent: the other half *existing* is the
consent, and each half carries its own lifetime and its own severance
lever. **Ruled (Engineer, 2026-08-25), after steelmanning:**

- **Four shapes, one record model.** A claim is one-sided until something
  answers it; what answers it is the shape.

  | shape | claims | consent is | pairs by | example |
  |---|---|---|---|---|
  | one-sided | one half, no counterpart | none — an assertion (F45: an unattested claim is a claim); required so vulpes can do what a Bluesky follow does | — | Kit claims `identity.email`; nobody has vouched. Kit "follows" Fox; Fox signs nothing. |
  | asymmetric | one half | the counterpart's attestation | strongRef | Kit's email claim + the attestor's attestation in Kit's repo — Kit's story. |
  | symmetric (**paired**) | two halves | the other half existing, ids equal | `id` | Kit writes `ownership {owner, fox}`; Fox writes `ownership {owned, kit}`; same `id`. Either deletes → severed. |
  | witnessed | any of the above | + witness signatures **embedded in each half** | `witnesses[].sig` | The sale went through Zurfur: Zurfur signs both halves before they are written. A buyer's policy may require it. |

  Contrast with the ecosystem: a Bluesky follow is one-sided; a label is a
  third party nobody invited. ACP's addition is not the paired shape alone
  — it is consent in every row past the first.

- **Paired is the recommended shape for relationship kinds.** Asymmetric
  stays valid and unchanged (F45's claim + counterpart attestation), so
  nothing already specified breaks. What paired buys: symmetry kills the
  per-kind direction rule (F47's "who claims / who attests" collapses to
  "each party claims its own side in its own repo"); each side holds its
  own lever natively — delete severs my half, `status` revokes it without
  deleting — so Rule §5 is satisfied by construction rather than by a
  mandate on attestations; the owner roster falls out (N `owner` halves
  against one character) and needs no kind of its own; and the kill test
  is trivial — two repos, two status lists, no third party to die.

- **The claim record grows, and `expiresAt` becomes required.**
  `net.got-paws.acp.claim` gains, top-level: `id` · `nonce` · `claimant` ·
  `expiresAt` (all **required**) and `witnesses` · `status` (optional).
  There is no `Option<expiresAt>` and no permanent mode: a far-future date
  is semantically permanent (the "permanent" future-change entry is
  retired). `claimant` is the repo DID **written into the record and
  checked against the repo it was fetched from — never read as the repo
  DID** (F36 stands); it gives claims the transplant check attestations
  already have and makes an exported claim self-contained.

- **The edge id.**
  `id = hex(sha256(min(a,b) ‖ "\n" ‖ max(a,b) ‖ "\n" ‖ expiresAt ‖ "\n" ‖ nonce))`
  with `a` the claimant and `b` the payload's counterpart DID if the kind
  names one, else `a` (an identity claim is a self-edge — F45's degenerate
  case, so every claim has an id). Byte-wise order of the full DID
  strings makes it order-independent; hashing the *strings* makes it
  method-agnostic (`did:web` has no integer to add — arithmetic on decoded
  `did:plc` bytes was considered and rejected for that reason); `expiresAt`
  is the canonical string both sides wrote, so `Z` vs `+00:00` cannot fork
  the id; `\n` cannot occur in a DID or an RFC 3339 datetime. A DID is
  immutable for the identity's life (handles, hosts and keys all change
  around it), so the id survives every migration. Renewal = a new
  `expiresAt` = a new id = a new term, never an edit. The `nonce` (16
  random bytes, hex, agreed in the handshake like `expiresAt`) is why a
  re-established edge — sell Fox, buy it back, same lifetime — cannot
  inherit the dead edge's id and a consumer's memory of that id's
  revocation. `witnesses` are per-half and outside the id: Kit's side may
  be witnessed, Fox's not.

- **Witnesses are embedded signatures, not records.** A witness is a
  notary: "I saw it happen, or it went through me — here is my
  signature." It is also the delegation answer: when a client writes on
  a user's behalf, the witness signature is what a verifier's policy
  weighs to believe the half at all. Each entry is `{did, sig, status?}`;
  the witness signs the half's pre-image CID with the injected `{$type,
  repository}` exactly as an attestor does (F36), the claimant collects
  the signatures and writes the record with them inside. The claim
  pre-image is the record minus the `witnesses` field entirely (plus the
  injected `$sig`), so witnesses sign before the write and party and
  witness signatures cannot disagree. No extra record, no witness repo that can die —
  kill-test-proof by construction. The optional per-witness `status` ref
  is the witness's revocation lever, since an embedded signature cannot
  otherwise be withdrawn. **No verdict requires a witness**; a policy may.
  A witness `sig` that fails to verify makes the half *visibly
  incomplete* in the report, not invalid.

- **The verdict is a report, not a bool.** `in_force`; `paired {verified,
  halves, ids_match, lifetime_agreed}`; per half `{repo, role, status,
  expires_at, witnesses [{did, sig_valid, status}]}`; `attestations
  [{attestor, on, in_force}]`; `custody: null` unless the consumer asked
  (F47 intact). A consumer that wants a bool reads `in_force`; one that
  wants to know *how* reads the rest. A one-sided claim reports `paired:
  none, attestations: []` — true, and proving nothing.

- **The ownership kind.** `relationship.ownership` is paired; roles
  `owner` / `owned`; at most one in-force edge per character (more is a
  conflict state — consumer guidance, axiom 3); the multi-owner roster is
  N `owner` halves against the character, so the separate roster kind is
  dropped; transfer = sever + a new term (new id).

**Steelman, and where it is weakest** (recorded so the next reader does
not rediscover it):

- *Strongest case* — symmetry, native levers, a public recomputable
  pairing key (a verifier recomputes the id from the two DIDs, the
  lifetime and the nonce and gets the agreed-lifetime check for free),
  trivial kill test, and "it is only referencing" — no semantics enter
  the protocol; `role` and `subject` remain the kind's.
- *Weakest* — a mirrored claim is a self-attestation, which changes what
  "claim" means; the spec therefore grows a **shape**, it does not
  redefine the word. `expiresAt` and `nonce` must be agreed before either
  write — a handshake, which is the Claim Handshake of the derivation and
  not new, but the reference tooling must carry the exchange. Third-party
  attestations still exist (an org vouching for Kit's half) and the text
  must say so, or "paired" will be read as "no attestations".

**Prior art** (researched 2026-08-25, cited not recalled):

- **Symmetric consent held by both sides** — XMPP RFC 6121 §2.1.2.5/§3:
  each roster carries its own `subscription` state, `both` = mutual,
  either side's cancel downgrades both — the closest precedent to "each
  side stores its half; either severs"
  (<https://www.rfc-editor.org/rfc/rfc6121.html>). ActivityPub §7.5–7.6
  (W3C REC 2018): Follow + Accept, each side updating its own collection
  — consent as a second artifact, activity-shaped rather than mirrored
  (<https://www.w3.org/TR/activitypub/>). Matrix room membership is one
  shared state event, not per-party — the contrast.
- **Unordered-pair id** — canonical-order-then-hash is the standard
  technique for hashing unordered pairs (XOR-combining the known weak
  alternative): O'Keefe, *How to Hash a Set* (2017),
  <https://www.preprints.org/manuscript/201710.0192/v1/download>. Nonce
  for replay: OIDC Core §15.5.2 "sufficient entropy MUST be present"
  (<https://openid.net/specs/openid-connect-core-1_0.html>); RFC 7519 §4.1.7
  `jti` (<https://www.rfc-editor.org/rfc/rfc7519.html>). Expiry as a hash
  *input* to an identifier has no found precedent (JWT keeps `jti` and
  `exp` independent) — novel, deliberate: renewal is a new term.
- **Several signatures, one payload** — W3C Data Integrity 1.0 *proof
  sets* (REC 2025-05-15): "the same data … secured by multiple entities",
  each proof computed with the `proof` attribute removed — the exact shape
  of `witnesses[]` over record-minus-signatures
  (<https://www.w3.org/TR/vc-data-integrity/>). JWS General Serialization
  RFC 7515 §7.2.1 (<https://www.rfc-editor.org/rfc/rfc7515.html>); DAG-JOSE
  (<https://ipld.io/specs/codecs/dag-jose/spec/>); COSE_Sign RFC 9052 §4.1,
  whose external-AAD slot is the analogue of the injected binding
  (<https://www.rfc-editor.org/rfc/rfc9052.html>). CMS RFC 5652 `SignerInfos`
  (parallel co-signers) vs `Countersignature` — ACP witnesses co-sign the
  pre-image (proof set), they do not countersign the parties' signatures.
- **One-sided assertions** — `app.bsky.graph.follow`: `subject` +
  `createdAt` in the follower's repo, nothing from the followed
  (<https://atproto.com/specs/repository>). Labels: signed third-party
  assertions with no subject consent, retracted via `neg`
  (<https://atproto.com/specs/label>) — the witness-nobody-invited.
- **Structured verifier result** — W3C VCALM `VerifyCredentialResult`:
  `verified` + `problemDetails[]` + per-check `results{…}`
  (<https://github.com/w3c/vcalm>).

**Cautions the research raised, answered in the ruling:**

1. *Witness key rotation.* Same rule as attestors (§Verification step 4):
   current keys only, no historical-key verification. A rotated witness
   key makes its `sig` fail → the half is *visibly incomplete*, never
   invalid; the witness re-signs and the claimant rewrites the record
   (new CID; the `id` is unaffected, attestations by strongRef are not —
   attest the new version or live without, as §Binding already says).
2. *The subject controls the container* and can drop a witness entry (or
   the whole record). Correct and intended: a witness signature exists for
   the **subject's** benefit (a stronger half), not the witness's. A
   witness that needs proof it signed keeps its own copy — or writes an
   attestation, which is the record it controls.
3. *Canonicalization.* Already fixed by F37/F38 (canonical DAG-CBOR, pinned
   fixtures). The claim pre-image is the record **minus the `witnesses`
   field entirely**, plus the injected `$sig` — one rule, no per-entry
   stripping, so party and witness signatures cannot disagree.
4. *Expiry in the id* is intended (renewal = new term) and leaks nothing:
   `expiresAt` is a public field of the record.
5. *Delete = sever vs. unreachable repo.* A half whose record is **gone
   from a reachable repo** is severed; a half whose repo is **unreachable**
   is *not checkable* — never severed, never in force (the kill-test
   distinction §Status lists already draws for lists). The report says
   which.

### F47. Administration and claims are two lanes — ownership is claims-only

**Where:** `docs/acp.md` §Relationships are attestations, §Claim kinds,
§Status lists, §Privacy and security; `docs/ccs.md` (verification rule,
kinds, transfer); the pending kind definitions and `acp::custody`.

F45 moved the rotation-key check out of the verifier but kept it in the
ownership *verdict* — the consumer's third fact. Working the character
model surfaced what that third fact actually was: an administrative
answer bolted onto a semantic question. **Ruled (Engineer, 2026-08-23):
the two lanes separate completely.**

- **The claims lane answers meaning** — who owns, who belongs, who
  consented. Records, attestations, rosters, status bits; severed by
  delete or revoke; verified by anyone with public infrastructure.
- **The administration lane answers mechanism** — who can write the repo,
  rotate keys, recover the DID, survive a host's death. Layout D (F46),
  CAR exports, the 72 h window, the watcher; "severed" by key rotation.
- They touch at exactly one point: the administrative controller holds
  the *pen* for a subject's side of the claims lane. One direction of
  influence, zero shared verdicts. A key compromise forges no history;
  a hostile claim touches no keys.

Consequences, each ruled in the same conversation:

- **Ownership is claims-only.** The verdict is the owner's claim + the
  counterpart's attestation — two facts, not three. The forgery defense
  the key check provided was illusory: whoever administers the character's
  repo can grant, revoke, or delete the consent anyway, so gating on keys
  misattributed a power it never removed. Dropping it also removes F40's
  completeness footgun (the silently-fail-open custodian set, F44's
  reason to exist) from the ownership path. `acp::custody` survives as an
  **optional administrative-health helper** — "can this owner win a key
  war" — for consumers that want it (a buyer's due diligence), never as
  an ownership gate.
- **Cardinality one.** A character has exactly one in-force ownership
  edge — a user, or an account when several humans share it. More than
  one is a conflict state. The protocol cannot forbid it (axiom 3); the
  kind definition records it as consumer guidance.
- **The owner roster.** A multi-owned character is account-owned, and the
  character claims who its owners are — one claim in the character's
  repo listing owner DIDs, each named human attesting their entry
  (one claim, N attestations — already the F45 shape). Character-scoped
  and *not* derivable from account membership: two of five collective
  members may own this character. Co-owner churn edits the roster —
  no keys, no transfer, no 72 h window. Roster-of-one makes discovery
  uniform: every character answers "who owns me" from its own repo.
- **Direction, pinned by the Rules of Claims** (below): the ownership
  edge is owner-claims / character-attests (the deed sits with the
  holder; deletion = renunciation, always instant); the roster is
  character-claims / humans-attest (N counterparts cannot share one
  claim in N repos). Symmetric relations carry identical `role`s, so
  direction carries no semantics — the proposer claims.
- **The Rules of Claims** — who claims what, for every kind present and
  future: (1) about yourself → you claim; (2) about a right over
  something → the holder claims, the thing's side attests; (3) about a
  circle → the circle's node claims, each named party attests; (4) the
  generator behind all three: *whose assertion is it — they claim*; no
  structurally required consent → it's a label, not a claim; (5)
  severance never waits on the calendar — the claimant deletes, the
  counterpart revokes; expiry bounds lifetime and is never the severance
  mechanism. Enforcement of (5): the **relationship category mandates
  `status`** on its attestations (categories fix mandatory fields, F45),
  so both sides always hold an instant lever. The cost is stated: a
  relationship attestor must republish within the freshness horizon
  (F43's 30 days, tighter `ttl` wins) or go stale — for continued
  consent, correct.
- **Status-list residence, reaffirmed while stress-testing this**
  (research: W3C Bitstring Status List REC 2025, IETF TSL/EUDI, the
  OCSP retirement): control is the attestor's signature, never the
  host's. Defaults: org attestors on their own domain, humans on their
  PDS, the reference instance as publisher-of-convenience and mirror.
  Two earmarks: the `list` identifier the reference tooling mints is
  decided with "The first attestor"; the TSL JWT/CWT envelope and its
  library (impierce's crate) stay deferred to the private lane — the
  public lane keeps the hand-rolled native artifact (F37 pattern).

### F46. Rotation-key layout D is the minted default, and the user's key is client-generated

**Where:** `MintPolicy` (`src/policy.rs`), `docs/ccs.md` §Rotation-key layout.

A did:plc carries up to five rotation keys in order of seniority; holding
one is not exclusive, and the only question that matters is *who outranks
whom*. The layouts considered (senior → junior), with what each failure
does to the character:

| layout | Zurfur dies | Vulpes dies | user loses key | Zurfur breached | Vulpes breached | sovereign |
|---|---|---|---|---|---|---|
| A `[zurfur]` | gone | — | — | gone | — | Zurfur |
| B `[vulpes, zurfur]` | ok | → A | — | ok | gone | Vulpes |
| C `[user, zurfur]` | ok | — | → A | ok | — | user |
| **D `[user, vulpes, zurfur]`** | ok | ok | → B | ok | ok | user |
| E `[user, user_backup, vulpes, zurfur]` | ok | ok | → D | ok | ok | user |
| F `[user, zurfur, vulpes]` | ok | ok | → Zurfur sovereign | Vulpes cannot revert | ok | user |
| G `[vulpes, user, zurfur]` | ok | ok | ok | ok | user cannot revert | Vulpes |

**Ruled (Engineer, 2026-08-22): D is minted by default; E is offered by
the client; F and G are never minted** (same keys, wrong order — F leaves
the recovery custodian unable to recover, G makes the reference instance
the landlord). B is the floor for a user who has not yet made a cold key,
and the client nags them into D. Every single failure in D lands on a
layout that is still recoverable; it takes two independent failures to
reach A, which is where an account without a recovery key lives every day.

The user's key is **generated client-side and never transits Zurfur or
Vulpes** — a server that has displayed the deed has held it, and that is D
in name only.

The 72-hour nullification window is did:plc's constant, enforced by the
directory, not ours to tune: a longer window would delay every transfer's
finality by the same amount it widened recovery, and it protects only
against a stolen *junior* key regardless of length. The lever is
detection — a watcher on the PLC log that alerts the user to any
operation on their DID they did not initiate. That is a Zurfur feature,
recorded on the roadmap beside this ruling.

### F45. Vulpes only does attestations — CCS is claims plus counterpart attestations

**Where:** `docs/ccs.md`, `docs/acp.md` §Record types, §Verification,
§Conformance; `src/acp/verify.rs` (the relationship path, removed in PR #17).

The 2026-08-11 CCS shape was a second record type (`relationship`) with its
own verification rule: two halves, one in each repo, each naming the
other, plus an ownership tier that checked rotation-key control inside the
verifier. Reviewing it surfaced a fork the shape could not answer (the
public "unanswered half") and a verdict it could not refuse (self-loops),
and every property already proven for attestations — kill test, transplant
defense, revocation, expiry, the SSRF posture — had to be proven again for
pairs.

**Ruled (Engineer, 2026-08-22): vulpes issues and verifies attestations,
and never decides what a claim means.** A relationship is not a second
system: it is a claim by one party, in that party's repo, **attested by
the counterpart** — the attestation signed with the counterpart's key and
stored where every attestation is stored, in the claimant's repo. Third
parties may attest the same claim; trust policy chooses whose signature
counts. Consequences:

- **Retired:** `net.got-paws.acp.relationship`, the `Relationship` type,
  `RelKind` and the pairing catalog, `verify_relationship`, the counterpart
  search, and the ownership tier *inside verification*. The relationship
  lexicon is deprecated in the spec and removed with the code.
- **F40 amended:** key control leaves the verifier. The seniority check
  (an owner's non-custodian key above every custodian key on the owned
  DID) and custodian discovery (the rotation keys common to two or more
  unrelated accounts on a host — F44's helper, landing as a custody helper
  rather than a policy field) stay in vulpes as pure functions in a
  future `acp::custody` module, never wired into a verdict.
  `TrustPolicy::custodian_keys` goes with them. Vulpes minted the layout
  (`MintPolicy`); reading it back is the same knowledge — *mechanism*,
  not meaning. Whether `owns` requires it is the consumer's rule; Zurfur,
  the reference consumer, calls it after an `owns` attestation verifies.
- **Ownership** = the owner's `owns` claim + the character's attestation
  of it + the owner senior on the character's rotation list, the third
  fact checked by the consumer. Consent is the signature (forgeable by
  whoever holds the pen); control is the deed (forgeable by no one).
- **Severance is asymmetric**, and the spec says so: the claimant deletes
  the claim and every attestation of it stops resolving; the counterpart
  cannot delete a record in another repo, so it revokes (status list) or
  declines to renew. A human counterpart without infrastructure uses a
  short expiry and silence. The old rule 3 ("delete your record and it
  dies") holds for the claimant only.
- **Lifetime:** ownership-kind attestations may carry a far-future
  `expiresAt`; the deferred permanent mode stays deferred and additive.
- **Dissolved:** the roadmap's ⚠ "unanswered half" fork (an unattested
  claim is just a claim — already the design) and the self-ownership
  question (`attestor == subject`, ruled 2026-08-12 as valid and adding no
  trust; policy decides).
- **Kinds (ruled the same day):** a claim `kind` is a five-segment NSID,
  `<tld>.<domain>.acp.<category>.<name>` — the authority owns the name and
  publishes its definition (atproto lexicon resolution), the category is a
  closed ACP list (`identity`, `relationship`; `consent` reserved, deferred
  behind takedown requests) that fixes who
  claims, who attests and the payload's mandatory fields, and the verifier
  checks the shape only. **One kind per relationship**, both sides using it
  and differing by a `role` in the payload
  (`…relationship.ownership` with `owner`/`owned`; never an
  `owns`/`ownedBy` pair) — the least contamination between sides.
  `docs/acp.md` §Claim kinds.

### F39. The status-list artifact is ACP-native DAG-CBOR, not a Token Status List JWT

**Where:** `src/acp/status.rs`, `docs/acp.md` §Status lists.

The spec asks for "Token Status List *semantics*". The IETF wire format is a
JWT/CWT around a DEFLATE-compressed bitstring — JOSE lives only behind `vc`,
and zlib would be a new dependency in the pure lane, for a second signature
path to review. **Ruled (Engineer, 2026-08-21): ACP-native envelope.**
`net.got-paws.acp.statusList { attestor, issuedAt, bits, sig }`, canonical
DAG-CBOR, signed CID-first with the very same `verify_cid` primitive as
attestations. TSL semantics kept in full (bit index, signed, timestamped,
mirrorable, newest-verifiable-wins). No `$sig` binding — not a repo record;
`$type` inside the signed bytes is the domain separator. The JWT/CWT
envelope can be added for the private lane where JOSE already exists.

**Amended 2026-08-21 (ship-gates review, ruled by the Engineer):** the signed
body gains `list`, the identifier every covering attestation's `status.list`
must equal. Without it a validly-signed copy of *any* of an attestor's lists
satisfied *any* pointer — the status-list analogue of the transplant the
`$sig` binding closes for attestations. `list` is an identifier, not a fetch
URL, so mirrors stay free to serve it from anywhere (kill test intact).

**Amended again 2026-08-22 (ruled by the Engineer after sourced research):**
the IETF Token Status List draft (draft-ietf-oauth-status-list) is the
direct precedent for both amendments and the shape now matches it: its
Status List Token `sub` "MUST specify the URI of the Status List Token" and
"MUST be equal to that of the `uri` claim" in the referenced token — our
`list`; and it carries `iat` (REQUIRED) with `exp`/`ttl` (RECOMMENDED) so
the *issuer* states how long a copy is evidence. The signed body gains
`ttl: Option<u64>` seconds after `issuedAt`. The verifier applies the
tighter of `ttl` and its policy's `max_status_age_secs`; a list with
neither stands until the attestations it covers expire, so a dead
attestor's last list still ages out rather than failing closed (kill
test). W3C Bitstring Status List makes the `id`/`statusListCredential`
match only a MAY — the gap the first amendment closed.

### F40. The verifier's I/O is three vulpes-owned `#[async_trait]` ports, and the attestor is not one of them

**Where:** `src/acp/ports.rs`, `src/acp/verify.rs`.

jacquard 0.12 (already in the graph via `oauth`) has resolution
(`IdentityResolver`), XRPC (`XrpcClient`) and the record types — but every
one of its traits returns `impl Future` with generic method parameters, so
none can be an `Arc<dyn _>`; the whole vulpes storage/directory seam is
`#[async_trait]` + `Arc<dyn _>`. **Ruled: own the ports** (`RepoReader`,
`DidResolver`, `StatusSource`), each with an opaque error per F1, each
honouring "absent is `Ok(None)`/empty; broken is `Err`"; jacquard-backed
implementations arrive with the PDS-client line and wrap, exactly as
`HttpPlcDirectory` wraps reqwest. Two consequences worth the ink:

- A `FetchedRecord` carries the **canonical DAG-CBOR bytes** and the
  repository DID it was read from. Bytes, not JSON — `sig` is a byte string
  and the CID must be computed over what the repo holds; the JSON→bytes step
  (`$bytes` handling) is the client's job at the boundary.
- **There is no attestor port.** The verifier cannot call one even by
  mistake, which is how `kill_test` passes by construction rather than by
  discipline. `VerifyError` (a port failed) is distinct from
  `Verdict::NotInForce` (the vouch is bad); the verifier never converts one
  into the other.

Key control for ownership-tier pairs was first checked as "at least one of
the owner's keys is among the owned DID's rotation keys". Superseded
2026-08-21 by "the owner's most senior rotation key is the owned DID's most
senior rotation key" — and that, too, **superseded 2026-08-22 (ruled by the
Engineer after sourced research):**

- The did:plc spec orders `rotationKeys` by descending authority, caps them
  at five, keeps them out of the DID document (`/data`, `/log/audit`), and
  **explicitly allows one key to be reused across many DIDs**. Seniority buys
  one thing — a 72-hour window in which a higher key can nullify a lower
  key's operation.
- bsky.social puts the same two operator keys on every account and refuses
  operations that drop its own; so "some key in both lists" passed any two
  co-hosted accounts. "Top equals top" fixed that only where the owner's
  personal key sits first on *both* DIDs — Bluesky's signup `unshift`s a
  user recovery key to the front, but `goat add-rotation-key` appends one
  last, a junior co-owner is never first, and two accounts carrying *only*
  the operator's keys have equal tops and passed anyway. A rule over the
  lists alone cannot work: **public data never says who holds a key.**
- **Superseded by F45 (2026-08-22):** `TrustPolicy::custodian_keys` is
  gone from the verifier; the rule below survives as a consumer-side helper
  (`acp::custody`, the PR after #17).
- **Ruled (as it stood):** the verifier names the custodians. `TrustPolicy::custodian_keys`
  (the same shape as `trusted_attestors`) lists operator rotation keys —
  bsky.social's two, Zurfur's vault key, whatever a deployment's subjects
  use. Ownership holds iff some owner rotation key that is *not* a
  custodian key appears in the owned DID's list above every custodian key
  there (or no custodian key is there). That is `docs/ccs.md`'s senior-key
  rule checked literally. Junior co-owners pass while above the custodian;
  pure-custody pairs fail closed; an **empty** custodian set is the
  documented permissive mode ("some key in both lists" — the verifier has
  opted out of the distinction).
- Only rotation keys count; verification (signing) keys confer no control
  per did:plc. `KeyMaterial::rotation` carries the `did:key` strings
  verbatim, in directory order, unparsed: the check is set membership and
  position, needs no key material, and parsing at the port would let one
  rotation key on an unsupported curve fail the whole `keys()` call —
  breaking plain-signature verification for an attestor whose rotation keys
  the verifier never uses. `DidResolver::keys` sources them from the PLC
  directory's `/data` (or the audit log), never from the DID document.

### F43. `BasicPolicy::default()` bounds status-list age at 30 days

**Where:** `src/acp/policy.rs` (`DEFAULT_MAX_STATUS_AGE_SECS`).

With no bound, the newest verifiable copy wins however old it is, so an
adversary who can withhold fresh copies pins a stale all-clear for the
attestation's whole lifetime — failing open against the one attacker the
status list exists to beat. With a short bound, an attestor's death becomes
a cliff a day later, which the spec's "age out at expiry" forbids.
**Ruled (Engineer, 2026-08-22): `Some(30 days)` by default;**
`permissive()` is the explicit `None`. Thirty days is longer than any sane
republish cadence and shorter than a human vouch's lifetime; the issuer's
signed `ttl` (F39) is the precise instrument and wins when tighter, so
attestors that know their cadence are unaffected by the default.

### F42. A status-list fetcher is a network policy, not a URL parser

**Where:** `src/acp/ports.rs` (`StatusSource`), `src/acp/record.rs`
(`StatusUri::fetchable`), `docs/acp.md` §Verification step 7, §Conformance.

The 2026-08-21 SSRF fix put the trust decision ahead of the status fetch
and added `StatusUri::fetchable` — a syntactic denylist (scheme, IP
literals in every WHATWG spelling, special-use names, label count). The
re-verification found bypasses on the first pass (`localhost.localdomain`,
bare names, hex IPv4) and would keep finding them: OWASP's SSRF cheat sheet
is blunt that deny-lists are bypass-prone and "URLs are difficult to
validate and the parser can be abused", and the JWT `jku`/`x5u` history
(a decade of IMDS pivots, still producing CVEs in 2026) says the same.
IETF Token Status List orders "validate the referenced token, then fetch";
W3C Bitstring Status List has no SSRF text at all.

**Ruled (Engineer, 2026-08-22): keep `fetchable()` in the pure lane — it
costs nothing and removes the cheap cases without DNS — and pin the
contract the HTTP implementation must meet when the PDS-client line lands,
at the strengths `StatusSource`'s doc and the spec carry: redirects
disabled (**MUST**); A/AAAA resolved and non-global addresses refused at
connect time, the only answer to rebinding (**MUST**); an injected
egress-guarded client, `with_client` as `HttpPlcDirectory` (**SHOULD**);
response size capped at `MAX_STATUS_LIST_BYTES` (**SHOULD**); at most
`MAX_STATUS_COPIES` copies returned (**SHOULD** — the verifier bounds its
verifications regardless).** The two SHOULDs are deployment-shaped (a
guard the network supplies, a cap a client library may not expose); the
two MUSTs are the defense. The spec says "necessary, not sufficient" in so
many words so that no conforming verifier mistakes the syntax check for
the defense.

### F44. Custodian keys are discovered from the directory, never shipped

**Where:** the future `acp::custody` module (F45 moved it there from
`BasicPolicy::with_custodians_from`).

F40 makes ownership key control depend on knowing every operator rotation
key among its subjects' hosts, and an incomplete set fails open silently.
The obvious convenience — a `BSKY_SOCIAL_ROTATION_KEYS` constant — would
put a fact the crate cannot keep true into a git-dep library, and per F40's
completeness rule a stale constant is worse than none. **Ruled (Engineer,
2026-08-22): no operator's keys live in vulpes.** A verifier names two or
more unrelated accounts on a host; the rotation keys common to all of them
are the operator's, fetched live through the `DidResolver`. Always current,
no registry to maintain, and no line of this crate that knows who Bluesky
is. One sample takes everything on it (the documented caveat); an
unresolvable sample is an error, never a quietly empty set.

**Amended by F45 (2026-08-22), same day:** key control left the verifier,
so this discovery is no longer a `TrustPolicy` constructor. PR #15 carried
the ruling and was closed unmerged for that reason — the entry is recorded
here because F45 depends on it and the intersection logic returns in
`acp::custody`, called by the consumer rather than the verifier.

### F41. `Datetime::to_unix` is hand-rolled

**Where:** `src/acp/record.rs`.

Expiry (step 5) needs a comparison; the pure lane has no `chrono`. Forty
lines of days-from-civil plus the RFC 3339 offset, pinned against known
epochs including a leap day and both offset signs. Fractional seconds
truncate. It compares; it never renders.

### F36. The attestation key signs the **CID** of the pre-image, not its bytes

**Where:** `src/acp/sign.rs`, `docs/acp.md` §Signing.

`acp.md` v0.1 said "computed over a pre-image, serialized as canonical
DAG-CBOR" and left the `$sig.$type` marker to be "aligned with the ecosystem
construction". The construction turned out to be Gerakines' CID-First
Attestation spec (badge.blue / the `atproto-attestation` crates), which
signs the **CIDv1** (dag-cbor, sha2-256, 36 raw bytes) of the pre-image and
leaves `$type` caller-minted — no fixed value exists anywhere.

**Ruled (Engineer, 2026-08-20): sign the CID bytes; `$type =
"net.got-paws.acp.sigBinding"`.** One extra hash buys a construction that
independent tooling reproduces (the vectors were cross-checked with python
`cbor2` canonical mode rather than the CLI, which needs Rust 1.90 — see F37).
Our stored shape still differs from that spec (a single `sig` bytes field,
not a `signatures` array), so this is byte-alignment of the *pre-image*, not
wire interop.

### F37. The ACP codec is hand-rolled on the IPLD crates; `atproto-record` is reference only

**Where:** `Cargo.toml` (`acp` feature), `src/acp/record.rs`.

The roadmap's open decision. `atproto-record` / `atproto-attestation` 0.14
do exactly this job but need Rust 1.90 (we are pinned at 1.88, F32), pull a
second `sha2` (0.11), and are one maintainer with near-zero downloads.
`serde_ipld_dagcbor` was already a direct, ungated dependency and already
proven canonical against a published PLC vector. **Ruled: hand-roll.** The
only new direct dependency is `serde_bytes` (so `sig` is a CBOR byte string,
not an array of integers). The CID is built by hand as in `plc::cid`, and a
test pins the two equal. Consequence recorded while building: a strongRef's
`cid` is a **text string** on the wire (`com.atproto.repo.strongRef` says
`format: cid` string), never a tag-42 link — "fixing" it changes every byte.

### F38. Opaque `payload` / `scope` are `serde_json::Value`, data-model-checked on construction

**Where:** `src/acp/record.rs` (`check_opaque`).

The lexicons type them `unknown`. Holding them as `Ipld` would add
`ipld-core` as a direct dependency for no wire difference; holding them as
`serde_json::Value` risks a float or `null` reaching the signer (forbidden by
the atproto data model, and `serde_ipld_dagcbor` would happily encode an
f64). **Ruled: `serde_json::Value`, rejected at `Claim::new` if it contains a
float, a `null`, or an integer beyond ±2⁵³.** `serde_json`'s `preserve_order` (on globally since F35) is harmless
here — the DAG-CBOR encoder re-sorts — and a test pins that. Known limit: a
`$bytes` value inside a payload will not round-trip through `Value`; no v0.1
kind carries one.

### F32. RUSTSEC-2026-0009 (`time`) — **fixed, MSRV raised to 1.88**

**Where:** `Cargo.toml` (`rust-version`), `Cargo.lock`, `deny.toml`.

The advisory (stack exhaustion parsing RFC 2822 dates) reached vulpes only as a
**dev-dependency** — `testcontainers → bollard → time 0.3.45` — never in a
consumer's build, and nothing here parses RFC 2822. The fix, `time` 0.3.47,
requires Rust 1.88, one minor above the crate's declared `rust-version = "1.85"`.

**Ruled (Engineer): take the real fix.** `Cargo.lock` pins `time` 0.3.47 (with
its `num-conv` / `time-core` / `time-macros` bumps), and `rust-version` is raised
to **1.88** — the library's own floor, not just the test toolchain. The advisory
allow-list entry is removed rather than kept: an ignore for something that no
longer fires is stale, and cargo-deny warns on it. The other four allow-list
entries stand (all upstream/unreachable). CI runs on `stable`, already well past
1.88, so no toolchain pin needed adjusting.

### F8. An update refuses a prior operation the policy does not describe — **strict, ruled**

**Where:** `src/minter.rs`, `Minter::carry_forward`.

The source refuses to build a handle update when the DID's latest operation is
not identity-only, with the comment *"carrying those forward is not
implemented"* and an error naming verbatim carry-forward as the extension point.
That guard was hard-coded to one shape, which a parameterized library cannot
keep: a `MintPolicy` that declares a PDS would mint operations its own updater
then refuses.

**Shipped:** the guard is generalized, not removed. An update carries the prior
operation's `rotationKeys`, `verificationMethods` and `services` forward
**verbatim**, but first checks that the prior shape is the one this policy mints
(verification-method IDs equal, services equal). Anything else is refused.

- Under `MintPolicy::identity_only()` — the preset the source runs — behaviour is
  **identical**, including the refusal of a PDS-bearing prior.
- A PDS-bearing policy can now update the identities it mints, which the
  hard-coded guard could not express.

**Ruled (Engineer): keep strict.** An update never carries an *arbitrary* prior
shape forward — one the operator's policy does not describe. A richer DID is a
richer `MintPolicy`, never a bypass of the shape check: to operate identities
with a PDS or extra verification methods, configure a policy that declares them,
and the same-shape check then passes. The permissive alternative — carry whatever
the row declares, so a binding added out of band silently survives an operation
the operator believes they control — is not offered. The `#[ignore]`d
placeholder test that held its place is deleted.

### F29. `Authenticator::start` takes a `Handle`, and the connector is the caller's

**Where:** `src/oauth/mod.rs`, `Authenticator::{start, with_client}`.

The source passes the raw login string straight to jacquard. jacquard's resolver
treats an input beginning `https://` as a PDS/entryway URL and **fetches it
directly**, so a raw string is an attacker-steered outbound request — the
classic SSRF shape. `start` therefore takes a validated `Handle`: a handle's
charset (`[a-z0-9-]` plus dots) cannot spell a scheme, so that branch is
unreachable by construction rather than by a check that can be forgotten.

That closes the *input*, not the *fetches the protocol requires*. jacquard still
resolves `https://<handle>/.well-known/atproto-did` and then whatever
`serviceEndpoint` the DID document names, with no host or scheme guard of its
own. `Authenticator::with_client` was added (mirroring
`HttpPlcDirectory::with_client`) so a deployment can install an SSRF-guarded
connector; the default client sets connect and request timeouts but deliberately
filters no addresses, because which ranges are private is a deployment fact.
Documented prominently on the module and in the README.

Consumption impact: `auth.start(&handle)` instead of `auth.start(&str)` — the
call site almost always already has a `Handle`.

### F13. OAuth clients are loopback-only — **ruled for v0.1.0**

**Where:** `src/oauth/mod.rs`, `OAuthConfig`.

The source builds `AtprotoClientMetadata::new_localhost`, deriving the
`client_id` from the redirect URI list. That is the localhost-development shape
of an atproto OAuth client; a public deployment eventually serves a hosted
`client_metadata.json` instead.

**Ruled (Engineer): loopback-only is deliberate for v0.1.0.** No hosted
public/confidential client is built now. `OAuthConfig::loopback` validates the
redirect against the two loopback literals (S1), and that is the whole surface
for this release. A hosted-metadata variant is a purely **additive** change to
`OAuthConfig` — a new constructor beside `loopback`, no reshape — gated on a
consumer actually needing it, so it is not speculatively built. Documented as a
limitation on the type and in the README.

---

## Naming

### F1. Error taxonomy: closed enums, plus two opaque wrappers

The source uses `anyhow::Result` throughout. A library returning `anyhow` gives
callers nothing to match on, so vulpes uses `thiserror` enums per concern —
`HandleError`, `DidError`, `VaultError`, `PlcError`, `PolicyError`, `MintError`,
`oauth::AuthError` — each naming its own failure modes.

Two errors *cannot* be closed, because the implementation is the caller's:
`StorageError` and `DirectoryError` are opaque newtypes over
`Box<dyn Error + Send + Sync>` with a `new` constructor and the cause preserved
as `source()`. `anyhow::Error` converts into that box, so an implementation
written in the source's style is a `.map_err(StorageError::new)` away.

Consumption impact: every vulpes error implements `std::error::Error`, so `?` into
an `anyhow` context works unchanged.

### F2. `Did` drops `Deref`, gains the std conversions

The source's `Did` derefs to `String`, which leaks `String`'s whole API onto a
domain type (`did.push_str(…)` compiles). Replaced with `as_str`, `Display`,
`AsRef<str>`, `Borrow<str>`, `From<Did> for String`.

`Did::new` is kept unchecked, for values from trusted sources — re-validating
what the network already accepted can only reject data that legitimately exists.
`FromStr` was **added**, validating the W3C DID Core ABNF, for untrusted input.

**Amended (Engineer, 2026-08-22): the `TryFrom` pair is withdrawn.** `TryFrom<&str>`
and `TryFrom<String>` were originally added alongside `FromStr` as a batch — "the
std conversions" — when `Deref` was dropped. Nothing ever called them: across
`Did`, `Handle`, `RecordCid`, `Datetime`, `AtUri` and `StatusUri` every use was in
the round-trip test that existed to test them, no `#[serde(try_from = …)]` exists
in the crate, and the one consumer (`wolven`) takes `Did` as a type only. The
ownership argument for `TryFrom<String>` was void in every impl: they each either
borrowed (`Self::parse(&raw)`) or funnelled into `Handle::try_new`, whose
`to_lowercase()` allocates regardless. Twelve impls removed; `FromStr` is the
single validating door, reached as `s.parse()`. `TryFrom<i32> for CustodyEnvelope`
is unaffected — that one has real call sites.

Consumption impact: a handful of `.as_str()` insertions where `Deref` was doing
the work.

### F3. `AccountKeys` → `CustodyKeys`, and `KeyRole` is new

"Account" is the originating service's entity, meaningless in a library that
knows only identities. The three fields (`cold_recovery`, `operational`,
`signing`) and their order are unchanged, so the sealed on-disk format is
byte-identical. `KeyRole` is new: `MintPolicy` needs to name a key without
positional indexing.

Consumption impact: one line —
`pub use vulpes::CustodyKeys as AccountKeys;` — if the old name is wanted.

### F4. One vault type, two callers

`adapter-atproto::secret_vault::SecretVault` and
`adapter-pg::key_vault::RootKey` were the same XChaCha20-Poly1305 envelope
written twice, flagged in-source as wanting unification. Unified as
`SecretVault` (the better name: it describes the thing, not its key), with the
generic `seal(aad, plaintext)` / `open(aad, blob)` pair.

`RootKey::wrap`/`unwrap` — which also did the three-scalar bundling — became
`CustodyKeys::seal(&vault, &did)` / `CustodyKeys::open(&vault, &did, blob)`. The
bundling lives with the type it bundles, so a non-PostgreSQL `KeyStore` gets it
for free rather than reimplementing it.

Blob format, nonce length, AAD binding and the on-disk bytes are unchanged.

### F6. `PlcDocument` is new; `identity_only` / `update_handle` became
`genesis` / `update`

The source's `PlcOperation::identity_only(...)` and `::update_handle(...)` bake
one document shape into the constructor names. Split into a `PlcDocument` value
(the public fields an operation asserts) and `PlcOperation::genesis(document)` /
`::update(document, prev)` — which is also what makes the update's
carry-forward expressible as data rather than as a second constructor.
`PlcDocument::identity_only(...)` preserves the convenience of the old call.

### F7. The preset is named for its shape, not its first consumer

The ruling asked for the originating behaviour as a *named preset*.
`MintPolicy::identity_only()` names what it produces; `MintPolicy::zurfur()`
would name who asked for it, which ages badly in a public crate. `Default` is
`identity_only()`. The doc comment states it is exactly the shipped
configuration of the service this came from.

### F22. `HandleDomain` is a newtype

The source carries the well-known route's namespace as a bare `String` on its
config struct. A library taking `&str` there would silently never match on a
typo or an uppercased value, so `HandleDomain::try_new` validates and normalizes
through the same `Handle` rules — a misconfiguration fails at construction.

### F26. `HandleResolver` is a new trait

The route was written against the service's own `AccountStore`. Generalized to a
one-method `HandleResolver` trait, which is what the `axum` feature actually
needs.

---

## Module layout

### F35. The op-log MAC sorts JSON keys itself (a feature-unification lesson)

`PlcOperationRecord::mac_message` always *documented* "serde_json, sorted
keys" — but the sorting was serde_json's default-feature behavior
(BTreeMap-backed maps), not our code. Adding the `vc` pins (VUL-2) pulled
crates that enable serde_json's `preserve_order` — and Cargo features unify
**globally**, so the whole binary's serde_json switched to insertion-order
maps. The MAC message then followed whatever key order Postgres `jsonb`
returned, and B2's tag stopped verifying against rows it had just written
(two Postgres minter tests red).

Ruling taken while finishing VUL-2: canonicalize explicitly — `canonicalize`
recursively sorts every object's keys before serialization. Byte-identical
to what default-feature serde_json always produced, so existing tags still
verify; immune to any future dependency flipping serde_json features. A
regression test pins key-order independence
(`key_order_does_not_change_the_mac_message`).

The general lesson, recorded for every future MAC/signature: **never let a
canonical form be an implicit property of a dependency's feature set** — any
crate anywhere in the graph can change it for everyone. (The PLC operation
*signatures* were never exposed: they go over DAG-CBOR, which is canonical
by construction.) Also inherited from the same unification, unused but
noted: `arbitrary_precision` and `float_roundtrip` — no numbers appear in
PLC operation JSON, so no current surface.

### F34. The VC wrap is `vc`, not part of `broker`, and prunes harder than the ruling listed

The wrapped SpruceID foundation (VUL-2's "wrapped third-party foundation"
checkbox) landed as feature `vc` → `pub mod vc`, a curated re-export surface
over the `ssi` 0.16 umbrella. Three judgment calls:

- **Name**: `vc`, not `broker`-anything — the broker→toolkit language ruling
  killed the word; the module sits beside (not inside) the in-progress
  `broker` module, which remains the Engineer's file to shape.
- **Pruning**: the machinery ruling listed the sub-crates
  (`ssi-vc`/`-jose-cose`/`-sd-jwt`/`-jws`/`-jwt`); the umbrella with
  `default-features = false, features = ["w3c", "secp256r1", "secp256k1"]`
  covers exactly those through `ssi::claims` while dropping the default
  extras the ruling never asked for (`rsa`, `ed25519`, `eip712`,
  `ripemd-160`). Verified in-graph: no `bbs`/`zkryptium`/`bls12` anywhere.
  Widening is a deliberate edit to `src/vc.rs` + the feature list, never a
  side effect.
- **Deliberately absent**: the `openid4vp`/`oid4vci-rs` git pins — that's
  VUL-2's *other* checkbox (version-locking the protocol libraries), not this
  one, and pinning unbuildable git deps has costs the Engineer may weigh
  differently.

`ssi` 0.16's MSRV is 1.87 — under our 1.88 floor, so no ruling was needed.

### F14. The OAuth split: storage stores bytes, the bridge does the sealing

The source's `AtprotoAuthStore` implemented jacquard's `ClientAuthStore`
*directly* over PostgreSQL, doing serialization, sealing and SQL in one type.
vulpes splits it:

- `OAuthStateStore` (core, no jacquard) — opaque byte blobs, six methods.
- `oauth::JacquardAuthStore<S>` — implements `ClientAuthStore` over any
  `OAuthStateStore`, and owns the JSON encoding and the sealing.
- `postgres::PgOAuthStateStore` — the SQL, and nothing else.

Two reasons: a storage backend can be written with no OAuth knowledge, and the
encryption exists in exactly one place, so a new backend cannot forget it. It
also keeps the feature graph simple — `postgres` alone compiles without
`jacquard`.

The AAD construction (table-name domain separation, the length-prefixed DID) is
carried over byte-for-byte.

### F33. `KeyStore` trades in sealed blobs, not plaintext (security review S7)

**Where:** `src/store.rs` (`KeyStore`), `src/keys.rs` (`SealedKeys`),
`src/postgres/key_store.rs`, `src/minter.rs`.

The extraction left one asymmetry: the OAuth store (F14) never saw a plaintext
secret, but the `KeyStore` took plaintext `CustodyKeys` and `PgKeyStore` did the
sealing — so a `KeyStore` implementation *could* write plaintext scalars, the
exact footgun F14 removed for tokens. Engineer ruled the reshape.

`KeyStore` now trades in `SealedKeys` — an opaque newtype over the AEAD
ciphertext plus its `CustodyEnvelope` version. The `Minter` (which now holds the
`SecretVault`) owns seal-before-put and open-after-get; `PgKeyStore` holds no
vault and never opens a blob, so a plaintext custody store is unrepresentable,
the same as a plaintext OAuth store. The H4 unknown-version rejection moved with
the opening — it now fires in the `Minter`, not the store. The on-disk columns
(`wrapped_keys`, `key_version`) and the sealed bytes are unchanged, so existing
rows are untouched.

Consumption impact: `Minter::new` gains a `vault` argument; `PgKeyStore::new`
drops its `vault` argument.

### F30. Operation-log integrity — HMAC (security review B2, Engineer ruled)

**Where:** `src/store.rs` (`op_mac`, `mac_message`), `src/vault.rs`
(`oplog_mac`), `src/minter.rs` (`maced` / `verify_mac`), migration
`20260809000004`.

`update_handle` reads the DID's latest logged operation and carries its
`rotationKeys`, `verificationMethods` and `services` forward into an operation it
then **signs**. Nothing authenticated that row, so whoever could write
`plc_operations` chose what the custody key signs — the signing oracle B2 named.
Of the candidate mitigations (HMAC column / verify the stored `sig` / re-derive
from custody), the **Engineer ruled HMAC**.

Each row carries an `op_mac`: HMAC-SHA256 over a length-prefixed
`(did, cid, prev, operation)`, keyed by a subkey HKDF-derived from the vault root
key (label `vulpes.oplog.mac.v1`) — a *dedicated* subkey, so the AEAD root key
stays single-purpose. The minter writes it on every append and **verifies it
before trusting a prior row** (in `carry_forward` and in `tombstone`, which reads
the prior for its `prev`). A row altered by a write-access attacker fails the tag
and is refused rather than signed. The operation is canonicalized (re-serialized
sorted-key JSON) so the tag survives the `jsonb` round-trip.

This is what H8's `check_prior_rotation_keys` is *not*: H8 is an availability
guard (a malformed-but-genuine row must not wedge the identity) that now runs
after the MAC has already established authenticity.

Fresh crate, so no backfill: `op_mac` is nullable and a NULL (a row from before
the column) reads back as an empty tag that fails verification — fail closed.
**Zurfur's adoption ticket owns backfilling its existing `plc_operations`
rows**; a fresh install never has any.

### F15. `Authenticator` is a struct, not a trait

The source implements its own `domain::ports::Authenticator` port. vulpes ships a
concrete `oauth::Authenticator` with `start`/`complete` and no trait — nothing
consumes it polymorphically here. A consumer implements its own port by
delegating, which is a three-line impl.

### F16. Collaborators are `Arc<dyn …>`, not `Box<dyn …>`

The source passes `Box<dyn PlcDirectory>`. `Arc` for all three of the minter's
collaborators means one minter can be shared and a test can hold a handle on the
fake it injected (which several tests need).

### F19. In-memory fakes are test-only

`MemoryKeyStore` / `MemoryPlcOperationLog` / `MemoryOAuthStateStore` exist under
`#[cfg(test)]`. Shipping them publicly (behind, say, a `testing` feature) would
help consumers whose own in-memory adapters must now implement vulpes's traits —
but that is a new feature, outside the approved map, so it is **offered, not
taken**.

### F24. Directory selection by config was left behind

`DirectoryConfig` / `plc_directory_from_config` are composition-root concerns.
vulpes ships `NoopPlcDirectory` and `HttpPlcDirectory::{new, canonical,
with_client}`; choosing between them from a config file is the application's job.

### F17 / F18. Deliberately not carried

- `StubDidMinter` — synthetic-DID test glue for the originating service, not a
  library concern.
- `tests/wipe_replay.rs` — despite being named in the brief, this test covers
  `AtprotoPublicRecords` and the `app.zurfur.feed.post` lexicon (records, not
  identity). Both are outside the approved feature map, so there is nothing here
  to port it against. The `auth_store` suite it was named alongside **is**
  ported, in `tests/postgres/oauth_bridge.rs`.
- Reserved-label namespaces, handle-change rate limiting and quarantine, the
  boot-time custody guard, login error-code contracts, session cookies, CSRF and
  user provisioning — all product policy, all left behind per the brief.

---

## Packaging

### F9. Table and column names are unchanged

`account_keys`, `plc_operations`, `atproto_oauth.client_session`,
`atproto_oauth.auth_request`, and every column, keep the source's names. A
`vulpes_` prefix was considered and **rejected**: the originating service already
has these tables and rows in them, and the shipped SQL must line up with what is
there or adoption means a data migration.

Consequence for other consumers: the names are unprefixed and could collide.
Documented rather than solved; making them configurable is not worth the
machinery.

The DDL is therefore plain `CREATE TABLE` / `CREATE SCHEMA`, not
`… IF NOT EXISTS`. With `IF NOT EXISTS` a collision would be recorded as a
successful migration that created nothing — after which vulpes reads and writes a
table it does not control and no later `migrate` ever creates the real one.
Each migration runs in a transaction, so the collision instead fails the call,
records nothing, and leaves the consumer's table untouched. Loud and recoverable
beats silent and permanent.

### F10. Three migrations, renumbered, with the fork index folded in

The source has four relevant migrations across two crates, one of which is a
follow-up adding the no-chain-fork index. vulpes ships three
(`20260809000001`–`3`), the fork index folded into the `plc_operations`
migration it belongs to — a fresh install has no reason to replay the history of
a fix.

Versions are fresh, not the source's, so a consumer embedding both sets does not
collide on the migration primary key.

### F11. Migrations are embedded by `build.rs`, not `sqlx::migrate!`

`sqlx::migrate!` lives behind sqlx's `macros` feature. Enabling it here would
turn it on for **every crate in a consumer's build** through feature
unification — and the originating service deliberately retired `macros` so that
reintroducing a compile-time query macro is a compile error by construction.
vulpes must not quietly re-arm that. `build.rs` generates the same
`(version, description, sql)` table the macro would, and `postgres::migrator()`
builds an identical `Migrator` with matching checksums, so a ledger written by
the sqlx CLI over the same files stays valid.

### F12. SQL lives in files; the codegen does not come along

The source generates typed query functions with `sqlx-rust-codegen`, a
tag-pinned build tool. Carrying that would make vulpes depend on the originating
project's toolchain. The convention it enforces is kept — every statement lives
in `queries/**.sql` and is `include_str!`-ed, so the SQL that runs is reviewable
as SQL — but the wrappers are hand-written.

### F20 / F21. Lockfile committed; publishing disabled in the manifest

`Cargo.lock` is committed and CI builds `--locked`, so a dependency cannot move
under the crate between a green run and a consumer's build. `publish = false`
enforces the no-crates.io ruling in the manifest rather than in a person's
memory.

### F25. Default features are `minter` + `directory`

The write path is the crate's reason to exist, so it is on by default;
`postgres`, `oauth` and `axum` pull heavy dependencies and are opt-in.
`--no-default-features` leaves the pure protocol core.

### F27 / F28. Small additions

- `key_version` is a `CustodyEnvelope` rather than an inlined literal, and is
  **read back**: `PgKeyStore::get` decodes the column and refuses a value it does
  not know instead of opening the blob under a guessed scheme. `V1` is the
  source's format (bare-DID associated data); `V2` — what vulpes writes — prefixes
  the associated data with `vulpes.custody\0`, domain-separating custody from
  every other family sealed under the same root key. **V1 rows still open**, so
  the originating service's existing `account_keys` are not stranded; they are
  simply never written again.
- `Did` and `Handle` are `Serialize`/`Deserialize` with `#[serde(transparent)]`,
  which the source's were not. Both are values that cross API boundaries;
  transparent means a DID is `"did:plc:…"` on the wire, never a tuple wrapper.
  **Both** `Deserialize` impls are hand-written and validating: a derived one
  would be `Did::new` with extra steps, so every JSON body and cached record
  could route around the grammar and the newtype would prove nothing about its
  contents. Deserialization is an untrusted boundary, so it parses. The wire
  shape is unchanged in both directions.

  For `Handle` this is load-bearing rather than tidy. `Authenticator::start`
  takes a `Handle` *instead of* a string specifically so jacquard's
  fetch-this-service-URL branch is unreachable (F29) — which is only true if
  every door into the type validates. A derived `Deserialize` would have handed
  back a `Handle` holding `https://169.254.169.254/…` straight from a JSON login
  body, the likeliest way a handle actually arrives, and walked it into the very
  fetch the type exists to prevent. Caught by cold review of the F29 change; the
  SSRF test now exercises both doors.

---

## Verified, not assumed

Recorded because the extraction turned three of them into enforced checks:

| fact | source |
|---|---|
| `rotationKeys` must hold 1–5 keys, no duplication | did:plc spec v0.1 — enforced in `MintPolicy::validate` |
| any listed rotation key may sign an operation | did:plc spec v0.1 — the preset signs with the lower-authority key on purpose |
| at most 10 `verificationMethods` per DID | did:plc spec v0.1 — enforced in `MintPolicy::validate` |
| a genesis `prev` is present with value `null`, not omitted | did:plc spec v0.1 — pinned by `genesis_prev_is_an_explicit_null` |
| DID = `base32(sha256(dag-cbor(signed op)))[..24]` | did:plc spec v0.1 — pinned to a published vector |
| signature = ECDSA-SHA256, low-S, 64-byte r‖s, base64url no-pad | did:plc spec v0.1 — asserted in the minter tests |
| `plc_tombstone` carries only `type`, `prev`, `sig` | did:plc spec v0.1 — pinned by `tombstone_shape_and_signing_bytes` |
| DID syntax ABNF (`method-name`, `method-specific-id`, `idchar`) | W3C DID Core — implemented in `<Did as FromStr>::from_str` |
