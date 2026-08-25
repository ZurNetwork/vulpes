# Vulpes — continue here (updated 2026-08-25, `acp::custody` landed)

## 2026-08-25: `acp::custody` — the administration lane's helpers

`src/acp/custody.rs`: `CustodianKeys` (`empty` / `from_keys` /
`discover` — F44's live intersection over the `DidResolver`),
`holds_senior_rotation_key` (the F40 rule, recovered from `7045189^` with
its adversarial tests), and `inspect` → `CustodyReport` for the ccs.md
handover checklist. `verify.rs` gains
`ownership_verdict_never_consults_custody` — F47 as a test. Next roadmap
line: the kind definitions (ownership, membership, owner roster).

---

## 2026-08-23/24: F47 — administration and claims are two lanes

Ruled in conversation and recorded (FORKS F47; `docs/acp.md` §Relationships
are attestations + changelog 2026-08-23; `docs/ccs.md` reshaped):

- **Ownership is claims-only** — claim + counterpart attestation, two
  facts; rotation-key seniority is the administration lane, and
  `acp::custody` becomes an optional due-diligence helper, never a gate.
- **One ownership edge per subject**; multi-human characters are
  account-owned with a character-claimed **owner roster** (each human
  attests their entry; roster ≠ account membership).
- **Rules of Claims** adopted (acp.md changelog has the list); direction
  pinned: owner claims / character attests; roster: character claims /
  humans attest.
- **Severance never waits on the calendar** — relationship-category
  attestations must carry `status`; expiry is lifetime, not exit.
- Status-list residence stated (control = signature, hosting = nothing);
  the `list`-identifier sub-fork deferred to "The first attestor"; TSL
  library earmarked for the private lane, own wheel on the public lane.

The bitmap/status-list design was stress-tested against prior art (W3C
Bitstring REC, IETF TSL/EUDI, OCSP retirement) and held unchanged.
Next code work: `acp::custody` (now administrative-health), then the
kind definitions (ownership, membership, owner roster).

---

## 2026-08-22: the ACP core is on `main` (PR #10, `dc8be4c`)

`src/acp/` — records with canonical DAG-CBOR, CID-first signing, the
status-list artifact, three ports, `TrustPolicy`, `verify_attestation` +
`verify_relationship`, the kill test (in-memory). Roadmap lines 2, 3 and 5
are ticked. Ship-gates ran (security · code · critique · document · Copilot
×4) and five fix rounds landed on the same branch — **too big for one PR;
Zuri's standing feedback is smaller PRs from here on.**

Rulings made during review, all recorded:
- **F40 amended** — ownership key control = the owner holds a rotation key
  senior to every *policy-named* custodian key (`TrustPolicy::custodian_keys`).
  Researched: did:plc allows key reuse across DIDs; Bluesky `createAccount`
  puts the user key first, `goat` appends last — so public data alone can't
  say who holds a key. Co-ownership falls out of the rule.
  **Superseded by F45 the same day**: key control leaves the verifier.
  `TrustPolicy::custodian_keys` is retired (PR #17); the seniority check
  becomes an `acp::custody` helper the consumer calls after an ownership
  attestation verifies. The research stands, the location moved.
- **F39 amended** — the signed status-list body carries `list` (its
  identifier; IETF Token Status List `sub` precedent) and an optional `ttl`.
- **F42 (new)** — status fetch contract: judgment before the fetch, `StatusUri`
  syntactic at decode + `fetchable()` before I/O, HTTP source MUST disable
  redirects and resolve-then-refuse non-global addresses.
- `docs/acp.md` §Verification: steps 6/7 swapped; step 1 pre-checks the
  claim URI's authority; changelog 2026-08-21 + 22.

Open, from the review — Zuri's calls, none blocking:
- `StatusUri` accepts punycode; `Handle` rejects it.
- Features matrix prints dead-code warnings for `src/memory.rs` fakes under
  some combos (`cargo check` only).

Ruled since, all 2026-08-22 — three more of that list, now closed:
- **F43** — `max_status_age_secs` is `Some(30 days)` in
  `BasicPolicy::default()`; `permissive()` is the explicit `None`. A
  withheld fresh copy reaches `StatusStale`, never "not revoked", and the
  attestor's signed `ttl` still wins when tighter (PR #14). This is the
  soft/hard freshness dial, ruled at the hard end.
- **F44** — vulpes ships no operator's rotation keys, so bsky.social's never
  become a constant. A verifier names two or more unrelated accounts on a
  host; the keys common to all of them are the operator's, resolved live
  through the `DidResolver`. PR #15 was closed and the helper moves to
  `acp::custody` under F45 — the ruling stands, its home changed.
- **F45** dissolves self-ownership: `attestor == subject` is valid and adds
  no trust (ruled 2026-08-12), and key control leaves the verifier
  altogether, so there is no trivial pass left to worry about.

**Same day, later (PR #16, `4268ab1`): the boundary ruling.** Vulpes
issues and verifies attestations and never decides what a claim means
(FORKS F45). CCS is claims + counterpart attestations; the relationship
record/verifier path is retired in code PRs that follow; ownership =
attestation + consumer-checked seniority (`acp::custody` helpers to come);
claim kinds are five-segment NSIDs with two v0.1 categories (`identity`,
`relationship`; `consent` deferred behind takedown requests); rotation
layout D `[user, vulpes, zurfur]` is the minted default, user key
client-generated (F46). Code PRs, with what has landed: drop relationships
(PR #17, merged) → `ClaimKind::parse` + lexicon `format: nsid` (PR #18,
merged) → **`acp::custody`** (next; until it lands no seniority check
exists in the crate, and the old one is recoverable from `7045189^`) →
define `relationship.ownership` / `.membership` → mint layout D.

Next roadmap line after those: **Talk to a PDS** — jacquard-backed ports, the `$bytes`
boundary, the Docker PDS, and the kill test re-run against it. The HTTP
`StatusSource` checklist is on the roadmap line (F42).

Local: the Postgres suite needs the host rebooted into the 7.1.8 kernel
(no `bridge` module under 7.1.5); CI covers it meanwhile.

---


Pick-up note. The 2026-08-11 pivot (decentralization first-class, NQ1 reopened →
holder-held, three-layer role, broker→toolkit, atproto public/private boundary)
**is now recorded** — a fork session ("Character Creation and Ownership in
Zurfur") executed the doc updates and extended the design. Delta below.

---

## Recorded since the last handoff (by the fork — Engineer-ruled)

- **NQ1 formally REOPENED → holder-held**; pivot recorded in
  `docs/identity-model.md` and Confluence.
- **Characters become ATProto subjects**: one did:plc per character, "character"
  is a new in-code identity kind (NQ3 catalog). Default public; private
  characters live in the Index only. Post-alpha (ZMVP-197).
- **Consensual Claims System (CCS)** named: a relationship between two DIDs
  exists iff BOTH assert it (bidirectional record pair, one in each repo);
  authority partitioned per side; unilateral severance; ownership-tier adds key
  control as a third fact. Complement to labels (unilateral broadcast → mutual
  handshake). First instances: character ownership, Account↔User membership,
  gallery consent. Spec task: VUL-8.
- **Public ownership is atproto-native — NO VC stack**: owner repo `owns` ↔
  character repo `ownedBy` + owner holds the character's rotation keys.
  Transfer = PLC key rotation + record swap, final after the ~72h plc recovery
  window.
- **Hard rules pinned**: senior-key custody rule (owner always holds
  equal-or-senior rotation key vs any custodian) + routine CAR export/mirroring.
  Kill tests pass for Vulpes dying and Zurfur dying.
- **T1 now "resolved structurally"** (Vulpes out of the disclosure loop).
- **Superseded 2026-08-22 by F45** — the CCS and public-ownership bullets
  above: there is no bidirectional record pair, no `owns` ↔ `ownedBy`. A
  relationship is one claim in the claimant's repo, attested by the
  counterpart, under a single kind (`…relationship.ownership`) whose
  payload carries the `role`. Ownership's third fact — the owner senior on
  the character's rotation list — is checked by the consumer, not the
  verifier. Everything else in this section stands.

## RULED 2026-08-11: public-and-linkable first; private lane is roadmap

The Path A/B fork is **deferred, no longer blocking**. Phase 1 ships the
**public lane only** (atproto-native): did:plc anchor + custody, the
Holder/aggregation model, public claims as PDS records/labels, CCS, atproto
OAuth. The private disclosure lane (holder-held VC/OID4VP, Path A BBS vs
Path B SD-JWT-VC) moves to the roadmap and is decided when it's built —
BBS maturity may settle it by then.

Guardrails the ruling carries:

- **The invariant survives**: public-first means public *disclosure* first.
  The aggregation graph (persona↔persona links) stays in the private Index
  from day one and is never published; there's just no cryptographic
  disclosure lane for private claims yet.
- **Don't preclude** (same caveat as T1): claims stay modeled as a
  VCDM-2.0-shaped envelope and the pipes format-agnostic, so the private
  lane bolts on later without reshaping the Holder↔RP contract.

## The prior-art session (2026-08-11 late, via Claude Web — recorded in the Ruling Record)

- **RULED: `$sig` repository binding** — attestation pre-image injects a
  never-stored `{$type, repository}` object; `repository` = DID of the repo
  the record was *retrieved from*, never read from the record. Transplant
  defense becomes unrepresentable; `subject` re-rationalized as export
  self-containment; transplant negative test mandatory. **Spec edit applied
  2026-08-12** (`docs/acp.md` §Signing/§Verification/§Privacy).
- **RULED 2026-08-12: v0.1 is passive-mode only.** Active and permanent are
  additive modes, deferred — the taxonomy's details stay parked on The
  Claims Model page. The soft/hard freshness dial (hard = soft +
  verifier-chosen max status age) was parked here; **ruled 2026-08-22 by
  F43** — the hard end is the default, bounded at 30 days.
- **OPEN**: CCS clean rejection (the unanswered half is public + squattable;
  two-phase content-commitment pattern is the candidate fix — on the CCS
  page). Gerakines-spec interop posture set, contact parked (his remote
  pattern fails the kill test; read attested.network + full spec first).
- **Consume, don't rebuild**: `atproto-record`, `-client`, `-identity`,
  `-jetstream` crates (MIT) cover record I/O / DAG-CBOR / TID / resolution —
  relevant to VUL-11 and VUL-13; the attestation CLIs double as byte-stability
  cross-checks for VUL-11's fixtures.

## Open / owed

- ~~PR for `docs/ccs-and-characters`~~ — opened and merged as PR #2.
- **Record the public-first ruling** (above) in `identity-model.md` + the
  Confluence Ruling Record (49184769); reframe the future disclosure epic as
  roadmap.
- **Gallery partial-consent policy** on multi-character pieces — parked until
  gallery work.
- T2 (does storing a claim need Holder consent?) — still open from the
  interview.

---

## Pointers

- **Repo**: github.com/ZurNetwork/vulpes · local `~/code/vulpes` · `v0.1.0` at
  `e133a7b` · design doc `bebcbb0` · pivot docs `ff5cfad` (branch
  `docs/ccs-and-characters`, worktree `worktree-docs-ccs-and-characters`).
- **The standard**: `docs/acp.md` — the **Attested Claims Protocol** (ACP),
  spec draft v0.1 on the did:plc template (concrete lexicons, verification
  algorithm, conformance classes, trust model, privacy/security, changelog).
  Vulpes is its reference implementation. Core rule: "Vulpes dying is an
  inconvenience, not a breaking factor" (the kill test). Lexicon namespace
  RULED 2026-08-12: `net.got-paws.acp.*` (`got-paws.net`, Zuri's domain,
  deliberately attestor-rank). DNS `_lexicon` publication owed later.
  Overlaps VUL-8 (CCS spec) — the
  relationship record shape lives here, full semantics in `docs/ccs.md`.
- **The manifesto**: `docs/manifesto.md` — Zuri's grievance essay (Telegram
  ban story, conectes, the inconvenience/breaking-factor pledge). DONE.
- **The explainer**: `docs/explainer.md` — worked example (Kit's email
  claim), diffs vs labels/VCs/OAuth/JWT, FAQ. Bridge between manifesto and
  spec.
- **Working contract**: Zuri is lead stakeholder AND lead coder on
  Vulpes/ACP; Claude guides and drafts, Zuri calls the shots (memory:
  `zuri-leads-vulpes-acp`). Next layer: reference implementation, Zuri-led.
- **Design log**: `docs/identity-model.md` (NQ1 REOPENED marker + pivot section).
- **New docs**: `docs/ccs.md`, `docs/characters-atproto.md` (on the branch).
- **Confluence VU**: Welcome/48922733, Preface/48922883, Introduction/48988161
  (de-brokered), Justification/49020929, The Claims Model/49086467,
  Moderation—Keycard/49152001, Ruling Record/49184769 (pivot recorded),
  **Vulpes and ATProto — the public/private boundary/49446913**,
  **The Consensual Claims System/49479681**,
  **The Attested Claims Protocol (ACP)/49905665** (pointer page; source of
  truth for the standard is the repo's `docs/`). Ruling Record + Introduction
  updated 2026-08-11 night (ACP named, public-first, attestation custody,
  expiry/renewal doctrine).
- **Tickets RETIRED for Vulpes (ruled 2026-08-12)**: too much ceremony for a
  solo conversational project. The plan lives in **`docs/ROADMAP.md`**
  (ordered checklist; elaborate each line in conversation when picked up).
  Confluence stays (rulings pay rent); PRs are the work record. Jira project
  VUL stays parked as history — epic VUL-1 (Holder/aggregation, Index-side),
  VUL-2..8, epic VUL-9 with VUL-10 (Done, PR #5) and VUL-11..17 (superseded
  by the roadmap). ZMVP-197 (Characters on ATProto) is Zurfur's, unaffected.
- **Memory**: `project_vulpes_library.md`.

## Parked (non-Vulpes — don't lose)

- **Zurfur Phase-1 crate-swap ticket** (ZMVP) — thin `adapter-atproto`
  delegating to the `vulpes` crate; near-zero diff (FORKS F9), needs the
  `op_mac` backfill. Owed, ready to carve.
- **PR #174** (Zurfur — delete stale React auth) — was open, CI green, awaiting
  merge.
- **ZMVP-163 fork sheet** (13 items) — parked when Vulpes took over.
- **Dead ZesTTY bookmarks** (`feature/zmvp-176/-177/-183`) — delete pending.
- **164 worktree/branch cleanup** — three git commands were permission-blocked.
