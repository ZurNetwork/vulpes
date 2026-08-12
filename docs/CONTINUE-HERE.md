# Vulpes — continue here (updated 2026-08-11, post-fork sync)

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
  verifier-chosen max status age) also remains parked, unruled.
- **OPEN**: CCS clean rejection (the unanswered half is public + squattable;
  two-phase content-commitment pattern is the candidate fix — on the CCS
  page). Gerakines-spec interop posture set, contact parked (his remote
  pattern fails the kill test; read attested.network + full spec first).
- **Consume, don't rebuild**: `atproto-record`, `-client`, `-identity`,
  `-jetstream` crates (MIT) cover record I/O / DAG-CBOR / TID / resolution —
  relevant to VUL-11 and VUL-13; the attestation CLIs double as byte-stability
  cross-checks for VUL-11's fixtures.

## Open / owed

- **PR for `docs/ccs-and-characters`** (commit `ff5cfad`, pushed) — not opened yet.
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
- **Jira**: epic VUL-1 (Holder/aggregation — stands unchanged, Index-side),
  VUL-2..VUL-7, **VUL-8** (CCS spec), **ZMVP-197** (Characters on ATProto,
  post-alpha). **NEW epic VUL-9 — "ACP v0.1: the public lane"** with
  VUL-10..17 in dependency order (lexicons → Rust types/DAG-CBOR → sign/verify
  → PDS I/O → verify_attestation + kill_test → email attestor → expiry/renewal
  → CCS pairs), written for Zuri-as-coder (each has "Done when" + "You'll
  learn"). VUL-2's ssi/OID4VP wrap is private-lane roadmap now — left
  untouched, re-scope when the lane ships.
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
