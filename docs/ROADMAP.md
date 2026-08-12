# Roadmap

The working plan, in dependency order. This file replaces per-ticket ceremony
(ruled 2026-08-12): each line gets elaborated in conversation when it's picked
up, rulings land in Confluence, finished work lands as PRs. The old VUL
tickets stay parked in Jira as historical detail.

## ACP v0.1 — the public lane (active)

Done when the **kill test** passes as an integration test: tear the attestor's
infrastructure down and every issued vouch still verifies.

- [x] **The lexicons** — the three record schemas under `net.got-paws.acp.*`
      (PR #5).
- [ ] **Record types in Rust** — `Claim` / `Attestation` / `Relationship`
      structs + canonical DAG-CBOR, so signing has stable bytes. Opens with
      one decision: wrap the ecosystem's `atproto-record` crate or hand-roll
      over our own deps. Fixtures pin exact bytes, including a *pre-image*
      fixture (the injected `$sig` binding).
- [ ] **Sign & verify** — the crypto heart. Pre-image = record minus `sig`
      plus the injected `{$type, repository}`; repository DID is an explicit
      parameter (fetch context, never read from the record). Negative tests
      carry it: tamper, wrong key, expired, algorithm confusion, and the
      mandatory **transplant test**. Security-nature: adversarial review
      before merge.
- [ ] **Talk to a PDS** — record create/get/list/delete over XRPC, strongRef
      fetch-and-check, local PDS in Docker as the test bed.
- [ ] **`verify_attestation` end-to-end** — the spec's 7 steps as one public
      function + mutual-claim verification. Contains the **`kill_test`**.
- [ ] **The first attestor** — email challenge → sign → deliver; Kit's story
      from the explainer running against the local PDS.
- [ ] **Expiry & renewal** — per-kind lifetimes, the auto-renew loop
      (re-runs diligence), human vouches never auto-renew, the
      strand-on-attestor-death test.
- [ ] **CCS relationship pairs** — write / sever / verify both halves.
      ⚠ Rule the **"unanswered half"** fork first (a public first-half names
      a counterpart who never agreed; commitment-first is the candidate fix).

## Owed, non-blocking

- [ ] DNS `_lexicon` TXT on `acp.got-paws.net` → the schema-hosting repo's
      DID (needs Zuri's DNS panel; publication, not correctness).
- [ ] Spec sentence: `attestor == subject` is valid, adds recency +
      exportability, adds no trust (ruled in conversation 2026-08-12).

## Later (in rough order)

- **The Holder / aggregation layer** (old VUL-1 epic: entity, identity-kind
  catalog, two-signature linking, private Index store, security review) —
  Index-side, independent of the ACP lane.
- **Zurfur consumes the ACP** — first external consumer; the crate-swap
  ticket (ZMVP, FORKS F9) and characters-on-ATProto (ZMVP-197).
- **The private lane** — holder-held VC/OID4VP for claims whose existence is
  private; Path A (BBS) vs Path B (SD-JWT-VC) decided then. The old VUL-2
  scaffolding re-scopes here.
- **Active + permanent vouch modes** — additive; taxonomy parked on The
  Claims Model page.
- **Soft/hard freshness dial** — verifier-chosen max status age; parked.
- **Announcement** — the manifesto ships publicly once the reference
  implementation demos Kit's story.
