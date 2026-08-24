# Roadmap

The working plan, in dependency order. This file replaces per-ticket ceremony
(ruled 2026-08-12): each line gets elaborated in conversation when it's picked
up, rulings land in Confluence, finished work lands as PRs. The old VUL
tickets stay parked in Jira as historical detail.

## ACP v0.1 — the public lane (active)

Done when the **kill test** passes as an integration test: tear the attestor's
infrastructure down and every issued vouch still verifies.

- [x] **The lexicons** — the record schemas under `net.got-paws.acp.*`
      (PR #5; the `relationship` schema was retired by F45, PR #17).
- [x] **Record types in Rust** — `Claim` / `Attestation` structs +
      canonical DAG-CBOR, so signing has stable bytes. Decided:
      hand-rolled over our own deps (FORKS F37). Fixtures pin exact bytes,
      including the *pre-image* fixture, cross-checked against an independent
      encoder (`src/acp/record.rs`).
- [x] **Sign & verify** — the crypto heart. Pre-image = record minus `sig`
      plus the injected `{$type, repository}`; repository DID is an explicit
      parameter (fetch context, never read from the record); the key signs
      the pre-image's CID (FORKS F36). Built in `src/acp/sign.rs` with the
      negative tests: tamper, wrong key, algorithm confusion, high-S, and the
      mandatory **transplant test** (`expired` belongs to
      `verify_attestation`). Adversarially reviewed 2026-08-21/22 (three
      security passes + Copilot, PR #10): F36 CID-first binding, algorithm
      confusion, high-S and the transplant defense all held.
- [ ] **Talk to a PDS** — record create/get/list/delete over XRPC, strongRef
      fetch-and-check, local PDS in Docker as the test bed. Now concretely:
      jacquard-backed `RepoReader` / `DidResolver` / `StatusSource` (and a
      `RepoWriter`), the `$bytes` JSON↔DAG-CBOR boundary, and the kill test
      re-run against the container. The HTTP `StatusSource` meets FORKS
      F42: redirects off · resolve A/AAAA and refuse non-global addresses at
      connect time · injected egress-guarded client · response capped at
      `MAX_STATUS_LIST_BYTES` · at most `MAX_STATUS_COPIES` copies returned.
      The `DidResolver` reads rotation keys from `/data` in directory order.
- [x] **`verify_attestation` end-to-end** — the spec's 7 steps as one public
      function (+ mutual-claim verification, retired by F45), over three ports (`RepoReader`,
      `DidResolver`, `StatusSource`; FORKS F40) with the status-list
      artifact (F39) and `TrustPolicy`. Contains the **`kill_test`** —
      passing against in-memory fakes; it re-runs against the Docker PDS
      when "Talk to a PDS" lands.
      **Ship-gates review 2026-08-21** (security, code, critique) landed:
      judgment before the status fetch + `StatusUri` (SSRF), signed `list`
      identifier on status lists, ownership key control against a
      policy-named custodian set (F40, ruled 2026-08-22 after research —
      co-ownership falls out of it), claim-in-subject-repo,
      canonical-bytes check at step 4, policy-set status-age bound,
      `did:key` panic guard, calendar-checked `Datetime`,
      order-independent counterpart search, `BasicPolicy::default()`
      checks revocation — and bounds that status age at 30 days
      (F43, ruled 2026-08-22), which retires the soft/hard freshness dial.
- [ ] **The first attestor** — email challenge → sign → deliver; Kit's story
      from the explainer running against the local PDS.
- [ ] **Expiry & renewal** — per-kind lifetimes, the auto-renew loop
      (re-runs diligence), human vouches never auto-renew, the
      strand-on-attestor-death test.
- [ ] **CCS as attestations** (FORKS F45, ruled 2026-08-22), in order:
      - [x] delete the relationship path — `Relationship`, `RelKind`,
            `verify_relationship`, the counterpart search, the
            `relationship` lexicon, `TrustPolicy::custodian_keys` (PR #17).
      - [ ] `acp::custody` — the seniority check and custodian discovery as
            pure helpers a consumer calls after an ownership-class
            attestation verifies. Until it lands no seniority check exists
            in the crate; the previous check and its adversarial tests are
            recoverable from `7045189^`.
      - [x] `ClaimKind::parse` for five-segment NSIDs and the two v0.1
            categories (`identity`, `relationship`; `consent` deferred);
            lexicon `kind` → `format: nsid`.
      - [ ] define `relationship.ownership` and `relationship.membership`
            (roles, who claims, who attests).
      - [ ] the consumer pattern — verify, then check seniority — in the
            explainer.
      The "unanswered half" fork is dissolved: an unattested claim is a claim.
- [ ] **Mint layout D** (FORKS F46) — `MintPolicy` mints
      `[user_cold, vulpes_recovery, zurfur_operational]` by default, offers
      E, refuses F/G; the user key is generated client-side.

## Owed, non-blocking

- [ ] DNS `_lexicon` TXT on `acp.got-paws.net` → the schema-hosting repo's
      DID (needs Zuri's DNS panel; publication, not correctness).
- [ ] Spec sentence: `attestor == subject` is valid, adds recency +
      exportability, adds no trust (ruled in conversation 2026-08-12). Now
      load-bearing: it is also the answer to self-ownership (F45).
- [ ] Confluence Ruling Record (49184769): record F45 (CCS is attestations)
      and F46 (rotation layout D) — they supersede the 2026-08-11
      `owns ↔ ownedBy + keys` shape.

## Later (in rough order)

- **The Holder / aggregation layer** (old VUL-1 epic: entity, identity-kind
  catalog, two-signature linking, private Index store, security review) —
  Index-side, independent of the ACP lane.
- **Zurfur consumes the ACP** — first external consumer; the crate-swap
  ticket (ZMVP, FORKS F9) and characters-on-ATProto (ZMVP-197). Includes
  the ownership pattern: verify the `owns` attestation, then the seniority
  helper against a complete custodian set.
- **PLC-log watcher** (Zurfur-side) — alert a user to any operation on
  their DID they did not initiate, inside the 72 h window. The window is
  did:plc's; detection is the lever (F46).
- **The private lane** — holder-held VC/OID4VP for claims whose existence is
  private; Path A (BBS) vs Path B (SD-JWT-VC) decided then. The old VUL-2
  scaffolding re-scopes here.
- **Active + permanent vouch modes** — additive; taxonomy parked on The
  Claims Model page.
- **Announcement** — the manifesto ships publicly once the reference
  implementation demos Kit's story.
