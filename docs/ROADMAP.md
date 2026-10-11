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
- [ ] **vulpes is a pure ACP library** (FORKS F49, ruled 2026-10-01) — it
      enforces the ACP; the consumer owns storage, transport and
      randomness. In order:
      - [x] `advisories` green on `main` (rustls 0.23.45, chacha20 0.10.2,
            clear_on_drop allow-listed until `vc` leaves), so the NODE.json
            migration could land first.
      - [ ] cut the non-ACP shells — `oauth`, `axum`, `vc`, `broker`, the
            reqwest `HttpPlcDirectory` (the `PlcDirectory` trait stays).
      - [ ] cut Postgres — the sqlx stores, `migrations/`, `queries/`,
            `build.rs`, the testcontainers suite; the F35 reorder-on-read
            case moves to a minter unit test.
      - [ ] randomness from the caller — `rng: &mut impl CryptoRngCore` on
            `SecretVault::seal`, `CustodyKeys::seal{,_current}`,
            `Minter::mint`; no RNG of vulpes' own left to reach for.
- [ ] **Talk to a PDS** — re-scoped by F49: vulpes owns the ports
      (`RepoReader` / `DidResolver` / `StatusSource`, F40; a `RepoWriter`
      when a writer needs one) and the `$bytes` JSON↔DAG-CBOR boundary
      they hand across. The jacquard-backed implementations and the Docker
      PDS test bed are Zurfur's (see "Zurfur consumes the ACP"). F42 binds
      whoever implements `StatusSource`: redirects off · resolve A/AAAA and
      refuse non-global addresses at connect time · injected egress-guarded
      client · response capped at `MAX_STATUS_LIST_BYTES` · at most
      `MAX_STATUS_COPIES` copies returned. A `DidResolver` reads rotation
      keys from `/data` in directory order.
- [x] **`verify_attestation` end-to-end** — the spec's 7 steps as one public
      function (+ mutual-claim verification, retired by F45), over three ports (`RepoReader`,
      `DidResolver`, `StatusSource`; FORKS F40) with the status-list
      artifact (F39) and `TrustPolicy`. Contains the **`kill_test`** —
      passing against in-memory fakes, which is where it stays (F49); the
      run against a real PDS is Zurfur's integration suite.
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
- [ ] **Expiry & renewal** — per-kind lifetimes, human vouches never
      auto-renew, the strand-on-attestor-death test. The auto-renew loop
      (re-runs diligence) is a service, so it is Zurfur's (F49).
- [ ] **CCS as attestations** (FORKS F45, ruled 2026-08-22; lanes
      separated by F47, 2026-08-23), in order:
      - [x] delete the relationship path — `Relationship`, `RelKind`,
            `verify_relationship`, the counterpart search, the
            `relationship` lexicon, `TrustPolicy::custodian_keys` (PR #17).
      - [x] `acp::custody` — the seniority check and custodian discovery
            as pure **administrative-health** helpers (F47: due diligence,
            never an ownership gate): `CustodianKeys::discover` (F44),
            `holds_senior_rotation_key`, `inspect` → `CustodyReport`; the
            F40 adversarial tests recovered, plus the verifier-side
            invariant test that an ownership verdict never consults it.
      - [x] `ClaimKind::parse` for five-segment NSIDs and the two v0.1
            categories (`identity`, `relationship`; `consent` deferred);
            lexicon `kind` → `format: nsid`.
      - [x] **F48 ruled and recorded** (2026-08-25): consent has four
            shapes; paired claims recommended; the edge `id`; witnesses
            as embedded signatures; the verdict is a report; `expiresAt`
            required, permanent mode retired; the roster kind dropped.
      - [ ] the claim record catches up with F48 — `Claim` gains `id`,
            `nonce`, `claimant`, `expiresAt`, `status`, `witnesses`;
            `edge_id()`; the claim pre-image + witness signing in
            `sign.rs`; **fixtures bump** (canonical bytes change).
      - [ ] paired verification + the report — `verify_claim` (any
            shape), `verify_pair`, `Report` replacing the bare verdict
            for consumers; the four-shapes tests; kill test re-run.
      - [ ] kind definitions as lexicon schema records —
            `relationship.ownership` (paired, one edge, roster = N
            halves), `relationship.membership` (paired, `grant`).
      - [ ] the consumer pattern — verify, read the report;
            `acp::custody` as buyer's due diligence — in the explainer.
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
- [ ] Confluence Ruling Record (49184769): record F45 (CCS is attestations),
      F46 (rotation layout D), F47 (two lanes; claims-only ownership;
      Rules of Claims), F48 (four shapes; paired claims; the edge id;
      witnesses) and F49 (pure ACP library) — F45–F48 supersede the
      2026-08-11 `owns ↔ ownedBy + keys` shape.

## Later (in rough order)

- **The Holder / aggregation layer** (old VUL-1 epic: entity, identity-kind
  catalog, two-signature linking, private Index store, security review) —
  Index-side, independent of the ACP lane.
- **Zurfur consumes the ACP** — first external consumer; the crate-swap
  ticket (ZMVP, FORKS F9) and characters-on-ATProto (ZMVP-197). Includes
  the ownership pattern (F47): verify the ownership attestation — the
  whole verdict — with `acp::custody` as due diligence where stakes
  demand it. Since F49 it also carries what a library can't: the
  jacquard-backed ports and the Docker PDS test bed (the kill test re-run
  against a real PDS); **the first attestor** — email challenge → sign →
  deliver, Kit's story end to end — which decides the deferred sub-fork
  (F47): the `list` identifier the reference tooling mints (baked into
  every signed attestation, so it must outlive hosts); and the auto-renew
  loop.
- **PLC-log watcher** (Zurfur-side) — alert a user to any operation on
  their DID they did not initiate, inside the 72 h window. The window is
  did:plc's; detection is the lever (F46).
- **The private lane** — holder-held VC/OID4VP for claims whose existence is
  private; Path A (BBS) vs Path B (SD-JWT-VC) decided then. The old VUL-2
  scaffolding (`vc`, `broker`) was removed by F49; the lane starts from its
  ruling, not from that wrap.
- **Active + permanent vouch modes** — additive; taxonomy parked on The
  Claims Model page.
- **Announcement** — the manifesto ships publicly once the reference
  implementation demos Kit's story.
