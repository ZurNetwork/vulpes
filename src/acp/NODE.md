---
path: src/acp
charted: 2026-08-21
fs:
  - name: record.rs
    role: `Claim` / `Attestation` / `Relationship` + canonical DAG-CBOR, pinned byte fixtures (F37)
    node: false
  - name: sign.rs
    role: pre-image (record − sig + injected `{$type, repository}`) → CID → sign/verify; negative tests incl. transplant (F36)
    node: false
  - name: verify.rs
    role: `verify_attestation` (spec's 7 steps) + `verify_relationship`; holds the `kill_test`
    node: false
  - name: ports.rs
    role: `RepoReader` / `DidResolver` / `StatusSource` — async, object-safe (F40)
    node: false
  - name: status.rs
    role: `net.got-paws.acp.statusList` — signed static mirrorable artifact (F39)
    node: false
  - name: policy.rs
    role: `TrustPolicy` — step 7, the verifier's own judgment
    node: false
  - name: error.rs
    role: closed error enums, one per concern (F1)
    node: false
  - name: memory.rs
    role: in-memory port fakes, test-only
    node: false
---
**Is:** the ACP reference implementation — pure (no I/O, no resolution); everything external comes through the three ports.

**Conventions:** field names follow `lexicons/` exactly; the repository DID is always an explicit parameter, never read from the record; `expired` is judged in `verify_attestation`, not `sign.rs`; fixtures pin exact bytes and are cross-checked against an independent encoder.

**Entry points:** `../acp.rs` (module docs), then `verify.rs` for the whole flow.

**Refs:** docs/acp.md (§Record types, §Signing, §Verification, §The kill test) · docs/ROADMAP.md "ACP v0.1" · FORKS F36–F41.
