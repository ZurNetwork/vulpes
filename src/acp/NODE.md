---
path: src/acp
charted: 2026-08-21
fs:
  - name: record.rs
    role: Claim / Attestation + canonical DAG-CBOR, pinned byte fixtures (F37, F38)
    node: false
  - name: sign.rs
    role: attestation pre-image, sign, verify — key signs the pre-image CID (F36); negatives incl. transplant
    node: false
  - name: verify.rs
    role: verify_attestation — the spec's seven steps; mutual-claim verify (senior-rotation-key rule); the kill_test
    node: false
  - name: ports.rs
    role: RepoReader / DidResolver / StatusSource async_trait ports (F40)
    node: false
  - name: status.rs
    role: net.got-paws.acp.statusList artifact, ACP-native DAG-CBOR (F39)
    node: false
  - name: policy.rs
    role: TrustPolicy — step 6, the verifier's judgment, ahead of the status fetch it gates
    node: false
  - name: error.rs
    role: one closed enum per concern
    node: false
  - name: memory.rs
    role: in-memory port fakes, test-only (F19)
    node: false
---
**Is:** the ACP reference implementation, pure and I/O-free — everything a verifier needs except the transport, which arrives through the three ports.

**Conventions:** the repository DID is always an explicit parameter, never read from a record. Canonical bytes are pinned by fixtures cross-checked against an independent encoder. The attestor is *not* a port — its death must not matter (the kill test).

**Entry points:** `verify.rs::verify_attestation`, then `sign.rs`, then `record.rs`.

**Refs:** `docs/acp.md` §Record types, §Status lists, §Verification, §The kill test; `docs/ROADMAP.md` "ACP v0.1"; FORKS F36–F41.
