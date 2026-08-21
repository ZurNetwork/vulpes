---
path: src
charted: 2026-08-21
fs:
  - name: lib.rs
    role: crate root — docs, module map, feature gates, re-exports
    node: false
  - name: acp/
    role: the ACP core (feature `acp`) — records, sign/verify, ports, status lists, policy
    node: true
  - name: acp.rs
    role: `pub mod acp` root + module docs
    node: false
  - name: plc.rs
    role: did:plc operations — build/sign/hash, byte-exact (pub always)
    node: false
  - name: minter.rs
    role: `Minter` — mint / update-handle / tombstone (feature `minter`)
    node: false
  - name: directory.rs
    role: HTTP submit to a PLC directory (feature `directory`)
    node: false
  - name: keys.rs
    role: `CustodyKeys` — roles + sealed on-disk form
    node: false
  - name: vault.rs
    role: `SecretVault` — envelope encryption under a root key
    node: false
  - name: store.rs
    role: the three storage traits + op-log record shape
    node: false
  - name: policy.rs
    role: `MintPolicy` — genesis-op choices as data
    node: false
  - name: did.rs
    role: `Did` newtype
    node: false
  - name: handle.rs
    role: `Handle` — validated, normalized
    node: false
  - name: error.rs
    role: the two open error types (implementor-produced)
    node: false
  - name: memory.rs
    role: in-memory storage fakes, `#[cfg(test)]` only (F19)
    node: false
  - name: broker.rs
    role: empty toolkit skeleton (VUL-2) — private lane lands here later
    node: false
  - name: vc.rs
    role: wrapped SpruceID `ssi` stack (feature `vc`), unused by the public lane (F34)
    node: false
  - name: oauth/
    role: atproto OAuth via jacquard (feature `oauth`) — mod.rs authenticator, store.rs `JacquardAuthStore` bridge (F14)
    node: false
  - name: postgres/
    role: sqlx impls of every storage trait (feature `postgres`)
    node: true
  - name: axum.rs
    role: `/.well-known/atproto-did` router (feature `axum`)
    node: false
---
**Is:** the crate body — a pure protocol core (`plc`, `did`, `handle`, `store` traits) with I/O, crypto, storage, and the ACP each behind a feature.

**Conventions:** private modules by default, `pub` only for `plc` and feature-gated surfaces; collaborators are `Arc<dyn …>` (F16); in-memory fakes are test-only (F19); stores trade in sealed blobs, never plaintext (F33); every file opens with a `//!` header that explains its place — read those first.

**Entry points:** `lib.rs` lines 86–131 (module map), then the target module's `//!` header.

**Refs:** FORKS.md §Module layout (F14–F35) · docs/identity-model.md.
