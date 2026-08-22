---
path: src
charted: 2026-08-21
fs:
  - name: lib.rs
    role: crate root — module map, feature gates, public re-exports
    node: false
  - name: acp.rs
    role: `acp` feature root — ACP core module docs + re-exports
    node: false
  - name: acp/
    role: the ACP core — records, sign/verify, ports, status lists, policy
    node: true
  - name: postgres/
    role: `postgres` feature — sqlx impls of the three storage traits
    node: true
  - name: oauth/
    role: `oauth` feature — jacquard-backed atproto OAuth (mod.rs) + durable state store trait/bridge (store.rs)
    node: false
  - name: plc.rs
    role: did:plc operations — build, sign, hash (byte-exact core, always on)
    node: false
  - name: minter.rs
    role: `minter` feature — Minter: mint / update handle / tombstone
    node: false
  - name: directory.rs
    role: `directory` feature — HTTP submit to a PLC directory
    node: false
  - name: keys.rs
    role: CustodyKeys + KeyRole (F3)
    node: false
  - name: vault.rs
    role: SecretVault — envelope encryption under a root key (F4)
    node: false
  - name: policy.rs
    role: MintPolicy — identity shape as data (F8 strict updates)
    node: false
  - name: store.rs
    role: the storage seam — three persistence traits + records
    node: false
  - name: did.rs / handle.rs
    role: Did and Handle newtypes (F2)
    node: false
  - name: error.rs
    role: the two open error wrappers (F1)
    node: false
  - name: broker.rs
    role: the toolkit layer — future credential behavior home
    node: false
  - name: vc.rs
    role: `vc` feature — curated SpruceID ssi 0.16 wrap; private lane only, excludable
    node: false
  - name: axum.rs
    role: `axum` feature — /.well-known/atproto-did router
    node: false
  - name: memory.rs
    role: cfg(test) in-memory storage fakes
    node: false
---
**Is:** the crate body — a feature-free substrate (`plc`, `did`, `handle`, `keys`, `vault`, `policy`, `store`, `error`) with each I/O or crypto surface behind its own feature.

**Conventions:** private modules re-exported from `lib.rs`; only `plc`, `acp`, `axum`, `oauth`, `postgres`, `vc` are `pub mod`. Unit tests live beside the code and use `memory.rs` fakes.

**Entry points:** `lib.rs` lines ~86–110 (module + feature map).
