---
path: src/postgres
charted: 2026-08-21
fs:
  - name: mod.rs
    role: module docs, schema notes, re-exports
    node: false
  - name: key_store.rs
    role: PgKeyStore
    node: false
  - name: plc_log.rs
    role: PgPlcOperationLog
    node: false
  - name: oauth_state.rs
    role: PgOAuthStateStore
    node: false
---
**Is:** the three sqlx-backed stores, each built from a caller-owned `PgPool`; cheap to clone, own no runtime.

**Conventions:** SQL lives in `queries/<store>/<op>.sql`, not inline; migrations come from `build.rs`'s embedded set. sqlx surface is `derive` only — never enable `macros`.

**Refs:** `tests/postgres/` exercises every store.
