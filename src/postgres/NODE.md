---
path: src/postgres
charted: 2026-08-21
fs:
  - name: mod.rs
    role: module docs, schema/migration wiring, re-exports
    node: false
  - name: key_store.rs
    role: `PgKeyStore` — sealed custody keys
    node: false
  - name: oauth_state.rs
    role: `PgOAuthStateStore` — opaque bytes, two tiers (auth request / session)
    node: false
  - name: plc_log.rs
    role: `PgPlcOperationLog` — append-only, HMAC-protected (F30)
    node: false
---
**Is:** the PostgreSQL backing for every `store.rs` trait.

**Conventions:** SQL lives in `queries/<store>/*.sql`, not inline (F12); table/column names are frozen (F9); migrations embedded via `build.rs` (F11).

**Entry points:** `mod.rs`.

**Refs:** FORKS.md §Packaging (F9–F12) · tests/postgres/.
