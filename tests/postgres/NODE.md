---
path: tests/postgres
charted: 2026-08-21
fs:
  - name: main.rs
    role: single test binary so the suite shares one container
    node: false
  - name: pg.rs
    role: harness — one container per process, migrated template DB, per-test clone via `CREATE DATABASE … TEMPLATE`
    node: false
  - name: migrations.rs
    role: runs the migration set on an empty DB
    node: false
  - name: key_store.rs
    role: PgKeyStore round-trips (sealed blobs)
    node: false
  - name: oauth_state.rs
    role: PgOAuthStateStore round-trips
    node: false
  - name: oauth_bridge.rs
    role: JacquardAuthStore over PgOAuthStateStore end to end
    node: false
  - name: plc_log.rs
    role: op-log ordering + both integrity constraints at the storage layer
    node: false
  - name: minter.rs
    role: the whole did:plc write path on real storage
    node: false
---
**Is:** the Docker-backed integration suite (testcontainers); needs Docker running.

**Conventions:** add a test as a new module in `main.rs`, get a DB from `pg.rs` — never spin your own container. No ACP integration tests yet; the kill test will re-run here once "Talk to a PDS" lands.

**Entry points:** `main.rs`, `pg.rs`.
